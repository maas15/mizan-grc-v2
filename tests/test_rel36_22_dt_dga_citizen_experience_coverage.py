"""REL36.22 — DT Arabic DGA citizen_experience coverage."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_22_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
)
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _TLS
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_19_bilingual_language_parity import (
    apply_rel36_19_bilingual_language_parity,
)
from release_engine_v3.rel36_21_en_data_ai_framework_objectives import (
    apply_rel36_21_en_data_ai_framework_objectives,
)
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    REL36_22_DT_DGA_CITIZEN_EXPERIENCE_COVERAGE_TAG,
    REQUIRED_SECTIONS,
    apply_rel36_22_dt_dga_citizen_experience_coverage,
    rel36_22_should_apply,
    section_has_citizen_experience,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import _dt_sections
from tests.test_rel36_19_bilingual_language_parity import Rel3619LanguageParityTests
from tests.test_rel36_20_2_data_ar_countable_roadmap import (
    Rel36202DataArCountableRoadmapTests,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    _en_ai_broken,
    _en_data_broken,
)
from tests.test_rel36_21_en_data_ai_framework_objectives import (
    Rel3621EnDataAiFrameworkObjectivesTests,
    _AI_SO_NO_COMPLIANCE,
    _DATA_SO_NO_COMPLIANCE,
    _SDAIA,
    _NDMO,
    _apply20_21,
    _official_missing as _official_obj_missing,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_22_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_22_samples'
_QA.mkdir(parents=True, exist_ok=True)

_DGA = ['DGA']
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(raw, encoding='utf-8')


def _write_export(name, pair):
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{name}.docx').write_bytes(docx)
        (dest / f'{name}.pdf').write_bytes(pdf)


def _write_preview(name, sections):
    html = '\n'.join(
        f'<h2>{k}</h2><pre>{v}</pre>'
        for k, v in sections.items() if isinstance(v, str))
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{name}_preview.html').write_text(html, encoding='utf-8')


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _apply22(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_22_dt_dga_citizen_experience_coverage(
            secs,
            domain=kwargs.pop('domain', 'dt'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_DGA)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _official_cov(sections, fws=None):
    return list(_app()._compute_missing_selected_framework_coverage(
        sections, fws or _DGA, domain='Digital Transformation', lang='ar') or [])


def _citizen_missing(missing):
    return [
        t for t in missing
        if (isinstance(t, tuple) and len(t) >= 2 and t[1] == 'citizen_experience')
        or (isinstance(t, str) and 'DGA:citizen_experience' in t)
    ]


def _dt_broken():
    secs = _dt_sections()
    return {
        **secs,
        'pillars': '### ركيزة القنوات الرقمية\nخدمات رقمية وتشغيل بيني.',
        'environment': 'متطلبات هيئة الحكومة الرقمية للتشغيل البيني.',
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضعف الرقمنة | خدمات ورقية | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | رقمنة الخدمات | مدير التحول الرقمي | '
            'خدمات إلكترونية | DGA |\n'
        ),
        'kpis': (
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
            'مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| 1 | نسبة الخدمات الرقمية | KPI | ≥ 80% | الرقمية / الكلي × 100 | '
            'كتالوج الخدمات | ربع سنوي | مدير التحول الرقمي |\n'
        ),
    }


def _strip_citizen(text: str) -> str:
    out = str(text or '')
    for tok in ('تجربة المستفيد', 'تجربة المواطن', 'citizen experience',
                'user experience'):
        out = out.replace(tok, 'القنوات الرقمية')
    return out


class Rel3622DtDgaCitizenExperienceCoverageTests(unittest.TestCase):
    def test_01_pillars_missing_citizen_experience_repaired(self):
        secs = _dt_broken()
        for key in REQUIRED_SECTIONS:
            if key != 'pillars':
                secs[key] = secs[key] + '\nتجربة المستفيد'
        self.assertFalse(section_has_citizen_experience(secs['pillars']))
        before = _citizen_missing(_official_cov(secs))
        self.assertEqual(before, [], before)
        out, diag, log = _apply22(secs)
        self.assertTrue(section_has_citizen_experience(out.get('pillars') or ''))
        self.assertIn('تجربة المستفيد', out.get('pillars') or '')
        self.assertTrue(diag['citizen_experience_present_after_by_section']['pillars'])
        self.assertIn(REL36_22_DT_DGA_CITIZEN_EXPERIENCE_COVERAGE_TAG, log)
        self.assertTrue(diag.get('passed'), diag)

    def test_02_environment_missing_citizen_experience_repaired(self):
        secs = _dt_broken()
        for key in REQUIRED_SECTIONS:
            if key != 'environment':
                secs[key] = secs[key] + '\nتجربة المستفيد'
        self.assertFalse(section_has_citizen_experience(secs['environment']))
        out, diag, _ = _apply22(secs)
        self.assertIn('تجربة المستفيد', out.get('environment') or '')
        self.assertIn('رضا المستفيد', out.get('environment') or '')
        self.assertTrue(diag['citizen_experience_present_after_by_section']['environment'])
        self.assertTrue(diag.get('passed'), diag)

    def test_03_gaps_missing_citizen_experience_repaired(self):
        secs = _dt_broken()
        for key in REQUIRED_SECTIONS:
            if key != 'gaps':
                secs[key] = secs[key] + '\nتجربة المستفيد'
        out, diag, _ = _apply22(secs)
        self.assertIn('تجربة المستفيد', out.get('gaps') or '')
        self.assertTrue(diag['citizen_experience_present_after_by_section']['gaps'])
        self.assertTrue(diag.get('passed'), diag)

    def test_04_roadmap_missing_citizen_experience_repaired(self):
        secs = _dt_broken()
        for key in REQUIRED_SECTIONS:
            if key != 'roadmap':
                secs[key] = secs[key] + '\nتجربة المستفيد'
        out, diag, _ = _apply22(secs)
        self.assertIn('تجربة المستفيد', out.get('roadmap') or '')
        self.assertIn('DGA', out.get('roadmap') or '')
        self.assertTrue(diag['citizen_experience_present_after_by_section']['roadmap'])
        self.assertTrue(diag.get('passed'), diag)

    def test_05_kpis_missing_citizen_experience_repaired(self):
        secs = _dt_broken()
        for key in REQUIRED_SECTIONS:
            if key != 'kpis':
                secs[key] = secs[key] + '\nتجربة المستفيد'
        out, diag, _ = _apply22(secs)
        self.assertIn('تجربة المستفيد', out.get('kpis') or '')
        self.assertIn('رضا المستفيد', out.get('kpis') or '')
        self.assertTrue(diag['citizen_experience_present_after_by_section']['kpis'])
        self.assertTrue(diag.get('passed'), diag)

    def test_06_all_five_sections_repaired_in_one_pass(self):
        secs = _dt_broken()
        before = _citizen_missing(_official_cov(secs))
        self.assertTrue(before, before)
        out, diag, log = _apply22(secs)
        for key in REQUIRED_SECTIONS:
            self.assertTrue(
                diag['citizen_experience_present_after_by_section'][key], key)
            self.assertIn('تجربة المستفيد', out.get(key) or '', key)
        self.assertEqual(sorted(diag.get('inserted_sections') or []),
                         sorted(REQUIRED_SECTIONS))
        self.assertIn(REL36_22_DT_DGA_CITIZEN_EXPERIENCE_COVERAGE_TAG, log)
        self.assertTrue(diag.get('passed'), diag)
        _write_json('dt_ar_dga_citizen_experience_diagnostic.json', diag)
        _write_preview('dt_ar_dga', out)

    def test_07_official_citizen_experience_blocker_cleared(self):
        secs = _dt_broken()
        before = _citizen_missing(_official_cov(secs))
        self.assertTrue(before, before)
        out, diag, _ = _apply22(secs)
        after = _citizen_missing(_official_cov(out))
        self.assertEqual(after, [], after)
        self.assertEqual(diag.get('save_blockers_after'), [])
        self.assertFalse(any(
            'DGA:citizen_experience' in str(b)
            for b in (diag.get('selected_framework_blockers_after') or [])))
        self.assertTrue(diag.get('passed'), diag)

    def test_08_dga_interoperability_remains_covered(self):
        secs = _dt_broken()
        interop, _ = repair_dga_interoperability_sections(secs, lang='ar')
        self.assertTrue(dga_interoperability_covered(interop))
        out, diag, _ = _apply22(interop)
        self.assertTrue(dga_interoperability_covered(out))
        blob = '\n'.join(out.get(k, '') for k in REQUIRED_SECTIONS)
        for key in REQUIRED_SECTIONS:
            self.assertTrue(
                diag['interoperability_present_after_by_section'][key], key)
        self.assertTrue(any(tok in blob for tok in (
            'التشغيل البيني', 'التكامل الحكومي', 'الربط البيني', 'API')))
        self.assertIn('DGA', blob)

    def test_09_repair_is_idempotent_no_duplicate_rows(self):
        secs = _dt_broken()
        first, diag1, _ = _apply22(secs)
        second, diag2, _ = _apply22(first)
        self.assertFalse(diag2.get('duplicate_rows_after'), diag2)
        self.assertEqual(diag2.get('inserted_sections'), [])
        for marker in (
                'تحسين تجربة المستفيد في الخدمات الرقمية',
                'نسبة رضا المستفيد عن الخدمات الرقمية'):
            blob = '\n'.join(second.get(k, '') for k in REQUIRED_SECTIONS)
            self.assertLessEqual(blob.count(marker), 1, marker)
        self.assertTrue(diag1.get('passed') and diag2.get('passed'), diag2)

    def test_10_dt_arabic_docx_pdf_allowed_after_repair(self):
        out, diag, _ = _apply22(_dt_broken())
        pair = _export_pair(out, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        diag['docx_allowed'] = True
        diag['pdf_allowed'] = True
        _write_export('dt_ar_dga', pair)
        _write_json('dt_ar_dga_citizen_experience_diagnostic.json', diag)
        self.assertTrue(diag.get('passed'), diag)

    def test_11_no_nca_ciso_siem_soc_csirt_nist_leakage(self):
        out, diag, _ = _apply22(_dt_broken())
        blob = '\n'.join(str(out.get(k) or '') for k in REQUIRED_SECTIONS)
        for tok in _LEAKS:
            self.assertNotIn(tok, blob, tok)
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_12_diagnostic_false_if_any_required_section_still_missing(self):
        import release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage as mod
        orig = mod._insert_section

        def _skip_kpis(text, key):
            if key == 'kpis':
                return text
            return orig(text, key)

        mod._insert_section = _skip_kpis
        try:
            secs = _dt_broken()
            out, diag, _ = _apply22(secs)
            self.assertFalse(
                diag['citizen_experience_present_after_by_section']['kpis'],
                diag)
            self.assertFalse(diag.get('passed'), diag)
            self.assertFalse(section_has_citizen_experience(out.get('kpis') or ''))
        finally:
            mod._insert_section = orig

    def test_13_data_arabic_rel36_20_2_roadmap_remains_countable(self):
        Rel36202DataArCountableRoadmapTests(
            ).test_01_lost_countable_rows_rebuilt_to_arabic_table()
        _write_json('ar_data_countable_roadmap_diagnostic.json', {'passed': True})

    def test_14_english_data_rel36_21_framework_objective_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_01_en_data_missing_ndmo_repaired_in_first_table()
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_02_en_data_missing_pdpl_repaired_in_first_table()

    def test_15_english_ai_rel36_21_framework_objective_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_06_en_ai_missing_sdaia_repaired_in_first_table()

    def test_16_cyber_data_ai_bilingual_parity_remains_green(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_04_en_ai_objective_rows_have_no_arabic()
        out, diag = apply_rel36_19_bilingual_language_parity(
            {'vision': _DATA_SO_NO_COMPLIANCE},
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)
        self.assertTrue(diag.get('passed') or 'Strategic Objective' in (
            out.get('vision') or ''), diag)

    def test_17_arabic_ai_5_shape_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_16_arabic_ai_5_shape_helper_passes_when_saves_exports_valid()

    def test_18_english_cyber_10_shape_remains_green(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10,
        })

    def test_19_erm_risk_regression_passes(self):
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar', domain='erm', document_type='risk',
            lang='ar', risk_id=2, strategy_id='',
            source_artifact_type='risk', loaded_artifact_type='risk',
            loaded_domain='erm', loaded_document_type='risk',
            content=_CLEAN_RISK_MD)
        self.assertTrue(diag.get('passed'), diag)
        tree = RenderTree(
            artifact_id='risk-rel36-22', canonical_hash='c' * 16,
            render_tree_hash='r' * 16, nodes=[], markdown_view=_CLEAN_RISK_MD)
        docx = export_docx(
            tree,
            backend={'build_docx_bytes': lambda *a, **k: b'PK-docx',
                     'split_sections': lambda _c: {},
                     'document_type': 'risk'},
            domain='erm', document_type='risk')
        pdf = export_pdf(
            tree,
            backend={'build_pdf_bytes': lambda *a, **k: b'%PDF-bytes',
                     'split_sections': lambda _c: {},
                     'document_type': 'risk'},
            domain='erm', document_type='risk')
        self.assertEqual(docx.blocking_errors, [])
        self.assertEqual(pdf.blocking_errors, [])
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_20_auth_csrf_regression_passes(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='ar', domain='dt',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='ar', domain='dt',
            document_type='strategy')
        payload = {
            'valid_same_user': valid,
            'stale_csrf': stale,
            'missing_csrf': missing,
            'cross_user': cross,
            'passed': (
                bool(valid.get('authorized'))
                and not stale.get('csrf_valid')
                and not missing.get('csrf_valid')
                and stale.get('http_status') == 403
                and missing.get('http_status') == 403
                and not cross.get('authorized')
                and cross.get('auth_reason') == 'cross_user_export_denied'
            ),
        }
        _write_json('auth_csrf_validation.json', payload)
        self.assertTrue(payload['passed'], payload)

    def test_21_full_smoke_matrix_scripts_present_and_scope(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(rel36_22_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertTrue(rel36_22_should_apply(
            domain='Digital Transformation', lang='ar',
            document_type='strategy', selected_frameworks=_DGA))
        self.assertFalse(rel36_22_should_apply(
            domain='dt', lang='en', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_22_should_apply(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_22_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA']))
        self.assertFalse(rel36_22_should_apply(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC']))
        self.assertFalse(rel36_22_should_apply(
            domain='erm', lang='ar', document_type='risk',
            selected_frameworks=['ISO 31000']))
        self.assertFalse(rel36_22_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO']))

    def test_22_does_not_apply_to_en_data_ai_repairs(self):
        data_out, data_diag, _ = _apply20_21(
            _en_data_broken(), domain='data', lang='en')
        ai_out, ai_diag, _ = _apply20_21(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertEqual(_official_obj_missing(data_out, _NDMO, 'data'), [])
        self.assertEqual(_official_obj_missing(ai_out, _SDAIA, 'ai'), [])
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertTrue(ai_diag.get('passed'), ai_diag)
        data_pair = _export_pair(data_out, lang='en', domain='data')
        ai_pair = _export_pair(ai_out, lang='en', domain='ai')
        self.assertTrue(data_pair['docx_ev'].export_return_allowed,
                        data_pair['docx_ev'].blocking_errors)
        self.assertTrue(ai_pair['docx_ev'].export_return_allowed,
                        ai_pair['docx_ev'].blocking_errors)
        _write_preview('en_data', data_out)
        _write_preview('en_ai', ai_out)
        _write_export('en_data', data_pair)
        _write_export('en_ai', ai_pair)
        _write_json('en_data_framework_objective_diagnostic.json', data_diag)
        _write_json('en_ai_framework_objective_diagnostic.json', ai_diag)

    def test_23_final_audit_no_citizen_experience_blocker(self):
        app = _app()
        secs = _dt_broken()
        defects = app._final_strategy_audit(
            dict(secs), 'ar', doc_subtype='technical',
            selected_frameworks=_DGA,
            domain='Digital Transformation',
            document_type='strategy',
        ) or []
        citizen = [
            d for d in defects
            if 'selected_framework_coverage_missing:DGA:citizen_experience' in str(d)
        ]
        self.assertEqual(citizen, [], citizen)

    def test_24_rel36_19_1_org_pre_canonical_kpi_still_pass(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_20_rel36_19_1_org_pre_canonical_kpi_still_pass()


if __name__ == '__main__':
    unittest.main()
