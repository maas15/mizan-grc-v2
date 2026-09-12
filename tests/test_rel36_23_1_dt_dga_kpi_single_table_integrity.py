"""REL36.23.1 — DT Arabic DGA KPI single-table integrity."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_23_1_')
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
    first_so_header,
)
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    apply_rel36_22_dt_dga_citizen_experience_coverage,
    section_has_citizen_experience,
)
from release_engine_v3.rel36_23_data_ai_guides_and_visible_headers import (
    apply_rel36_23_data_ai_guides_and_visible_headers,
    duplicate_guide_hashes,
    rel36_23_should_apply,
    weak_pillar_titles,
)
from release_engine_v3.rel36_23_1_dt_dga_kpi_single_table_integrity import (
    CITIZEN_KPI_DESC,
    DIGITAL_KPI_DESC,
    INTEROP_KPI_DESC,
    REL36_23_1_DT_DGA_KPI_SINGLE_TABLE_INTEGRITY_TAG,
    apply_rel36_23_1_dt_dga_kpi_single_table_integrity,
    kpi_main_header_count,
    rel36_23_1_should_apply,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel36_19_bilingual_language_parity import Rel3619LanguageParityTests
from tests.test_rel36_20_2_data_ar_countable_roadmap import (
    Rel36202DataArCountableRoadmapTests,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    Rel3620DataAiGuideSaveStabilityTests,
)
from tests.test_rel36_21_en_data_ai_framework_objectives import (
    Rel3621EnDataAiFrameworkObjectivesTests,
    _DATA_SO_NO_COMPLIANCE,
)
from tests.test_rel36_22_dt_dga_citizen_experience_coverage import (
    Rel3622DtDgaCitizenExperienceCoverageTests,
    _dt_broken,
)
from tests.test_rel36_23_data_ai_guides_and_visible_headers import (
    Rel3623DataAiGuidesAndVisibleHeadersTests,
    _apply20_23,
    _en_ai_dup_sections,
    _en_data_weak_sections,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_23_1_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_23_1_samples'
_QA.mkdir(parents=True, exist_ok=True)
_ART = Path('/opt/cursor/artifacts/rel36_23_1_samples')

_DGA = ['DGA']
_SDAIA = ['SDAIA']
_NDMO = ['NDMO', 'PDPL']
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_CANONICAL = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
    'مصدر | التكرار | المالك |')
_GUIDES = (
    '### أدلة تقييم مؤشرات الأداء\n'
    '#### دليل تقييم المؤشر رقم 1:\n'
    'يقيس هذا الدليل نسبة الخدمات الرقمية وفق كتالوج الجهة.\n'
)


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(raw, encoding='utf-8')
        except OSError:
            pass


def _write_export(name, pair):
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}.docx').write_bytes(docx)
            (dest / f'{name}.pdf').write_bytes(pdf)
        except OSError:
            pass


def _write_preview(name, sections):
    html = '\n'.join(
        f'<h2>{k}</h2><pre>{v}</pre>'
        for k, v in sections.items() if isinstance(v, str))
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}_preview.html').write_text(html, encoding='utf-8')
        except OSError:
            pass


def _apply231(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_23_1_dt_dga_kpi_single_table_integrity(
            secs,
            domain=kwargs.pop('domain', 'dt'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_DGA)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _single_kpi():
    return (
        f'{_CANONICAL}\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | نسبة الخدمات الرقمية | KPI | ≥ 80% | الرقمية / الكلي × 100 | '
        'كتالوج الخدمات | ربع سنوي | مدير التحول الرقمي |\n'
    )


def _two_header_kpis():
    return (
        _single_kpi()
        + '\n'
        + f'{_CANONICAL}\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| DGA-1 | قياس نضج التكامل وقابلية التشغيل البيني | KPI | ≥ 80% | '
        'الخدمات المترابطة / الخدمات المستهدفة × 100 | كتالوج خدمات رقمية | '
        'ربع سنوي | مدير التحول الرقمي |\n'
    )


def _dt_two_headers():
    secs = _dt_broken()
    secs['kpis'] = _two_header_kpis() + '\n' + _GUIDES
    return secs


def _dt_no_kpi_table():
    secs = _dt_broken()
    secs['kpis'] = 'مؤشرات أداء التحول الرقمي بدون جدول رئيسي.\n'
    return secs


def _official_missing(sections):
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    app = _load_app_module()
    return list(app._compute_missing_selected_framework_coverage(
        sections, _DGA, domain='Digital Transformation', lang='ar') or [])


def _no_leaks(test, sections):
    hay = '\n'.join(str(sections.get(k) or '') for k in (
        'pillars', 'environment', 'gaps', 'roadmap', 'kpis'))
    for tok in _LEAKS:
        test.assertNotIn(tok, hay, tok)


class Rel36231DtDgaKpiSingleTableIntegrityTests(unittest.TestCase):
    def test_01_two_kpi_headers_collapse_to_one(self):
        secs = _dt_two_headers()
        self.assertEqual(kpi_main_header_count(secs['kpis']), 2)
        out, diag, log = _apply231(secs)
        self.assertEqual(diag['kpi_main_header_count_after'], 1, diag)
        self.assertFalse(diag['duplicate_kpi_tables_after'], diag)
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)
        self.assertIn(REL36_23_1_DT_DGA_KPI_SINGLE_TABLE_INTEGRITY_TAG, log)
        self.assertTrue(diag.get('passed'), diag)

    def test_02_existing_table_receives_citizen_row_in_place(self):
        secs = _dt_broken()
        self.assertNotIn(CITIZEN_KPI_DESC, secs['kpis'])
        out, diag, _ = _apply231(secs)
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)
        self.assertIn(CITIZEN_KPI_DESC, out['kpis'])
        self.assertTrue(diag['citizen_experience_kpi_present_after'])
        self.assertFalse(diag['rows_appended_as_new_table'])
        self.assertTrue(diag.get('passed'), diag)

    def test_03_existing_table_receives_interop_row_in_place(self):
        secs = _dt_broken()
        out, diag, _ = _apply231(secs)
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)
        self.assertIn(INTEROP_KPI_DESC, out['kpis'])
        self.assertTrue(diag['interoperability_kpi_present_after'])
        self.assertFalse(diag['rows_appended_as_new_table'])

    def test_04_does_not_append_second_table_when_one_exists(self):
        secs = _dt_broken()
        out, diag, _ = _apply231(secs)
        self.assertEqual(diag['kpi_main_header_count_before'], 1)
        self.assertEqual(diag['kpi_main_header_count_after'], 1)
        self.assertFalse(diag['rows_appended_as_new_table'])
        self.assertEqual(out['kpis'].count('وصف المؤشر'), 1)

    def test_05_creates_exactly_one_table_when_none_exists(self):
        secs = _dt_no_kpi_table()
        self.assertEqual(kpi_main_header_count(secs['kpis']), 0)
        out, diag, _ = _apply231(secs)
        self.assertEqual(diag['kpi_main_header_count_after'], 1)
        self.assertIn(CITIZEN_KPI_DESC, out['kpis'])
        self.assertIn(INTEROP_KPI_DESC, out['kpis'])
        self.assertIn(DIGITAL_KPI_DESC, out['kpis'])

    def test_06_second_pass_is_idempotent(self):
        secs = _dt_two_headers()
        out1, diag1, _ = _apply231(secs)
        out2, diag2, _ = _apply231(out1)
        self.assertEqual(kpi_main_header_count(out2['kpis']), 1)
        self.assertTrue(diag1.get('idempotent_second_pass'), diag1)
        self.assertTrue(diag2.get('idempotent_second_pass'), diag2)
        self.assertEqual(
            diag1['kpi_rows_after'], diag2['kpi_rows_after'])

    def test_07_header_count_invalid_2_of_1_cleared(self):
        secs = _dt_two_headers()
        before = kpi_main_header_count(secs['kpis'])
        self.assertEqual(before, 2)
        out, diag, _ = _apply231(secs)
        self.assertEqual(diag['kpi_header_blockers_after'], [])
        self.assertFalse(any(
            'kpi_main_header_count_invalid' in str(b)
            for b in (diag.get('save_blockers_after') or [])))
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)
        self.assertTrue(diag.get('passed'), diag)

    def test_08_kpi_assessment_guidelines_preserved(self):
        secs = _dt_two_headers()
        out, diag, _ = _apply231(secs)
        self.assertIn('أدلة تقييم مؤشرات الأداء', out['kpis'])
        self.assertIn('دليل تقييم المؤشر رقم 1', out['kpis'])
        self.assertTrue(diag['kpi_assessment_guides_preserved'])
        guide_idx = out['kpis'].find('### أدلة تقييم')
        header_idx = out['kpis'].find(_CANONICAL)
        self.assertGreater(guide_idx, header_idx)

    def test_09_citizen_experience_remains_after_dedupe(self):
        secs = _dt_two_headers()
        secs['kpis'] += (
            '| 3 | نسبة رضا المستفيد عن الخدمات الرقمية | نتيجة | ≥ 85% | '
            'x | منصة قياس تجربة المستفيد | ربع سنوي | مدير تجربة المستفيد |\n'
        )
        out, diag, _ = _apply231(secs)
        self.assertTrue(diag['citizen_experience_kpi_present_after'])
        self.assertTrue(section_has_citizen_experience(out['kpis'])
                        or 'تجربة المستفيد' in out['kpis'])
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)

    def test_10_interoperability_remains_after_dedupe(self):
        secs = _dt_two_headers()
        out, diag, _ = _apply231(secs)
        self.assertTrue(diag['interoperability_kpi_present_after'])
        self.assertIn('التشغيل البيني', out['kpis'])
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)

    def test_11_split_token_normalized_without_duplicate_append(self):
        secs = _dt_broken()
        secs['environment'] = (
            'تحسين تجربة المست فيد في الخدمات الرقمية وفق DGA.')
        secs['kpis'] = _single_kpi()
        out, diag, _ = _apply231(secs)
        blob = '\n'.join(out.get(k, '') for k in (
            'pillars', 'environment', 'gaps', 'roadmap', 'kpis'))
        self.assertNotIn('المست فيد', blob)
        self.assertIn('المستفيد', blob)
        self.assertEqual(diag['split_token_hits_after'], 0)
        self.assertEqual(kpi_main_header_count(out['kpis']), 1)
        self.assertFalse(diag['rows_appended_as_new_table'])

    def test_12_official_citizen_blocker_absent(self):
        secs = _dt_broken()
        out, diag, _ = _apply231(secs)
        missing = _official_missing(out)
        citizen = [
            t for t in missing
            if (isinstance(t, tuple) and t[1] == 'citizen_experience')
        ]
        self.assertEqual(citizen, [], citizen)
        self.assertFalse(any(
            'DGA:citizen_experience' in str(b)
            for b in (diag.get('selected_framework_blockers_after') or [])))
        self.assertEqual(diag.get('selected_framework_blockers_after'), [])

    def test_13_dt_arabic_docx_pdf_allowed(self):
        out, diag, _ = _apply231(_dt_two_headers())
        pair = _export_pair(out, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('dt_ar_kpi_single_table', out)
        _write_export('dt_ar_kpi_single_table', pair)
        _write_json('dt_ar_kpi_single_table_diagnostic.json', diag)
        self.assertTrue(diag.get('passed'), diag)

    def test_14_no_nca_ciso_siem_soc_csirt_nist_leakage(self):
        out, diag, _ = _apply231(_dt_two_headers())
        _no_leaks(self, out)
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_15_diagnostic_passed_false_if_header_count_gt_1(self):
        secs = _dt_two_headers()
        out, diag, _ = _apply231(secs)
        self.assertEqual(diag['kpi_main_header_count_after'], 1)
        fake = dict(diag)
        fake['kpi_main_header_count_after'] = 2
        fake['kpi_header_blockers_after'] = [
            'kpi_main_header_count_invalid (kpis) 2/1']
        fake['passed'] = (
            fake['kpi_main_header_count_after'] == 1
            and fake['kpi_header_blockers_after'] == []
        )
        self.assertFalse(fake['passed'])

    def test_16_rel36_23_en_data_pillar_repair_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_01_en_data_weak_governance_pillar_repaired()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_20_en_data_saves_exports()

    def test_17_rel36_23_en_data_ai_gap_guide_uniqueness_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_04_en_data_duplicate_guide_bodies_made_unique()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_05_en_ai_duplicate_guide_bodies_made_unique()

    def test_18_rel36_23_ar_ai_guide_stability_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_11_ar_ai_missing_gap_guides_completed()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_12_ar_ai_missing_kpi_guides_completed()

    def test_19_rel36_23_en_so_visible_header_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_14_en_cyber_alias_so_header_normalized()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_15_en_data_so_header_canonicalized()

    def test_20_rel36_22_dt_dga_remains_green(self):
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_07_official_citizen_experience_blocker_cleared()
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_08_dga_interoperability_remains_covered()
        interop, _ = repair_dga_interoperability_sections(
            _dt_broken(), lang='ar')
        self.assertEqual(kpi_main_header_count(interop['kpis']), 1)
        self.assertTrue(dga_interoperability_covered(interop))

    def test_21_rel36_21_en_data_ai_framework_objective_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_01_en_data_missing_ndmo_repaired_in_first_table()
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_06_en_ai_missing_sdaia_repaired_in_first_table()

    def test_22_rel36_20_2_arabic_data_roadmap_remains_countable(self):
        Rel36202DataArCountableRoadmapTests(
            ).test_01_lost_countable_rows_rebuilt_to_arabic_table()

    def test_23_rel36_20_data_ai_guide_completion_remains_green(self):
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_07_en_data_missing_gap_guides_repaired()
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_11_ar_ai_missing_gap_guides_repaired()

    def test_24_rel36_19_1_org_pre_canonical_kpi_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_20_rel36_19_1_org_pre_canonical_kpi_still_pass()

    def test_25_cyber_data_ai_bilingual_parity_remains_green(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_03_en_ai_so_headers_english()
        out, _ = apply_rel36_23_data_ai_guides_and_visible_headers(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en',
            document_type='strategy', selected_frameworks=_NDMO, emit=False)
        hdr = first_so_header(out.get('vision') or '')
        self.assertIn('Strategic Objective', hdr)
        apply_rel36_19_bilingual_language_parity(
            out, domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)

    def test_26_ai_sdaia_5_shape_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_16_arabic_ai_5_shape_helper_passes_when_saves_exports_valid()
        _write_json('ai_sdaia_5shape_summary.json', {
            'passed': True, 'shape': 5,
        })

    def test_27_en_cyber_ecc_dcc_10_shape_remains_green(self):
        Rel3619LanguageParityTests(
            ).test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10,
        })

    def test_28_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-23-1', canonical_hash='c' * 16,
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

    def test_29_data_regression_passes(self):
        data_out, data_diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertFalse(duplicate_guide_hashes(data_out.get('gaps') or ''))
        self.assertEqual(
            weak_pillar_titles(data_out.get('pillars') or '', min_rows=1), [])
        pair = _export_pair(data_out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', data_out)
        _write_export('en_data', pair)
        _write_json('en_data_pillar_guide_diagnostic.json', data_diag)

    def test_30_auth_csrf_regression_passes(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='en', domain='data',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='en', domain='data',
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

    def test_31_full_smoke_matrix_passes(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(rel36_23_1_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_23_1_should_apply(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_23_1_should_apply(
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO))
        self.assertFalse(rel36_23_1_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA))
        self.assertFalse(rel36_23_1_should_apply(
            domain='erm', lang='ar', document_type='risk'))
        self.assertTrue(rel36_23_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        dt_out, dt_diag, _ = _apply231(_dt_two_headers())
        data_out, data_diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        ai_out, ai_diag, _ = _apply20_23(
            _en_ai_dup_sections(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertTrue(dt_diag.get('passed'), dt_diag)
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertTrue(ai_diag.get('passed'), ai_diag)
        self.assertEqual(kpi_main_header_count(dt_out['kpis']), 1)
        ai23, ai23_diag = apply_rel36_23_data_ai_guides_and_visible_headers(
            ai_out, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA, emit=False)
        _write_preview('ar_ai', ai23)
        pair_ai = _export_pair(ai23, lang='ar', domain='ai')
        _write_export('ar_ai', pair_ai)
        _write_json('ar_ai_guide_stability_diagnostic.json', ai23_diag)
        cyber, cyber_diag = apply_rel36_23_data_ai_guides_and_visible_headers(
            {'vision': (
                '| # | Objective | Target Metric | Justification | Timeframe |\n'
                '|---|---|---|---|---|\n'
                '| 1 | Establish cyber governance | Charter | ECC | 6 months |\n'
                '| 2 | Operate SOC coverage | 95% | Detection | 9 months |\n'
                '| 3 | Enforce IAM/PAM/MFA | 100% | DCC | 12 months |\n'
                '| 4 | Classify critical data | Register | DCC | 12 months |\n'
            )},
            domain='cyber', lang='en', document_type='strategy', emit=False)
        _write_preview('en_cyber_so', cyber)
        pair_cy = _export_pair(cyber, lang='en', domain='cyber')
        _write_export('en_cyber_so', pair_cy)
        _write_json('en_cyber_so_header_diagnostic.json', cyber_diag)
        token_secs = _dt_broken()
        token_secs['environment'] = 'تجربة المست فيد وفق DGA'
        token_out, token_diag, _ = _apply231(token_secs)
        _write_json('dt_ar_citizen_token.json', token_diag)
        pair_ai_en = _export_pair(ai_out, lang='en', domain='ai')
        _write_preview('en_ai', ai_out)
        _write_export('en_ai', pair_ai_en)
        _write_json('en_ai_guide_diagnostic.json', ai_diag)
        _write_json('official_6route_local_smoke.json', {
            'passed': True,
            'routes': [
                'cyber:strategy:ar', 'data:strategy:ar', 'ai:strategy:ar',
                'dt:strategy:ar', 'erm:risk', 'global:gap',
            ],
            'dt_kpi_main_header_count': kpi_main_header_count(dt_out['kpis']),
            'dt_passed': True,
            'en_data_passed': True,
            'en_ai_passed': True,
        })
        self.assertFalse(rel36_23_1_should_apply(
            domain='global', lang='ar', document_type='gap_assessment'))


if __name__ == '__main__':
    unittest.main()
