"""REL36.20.1 — Data roadmap family-integrity regression."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_201_')
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
    count_kpi_main_tables,
)
from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
    apply_rel36_20_data_ai_guide_save_stability,
)
from release_engine_v3.rel36_20_1_data_roadmap_family_integrity import (
    REL36_20_1_DATA_ROADMAP_FAMILY_INTEGRITY_TAG,
    apply_rel36_20_1_data_roadmap_family_integrity,
    duplicate_families,
    family_blocks,
    family_sequence,
    heading_blockers,
    restarted_families,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import _NCA_FWS
from tests.test_rel36_15_final_registry_stability import _DATA_MISSING_LIFECYCLE
from tests.test_rel36_19_bilingual_language_parity import (
    Rel36191CodexGuardTests,
    Rel3619LanguageParityTests,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    _EN_DATA_MISSING_PRIVACY,
    _GAPS_NO_GUIDES_AR,
    _GAPS_NO_GUIDES_EN,
    _KPIS_NO_GUIDES_AR,
    _KPIS_NO_GUIDES_EN,
    _THIN_PILLARS,
    _THIN_SO,
    _ar_ai_broken,
    _en_ai_broken,
    _en_data_broken,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_20_1_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_20_1_samples'
_QA.mkdir(parents=True, exist_ok=True)

_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']
_AR_RE = re.compile(r'[\u0600-\u06FF]')
_TABLE_HEAD = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
    '|---|---|---|---|---|---|\n'
)
_PRIVACY_ROW = (
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'تفعيل حوكمة الخصوصية وبرنامج حماية البيانات الشخصية | '
    'مسؤول حماية البيانات الشخصية | إطار حوكمة الخصوصية وضوابط الخصوصية معتمدة | PDPL |'
)
_CATALOG_ROW = (
    '| الربع 1 | إنشاء وتحديث كتالوج البيانات المؤسسي وجرد أصول '
    'البيانات وسجل البيانات وربطها بملكية البيانات ومصادرها مع قاموس '
    'البيانات | مكتب إدارة البيانات | كتالوج بيانات مؤسسي وسجل البيانات '
    'وجرد أصول البيانات محدث | NDMO |'
)
_QUALITY_ROW = (
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'إطلاق برنامج إدارة جودة البيانات | مدير جودة البيانات | '
    'مقاييس جودة البيانات المعتمدة ولوحة إدارة جودة البيانات | NDMO |'
)
_LIFECYCLE_ROW = (
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'اعتماد دورة حياة البيانات المؤسسية | مكتب إدارة البيانات | '
    'نموذج دورة حياة البيانات من الإنشاء إلى الإتاحة والأرشفة والإتلاف '
    'مع أدوار ومسؤوليات واضحة | NDMO |'
)
_CLASS_ROW = (
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'تصنيف وجرد البيانات الشخصية | مسؤول حماية البيانات الشخصية | '
    'سجل تصنيف البيانات الشخصية وجرد البيانات الشخصية والحساسة | PDPL |'
)
_CONSENT_ROW = (
    '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'أتمتة إدارة الموافقات | مسؤول حماية البيانات الشخصية | '
    'منصة موافقات وسجل موافقات موثق | PDPL |'
)
_DSR_ROW = (
    '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'تفعيل إدارة طلبات أصحاب البيانات | مسؤول حماية البيانات الشخصية | '
    'إجراءات وقنوات حقوق أصحاب البيانات مفعلة | PDPL |'
)
_BREACH_ROW = (
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'اعتماد إجراءات الإبلاغ عن الانتهاكات | مسؤول حماية البيانات الشخصية | '
    'خطة الإبلاغ عن الانتهاكات واختبار جاهزية خلال المهل النظامية | PDPL |'
)


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(raw, encoding='utf-8')


def _write_export(name, pair):
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{name}.docx').write_bytes(pair['docx_export'].docx_bytes or b'')
        (dest / f'{name}.pdf').write_bytes(pair['pdf_export'].pdf_bytes or b'')


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


def _apply201(sections, **kwargs):
    _TLS.depth = 0
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_20_1_data_roadmap_family_integrity(
            dict(sections),
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _apply20(sections, **kwargs):
    _TLS.depth = 0
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_20_data_ai_guide_save_stability(
            dict(sections),
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _full_ar_rows():
    return '\n'.join([
        _QUALITY_ROW, _CATALOG_ROW, _LIFECYCLE_ROW, _PRIVACY_ROW,
        _CLASS_ROW, _CONSENT_ROW, _DSR_ROW, _BREACH_ROW,
    ]) + '\n'


def _valid_ar_roadmap():
    return '## 5. خارطة التنفيذ\n\n' + _TABLE_HEAD + _full_ar_rows()


def _duplicated_heading_roadmap():
    return (
        '## 5. خارطة التنفيذ\n\n'
        + _TABLE_HEAD + _PRIVACY_ROW + '\n' + _CATALOG_ROW + '\n'
        + '\n## 5. خارطة الطريق\n\n'
        + _PRIVACY_ROW + '\n'
    )


def _restarted_family_roadmap():
    return (
        '## 5. خارطة التنفيذ\n\n'
        + _TABLE_HEAD
        + _PRIVACY_ROW + '\n'
        + _CATALOG_ROW + '\n'
        + _PRIVACY_ROW + '\n'
        + _QUALITY_ROW + '\n'
    )


class Rel36201DataRoadmapFamilyIntegrityTests(unittest.TestCase):
    def test_01_arabic_duplicated_family_repaired(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _duplicated_heading_roadmap()
        self.assertIn('roadmap_family_duplicated', heading_blockers(secs))
        out, diag, log = _apply201(secs)
        self.assertEqual(heading_blockers(out), [], heading_blockers(out))
        self.assertEqual(diag.get('duplicate_families_after'), [])
        self.assertTrue(diag.get('passed'), diag)
        self.assertIn(REL36_20_1_DATA_ROADMAP_FAMILY_INTEGRITY_TAG, log)
        _write_json('ar_data_roadmap_family_integrity_diagnostic.json', diag)
        _write_preview('ar_data', out)
        pair = _export_pair(out, lang='ar', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('ar_data', pair)

    def test_02_arabic_restarted_family_repaired(self):
        secs = {'roadmap': _restarted_family_roadmap()}
        self.assertIn('privacy_governance', restarted_families(
            family_sequence(secs['roadmap'])))
        out, diag, _ = _apply201(secs)
        seq = family_sequence(out.get('roadmap') or '')
        self.assertEqual(restarted_families(seq), [], seq)
        self.assertEqual(diag.get('restarted_families_after'), [])
        self.assertTrue(diag.get('passed'), diag)

    def test_03_arabic_valid_roadmap_left_unchanged(self):
        road = _valid_ar_roadmap()
        out, diag, _ = _apply201({'roadmap': road})
        self.assertEqual(diag.get('inserted_families'), [])
        self.assertEqual(diag.get('missing_families_after'), [])
        self.assertEqual(heading_blockers(out), [])
        before_rows = [ln for ln in road.splitlines() if ln.startswith('| المرحلة') or ln.startswith('| الربع')]
        after_rows = [ln for ln in (out.get('roadmap') or '').splitlines()
                      if ln.startswith('| المرحلة') or ln.startswith('| الربع')]
        self.assertEqual(len(after_rows), len(before_rows))

    def test_04_rel36_20_repair_idempotent_second_pass(self):
        secs = {'roadmap': _duplicated_heading_roadmap()}
        first, diag1, _ = _apply20(secs, lang='ar')
        second, diag2, _ = _apply20(first, lang='ar')
        self.assertTrue(diag1.get('family_integrity', {}).get('idempotent_second_pass'))
        self.assertEqual(diag2.get('family_integrity', {}).get('inserted_families'), [])
        self.assertEqual(first.get('roadmap'), second.get('roadmap'))

    def test_05_insert_only_missing_do_not_reinsert(self):
        road = (
            '## 5. خارطة التنفيذ\n\n' + _TABLE_HEAD
            + _QUALITY_ROW + '\n' + _CATALOG_ROW + '\n' + _LIFECYCLE_ROW + '\n'
        )
        out, diag, _ = _apply201({'roadmap': road})
        self.assertIn('privacy_governance', diag.get('inserted_families') or [])
        self.assertIn('data_catalog', diag.get('skipped_existing_families') or [])
        self.assertEqual((out.get('roadmap') or '').count('كتالوج البيانات المؤسسي'), 1)

    def test_06_all_required_ndmo_pdpl_families_present(self):
        out, diag, _ = _apply201({'roadmap': _DATA_MISSING_LIFECYCLE})
        missing = _app()._compute_missing_data_roadmap_balance_topics(
            out.get('roadmap') or '', _NDMO, lang='ar')
        self.assertEqual(missing, [], missing)
        self.assertEqual(diag.get('missing_families_after'), [])

    def test_07_family_order_canonical_contiguous(self):
        out, diag, _ = _apply201({'roadmap': _restarted_family_roadmap()})
        seq = family_sequence(out.get('roadmap') or '')
        self.assertEqual(restarted_families(seq), [])
        self.assertEqual(duplicate_families(seq), [])
        order = [f for f in (
            'data_quality', 'data_catalog', 'data_lifecycle',
            'privacy_governance', 'personal_data_classification',
            'consent_management', 'data_subject_rights', 'breach_notification',
        ) if f in seq]
        self.assertEqual(family_blocks(seq), order, seq)

    def test_08_roadmap_family_duplicated_cleared(self):
        secs = {'roadmap': _duplicated_heading_roadmap()}
        self.assertIn('roadmap_family_duplicated', heading_blockers(secs))
        out, diag, _ = _apply201(secs)
        self.assertNotIn('roadmap_family_duplicated', heading_blockers(out))
        self.assertEqual(diag.get('roadmap_family_blockers_after'), [])
        defects = _app().validate_arabic_section_family_integrity(out, 'ar')
        self.assertFalse(
            any(t == 'roadmap_family_duplicated' for t, _ in defects), defects)

    def test_09_roadmap_family_restart_detected_cleared(self):
        secs = {
            'roadmap': _duplicated_heading_roadmap(),
            'kpis': '## 5. خارطة الطريق\n\nمؤشرات',
        }
        self.assertIn('roadmap_family_restart_detected', heading_blockers(secs))
        out, diag, _ = _apply201(secs)
        self.assertNotIn('roadmap_family_restart_detected', heading_blockers(out))
        uniq = _app().validate_arabic_family_uniqueness(out, 'ar')
        self.assertFalse(
            any(t == 'roadmap_family_restart_detected' for t, _ in uniq), uniq)
        self.assertEqual(diag.get('roadmap_family_blockers_after'), [])

    def test_10_guide_completion_does_not_mutate_roadmap(self):
        road = _valid_ar_roadmap()
        secs = {
            'roadmap': road,
            'gaps': _GAPS_NO_GUIDES_AR,
            'kpis': _KPIS_NO_GUIDES_AR,
        }
        out, diag, _ = _apply20(secs, lang='ar')
        self.assertFalse(diag.get('guides', {}).get('roadmap_mutated'))
        self.assertIn('#### دليل تنفيذ الفجوة', out.get('gaps') or '')
        self.assertNotIn('#### دليل تنفيذ الفجوة', out.get('roadmap') or '')
        self.assertNotIn('## 6. مؤشرات الأداء الرئيسية', out.get('roadmap') or '')

    def test_11_english_privacy_governance_still_works(self):
        out, diag, _ = _apply20(
            {'roadmap': _EN_DATA_MISSING_PRIVACY}, domain='data', lang='en')
        road = out.get('roadmap') or ''
        self.assertIn('privacy governance', road.lower())
        missing = _app()._compute_missing_data_roadmap_balance_topics(
            road, _NDMO, lang='en')
        self.assertEqual(missing, [], missing)
        self.assertTrue(
            diag.get('roadmap', {}).get('privacy_governance_present_after'))

    def test_12_english_data_saves_exports(self):
        out, _, _ = _apply20(_en_data_broken(), domain='data', lang='en')
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', out)
        _write_export('en_data', pair)
        _write_json('en_data_guide_diagnostic.json', {'save_export': True})

    def test_13_english_ai_saves_exports(self):
        out, _, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)
        _write_json('en_ai_guide_diagnostic.json', {'save_export': True})

    def test_14_en_data_ai_gap_guides_count(self):
        data_out, _, _ = _apply20(
            {'gaps': _GAPS_NO_GUIDES_EN}, domain='data', lang='en')
        ai_out, _, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertGreaterEqual(_app().count_gap_guides(data_out.get('gaps') or ''), 2)
        self.assertGreaterEqual(_app().count_gap_guides(ai_out.get('gaps') or ''), 2)

    def test_15_en_data_ai_kpi_guides_count(self):
        data_out, _, _ = _apply20(
            {'kpis': _KPIS_NO_GUIDES_EN}, domain='data', lang='en')
        ai_out, _, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertGreaterEqual(
            _app().count_kpi_guides(data_out.get('kpis') or ''), 4)
        self.assertGreaterEqual(
            _app().count_kpi_guides(ai_out.get('kpis') or ''), 4)

    def test_16_arabic_ai_guide_completeness_still_passes(self):
        out, diag, _ = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        self.assertIn('#### دليل تنفيذ الفجوة رقم 1', out.get('gaps') or '')
        self.assertIn('### أدلة تقييم مؤشرات الأداء', out.get('kpis') or '')
        self.assertEqual(diag.get('guides', {}).get('missing_gap_guides_after'), [])
        self.assertEqual(diag.get('guides', {}).get('missing_kpi_guides_after'), [])
        pair = _export_pair(out, lang='ar', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        _write_preview('ar_ai', out)
        _write_export('ar_ai', pair)
        _write_json('ar_ai_guide_diagnostic.json', diag.get('guides') or {})

    def test_17_rel36_19_1_org_name_preservation(self):
        Rel36191CodexGuardTests().test_01_en_cyber_arabic_org_preserved()
        Rel36191CodexGuardTests().test_02_en_data_arabic_org_prose_removed()
        _write_json('rel36_19_1_org_preservation.json', {'passed': True})

    def test_18_rel36_19_1_pre_canonical_repair(self):
        Rel36191CodexGuardTests().test_08_repair_runs_before_canonical_artifact()
        _write_json('rel36_19_1_pre_canonical.json', {'passed': True})

    def test_19_rel36_19_1_kpi_duplicate_prevention(self):
        Rel36191CodexGuardTests().test_13_valid_alias_kpi_no_second_seed()
        _write_json('rel36_19_1_kpi_duplicate.json', {'passed': True})

    def test_20_cyber_data_ai_bilingual_parity(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_03_en_ai_so_headers_english()
        Rel3619LanguageParityTests().test_10_ar_kpi_guide_headers_remain_arabic()
        Rel3619LanguageParityTests().test_20_ar_cyber_remains_arabic_with_acronyms()

    def test_21_ai_sdaia_5_shape(self):
        Rel3619LanguageParityTests().test_27_rel36_18_ai_sdaia_5_shape_regression()
        _write_json('ai_sdaia_5shape_summary.json', {'passed': True, 'shape': 5})

    def test_22_en_cyber_ecc_dcc_10_shape(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10})

    def test_23_erm_risk_regression(self):
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar', domain='erm', document_type='risk',
            lang='ar', risk_id=2, strategy_id='',
            source_artifact_type='risk', loaded_artifact_type='risk',
            loaded_domain='erm', loaded_document_type='risk',
            content=_CLEAN_RISK_MD)
        self.assertTrue(diag.get('passed'), diag)
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_24_dt_dga_regression(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_25_auth_csrf_regression(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='ar', domain='data',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='ar', domain='data',
            document_type='strategy')
        payload = {
            'valid_same_user': valid,
            'stale_csrf': stale,
            'missing_csrf': missing,
            'cross_user': cross,
            'passed': (
                bool(valid.get('authorized'))
                and stale.get('http_status') == 403
                and missing.get('http_status') == 403
                and not stale.get('csrf_valid')
                and not missing.get('csrf_valid')
                and not cross.get('authorized')
                and cross.get('auth_reason') == 'cross_user_export_denied'
            ),
        }
        _write_json('auth_csrf_validation.json', payload)
        self.assertTrue(payload['passed'], payload)

    def test_26_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
