"""REL36.20.2 — Arabic Data countable roadmap preservation."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_202_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

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
from release_engine_v3.rel36_20_1_data_roadmap_family_integrity import (
    apply_rel36_20_1_data_roadmap_family_integrity,
    family_blocks,
    family_sequence,
    heading_blockers,
    restarted_families,
)
from release_engine_v3.rel36_20_2_data_ar_countable_roadmap import (
    CANONICAL_AR_HEADER,
    REL36_20_2_DATA_AR_COUNTABLE_ROADMAP_TAG,
    apply_rel36_20_2_data_ar_countable_roadmap,
)
from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
    REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG,
    REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG,
    REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG,
    apply_rel36_20_data_ai_guide_save_stability,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_19_bilingual_language_parity import (
    Rel36191CodexGuardTests,
    Rel3619LanguageParityTests,
)
from tests.test_rel36_20_1_data_roadmap_family_integrity import (
    _BREACH_ROW,
    _CATALOG_ROW,
    _CLASS_ROW,
    _CONSENT_ROW,
    _DSR_ROW,
    _GAPS_NO_GUIDES_AR,
    _KPIS_NO_GUIDES_AR,
    _LIFECYCLE_ROW,
    _PRIVACY_ROW,
    _TABLE_HEAD,
    _duplicated_heading_roadmap,
    _valid_ar_roadmap,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    _EN_DATA_MISSING_PRIVACY,
    _ar_ai_broken,
    _en_ai_broken,
    _en_data_broken,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_20_2_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_20_2_samples'
_QA.mkdir(parents=True, exist_ok=True)
_ART = Path('/opt/cursor/artifacts/rel36_20_2_samples')

_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']
_CANONICAL_HEADER_CELLS = (
    'المرحلة', 'الفترة', 'المبادرة', 'المسؤول', 'المخرج المتوقع', 'الإطار',
)


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(raw, encoding='utf-8')
        except Exception:
            pass


def _write_export(name, pair):
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}.docx').write_bytes(pair['docx_export'].docx_bytes or b'')
            (dest / f'{name}.pdf').write_bytes(pair['pdf_export'].pdf_bytes or b'')
        except Exception:
            pass


def _write_preview(name, sections):
    html = '\n'.join(
        f'<h2>{k}</h2><pre>{v}</pre>'
        for k, v in sections.items() if isinstance(v, str))
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}_preview.html').write_text(html, encoding='utf-8')
        except Exception:
            pass


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _count(text):
    return _app()._count_substantive_roadmap_rows(text or '')


def _apply202(sections, **kwargs):
    _TLS.depth = 0
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_20_2_data_ar_countable_roadmap(
            dict(sections),
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


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


def _rows_without_header():
    return (
        '## 5. خارطة التنفيذ\n\n'
        + _PRIVACY_ROW + '\n' + _CATALOG_ROW + '\n'
        + _LIFECYCLE_ROW + '\n' + _CLASS_ROW + '\n'
    )


def _header_ok(text):
    return all(tok in (_first_header(text) or '') for tok in (
        'المرحلة', 'المبادرة', 'المسؤول'))


def _first_header(text):
    for ln in (text or '').splitlines():
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and '---' not in s:
            return s
    return ''


class Rel36202DataArCountableRoadmapTests(unittest.TestCase):
    def test_01_lost_countable_rows_rebuilt_to_arabic_table(self):
        before = _rows_without_header()
        self.assertEqual(_count(before), 0, before)
        out, diag, log = _apply202({'roadmap': before})
        road = out.get('roadmap') or ''
        self.assertGreaterEqual(_count(road), 4, road)
        self.assertTrue(_header_ok(road), _first_header(road))
        self.assertIn(CANONICAL_AR_HEADER, road)
        self.assertIn(REL36_20_2_DATA_AR_COUNTABLE_ROADMAP_TAG, log)
        self.assertTrue(diag.get('passed'), diag)
        _write_json('ar_data_countable_roadmap_diagnostic.json', diag)
        _write_preview('ar_data', out)
        pair = _export_pair(out, lang='ar', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('ar_data', pair)

    def test_02_roadmap_rows_insufficient_0_of_4_cleared(self):
        before = _rows_without_header()
        self.assertEqual(_count(before), 0)
        out, diag, _ = _apply201({'roadmap': before})
        road = out.get('roadmap') or ''
        self.assertGreaterEqual(_count(road), 4, road)
        self.assertEqual(diag.get('countable_roadmap', {}).get(
            'roadmap_rows_blockers_after'), [])
        defects = []
        n = _count(road)
        if n < 4:
            defects.append(f'roadmap_rows_insufficient:{n}/4')
        self.assertEqual(defects, [])

    def test_03_canonical_arabic_header_recognized_by_counter(self):
        out, _, _ = _apply202({'roadmap': _rows_without_header()})
        header = _first_header(out.get('roadmap') or '')
        self.assertEqual(header, CANONICAL_AR_HEADER)
        for cell in _CANONICAL_HEADER_CELLS:
            self.assertIn(cell, header)
        self.assertGreaterEqual(_count(out.get('roadmap') or ''), 4)

    def test_04_at_least_four_countable_rows_remain(self):
        out, diag, _ = _apply202({'roadmap': _rows_without_header()})
        self.assertGreaterEqual(diag.get('countable_rows_after'), 4)
        self.assertGreaterEqual(diag.get('roadmap_rows_count_after'), 4)
        self.assertGreaterEqual(_count(out.get('roadmap') or ''), 4)

    def test_05_all_required_data_families_remain(self):
        out, diag, _ = _apply202({'roadmap': _rows_without_header()})
        missing = _app()._compute_missing_data_roadmap_balance_topics(
            out.get('roadmap') or '', _NDMO, lang='ar')
        self.assertEqual(missing, [], missing)
        self.assertEqual(diag.get('missing_families_after'), [])

    def test_06_no_roadmap_family_duplicated(self):
        secs = {'roadmap': _duplicated_heading_roadmap()}
        self.assertIn('roadmap_family_duplicated', heading_blockers(secs))
        out, diag, _ = _apply201(secs)
        self.assertNotIn('roadmap_family_duplicated', heading_blockers(out))
        self.assertEqual(
            (diag.get('countable_roadmap') or diag).get(
                'roadmap_family_blockers_after', heading_blockers(out)),
            [])
        defects = _app().validate_arabic_section_family_integrity(out, 'ar')
        self.assertFalse(
            any(t == 'roadmap_family_duplicated' for t, _ in defects), defects)

    def test_07_no_roadmap_family_restart_detected(self):
        secs = {
            'roadmap': _duplicated_heading_roadmap(),
            'kpis': '## 5. خارطة الطريق\n\nمؤشرات',
        }
        out, diag, _ = _apply201(secs)
        self.assertNotIn('roadmap_family_restart_detected', heading_blockers(out))
        uniq = _app().validate_arabic_family_uniqueness(out, 'ar')
        self.assertFalse(
            any(t == 'roadmap_family_restart_detected' for t, _ in uniq), uniq)

    def test_08_family_rows_contiguous_canonical(self):
        out, _, _ = _apply202({'roadmap': (
            '## 5. خارطة التنفيذ\n\n'
            + _PRIVACY_ROW + '\n' + _CATALOG_ROW + '\n' + _PRIVACY_ROW + '\n'
        )})
        seq = family_sequence(out.get('roadmap') or '')
        self.assertEqual(restarted_families(seq), [], seq)
        order = [f for f in (
            'data_quality', 'data_catalog', 'data_lifecycle',
            'privacy_governance', 'personal_data_classification',
            'consent_management', 'data_subject_rights', 'breach_notification',
        ) if f in seq]
        self.assertEqual(family_blocks(seq), order, seq)

    def test_09_second_pass_idempotent_keeps_rows(self):
        first, d1, _ = _apply202({'roadmap': _rows_without_header()})
        second, d2, _ = _apply202(first)
        self.assertTrue(d1.get('idempotent_second_pass'), d1)
        self.assertEqual(_count(first.get('roadmap') or ''),
                         _count(second.get('roadmap') or ''))
        self.assertGreaterEqual(_count(second.get('roadmap') or ''), 4)
        self.assertEqual(d2.get('inserted_families', []), [])

    def test_10_guide_headings_not_inside_roadmap(self):
        secs = {
            'roadmap': (
                _rows_without_header()
                + '\n#### دليل تنفيذ الفجوة رقم 1\n'
            ),
            'gaps': _GAPS_NO_GUIDES_AR,
            'kpis': _KPIS_NO_GUIDES_AR,
        }
        out, diag, _ = _apply20(secs, lang='ar')
        road = out.get('roadmap') or ''
        self.assertNotIn('#### دليل تنفيذ الفجوة', road)
        self.assertNotIn('### أدلة تقييم مؤشرات', road)
        self.assertIn('#### دليل تنفيذ الفجوة', out.get('gaps') or '')
        countable = (diag.get('family_integrity') or {}).get(
            'countable_roadmap') or {}
        self.assertEqual(
            countable.get('guide_headings_inside_roadmap_after', []), [])

    def test_11_valid_arabic_roadmap_unchanged_except_safe_norm(self):
        road = _valid_ar_roadmap()
        before_rows = [
            ln for ln in road.splitlines()
            if ln.startswith('| المرحلة') or ln.startswith('| الربع')
        ]
        out, diag, _ = _apply202({'roadmap': road})
        after_rows = [
            ln for ln in (out.get('roadmap') or '').splitlines()
            if ln.startswith('| المرحلة') or ln.startswith('| الربع')
        ]
        self.assertGreaterEqual(len(after_rows), 4)
        self.assertEqual(len(after_rows), len(before_rows), after_rows)
        self.assertGreaterEqual(_count(out.get('roadmap') or ''), 4)

    def test_12_no_nca_ciso_siem_soc_csirt_nist_leakage(self):
        out, diag, _ = _apply202({'roadmap': _rows_without_header()})
        blob = '\n'.join(str(v) for v in out.values())
        for tok in (
                'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
                'NIST CSF', 'NIST AI RMF'):
            self.assertNotIn(tok, blob)
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_13_english_data_privacy_governance_and_guides(self):
        out, diag, log = _apply20(
            {'roadmap': _EN_DATA_MISSING_PRIVACY,
             'gaps': _en_data_broken()['gaps'],
             'kpis': _en_data_broken()['kpis']},
            domain='data', lang='en')
        self.assertIn('privacy governance', (out.get('roadmap') or '').lower())
        self.assertTrue(
            (diag.get('roadmap') or {}).get('privacy_governance_present_after'))
        self.assertIn(REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG, log)
        _write_json('en_data_roadmap_guide_diagnostic.json', diag.get('roadmap') or {})

    def test_14_english_data_saves_exports(self):
        out, diag, _ = _apply20(_en_data_broken(), domain='data', lang='en')
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', out)
        _write_export('en_data', pair)
        _write_json('en_data_guide_diagnostic.json', diag.get('guides') or {})

    def test_15_english_ai_saves_exports(self):
        out, diag, log = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        self.assertIn(REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG, log)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)
        _write_json('en_ai_guide_diagnostic.json', diag.get('guides') or {})

    def test_16_arabic_ai_guide_completeness_still_passes(self):
        out, diag, log = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        self.assertIn('#### دليل تنفيذ الفجوة رقم 1', out.get('gaps') or '')
        self.assertIn('### أدلة تقييم مؤشرات الأداء', out.get('kpis') or '')
        self.assertEqual((diag.get('guides') or {}).get('missing_gap_guides_after'), [])
        self.assertEqual((diag.get('guides') or {}).get('missing_kpi_guides_after'), [])
        self.assertIn(REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG, log)
        pair = _export_pair(out, lang='ar', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        _write_preview('ar_ai', out)
        _write_export('ar_ai', pair)
        _write_json('ar_ai_guide_diagnostic.json', diag.get('guides') or {})

    def test_17_rel36_20_guide_diagnostics_still_pass(self):
        out, diag, log = _apply20(_en_data_broken(), domain='data', lang='en')
        self.assertTrue((diag.get('roadmap') or {}).get('passed'), diag.get('roadmap'))
        self.assertTrue((diag.get('guides') or {}).get('passed'), diag.get('guides'))
        self.assertIn(REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG, log)

    def test_18_rel36_19_1_org_precanonical_kpi(self):
        Rel36191CodexGuardTests().test_01_en_cyber_arabic_org_preserved()
        Rel36191CodexGuardTests().test_08_repair_runs_before_canonical_artifact()
        Rel36191CodexGuardTests().test_13_valid_alias_kpi_no_second_seed()
        _write_json('rel36_19_1_org_preservation.json', {'passed': True})
        _write_json('rel36_19_1_pre_canonical.json', {'passed': True})
        _write_json('rel36_19_1_kpi_duplicate.json', {'passed': True})

    def test_19_cyber_data_ai_bilingual_parity(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_03_en_ai_so_headers_english()
        Rel3619LanguageParityTests().test_10_ar_kpi_guide_headers_remain_arabic()
        Rel3619LanguageParityTests().test_20_ar_cyber_remains_arabic_with_acronyms()

    def test_20_ai_sdaia_5_shape(self):
        Rel3619LanguageParityTests().test_27_rel36_18_ai_sdaia_5_shape_regression()
        _write_json('ai_sdaia_5shape_summary.json', {'passed': True, 'shape': 5})

    def test_21_en_cyber_ecc_dcc_10_shape(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10})

    def test_22_erm_risk_regression(self):
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

    def test_23_dt_dga_regression(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_24_auth_csrf_regression(self):
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

    def test_25_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
