"""REL36.18 — AI SDAIA Arabic KPI synthesis first-table repair."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_18_')
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
    detect_visible_frameworks,
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_7_data_pdpl_roadmap_balance import (
    apply_rel36_7_data_pdpl_roadmap_balance,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _TLS
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    apply_rel36_10_data_catalog_roadmap_balance,
)
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    apply_rel36_15_final_registry_stability,
)
from release_engine_v3.rel36_17_en_cyber_final_save_gate_stabilizer import (
    apply_rel36_17_en_cyber_final_save_gate_stabilizer,
)
from release_engine_v3.rel36_18_ai_sdaia_kpi_synth import (
    REL36_18_AI_SDAIA_KPI_SYNTH_REPAIR_TAG,
    apply_rel36_18_ai_sdaia_kpi_synth,
    rel36_18_should_apply,
    repair_first_kpi_table,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import _NCA_FWS
from tests.test_rel36_15_final_registry_stability import _DATA_MISSING_LIFECYCLE
from tests.test_rel36_17_english_cyber_final_save_gate_stabilizer import (
    _apply17,
    _assert_save_clean,
    _official_so_gate,
    _prior_repairs,
    _seed_sections,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_18_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_18_samples'
_QA.mkdir(parents=True, exist_ok=True)

_SDAIA = ['SDAIA']
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'IAM', 'PAM',
    'MFA', 'CSIRT', 'NIST CSF', 'NIST Cybersecurity Framework',
    'NIST AI RMF',
)

_MISSING_KPI = '## 6. مؤشرات الأداء الرئيسية\n\nلا يوجد جدول مؤشرات.\n'
_MALFORMED_FIRST_PLUS_LATER = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | KPI | Target |\n'
    '|---|---|---|\n'
    '| 1 | TBD | TBD |\n\n'
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | تغطية سجل النماذج | لاحق | 100% | المسجلة ÷ المنتجة × 100 | سجل النماذج | ربع سنوي | مدير مخاطر النماذج |\n'
)
_NO_GUIDES = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | تغطية سجل النماذج | لاحق | 100% | المسجلة ÷ المنتجة × 100 | سجل النماذج | ربع سنوي | مدير مخاطر النماذج |\n'
)
_CYBER_LEAK_KPI = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | تغطية NCA ECC | لاحق | 95% | الضوابط ÷ النطاق | سجل CISO | ربع سنوي | CISO |\n'
    '| 2 | زمن استجابة SIEM | قائد | 15 دقيقة | التنبيهات ضمن SLA | SOC/SIEM | شهري | SOC Manager |\n'
)


def _app():
    import app as app_mod
    return app_mod


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


def _ai_secs(kpis=None):
    secs = dict(_ai_sections())
    if kpis is not None:
        secs['kpis'] = kpis
    return secs


def _apply18(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _ai_secs(_MISSING_KPI))
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_18_ai_sdaia_kpi_synth(
            secs,
            domain=kwargs.pop('domain', 'ai'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', _SDAIA),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            task_id=kwargs.pop('task_id', 'local-rel36-18'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _assert_synth_kpi_noop(testcase, sections):
    app = _app()
    os.environ['OPENAI_API_KEY'] = ''
    before = sections.get('kpis')
    added = app.synthesize_kpi_depth(
        sections, 'ar', domain='Artificial Intelligence', fw_short='SDAIA',
        generation_mode='drafting')
    testcase.assertEqual(added, 0, added)
    testcase.assertEqual(sections.get('kpis'), before)


def _assert_no_leaks(testcase, text):
    hay = str(text or '')
    for tok in _LEAKS:
        testcase.assertNotIn(tok, hay, tok)


class Rel3618RepairTests(unittest.TestCase):
    def test_01_malformed_or_missing_kpi_repaired_before_synth(self):
        before = _app().count_substantive_kpis(_MISSING_KPI)
        self.assertLess(before, 4)
        out, diag, log = _apply18(_ai_secs(_MISSING_KPI))
        self.assertGreaterEqual(diag.get('kpi_rows_after'), 4, diag)
        self.assertEqual(diag.get('synth_kpis_blockers_after'), [], diag)
        self.assertTrue(diag.get('schema_valid_after'), diag)
        self.assertIn(REL36_18_AI_SDAIA_KPI_SYNTH_REPAIR_TAG, log)
        _assert_synth_kpi_noop(self, dict(out))
        _write_json('ai_sdaia_kpi_diagnostic.json', diag)

    def test_02_first_counted_table_replaced_not_second_ignored(self):
        out, diag, _ = _apply18(_ai_secs(_MALFORMED_FIRST_PLUS_LATER))
        kpis = out.get('kpis') or ''
        headers = list(re.finditer(
            r'(?im)^\|\s*#\s*\|\s*(?:وصف المؤشر|KPI Description|KPI)\s*\|',
            kpis))
        self.assertEqual(len(headers), 1, kpis)
        self.assertIn('وصف المؤشر', diag.get('first_kpi_table_header_after') or '')
        self.assertNotIn('| # | KPI | Target |', kpis)
        self.assertGreaterEqual(diag.get('first_kpi_table_rows_after'), 4, diag)

    def test_03_arabic_header_matches_official_schema(self):
        out, diag, _ = _apply18(_ai_secs(_NO_GUIDES))
        hdr = diag.get('first_kpi_table_header_after') or ''
        for col in (
                'وصف المؤشر', 'النوع', 'القيمة المستهدفة', 'صيغة الاحتساب',
                'مصدر', 'التكرار', 'المالك'):
            self.assertIn(col, hdr, hdr)
        self.assertTrue(diag.get('schema_valid_after'), diag)
        self.assertIn('| # | وصف المؤشر |', out.get('kpis') or '')

    def test_04_kpi_row_count_passes_real_gate(self):
        out, diag, _ = _apply18(_ai_secs(_MISSING_KPI))
        self.assertGreaterEqual(
            _app().count_substantive_kpis(out.get('kpis') or ''), 4)
        self.assertGreaterEqual(diag.get('kpi_rows_after'), 4, diag)
        _assert_synth_kpi_noop(self, dict(out))

    def test_05_synth_failed_kpis_cleared_after_real_repair(self):
        secs = _ai_secs(_MISSING_KPI)
        blockers_before = apply_rel36_18_ai_sdaia_kpi_synth(
            dict(secs), domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA, emit=False)[1]
        # Force inspect before by calling blockers on raw text via after-apply.
        out, diag, _ = _apply18(secs)
        self.assertIn('synth_failed:kpis',
                      diag.get('synth_kpis_blockers_before') or [])
        self.assertNotIn('synth_failed:kpis',
                         diag.get('synth_kpis_blockers_after') or [])
        self.assertEqual(diag.get('synth_kpis_blockers_after'), [], diag)
        self.assertTrue(diag.get('passed'), diag)
        del blockers_before

    def test_06_ai_governance_roles_not_cyber(self):
        out, diag, _ = _apply18(_ai_secs(_CYBER_LEAK_KPI))
        blob = out.get('kpis') or ''
        self.assertTrue(diag.get('ai_domain_roles_after'), diag)
        self.assertIn('مسؤول حوكمة الذكاء الاصطناعي', blob)
        self.assertIn('سجل نماذج الذكاء الاصطناعي', blob)
        for tok in ('CISO', 'SOC Manager', 'IAM/PAM'):
            self.assertNotIn(tok, blob)

    def test_07_no_nca_ciso_siem_soc_iam_pam_mfa_csirt_leakage(self):
        out, diag, _ = _apply18(_ai_secs(_CYBER_LEAK_KPI))
        _assert_no_leaks(self, out.get('kpis') or '')
        self.assertEqual(diag.get('leakage_terms_after'), [], diag)

    def test_08_no_nist_leakage_unless_selected(self):
        leaked = dict(_ai_sections())
        leaked['kpis'] = (
            _NO_GUIDES
            + '\nNIST CSF and NIST AI RMF and NIST Cybersecurity Framework\n')
        out, diag, _ = _apply18(leaked)
        _assert_no_leaks(self, out.get('kpis') or '')
        self.assertEqual(diag.get('leakage_terms_after'), [], diag)
        self.assertFalse(rel36_18_should_apply(
            domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=_NCA_FWS))

    def test_09_ai_sdaia_generate_save_equivalent_passes(self):
        out, diag, _ = _apply18(_ai_secs(_MISSING_KPI))
        self.assertTrue(diag.get('passed'), diag)
        self.assertEqual(diag.get('save_blockers_after'), [], diag)
        _assert_synth_kpi_noop(self, dict(out))
        self.assertIn('SDAIA', ' '.join(_SDAIA))
        self.assertIn('سدايا', out.get('kpis') or '')

    def test_10_ai_sdaia_docx_pdf_allowed(self):
        out, diag, _ = _apply18(_ai_secs(_MISSING_KPI))
        pair = _export_pair(out, lang='ar', domain='ai')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('ai_sdaia', pair)
        diag['docx_allowed'] = True
        diag['pdf_allowed'] = True
        _write_json('ai_sdaia_kpi_diagnostic.json', diag)


class Rel3618RegressionTests(unittest.TestCase):
    def test_11_english_cyber_rel36_17_10_shape_regression_passes(self):
        from tests.test_rel36_13_english_cyber_core_completeness import (
            _WEAK_CONF, _WEAK_ENV, _WEAK_GAPS, _WEAK_KPI, _WEAK_VISION,
        )
        from tests.test_rel36_14_english_cyber_final_counted_structures import (
            _duplicate_gap_guides, _empty_first_csf_plus_second_table,
            _imbalanced_roadmap_ecc2_dcc8,
        )
        from tests.test_rel36_15_final_registry_stability import (
            _NO_CLASSIFICATION_ROADMAP, _REL3613_KPI,
        )
        from tests.test_rel36_16_english_cyber_vision_pillars_objectives import (
            _empty_so_vision, _malformed_first_so_plus_later,
            _no_fw_compliance_vision, _residue_pillars,
        )
        from tests.test_rel36_8_english_cyber_pillars_parity import (
            _malformed_en_cyber_pillars,
        )
        from tests.test_rel36_17_english_cyber_final_save_gate_stabilizer import (
            _duplicate_gov_so, _target_like_so,
        )
        shapes = [
            ('s1', _seed_sections(vision=_duplicate_gov_so())),
            ('s2', _seed_sections(vision=_target_like_so())),
            ('s3', _seed_sections(vision=_empty_so_vision(),
                                  pillars=_residue_pillars())),
            ('s4', _seed_sections(vision=_malformed_first_so_plus_later(),
                                  gaps=_WEAK_GAPS)),
            ('s5', _seed_sections(vision=_no_fw_compliance_vision(),
                                  confidence=_WEAK_CONF)),
            ('s6', _seed_sections(pillars=_malformed_en_cyber_pillars(),
                                  gaps=_duplicate_gap_guides())),
            ('s7', _seed_sections(confidence=_empty_first_csf_plus_second_table(),
                                  kpis=_REL3613_KPI,
                                  roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s8', _seed_sections(vision=_target_like_so(),
                                  pillars=_malformed_en_cyber_pillars(),
                                  roadmap=_imbalanced_roadmap_ecc2_dcc8())),
            ('s9', _seed_sections(
                vision=_duplicate_gov_so(),
                pillars=_malformed_en_cyber_pillars(),
                gaps=_WEAK_GAPS,
                confidence=_empty_first_csf_plus_second_table())),
            ('s10', _seed_sections(
                vision=_target_like_so(),
                pillars=_residue_pillars(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table(),
                kpis=_WEAK_KPI,
                roadmap=_imbalanced_roadmap_ecc2_dcc8())),
        ]
        summary = []
        for attempt_id, secs in shapes:
            prior = _prior_repairs(secs)
            out17, diag17, _ = _apply17(
                prior, attempt_id=attempt_id, task_id=attempt_id)
            out18, diag18, _ = _apply18(
                out17, domain='cyber', lang='en',
                selected_frameworks=_NCA_FWS, task_id=attempt_id)
            self.assertFalse(diag18.get('applied'), diag18)
            pair = _export_pair(out17, lang='en', domain='cyber')
            so_gate = _official_so_gate(out17.get('vision') or '')
            rec = {
                'attempt_id': attempt_id,
                'rel36_17_passed': bool(diag17.get('passed')),
                'rel36_18_applied': bool(diag18.get('applied')),
                'so_gate_passed': bool(so_gate.get('gate_passed')),
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'passed': (
                    bool(diag17.get('passed'))
                    and not diag18.get('applied')
                    and bool(so_gate.get('gate_passed'))
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        self.assertEqual(payload['pass_count'], 10)
        pair = _export_pair(out17, lang='en', domain='cyber')
        _write_export('en_cyber_ecc_dcc', pair)

    def test_12_data_ndmo_pdpl_regression_passes(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        out15, _ = apply_rel36_15_final_registry_stability(
            secs, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        out, diag, _ = _apply18(
            out15, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        self.assertFalse(diag.get('applied'), diag)
        official = _app()._compute_missing_data_roadmap_balance_topics(
            out15.get('roadmap') or '', ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(official, [], official)
        pair = _export_pair(out15, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_13_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        out, diag, _ = _apply18(
            sections, domain='cyber', lang='ar', selected_frameworks=_NCA_FWS)
        self.assertFalse(diag.get('applied'), diag)
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_14_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-18', canonical_hash='c' * 16,
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
        for dest in (_OUT, _QA):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
            (dest / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_15_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        out, diag, _ = _apply18(
            repaired, domain='dt', lang='ar', selected_frameworks=['DGA'])
        self.assertFalse(diag.get('applied'), diag)
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_16_auth_csrf_regression_passes(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='ar', domain='ai',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='ar', domain='ai',
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
        self.assertEqual(valid.get('http_status'), 200)
        self.assertEqual(cross.get('http_status'), 403)

    def test_17_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
