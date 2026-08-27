"""REL36.7 — Data NDMO/PDPL roadmap balance first-run coverage."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_7_')
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
    REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG,
    REQUIRED_PDPL_ROADMAP_FAMILIES,
    apply_rel36_7_data_pdpl_roadmap_balance,
    detect_families,
    emit_rel36_7_data_pdpl_roadmap_balance,
    evaluate_rel36_7_data_pdpl_roadmap_balance,
    missing_families,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_en_sections,
    _export_pair,
)

_DATA_GENERATED_ROADMAP_MISSING_THREE = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'إطلاق برنامج إدارة جودة البيانات | مدير جودة البيانات | '
    'مقاييس جودة البيانات معتمدة | NDMO |\n'
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'بناء كتالوج البيانات والبيانات الوصفية | '
    'مدير البيانات الوصفية والكتالوج | كتالوج بيانات تشغيلي | NDMO |\n'
    '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'حوكمة دورة حياة البيانات والاحتفاظ | مدير دورة حياة البيانات | '
    'سياسة الاحتفاظ وإتلاف البيانات | NDMO |\n'
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'تفعيل حوكمة الخصوصية | مسؤول حماية البيانات الشخصية | '
    'إطار حوكمة الخصوصية | PDPL |\n'
    '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'اعتماد تصنيف البيانات الشخصية | مسؤول حماية البيانات الشخصية | '
    'سجل تصنيف البيانات الشخصية | PDPL |\n'
)


def _data_generated_missing_three() -> dict:
    secs = dict(_data_sections())
    secs['roadmap'] = _DATA_GENERATED_ROADMAP_MISSING_THREE
    return secs


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


class Rel367DetectorFixtureTests(unittest.TestCase):
    def test_generated_fixture_is_missing_only_the_three_pdpl_families(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            _DATA_GENERATED_ROADMAP_MISSING_THREE,
            ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(set(missing), {
            'consent_management',
            'data_subject_rights',
            'breach_notification',
        }, missing)
        self.assertEqual(
            set(missing_families(_DATA_GENERATED_ROADMAP_MISSING_THREE)),
            set(REQUIRED_PDPL_ROADMAP_FAMILIES))


class Rel367FamilyRowTests(unittest.TestCase):
    def setUp(self):
        self.buf = io.StringIO()
        with redirect_stdout(self.buf):
            self.secs, self.diag = apply_rel36_7_data_pdpl_roadmap_balance(
                _data_generated_missing_three(),
                domain='data',
                document_type='strategy',
                lang='ar',
                selected_frameworks=['NDMO', 'PDPL'],
            )
        self.roadmap = str(self.secs.get('roadmap') or '')
        self.log = self.buf.getvalue()

    def test_01_contains_consent_management_row(self):
        self.assertIn('consent_management', detect_families(self.roadmap))
        self.assertIn('أتمتة إدارة الموافقات', self.roadmap)
        self.assertIn('PDPL', self.roadmap)

    def test_02_contains_data_subject_rights_row(self):
        self.assertIn('data_subject_rights', detect_families(self.roadmap))
        self.assertIn('طلبات أصحاب البيانات', self.roadmap)

    def test_03_contains_breach_notification_row(self):
        self.assertIn('breach_notification', detect_families(self.roadmap))
        self.assertIn('الإبلاغ عن الانتهاكات', self.roadmap)

    def test_04_balance_detector_passes_on_first_repaired_artifact(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            self.roadmap, ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, [], missing)
        defects = app._final_strategy_audit(
            dict(self.secs), 'ar', None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management',
            document_type='strategy',
        )
        bal = [d[1] for d in defects
               if str(d[1]).startswith('data_roadmap_balance_missing:')]
        self.assertEqual(bal, [], bal)

    def test_05_diagnostic_missing_families_after_empty(self):
        self.assertEqual(self.diag.get('missing_families_after'), [])
        self.assertTrue(self.diag.get('passed'), self.diag)
        self.assertTrue(self.diag.get('roadmap_balance_passed'), self.diag)
        self.assertEqual(self.diag.get('blocking_errors'), [])
        self.assertIn(REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG, self.log)
        payload = evaluate_rel36_7_data_pdpl_roadmap_balance(
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'],
            roadmap_text=self.roadmap,
            repair_applied=True,
            inserted_rows=self.diag.get('inserted_rows'),
            missing_before=REQUIRED_PDPL_ROADMAP_FAMILIES,
        )
        for key in (
                'domain', 'document_type', 'lang', 'selected_frameworks',
                'required_families', 'detected_families_before',
                'missing_families_before', 'inserted_rows',
                'detected_families_after', 'missing_families_after',
                'repair_applied', 'roadmap_balance_passed',
                'blocking_errors', 'passed'):
            self.assertIn(key, payload)
        self.assertEqual(payload['missing_families_after'], [])
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel36_7_data_pdpl_roadmap_balance(payload)
        self.assertIn(REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG, buf.getvalue())

    def test_06_data_docx_pdf_allowed(self):
        out = _export_pair(self.secs, lang='ar', domain='data')
        self.assertTrue(
            out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertTrue(
            out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertGreater(len(out['docx_export'].docx_bytes or b''), 100)
        self.assertGreater(len(out['pdf_export'].pdf_bytes or b''), 100)

    def test_07_no_nca_ciso_siem_csirt(self):
        blob = '\n'.join(str(v) for v in self.secs.values())
        for tok in ('NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'CSIRT'):
            self.assertNotIn(tok, blob)
            self.assertNotIn(tok, self.roadmap)

    def test_08_no_nist_csf_or_nist_ai_rmf(self):
        blob = '\n'.join(str(v) for v in self.secs.values())
        self.assertNotIn('NIST CSF', blob)
        self.assertNotIn('NIST Cybersecurity Framework', blob)
        self.assertNotIn('NIST AI RMF', blob)
        fw = detect_visible_frameworks(blob)
        self.assertIn('NDMO', fw)
        self.assertIn('PDPL', fw)
        self.assertNotIn('NIST CSF', fw)
        self.assertNotIn('NIST AI RMF', fw)


class Rel367FirstRunConvergenceTests(unittest.TestCase):
    def test_first_cycle_inserts_three_families_without_ai(self):
        app = _app()
        secs = _data_generated_missing_three()
        before = app._compute_missing_data_roadmap_balance_topics(
            secs['roadmap'], ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(set(before), {
            'consent_management', 'data_subject_rights', 'breach_notification',
        })
        buf = io.StringIO()
        with redirect_stdout(buf):
            log = app.converge_strategy_sections(
                secs, 'ar', 'Data Management', 'NDMO',
                ctx={'frameworks': ['NDMO', 'PDPL'],
                     'document_type': 'strategy',
                     'org_structure_is_none': False},
                doc_subtype=None, max_iter=1,
            )
        after = app._compute_missing_data_roadmap_balance_topics(
            secs.get('roadmap') or '', ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(after, [], after)
        final_tags = [t for _s, t, _c, _m in (log.get('final_defects') or [])]
        self.assertFalse(
            any(str(t).startswith('data_roadmap_balance_missing:')
                for t in final_tags),
            final_tags)
        self.assertIn(REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG, buf.getvalue())
        self.assertIn('أتمتة إدارة الموافقات', secs.get('roadmap') or '')

    def test_audit_gate_still_reports_remaining_office_only_families(self):
        app = _app()
        office = (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | تأسيس مكتب البيانات | CDO | إطار NDMO | NDMO |\n'
        )
        defects = app._final_strategy_audit(
            {'vision': '', 'pillars': '', 'environment': '',
             'gaps': '', 'roadmap': office, 'kpis': '', 'confidence': ''},
            'ar', None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management',
            document_type='strategy',
        )
        bal = [d[1] for d in defects
               if str(d[1]).startswith('data_roadmap_balance_missing:')]
        self.assertEqual(len(bal), 1, defects)
        self.assertIn('data_quality', bal[0])
        self.assertIn('breach_notification', bal[0])


class Rel367RegressionTests(unittest.TestCase):
    def test_09_english_cyber_ecc_dcc_docx_pdf_still_allowed(self):
        out = _export_pair(_cyber_en_sections(), lang='en', domain='cyber')
        self.assertTrue(
            out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertTrue(
            out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        joined = ' '.join(str(b) for b in list(out['docx_ev'].blocking_errors or [])
                          + list(out['pdf_ev'].blocking_errors or []))
        self.assertNotIn('pillar_owner_missing', joined)
        self.assertNotIn('family:', joined)
        self.assertNotIn('actual PDF evidence validation failed', joined)

    def test_10_erm_risk_isolation_still_passes(self):
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar',
            domain='erm',
            document_type='risk',
            lang='ar',
            risk_id=2,
            strategy_id='',
            source_artifact_type='risk',
            loaded_artifact_type='risk',
            loaded_domain='erm',
            loaded_document_type='risk',
            content=_CLEAN_RISK_MD,
        )
        self.assertTrue(diag.get('passed'), diag)
        self.assertFalse(diag.get('contains_cyber_primary'), diag)
        tree = RenderTree(
            artifact_id='risk-rel36-7', canonical_hash='c' * 16,
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
        self.assertNotIn('rel33_domain_contamination',
                         ' '.join(docx.blocking_errors + pdf.blocking_errors))

    def test_11_ai_sdaia_has_no_nist_leakage(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF '
            'and NCA ECC CISO SIEM CSIRT.'
        )
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('SDAIA', fw)
        for tok in (
                'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
                'NCA ECC', 'CISO', 'SIEM', 'CSIRT'):
            self.assertNotIn(tok, blob)
        clean = '\n'.join(str(v) for v in _ai_sections().values())
        for tok in ('IAM', 'PAM', 'MFA', 'CISO', 'SIEM', 'CSIRT'):
            self.assertNotIn(tok, clean)
        self.assertNotIn(
            'rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_12_dt_dga_interoperability_still_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_fidelity_repair_preserves_inserted_pdpl_rows(self):
        secs, _ = apply_rel36_7_data_pdpl_roadmap_balance(
            _data_generated_missing_three(),
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        repaired, _ = repair_sections_for_fidelity(
            secs, domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], lang='ar')
        road = repaired.get('roadmap') or ''
        self.assertEqual(missing_families(road), [])
        self.assertNotIn('NIST CSF', '\n'.join(str(v) for v in repaired.values()))
        self.assertNotIn('CISO', road)

    def test_erm_risk_fixture_namespace(self):
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])


if __name__ == '__main__':
    unittest.main()
