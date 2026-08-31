"""REL36.10 — Data Arabic data_catalog roadmap balance hotfix."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_10_')
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
    detect_families as detect_pdpl_36_7,
    missing_families as missing_pdpl_36_7,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _TLS,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    DATA_CATALOG_DETECT_TOKENS,
    REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG,
    REQUIRED_PDPL_FAMILIES,
    apply_rel36_10_data_catalog_roadmap_balance,
    data_catalog_present,
    detect_pdpl_families,
    emit_rel36_10_data_catalog_roadmap_balance,
    evaluate_rel36_10_data_catalog_roadmap_balance,
    missing_balance_families,
)
from release_engine.rel27_export_checks import check_roadmap_coverage
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
    _shifted_staging_pillars,
)
from tests.test_rel36_9_english_cyber_live_stability import (
    _apply,
    _apply_3691,
    _en_sections,
    _family_residue_roadmap,
    _headingless_roadmap,
    _invisible_export_roadmap,
    _roadmap_heading_variant,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _cyber_en_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_10_samples')
_OUT.mkdir(parents=True, exist_ok=True)

_TABLE_HEAD = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
    '|---|---|---|---|---|---|\n'
)

# Official-shaped main-staging failure: NDMO quality/lifecycle + all
# four PDPL families + privacy_governance, but no catalog detector token.
_DATA_STAGING_MISSING_CATALOG = (
    _TABLE_HEAD
    + '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'إطلاق برنامج إدارة جودة البيانات | مدير جودة البيانات | '
    'مقاييس جودة البيانات معتمدة | NDMO |\n'
    + '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'حوكمة دورة حياة البيانات والاحتفاظ | مدير دورة حياة البيانات | '
    'سياسة الاحتفاظ وإتلاف البيانات | NDMO |\n'
    + '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'تفعيل حوكمة الخصوصية | مسؤول حماية البيانات الشخصية | '
    'إطار حوكمة الخصوصية | PDPL |\n'
    + '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'تصنيف وجرد البيانات الشخصية | مسؤول حماية البيانات الشخصية | '
    'سجل تصنيف البيانات الشخصية | PDPL |\n'
    + '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'أتمتة إدارة الموافقات | مسؤول حماية البيانات الشخصية | '
    'منصة موافقات وسجل موافقات موثق | PDPL |\n'
    + '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
    'تفعيل إدارة طلبات أصحاب البيانات | مسؤول حماية البيانات الشخصية | '
    'إجراءات وقنوات DSR مفعلة | PDPL |\n'
    + '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'اعتماد إجراءات الإبلاغ عن الانتهاكات | مسؤول حماية البيانات الشخصية | '
    'خطة الإبلاغ عن الانتهاكات | PDPL |\n'
)

# Common Arabic catalog wording that the official detector does NOT map.
_DATA_NEAR_MISS_CATALOG_WORDING = (
    _DATA_STAGING_MISSING_CATALOG
    + '| المرحلة 1 | 1-6 أشهر | '
    'جرد أصول البيانات وتوثيق سجل البيانات وملكية البيانات وقاموس البيانات | '
    'مكتب إدارة البيانات | سجل أصول محدث | NDMO |\n'
)


def _data_missing_catalog() -> dict:
    secs = dict(_data_sections())
    secs['roadmap'] = _DATA_STAGING_MISSING_CATALOG
    return secs


def _data_near_miss_catalog() -> dict:
    secs = dict(_data_sections())
    secs['roadmap'] = _DATA_NEAR_MISS_CATALOG_WORDING
    return secs


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _write_export(path_stem: str, pair: dict) -> None:
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    (_OUT / f'{path_stem}.docx').write_bytes(docx)
    (_OUT / f'{path_stem}.pdf').write_bytes(pdf)


class Rel3610ReproduceMainFailureTests(unittest.TestCase):
    def test_00_official_detector_tokens_do_not_include_near_miss_arabic(self):
        for tok in (
                'جرد أصول البيانات', 'سجل البيانات',
                'ملكية البيانات', 'قاموس البيانات'):
            self.assertNotIn(tok, DATA_CATALOG_DETECT_TOKENS)
        self.assertIn('كتالوج البيانات', DATA_CATALOG_DETECT_TOKENS)

    def test_00b_reproduces_main_data_catalog_missing(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            _DATA_STAGING_MISSING_CATALOG, ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, ['data_catalog'], missing)
        self.assertFalse(data_catalog_present(_DATA_STAGING_MISSING_CATALOG))
        defects = app._final_strategy_audit(
            _data_missing_catalog(), 'ar', None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management',
            document_type='strategy',
        )
        bal = [d[1] for d in defects
               if str(d[1]).startswith('data_roadmap_balance_missing:')]
        self.assertTrue(bal, defects)
        self.assertIn('data_catalog', bal[0])
        self.assertNotIn('consent_management', bal[0])
        self.assertNotIn('personal_data_classification', bal[0])

    def test_00c_near_miss_arabic_still_fails_official_detector(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            _DATA_NEAR_MISS_CATALOG_WORDING, ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, ['data_catalog'], missing)
        self.assertFalse(data_catalog_present(_DATA_NEAR_MISS_CATALOG_WORDING))


class Rel3610CatalogRepairTests(unittest.TestCase):
    def setUp(self):
        self.buf = io.StringIO()
        with redirect_stdout(self.buf):
            self.secs, self.diag = apply_rel36_10_data_catalog_roadmap_balance(
                _data_missing_catalog(),
                domain='data',
                document_type='strategy',
                lang='ar',
                selected_frameworks=['NDMO', 'PDPL'],
            )
        self.roadmap = str(self.secs.get('roadmap') or '')
        self.log = self.buf.getvalue()
        pair = _export_pair(self.secs, lang='ar', domain='data')
        self.pair = pair
        self.diag = evaluate_rel36_10_data_catalog_roadmap_balance(
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'],
            roadmap_text=self.roadmap,
            roadmap_text_before=_DATA_STAGING_MISSING_CATALOG,
            repair_applied=True,
            inserted_rows=self.diag.get('inserted_rows'),
            docx_allowed=pair['docx_ev'].export_return_allowed,
            pdf_allowed=pair['pdf_ev'].export_return_allowed,
        )
        (_OUT / 'data_ndmo_pdpl_catalog_diagnostic.json').write_text(
            json.dumps(self.diag, ensure_ascii=False, indent=2, default=str),
            encoding='utf-8')
        _write_export('data_ndmo_pdpl', pair)

    def test_01_missing_data_catalog_gets_deterministic_row(self):
        self.assertIn('data_catalog', self.diag.get('inserted_rows') or [])
        self.assertIn('كتالوج البيانات', self.roadmap)
        self.assertIn('جرد أصول البيانات', self.roadmap)
        self.assertIn('سجل البيانات', self.roadmap)
        self.assertIn('ملكية البيانات', self.roadmap)
        self.assertIn('قاموس البيانات', self.roadmap)
        self.assertIn('مكتب إدارة البيانات', self.roadmap)
        self.assertTrue(data_catalog_present(self.roadmap))
        self.assertTrue(self.diag.get('data_catalog_present_after'))
        self.assertFalse(self.diag.get('data_catalog_present_before'))

    def test_02_data_roadmap_balance_missing_catalog_cleared(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            self.roadmap, ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, [], missing)
        self.assertEqual(self.diag.get('missing_families_after'), [])
        self.assertEqual(self.diag.get('save_blockers_after'), [])
        self.assertIn(
            'data_roadmap_balance_missing:data_catalog',
            self.diag.get('save_blockers_before') or [])
        defects = app._final_strategy_audit(
            dict(self.secs), 'ar', None,
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management',
            document_type='strategy',
        )
        bal = [d[1] for d in defects
               if str(d[1]).startswith('data_roadmap_balance_missing:')]
        self.assertEqual(bal, [], bal)

    def test_03_existing_pdpl_family_rows_are_preserved(self):
        self.assertIn('أتمتة إدارة الموافقات', self.roadmap)
        self.assertIn('طلبات أصحاب البيانات', self.roadmap)
        self.assertIn('الإبلاغ عن الانتهاكات', self.roadmap)
        self.assertIn('تصنيف وجرد البيانات الشخصية', self.roadmap)
        for fam in REQUIRED_PDPL_FAMILIES:
            self.assertIn(fam, self.diag.get('pdpl_families_present_after') or [])

    def test_04_personal_data_classification_remains_present(self):
        self.assertIn(
            'personal_data_classification', detect_pdpl_families(self.roadmap))
        self.assertIn('تصنيف البيانات الشخصية', self.roadmap)

    def test_05_consent_management_remains_present(self):
        self.assertIn('consent_management', detect_pdpl_families(self.roadmap))
        self.assertIn('إدارة الموافقات', self.roadmap)

    def test_06_data_subject_rights_remains_present(self):
        self.assertIn('data_subject_rights', detect_pdpl_families(self.roadmap))
        self.assertIn('أصحاب البيانات', self.roadmap)

    def test_07_breach_notification_remains_present(self):
        self.assertIn('breach_notification', detect_pdpl_families(self.roadmap))
        self.assertIn('الإبلاغ عن الانتهاكات', self.roadmap)

    def test_08_data_docx_pdf_allowed(self):
        self.assertTrue(
            self.pair['docx_ev'].export_return_allowed,
            self.pair['docx_ev'].blocking_errors)
        self.assertTrue(
            self.pair['pdf_ev'].export_return_allowed,
            self.pair['pdf_ev'].blocking_errors)
        self.assertTrue(self.diag.get('docx_allowed'))
        self.assertTrue(self.diag.get('pdf_allowed'))
        self.assertGreater(len(self.pair['docx_export'].docx_bytes or b''), 100)
        self.assertGreater(len(self.pair['pdf_export'].pdf_bytes or b''), 100)

    def test_09_no_nca_ciso_siem_soc_csirt_leakage(self):
        blob = '\n'.join(str(v) for v in self.secs.values())
        for tok in ('NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT'):
            self.assertNotIn(tok, blob)
            self.assertNotIn(tok, self.roadmap)
        self.assertEqual(self.diag.get('leakage_terms_after'), [])

    def test_10_no_nist_csf_leakage(self):
        blob = '\n'.join(str(v) for v in self.secs.values())
        self.assertNotIn('NIST CSF', blob)
        self.assertNotIn('NIST Cybersecurity Framework', blob)
        fw = detect_visible_frameworks(blob)
        self.assertNotIn('NIST CSF', fw)

    def test_11_no_nist_ai_rmf_leakage(self):
        blob = '\n'.join(str(v) for v in self.secs.values())
        self.assertNotIn('NIST AI RMF', blob)
        fw = detect_visible_frameworks(blob)
        self.assertNotIn('NIST AI RMF', fw)
        self.assertIn('NDMO', fw)
        self.assertIn('PDPL', fw)

    def test_12_diagnostic_passed_only_when_catalog_actually_present(self):
        self.assertTrue(self.diag.get('passed'), self.diag)
        self.assertIn(REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG, self.log)
        fail = evaluate_rel36_10_data_catalog_roadmap_balance(
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'],
            roadmap_text=_DATA_STAGING_MISSING_CATALOG,
            docx_allowed=True, pdf_allowed=True,
        )
        self.assertFalse(fail.get('data_catalog_present_after'))
        self.assertFalse(fail.get('passed'), fail)
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel36_10_data_catalog_roadmap_balance(self.diag)
        self.assertIn(
            REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG, buf.getvalue())

    def test_near_miss_wording_still_receives_detector_visible_row(self):
        secs, diag = apply_rel36_10_data_catalog_roadmap_balance(
            _data_near_miss_catalog(),
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        road = secs.get('roadmap') or ''
        self.assertTrue(data_catalog_present(road))
        self.assertIn('كتالوج البيانات', road)
        self.assertIn('data_catalog', diag.get('inserted_rows') or [])
        app = _app()
        self.assertEqual(
            app._compute_missing_data_roadmap_balance_topics(
                road, ['NDMO', 'PDPL'], lang='ar'),
            [])

    def test_idempotent_when_catalog_already_present(self):
        first, _ = apply_rel36_10_data_catalog_roadmap_balance(
            _data_missing_catalog(),
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        second, diag = apply_rel36_10_data_catalog_roadmap_balance(
            first,
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(first.get('roadmap'), second.get('roadmap'))
        self.assertEqual(diag.get('inserted_rows'), [])
        self.assertTrue(diag.get('data_catalog_present_after'))

    def test_does_not_apply_to_english_cyber(self):
        secs = dict(_cyber_en_sections())
        before = secs.get('roadmap')
        out, diag = apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='cyber', document_type='strategy', lang='en',
            selected_frameworks=_NCA_FWS, emit=False)
        self.assertFalse(diag.get('in_scope'))
        self.assertEqual(out.get('roadmap'), before)

    def test_first_cycle_inserts_catalog_without_ai(self):
        app = _app()
        secs = _data_missing_catalog()
        before = app._compute_missing_data_roadmap_balance_topics(
            secs['roadmap'], ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(before, ['data_catalog'], before)
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
        self.assertIn('كتالوج البيانات', secs.get('roadmap') or '')
        final_tags = [t for _s, t, _c, _m in (log.get('final_defects') or [])]
        self.assertFalse(
            any(str(t).startswith('data_roadmap_balance_missing:')
                for t in final_tags),
            final_tags)
        self.assertIn(REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG, buf.getvalue())
        self.assertEqual(missing_pdpl_36_7(secs.get('roadmap') or ''), [])


class Rel3610RegressionTests(unittest.TestCase):
    def test_13_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        out, diag = apply_rel36_10_data_catalog_roadmap_balance(
            dict(sections),
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=_NCA_FWS, emit=False)
        self.assertFalse(diag.get('in_scope'))
        self.assertEqual(out['roadmap'], sections['roadmap'])
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)
        blob = '\n'.join(str(v) for v in sections.values())
        self.assertTrue(any(h in blob for h in (
            'ركيزة', 'الهدف', 'المرحلة', 'الفجوة')))

    def test_14_english_cyber_rel36_9_1_five_shape_still_clean(self):
        _TLS.depth = 0
        shapes = [
            ('attempt-1-headingless',
             render_canonical_english_cyber_pillars(),
             _headingless_roadmap()),
            ('attempt-2-implementation-heading',
             render_canonical_english_cyber_pillars(),
             '## Implementation Roadmap\n\n' + _headingless_roadmap()),
            ('attempt-3-roadmap-heading',
             render_canonical_english_cyber_pillars(),
             _roadmap_heading_variant()),
            ('attempt-4-malformed-pillars',
             _malformed_en_cyber_pillars(),
             _invisible_export_roadmap()),
            ('attempt-5-shifted-owners',
             _shifted_staging_pillars(),
             _family_residue_roadmap()),
        ]
        summary = []
        last_pair = None
        for attempt_id, pillars, roadmap in shapes:
            out9, d9, _ = _apply(
                _en_sections(pillars, roadmap), attempt_id=attempt_id)
            out91, d91, _ = _apply_3691(out9)
            out10, d10 = apply_rel36_10_data_catalog_roadmap_balance(
                out91, domain='cyber', lang='en',
                document_type='strategy', selected_frameworks=_NCA_FWS,
                emit=False)
            self.assertFalse(d10.get('in_scope'))
            cov = check_roadmap_coverage(out10['roadmap'], domain='cyber')
            pair = _export_pair(out10, lang='en', domain='cyber')
            rec = {
                'attempt_id': attempt_id,
                'rel36_9_passed': d9.get('passed'),
                'rel36_9_1_passed': d91.get('passed'),
                'roadmap_visible_row_count': cov.get('visible_row_count'),
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'vision_contains_prompt_residue': (
                    'vision_contains_prompt_residue'
                    in json.dumps(d91, default=str)),
            }
            summary.append(rec)
            self.assertTrue(d9.get('passed'), rec)
            self.assertTrue(d91.get('passed'), rec)
            self.assertGreater(int(cov.get('visible_row_count') or 0), 0, rec)
            self.assertTrue(rec['docx_allowed'], rec)
            self.assertTrue(rec['pdf_allowed'], rec)
            last_pair = pair
        (_OUT / 'en_cyber_ecc_dcc_5shape_summary.json').write_text(
            json.dumps(
                {'attempts': summary, 'pass_count': 5, 'required': 5},
                indent=2, ensure_ascii=False),
            encoding='utf-8')
        if last_pair is not None:
            _write_export('en_cyber_ecc_dcc', last_pair)
        self.assertEqual(len(summary), 5)
        self.assertTrue(all(r['docx_allowed'] and r['pdf_allowed']
                            for r in summary))

    def test_15_erm_regression_passes(self):
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
            artifact_id='risk-rel36-10', canonical_hash='c' * 16,
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
        self.assertNotIn(
            'rel33_domain_contamination',
            ' '.join(docx.blocking_errors + pdf.blocking_errors))
        (_OUT / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
        (_OUT / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_16_ai_sdaia_regression_passes(self):
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
        pair = _export_pair(_ai_sections(), lang='ar', domain='ai')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('ai_sdaia', pair)
        self.assertNotIn(
            'rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_17_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_18_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())

    def test_rel36_7_still_clears_pdpl_families_with_catalog_repair(self):
        from tests.test_rel36_7_data_roadmap_balance import (
            _data_generated_missing_three,
        )
        secs = _data_generated_missing_three()
        repaired, d367 = apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        repaired, d3610 = apply_rel36_10_data_catalog_roadmap_balance(
            repaired, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        road = repaired.get('roadmap') or ''
        self.assertEqual(missing_pdpl_36_7(road), [])
        self.assertTrue(data_catalog_present(road))
        self.assertEqual(
            missing_balance_families(road, ['NDMO', 'PDPL']), [])
        self.assertTrue(d367.get('passed'), d367)
        self.assertTrue(data_catalog_present(road) or d3610.get('passed'))


if __name__ == '__main__':
    unittest.main()
