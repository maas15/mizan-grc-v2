"""REL36.15 — Data registry balance + English Cyber KPI / family repair."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_15_')
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
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _TLS,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    apply_rel36_10_data_catalog_roadmap_balance,
)
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    apply_rel36_13_en_cyber_core_completeness,
    repair_kpis as rel36_13_repair_kpis,
)
from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
    apply_rel36_14_en_cyber_final_counted_structures,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    REL36_15_DATA_ROADMAP_REGISTRY_BALANCE_TAG,
    REL36_15_EN_CYBER_FINAL_STABILITY_TAG,
    REL36_15_EN_CYBER_KPI_SYNTH_REPAIR_TAG,
    REL36_15_EN_CYBER_ROADMAP_FAMILY_BALANCE_TAG,
    apply_rel36_15_data_roadmap_registry_balance,
    apply_rel36_15_en_cyber_kpi_synth_repair,
    apply_rel36_15_en_cyber_roadmap_family_balance,
    apply_rel36_15_final_registry_stability,
    official_cyber_missing_families,
    official_data_missing_families,
    repair_first_kpi_table,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
)
from tests.test_rel36_9_english_cyber_live_stability import (
    _en_sections,
    _headingless_roadmap,
)
from tests.test_rel36_13_english_cyber_core_completeness import (
    _WEAK_CONF,
    _WEAK_ENV,
    _WEAK_GAPS,
    _WEAK_KPI,
    _WEAK_VISION,
)
from tests.test_rel36_14_english_cyber_final_counted_structures import (
    _duplicate_gap_guides,
    _empty_first_csf_plus_second_table,
    _imbalanced_roadmap_ecc2_dcc8,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_15_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_15_samples'
_QA.mkdir(parents=True, exist_ok=True)

_TABLE_HEAD = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
    '|---|---|---|---|---|---|\n'
)

# Official Data miss: catalog + PDPL + quality present, no lifecycle tokens.
_DATA_MISSING_LIFECYCLE = (
    _TABLE_HEAD
    + '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
    'إطلاق برنامج إدارة جودة البيانات | مدير جودة البيانات | '
    'مقاييس جودة البيانات معتمدة | NDMO |\n'
    + '| الربع 1 | إنشاء وتحديث كتالوج البيانات المؤسسي | '
    'مكتب إدارة البيانات | كتالوج بيانات مؤسسي محدث | NDMO |\n'
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

# Multiple official families missing (quality, lifecycle, privacy, catalog).
_DATA_MISSING_MANY = (
    _TABLE_HEAD
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

_REL3613_KPI, _ = rel36_13_repair_kpis(_WEAK_KPI, {'kpi': 4})

_KPI_IGNORED_SECOND_TABLE = (
    '## 6. Key Performance Indicators\n\n'
    '| # | KPI Description | Target | Formula | Justification | Timeframe |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | TBD | TBD | TBD | TBD | TBD |\n\n'
    '### Other Metrics\n\n'
    '| # | KPI Description | Type | Target Value | Calculation Formula | '
    'Source | Frequency | Owner |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | NCA ECC control implementation coverage | Lagging | 95% | '
    'implemented / in-scope | Control register | Quarterly | CISO |\n'
)

_NO_CLASSIFICATION_ROADMAP = (
    '## 5. Implementation Roadmap\n\n'
    '| Phase | Period | Initiative | Owner | Expected Deliverable | '
    'Linked Framework |\n'
    '|---|---|---|---|---|---|\n'
    '| Phase 1 | 1-6 months | Appoint a CISO | CISO | CISO charter | NCA ECC |\n'
    '| Phase 1 | 1-6 months | Establish a cybersecurity governance committee | '
    'Cybersecurity Governance Manager | Steering Committee charter | NCA ECC |\n'
    '| Phase 2 | 7-18 months | Enforce IAM/PAM/MFA | IAM/PAM Manager | '
    'IAM platform | NCA ECC |\n'
    '| Phase 2 | 7-18 months | Operate SOC/SIEM | SOC Manager | SIEM coverage | '
    'NCA ECC |\n'
    '| Phase 2 | 7-18 months | Stand up CSIRT incident response | CSIRT Lead | '
    'Incident response plan | NCA ECC |\n'
    '| Phase 2 | 7-18 months | Operate vulnerability management | '
    'Vulnerability Manager | Patch SLA | NCA ECC |\n'
    '| Phase 2 | 7-18 months | Apply encryption and key management | '
    'Data Protection Officer | Encryption controls | NCA DCC |\n'
    '| Phase 2 | 7-18 months | Enable DLP and data loss prevention | '
    'Data Protection Officer | DLP rules | NCA DCC |\n'
    '| Phase 2 | 7-18 months | Approve sensitive data handling procedures | '
    'Data Protection Officer | Handling SOP | NCA DCC |\n'
    '| Phase 3 | 19-24 months | Protect data at rest and in transit | '
    'Data Protection Officer | Data protection controls | NCA DCC |\n'
)


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _backend():
    return _app()._rel2_backend_callables()


def _write_export(path_stem: str, pair: dict) -> None:
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{path_stem}.docx').write_bytes(docx)
        (dest / f'{path_stem}.pdf').write_bytes(pdf)


def _write_json(name: str, payload: dict) -> Path:
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(text, encoding='utf-8')
    return _OUT / name


def _seed_sections(*, vision=None, environment=None, gaps=None,
                   roadmap=None, confidence=None, kpis=None,
                   pillars=None) -> dict:
    secs = _en_sections(
        pillars or render_canonical_english_cyber_pillars(),
        roadmap if roadmap is not None else _headingless_roadmap(),
        vision if vision is not None else _WEAK_VISION,
    )
    if environment is not None:
        secs['environment'] = environment
    if gaps is not None:
        secs['gaps'] = gaps
    if confidence is not None:
        secs['confidence'] = confidence
    if kpis is not None:
        secs['kpis'] = kpis
    return secs


def _apply15(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _seed_sections(
        environment=_WEAK_ENV, gaps=_WEAK_GAPS,
        confidence=_WEAK_CONF, kpis=_REL3613_KPI,
        roadmap=_NO_CLASSIFICATION_ROADMAP))
    domain = kwargs.pop('domain', 'cyber')
    lang = kwargs.pop('lang', 'en')
    fws = kwargs.pop('selected_frameworks', _NCA_FWS)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_15_final_registry_stability(
            secs,
            domain=domain,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-15'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


class Rel3615DataRegistryTests(unittest.TestCase):
    def test_01_data_missing_lifecycle_gets_deterministic_row(self):
        app = _app()
        before = app._compute_missing_data_roadmap_balance_topics(
            _DATA_MISSING_LIFECYCLE, ['NDMO', 'PDPL'], lang='ar')
        self.assertIn('data_lifecycle', before, before)
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        still = official_data_missing_families(
            secs.get('roadmap') or '', ['NDMO', 'PDPL'])
        self.assertIn('data_lifecycle', still, still)
        out, diag, log = _apply15(
            secs, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        road = out.get('roadmap') or ''
        self.assertIn('دورة حياة البيانات', road)
        self.assertIn('إنشاء', road)
        self.assertIn('إتاحة', road)
        self.assertIn('أرشفة', road)
        self.assertIn('إتلاف', road)
        self.assertIn('مكتب إدارة البيانات', road)
        self.assertIn('NDMO', road)
        self.assertIn('data_lifecycle', diag.get('detected_families_after'), diag)
        self.assertEqual(diag.get('missing_families_after'), [], diag)
        self.assertTrue(diag.get('passed'), diag)
        self.assertIn(REL36_15_DATA_ROADMAP_REGISTRY_BALANCE_TAG, log)
        _write_json('data_roadmap_registry_diagnostic.json', diag)

    def test_02_registry_inserts_all_missing_not_only_last_family(self):
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            _DATA_MISSING_MANY, ['NDMO', 'PDPL'], lang='ar')
        self.assertGreaterEqual(len(missing), 3, missing)
        self.assertIn('data_lifecycle', missing)
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_MANY
        out, diag, _ = _apply15(
            secs, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        inserted = diag.get('inserted_families') or []
        self.assertIn('data_lifecycle', inserted, diag)
        self.assertGreaterEqual(len(inserted), 3, inserted)
        self.assertEqual(diag.get('missing_families_after'), [], diag)

    def test_03_data_detector_missing_families_after_empty(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        out, diag, _ = _apply15(
            secs, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        official = _app()._compute_missing_data_roadmap_balance_topics(
            out.get('roadmap') or '', ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(official, [], official)
        self.assertEqual(diag.get('missing_families_after'), [], diag)
        self.assertEqual(diag.get('save_blockers_after'), [], diag)

    def test_04_data_output_has_no_cyber_nist_leakage(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_MANY
        out, diag, _ = _apply15(
            secs, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        blob = '\n'.join(str(v) for v in out.values())
        for tok in (
                'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
                'NIST CSF', 'NIST AI RMF'):
            self.assertNotIn(tok, blob)
        self.assertEqual(diag.get('leakage_terms_after'), [], diag)
        pair = _export_pair(out, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)


class Rel3615EnCyberKpiTests(unittest.TestCase):
    def test_05_kpi_synth_failure_shape_is_repaired(self):
        secs = _seed_sections(kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)
        self.assertNotIn('| Source | Frequency | Owner |', secs['kpis'])
        out, diag = apply_rel36_15_en_cyber_kpi_synth_repair(
            secs, selected_frameworks=_NCA_FWS, emit=False)
        kdiag = diag
        self.assertGreaterEqual(kdiag.get('kpi_rows_after'), 4, kdiag)
        self.assertEqual(kdiag.get('synth_kpis_blockers_after'), [], kdiag)
        self.assertTrue(kdiag.get('schema_valid_after'), kdiag)
        self.assertTrue(kdiag.get('passed'), kdiag)
        self.assertIn('Frequency', out.get('kpis') or '')
        self.assertIn('### KPI Assessment Guidelines', out.get('kpis') or '')
        _write_json('en_cyber_kpi_diagnostic.json', kdiag)

    def test_06_first_counted_kpi_table_replaced_not_appended(self):
        repaired, n = repair_first_kpi_table(_KPI_IGNORED_SECOND_TABLE)
        self.assertGreaterEqual(n, 4)
        headers = [
            ln for ln in repaired.splitlines()
            if ln.lower().startswith('| # | kpi description')
        ]
        self.assertEqual(len(headers), 1, headers)
        self.assertIn('Frequency', headers[0])
        self.assertNotIn('| 1 | TBD |', repaired)

    def test_07_english_cyber_kpi_schema_is_valid(self):
        out, diag = apply_rel36_15_en_cyber_kpi_synth_repair(
            _seed_sections(kpis=_WEAK_KPI), selected_frameworks=_NCA_FWS,
            emit=False)
        hdr = (diag.get('first_kpi_table_header_after') or '').lower()
        for col in (
                'kpi description', 'type', 'target value',
                'calculation formula', 'source', 'frequency', 'owner'):
            self.assertIn(col, hdr, hdr)
        self.assertGreaterEqual(
            _app().count_substantive_kpis(out.get('kpis') or ''), 4)


class Rel3615EnCyberRoadmapFamilyTests(unittest.TestCase):
    def test_08_missing_data_classification_is_repaired(self):
        missing = official_cyber_missing_families(
            _NO_CLASSIFICATION_ROADMAP, _NCA_FWS)
        self.assertIn('data_classification', missing, missing)
        secs = _seed_sections(roadmap=_NO_CLASSIFICATION_ROADMAP)
        out, diag = apply_rel36_15_en_cyber_roadmap_family_balance(
            secs, selected_frameworks=_NCA_FWS, emit=False)
        self.assertIn(
            'data_classification', diag.get('detected_families_after'), diag)
        self.assertEqual(diag.get('missing_families_after'), [], diag)
        self.assertTrue(diag.get('passed'), diag)
        _write_json('en_cyber_roadmap_family_diagnostic.json', diag)

    def test_09_data_classification_row_is_detector_visible(self):
        secs = _seed_sections(roadmap=_NO_CLASSIFICATION_ROADMAP)
        out, _ = apply_rel36_15_en_cyber_roadmap_family_balance(
            secs, selected_frameworks=_NCA_FWS, emit=False)
        road = out.get('roadmap') or ''
        self.assertIn('Classify and inventory sensitive data assets', road)
        self.assertIn('Sensitive data classification', road)
        self.assertIn('NCA DCC', road)
        official = _app()._compute_missing_cyber_roadmap_balance_topics(
            road, _NCA_FWS, lang='en')
        self.assertNotIn('data_classification', official, official)

    def test_10_classification_repair_does_not_break_prcy74(self):
        secs = _seed_sections(roadmap=_imbalanced_roadmap_ecc2_dcc8())
        out, diag = apply_rel36_15_en_cyber_roadmap_family_balance(
            secs, selected_frameworks=_NCA_FWS, emit=False)
        self.assertEqual(diag.get('prcy74_blockers_after'), [], diag)
        self.assertGreaterEqual(diag.get('ecc_rows_after'), 3, diag)
        self.assertGreaterEqual(diag.get('dcc_rows_after'), 3, diag)
        dcc, ecc = _app()._prcy68_count_roadmap_framework_rows(
            out.get('roadmap') or '')
        self.assertGreaterEqual(ecc, 3, (ecc, dcc))
        self.assertGreaterEqual(dcc, 3, (ecc, dcc))


class Rel3615CombinedAndRegressionTests(unittest.TestCase):
    def test_11_combined_kpi_and_roadmap_defects_pass_final_blockers(self):
        secs = _seed_sections(
            vision=_WEAK_VISION, environment=_WEAK_ENV, gaps=_duplicate_gap_guides(),
            confidence=_empty_first_csf_plus_second_table(),
            kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP,
            pillars=_malformed_en_cyber_pillars())
        out13, _ = apply_rel36_13_en_cyber_core_completeness(
            secs, domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=_NCA_FWS, emit=False)
        out14, _ = apply_rel36_14_en_cyber_final_counted_structures(
            out13, domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=_NCA_FWS, emit=False)
        out, diag, log = _apply15(out14)
        self.assertEqual(diag.get('all_blockers_after'), [], diag)
        self.assertTrue(diag.get('passed'), diag)
        self.assertTrue(diag.get('kpi_passed'), diag)
        self.assertTrue(diag.get('roadmap_family_passed'), diag)
        self.assertIn(REL36_15_EN_CYBER_FINAL_STABILITY_TAG, log)
        self.assertIn(REL36_15_EN_CYBER_KPI_SYNTH_REPAIR_TAG, log)
        self.assertIn(REL36_15_EN_CYBER_ROADMAP_FAMILY_BALANCE_TAG, log)
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_json('en_cyber_final_stability_diagnostic.json', diag)
        _write_export('en_cyber_ecc_dcc', pair)

    def test_12_english_cyber_10_seeded_shapes_pass(self):
        shapes = [
            ('s1', _seed_sections(kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s2', _seed_sections(kpis=_WEAK_KPI, roadmap=_imbalanced_roadmap_ecc2_dcc8())),
            ('s3', _seed_sections(
                kpis=_KPI_IGNORED_SECOND_TABLE, roadmap=_NO_CLASSIFICATION_ROADMAP,
                gaps=_duplicate_gap_guides())),
            ('s4', _seed_sections(
                kpis=_REL3613_KPI, confidence=_empty_first_csf_plus_second_table(),
                roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s5', _seed_sections(
                vision=_WEAK_VISION, kpis=_WEAK_KPI, roadmap=_headingless_roadmap())),
            ('s6', _seed_sections(
                environment='', kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s7', _seed_sections(
                gaps=_WEAK_GAPS, kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s8', _seed_sections(
                pillars=_malformed_en_cyber_pillars(), kpis=_REL3613_KPI,
                roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s9', _seed_sections(
                kpis=_REL3613_KPI, roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                confidence=_WEAK_CONF)),
            ('s10', _seed_sections(
                kpis=_KPI_IGNORED_SECOND_TABLE,
                roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table())),
        ]
        summary = []
        for attempt_id, secs in shapes:
            out13, _ = apply_rel36_13_en_cyber_core_completeness(
                secs, domain='cyber', lang='en', document_type='strategy',
                selected_frameworks=_NCA_FWS, emit=False)
            out14, d14 = apply_rel36_14_en_cyber_final_counted_structures(
                out13, domain='cyber', lang='en', document_type='strategy',
                selected_frameworks=_NCA_FWS, emit=False)
            out, diag, _ = _apply15(out14, attempt_id=attempt_id, task_id=attempt_id)
            pair = _export_pair(out, lang='en', domain='cyber')
            missing = official_cyber_missing_families(
                out.get('roadmap') or '', _NCA_FWS)
            rec = {
                'attempt_id': attempt_id,
                'kpi_rows': (diag.get('kpis') or {}).get('kpi_rows_after'),
                'synth_kpis': (diag.get('kpis') or {}).get('synth_kpis_blockers_after'),
                'missing_families': missing,
                'prcy74': (diag.get('roadmap') or {}).get('prcy74_blockers_after'),
                'all_blockers_after': diag.get('all_blockers_after'),
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'rel36_14_passed': bool(d14.get('passed')),
                'passed': bool(diag.get('passed')) and not missing
                and pair['docx_ev'].export_return_allowed
                and pair['pdf_ev'].export_return_allowed,
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

    def test_13_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
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
            artifact_id='risk-rel36-15', canonical_hash='c' * 16,
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

    def test_15_ai_sdaia_regression_passes(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF '
            + 'and NCA ECC CISO SIEM CSIRT.'
        )
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertIn('SDAIA', detect_visible_frameworks(blob))
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

    def test_16_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_17_auth_csrf_regression_passes(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='en', domain='cyber',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='en', domain='cyber',
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

    def test_18_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
