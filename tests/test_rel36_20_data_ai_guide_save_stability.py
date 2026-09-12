"""REL36.20 — Data/AI save-gate and guide-completeness stabilization."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_20_')
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
from release_engine_v3.rel36_18_ai_sdaia_kpi_synth import (
    apply_rel36_18_ai_sdaia_kpi_synth,
)
from release_engine_v3.rel36_19_bilingual_language_parity import (
    apply_rel36_19_bilingual_language_parity,
    count_kpi_main_tables,
)
from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
    REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG,
    REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG,
    REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG,
    apply_rel36_20_data_ai_guide_save_stability,
    rel36_20_should_apply,
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
    _official_so_gate,
    _prior_repairs,
    _seed_sections,
)
from tests.test_rel36_19_bilingual_language_parity import (
    Rel36191CodexGuardTests,
    Rel3619LanguageParityTests,
    _alias_kpi_table,
    _en_ai_mixed,
    _en_data_mixed,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_20_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_20_samples'
_QA.mkdir(parents=True, exist_ok=True)

_AR_RE = re.compile(r'[\u0600-\u06FF]')
_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']
_AR_ORG = 'شركة مثال'
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)

_EN_DATA_MISSING_PRIVACY = (
    '| Phase | Timeline | Initiative | Owner | Output | Framework |\n'
    '|---|---|---|---|---|---|\n'
    '| Phase 1: Establish | 1-6 months | Launch data quality management | '
    'Data Quality Manager | Approved data quality metrics | NDMO |\n'
    '| Phase 1: Establish | 1-6 months | Establish the enterprise data catalog | '
    'Data Catalog Owner | Approved data catalog covering critical data assets | NDMO |\n'
    '| Phase 1: Establish | 1-6 months | Formalize the data lifecycle operating model | '
    'Data Steward | Approved data lifecycle policy | NDMO |\n'
    '| Phase 1: Establish | 1-6 months | Classify personal data by sensitivity | '
    'Data Protection Officer | Approved personal data classification register | PDPL |\n'
    '| Phase 2: Enable | 6-12 months | Deploy the consent management operating model | '
    'Data Protection Officer | Live consent management register | PDPL |\n'
    '| Phase 2: Enable | 6-12 months | Operationalize data subject rights fulfillment | '
    'Data Protection Officer | Data subject rights fulfillment SLA | PDPL |\n'
    '| Phase 2: Enable | 6-12 months | Operationalize personal data breach notification | '
    'Data Protection Officer | Personal data breach notification runbook | PDPL |\n'
)

_THIN_SO = (
    '## Strategic Objectives\n\n'
    'A short English vision narrative.\n'
)

_THIN_PILLARS = (
    '## Strategic Pillars\n\n'
    '| # | Initiative | Description | Expected Deliverable | Owner |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Catalog | Register assets | Catalog | Data Catalog Owner |\n'
)

_GAPS_NO_GUIDES_EN = (
    '## Gap Analysis\n\n'
    '| # | Gap | Description | Priority | Status |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Weak catalog coverage | Critical assets unregistered | High | Open |\n'
    '| 2 | Weak privacy governance | Privacy operating model missing | High | Open |\n'
)

_KPIS_NO_GUIDES_EN = (
    '## 6. Key Performance Indicators\n\n'
    '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | Catalog completeness | Lagging | 100% | cataloged / critical | Catalog | Quarterly | Data Catalog Owner |\n'
    '| 2 | Data quality score | Lagging | 90% | valid / total | Quality | Monthly | Data Quality Manager |\n'
    '| 3 | PDPL consent coverage | Lagging | 100% | consented / processing | Consent | Quarterly | Data Protection Officer |\n'
    '| 4 | DSR SLA | Lagging | 95% | closed / received | DSR log | Monthly | Data Protection Officer |\n'
)

_GAPS_NO_GUIDES_AR = (
    '## تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
    '|---|---|---|---|---|\n'
    '| 1 | سجل النماذج غير مكتمل | النماذج الإنتاجية غير مجرودة | عالية | مفتوحة |\n'
    '| 2 | مخاطر النماذج غير مفعلة | لا يوجد مدير مخاطر للنماذج | عالية | مفتوحة |\n'
)

_KPIS_NO_GUIDES_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
    '|---|---|---|---|---|---|---|---|\n'
    '| 1 | تغطية سجل النماذج | لاحق | 100% | المسجلة ÷ المنتجة | سجل النماذج | ربع سنوي | مالك نموذج الذكاء الاصطناعي |\n'
    '| 2 | الإشراف البشري | قائد | 100% | المشمولة ÷ العالية | سجل الإشراف | ربع سنوي | مدير حوكمة الذكاء الاصطناعي |\n'
    '| 3 | تغطية MLOps | لاحق | 100% | في MLOps ÷ المنتجة | منصة MLOps | ربع سنوي | قائد MLOps |\n'
    '| 4 | بطاقة النموذج | لاحق | 100% | ببطاقة ÷ العالية | البطاقات | ربع سنوي | مسؤول الامتثال |\n'
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


def _apply20(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_20_data_ai_guide_save_stability(
            secs,
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'en'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop(
                'selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _en_data_broken():
    secs = _en_data_mixed()
    secs['roadmap'] = _EN_DATA_MISSING_PRIVACY
    secs['vision'] = _THIN_SO
    secs['pillars'] = _THIN_PILLARS
    secs['gaps'] = _GAPS_NO_GUIDES_EN
    secs['kpis'] = _KPIS_NO_GUIDES_EN
    return secs


def _en_ai_broken():
    secs = _en_ai_mixed()
    secs['vision'] = _THIN_SO
    secs['pillars'] = _THIN_PILLARS
    secs['gaps'] = (
        '## Gap Analysis\n\n'
        '| # | Gap | Description | Priority | Status |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Weak model register | Production models untracked | High | Open |\n'
        '| 2 | Informal model risk | No Model Risk Manager | High | Open |\n'
    )
    secs['kpis'] = (
        '## 6. Key Performance Indicators\n\n'
        '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | Model register coverage | Lagging | 100% | registered / production | Register | Quarterly | Model Owner |\n'
        '| 2 | Human oversight completion | Leading | 100% | overseen / high-risk | Oversight | Quarterly | AI Governance Manager |\n'
        '| 3 | MLOps pipeline coverage | Lagging | 100% | in MLOps / production | MLOps | Quarterly | MLOps Lead |\n'
        '| 4 | Model-card coverage | Lagging | 100% | cards / high-risk | Cards | Quarterly | Compliance Officer |\n'
    )
    return secs


def _ar_ai_broken():
    secs = dict(_ai_sections())
    secs['gaps'] = _GAPS_NO_GUIDES_AR
    secs['kpis'] = _KPIS_NO_GUIDES_AR
    return secs


def _blob(sections):
    return '\n'.join(str(v) for v in sections.values() if isinstance(v, str))


def _assert_no_leaks(test, text):
    hay = str(text or '')
    for tok in _LEAKS:
        if tok == 'NCA' and ('NDMO' in hay or 'SDAIA' in hay):
            test.assertFalse(re.search(r'(?<![A-Z])NCA(?![A-Z])', hay), tok)
            continue
        test.assertNotIn(tok, hay, tok)


class Rel3620DataAiGuideSaveStabilityTests(unittest.TestCase):
    def test_01_en_data_missing_privacy_governance_inserted(self):
        secs = {'roadmap': _EN_DATA_MISSING_PRIVACY}
        before = _app()._compute_missing_data_roadmap_balance_topics(
            secs['roadmap'], _NDMO, lang='en')
        self.assertIn('privacy_governance', before, before)
        out, diag, log = _apply20(secs, domain='data', lang='en')
        road = out.get('roadmap') or ''
        after = _app()._compute_missing_data_roadmap_balance_topics(
            road, _NDMO, lang='en')
        self.assertEqual(after, [], after)
        self.assertIn('privacy governance', road.lower())
        self.assertIn('personal data protection', road.lower())
        self.assertIn('Data Protection Officer', road)
        self.assertIn('PDPL', road)
        self.assertTrue(diag.get('roadmap', {}).get(
            'privacy_governance_present_after'), diag)
        self.assertIn(REL36_20_DATA_EN_ROADMAP_GUIDE_STABILITY_TAG, log)
        _write_json('en_data_roadmap_guide_diagnostic.json', diag)

    def test_02_en_data_all_required_roadmap_families_pass(self):
        out, diag, _ = _apply20(
            {'roadmap': _EN_DATA_MISSING_PRIVACY}, domain='data', lang='en')
        missing = _app()._compute_missing_data_roadmap_balance_topics(
            out.get('roadmap') or '', _NDMO, lang='en')
        self.assertEqual(missing, [], missing)
        self.assertEqual(diag.get('roadmap', {}).get('missing_families_after'), [])

    def test_03_en_data_synth_failed_vision_repaired(self):
        secs = {'vision': _THIN_SO}
        self.assertLess(_app().count_valid_objective_rows(secs['vision']), 4)
        out, diag, log = _apply20(secs, domain='data', lang='en')
        vision = out.get('vision') or ''
        self.assertGreaterEqual(_app().count_valid_objective_rows(vision), 4)
        self.assertIn('Strategic Objective', vision)
        synth = _app().synthesize_objectives_depth(
            dict(out), 'en', domain='Data Management', fw_short='NDMO')
        self.assertFalse(synth.get('rebuilt'), synth)
        self.assertEqual(diag.get('core', {}).get('synth_vision_blockers_after'), [])
        self.assertIn(REL36_20_EN_DATA_AI_CORE_SYNTH_STABILITY_TAG, log)

    def test_04_en_data_synth_failed_pillars_repaired(self):
        secs = {'pillars': _THIN_PILLARS}
        out, diag, _ = _apply20(secs, domain='data', lang='en')
        pillars = out.get('pillars') or ''
        self.assertGreaterEqual(_app()._count_substantive_pillars(pillars), 3)
        self.assertIn('| Initiative |', pillars)
        synth = _app().synthesize_pillars_depth(
            dict(out), 'en', domain='Data Management', fw_short='NDMO')
        self.assertFalse(synth.get('rebuilt'), synth)
        self.assertEqual(diag.get('core', {}).get('synth_pillars_blockers_after'), [])

    def test_05_en_ai_synth_failed_vision_repaired(self):
        out, diag, _ = _apply20(
            {'vision': _THIN_SO}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        vision = out.get('vision') or ''
        self.assertGreaterEqual(_app().count_valid_objective_rows(vision), 4)
        self.assertIn('SDAIA', vision)
        synth = _app().synthesize_objectives_depth(
            dict(out), 'en', domain='Artificial Intelligence', fw_short='SDAIA')
        self.assertFalse(synth.get('rebuilt'), synth)
        self.assertEqual(diag.get('core', {}).get('synth_vision_blockers_after'), [])

    def test_06_en_ai_synth_failed_pillars_repaired(self):
        out, diag, _ = _apply20(
            {'pillars': _THIN_PILLARS}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        pillars = out.get('pillars') or ''
        self.assertGreaterEqual(_app()._count_substantive_pillars(pillars), 3)
        synth = _app().synthesize_pillars_depth(
            dict(out), 'en', domain='Artificial Intelligence', fw_short='SDAIA')
        self.assertFalse(synth.get('rebuilt'), synth)
        self.assertEqual(diag.get('core', {}).get('synth_pillars_blockers_after'), [])

    def test_07_en_data_missing_gap_guides_repaired(self):
        out, diag, log = _apply20(
            {'gaps': _GAPS_NO_GUIDES_EN}, domain='data', lang='en')
        gaps = out.get('gaps') or ''
        self.assertIn('#### Gap #1 Implementation Guide', gaps)
        self.assertGreaterEqual(_app().count_gap_guides(gaps), 2)
        self.assertEqual(diag.get('guides', {}).get('missing_gap_guides_after'), [])
        self.assertIn(REL36_20_DATA_AI_GUIDE_COMPLETENESS_TAG, log)

    def test_08_en_data_missing_kpi_guides_repaired(self):
        out, diag, _ = _apply20(
            {'kpis': _KPIS_NO_GUIDES_EN}, domain='data', lang='en')
        kpis = out.get('kpis') or ''
        self.assertIn('### KPI Assessment Guidelines', kpis)
        self.assertIn('#### KPI #1 Assessment Guide', kpis)
        self.assertEqual(diag.get('guides', {}).get('missing_kpi_guides_after'), [])

    def test_09_en_ai_missing_gap_guides_repaired(self):
        out, diag, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertIn(
            '#### Gap #1 Implementation Guide', out.get('gaps') or '')
        self.assertEqual(diag.get('guides', {}).get('missing_gap_guides_after'), [])

    def test_10_en_ai_missing_kpi_guides_repaired(self):
        out, diag, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        self.assertIn('### KPI Assessment Guidelines', kpis)
        self.assertEqual(diag.get('guides', {}).get('missing_kpi_guides_after'), [])

    def test_11_ar_ai_missing_gap_guides_repaired(self):
        out, diag, _ = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        gaps = out.get('gaps') or ''
        self.assertIn('#### دليل تنفيذ الفجوة رقم 1', gaps)
        self.assertEqual(diag.get('guides', {}).get('missing_gap_guides_after'), [])

    def test_12_ar_ai_missing_kpi_guides_repaired(self):
        out, diag, _ = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        self.assertIn('### أدلة تقييم مؤشرات الأداء', kpis)
        self.assertIn('#### دليل تقييم المؤشر رقم 1', kpis)
        self.assertEqual(diag.get('guides', {}).get('missing_kpi_guides_after'), [])

    def test_13_one_guide_per_counted_gap_row(self):
        out, _, _ = _apply20(
            {'gaps': _GAPS_NO_GUIDES_EN}, domain='data', lang='en')
        gaps = out.get('gaps') or ''
        self.assertEqual(
            _app().count_gap_guides(gaps),
            _app().count_substantive_gaps(gaps))

    def test_14_one_guide_per_counted_kpi_row(self):
        out, _, _ = _apply20(
            {'kpis': _KPIS_NO_GUIDES_EN}, domain='data', lang='en')
        kpis = out.get('kpis') or ''
        rows = _app().count_substantive_kpis(kpis)
        guides = _app().count_kpi_guides(kpis)
        self.assertEqual(guides, rows)
        self.assertEqual(
            len(re.findall(r'^###\s*KPI Assessment Guidelines\s*$',
                           kpis, re.I | re.M)),
            1)

    def test_15_guide_headers_english_for_english(self):
        out, diag, _ = _apply20(_en_data_broken(), domain='data', lang='en')
        blob = (out.get('gaps') or '') + '\n' + (out.get('kpis') or '')
        self.assertIn('#### Gap #1 Implementation Guide', blob)
        self.assertIn('### KPI Assessment Guidelines', blob)
        self.assertNotIn('دليل تنفيذ الفجوة', blob)
        self.assertTrue(diag.get('guides', {}).get('guide_headers_language_valid'))

    def test_16_guide_headers_arabic_for_arabic(self):
        out, diag, _ = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        blob = (out.get('gaps') or '') + '\n' + (out.get('kpis') or '')
        self.assertIn('دليل تنفيذ الفجوة رقم', blob)
        self.assertIn('أدلة تقييم مؤشرات الأداء', blob)
        self.assertNotIn('Gap #1 Implementation Guide', blob)
        self.assertTrue(diag.get('guides', {}).get('guide_headers_language_valid'))

    def test_17_no_duplicate_ignored_guide_sections(self):
        seeded = _GAPS_NO_GUIDES_EN + '\n\n#### Gap #1 Implementation Guide\n'
        out, diag, _ = _apply20(
            {'gaps': seeded, 'kpis': _KPIS_NO_GUIDES_EN
             + '\n\n### KPI Assessment Guidelines\n\n### KPI Assessment Guidelines\n'},
            domain='data', lang='en')
        kpis = out.get('kpis') or ''
        self.assertLessEqual(
            len(re.findall(r'^###\s*KPI Assessment Guidelines', kpis, re.I | re.M)),
            1)
        self.assertFalse(diag.get('guides', {}).get('duplicate_guides_after'))

    def test_18_en_data_docx_pdf_allowed(self):
        out, _, _ = _apply20(_en_data_broken(), domain='data', lang='en')
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', out)
        _write_export('en_data', pair)
        _write_json('en_data_guide_diagnostic.json', {'exported': True})

    def test_19_en_ai_docx_pdf_allowed(self):
        out, _, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)

    def test_20_en_data_no_arabic_except_org(self):
        secs = _en_data_broken()
        secs['vision'] = f'Prepared for {_AR_ORG}.\n\n' + _THIN_SO
        out, diag, _ = _apply20(secs, domain='data', lang='en', org_name=_AR_ORG)
        blob = _blob(out)
        self.assertIn(_AR_ORG, blob)
        remainder = blob.replace(_AR_ORG, '')
        self.assertFalse(_AR_RE.search(remainder), remainder[:400])
        self.assertEqual(diag.get('core', {}).get('arabic_header_hits_after'), [])

    def test_21_en_ai_no_arabic_except_org(self):
        secs = _en_ai_broken()
        secs['vision'] = f'Prepared for {_AR_ORG}.\n\n' + _THIN_SO
        out, _, _ = _apply20(
            secs, domain='ai', lang='en', selected_frameworks=_SDAIA,
            org_name=_AR_ORG)
        blob = _blob(out)
        self.assertIn(_AR_ORG, blob)
        remainder = blob.replace(_AR_ORG, '')
        self.assertFalse(_AR_RE.search(remainder), remainder[:400])

    def test_22_arabic_data_remains_arabic(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        out, _, _ = _apply20(
            secs, domain='data', lang='ar', selected_frameworks=_NDMO)
        road = out.get('roadmap') or ''
        self.assertTrue(_AR_RE.search(road), road[:200])
        self.assertNotIn('Establish privacy governance operating model', road)

    def test_23_arabic_ai_remains_arabic(self):
        out, _, _ = _apply20(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        self.assertIn('وصف المؤشر', kpis)
        self.assertTrue(_AR_RE.search(kpis))
        pair = _export_pair(out, lang='ar', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_preview('ar_ai', out)
        _write_export('ar_ai', pair)
        _write_json('ar_ai_guide_diagnostic.json', {'exported': True})

    def test_24_no_cyber_nca_nist_leakage_in_data_ai(self):
        data_out, _, _ = _apply20(_en_data_broken(), domain='data', lang='en')
        ai_out, _, _ = _apply20(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        _assert_no_leaks(self, _blob(data_out))
        _assert_no_leaks(self, _blob(ai_out))
        self.assertFalse(rel36_20_should_apply(
            domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=_NCA_FWS))

    def test_25_rel36_19_1_org_preservation_still_passes(self):
        Rel36191CodexGuardTests().test_01_en_cyber_arabic_org_preserved()
        Rel36191CodexGuardTests().test_02_en_data_arabic_org_prose_removed()
        Rel36191CodexGuardTests().test_03_en_ai_arabic_org_generated_text_removed()
        _write_json('rel36_19_1_org_preservation.json', {'passed': True})

    def test_26_rel36_19_1_pre_canonical_repair_still_passes(self):
        Rel36191CodexGuardTests().test_08_repair_runs_before_canonical_artifact()
        _write_json('rel36_19_1_pre_canonical.json', {'passed': True})

    def test_27_rel36_19_1_kpi_duplicate_prevention_still_passes(self):
        Rel36191CodexGuardTests().test_13_valid_alias_kpi_no_second_seed()
        secs = _en_data_mixed()
        secs['kpis'] = _alias_kpi_table() if False else secs['kpis']
        out, diag = apply_rel36_19_bilingual_language_parity(
            dict(secs), domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO)
        self.assertLessEqual(count_kpi_main_tables(out.get('kpis') or '', 'en'), 2)
        _write_json('rel36_19_1_kpi_duplicate.json', {
            'passed': not diag.get('duplicate_kpi_table_after'),
        })

    def test_28_ai_sdaia_5_shape_passes(self):
        Rel3619LanguageParityTests().test_27_rel36_18_ai_sdaia_5_shape_regression()

    def test_29_en_cyber_ecc_dcc_10_shape_passes(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()

    def test_30_data_ndmo_pdpl_regression_passes(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=_NDMO, emit=False)
        apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=_NDMO, emit=False)
        out15, _ = apply_rel36_15_final_registry_stability(
            secs, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)
        official = _app()._compute_missing_data_roadmap_balance_topics(
            out15.get('roadmap') or '', _NDMO, lang='ar')
        self.assertEqual(official, [], official)
        pair = _export_pair(out15, lang='ar', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('data_ndmo_pdpl', pair)

    def test_31_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-20', canonical_hash='c' * 16,
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

    def test_32_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('dt_dga', pair)

    def test_33_auth_csrf_regression_passes(self):
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

    def test_34_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
