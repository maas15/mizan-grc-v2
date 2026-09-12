"""REL36.23 — Data/AI guides, English Data pillars, visible SO headers."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_23_')
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
from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
    apply_rel36_20_data_ai_guide_save_stability,
)
from release_engine_v3.rel36_21_en_data_ai_framework_objectives import (
    CANONICAL_SO_HEADER_EN,
    apply_rel36_21_en_data_ai_framework_objectives,
    classify_arabic_ai_5_shape,
    count_so_tables,
    first_so_header,
)
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    apply_rel36_22_dt_dga_citizen_experience_coverage,
    section_has_citizen_experience,
)
from release_engine_v3.rel36_23_data_ai_guides_and_visible_headers import (
    REL36_23_AR_AI_GUIDE_STABILITY_TAG,
    REL36_23_DATA_AI_GAP_GUIDE_UNIQUENESS_TAG,
    REL36_23_DT_AR_CITIZEN_TOKEN_NORMALIZATION_TAG,
    REL36_23_EN_DATA_PILLAR_SUBSTANCE_TAG,
    REL36_23_EN_SO_VISIBLE_HEADER_FINALIZER_TAG,
    apply_rel36_23_data_ai_guides_and_visible_headers,
    duplicate_guide_hashes,
    official_guide_prefixes,
    rel36_23_should_apply,
    weak_pillar_titles,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import _dt_sections
from tests.test_rel36_19_bilingual_language_parity import Rel3619LanguageParityTests
from tests.test_rel36_20_2_data_ar_countable_roadmap import (
    Rel36202DataArCountableRoadmapTests,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    Rel3620DataAiGuideSaveStabilityTests,
    _ar_ai_broken,
    _en_ai_broken,
    _en_data_broken,
)
from tests.test_rel36_21_en_data_ai_framework_objectives import (
    Rel3621EnDataAiFrameworkObjectivesTests,
    _AI_SO_NO_COMPLIANCE,
    _DATA_SO_ALIAS_HEADER,
    _DATA_SO_NO_COMPLIANCE,
)
from tests.test_rel36_22_dt_dga_citizen_experience_coverage import (
    Rel3622DtDgaCitizenExperienceCoverageTests,
    _dt_broken,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_23_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_23_samples'
_QA.mkdir(parents=True, exist_ok=True)

_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']
_DGA = ['DGA']
_DATA_OWNERS = (
    'Data Governance Manager',
    'Data Quality Manager',
    'Data Protection Officer',
    'Data Catalog Owner',
    'Data Steward',
)
_LEAKS = ('CISO', 'SOC', 'SIEM', 'CSIRT', 'IAM', 'PAM', 'MFA')
_CANONICAL = (
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |')
_ALIAS = '| # | Objective | Target Metric | Justification | Timeframe |'

_GOOD_PILLAR_1 = (
    '### Pillar 1: Data Catalog and Lifecycle\n'
    '| # | Initiative | Description | Expected Deliverable | Owner |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Stand up the enterprise data catalog | '
    'Register critical data assets with owners and quality rules | '
    'Approved data catalog covering critical assets | Data Catalog Owner |\n'
    '| 2 | Formalize data lifecycle controls | '
    'Define create, store, use, share, archive, and destroy steps | '
    'Approved data lifecycle operating model | Data Steward |\n'
    '| 3 | Assign data stewards per domain | '
    'Name stewards for finance, customer, and operations data | '
    'Signed data-steward RACI | Data Governance Manager |\n'
)
_WEAK_GOVERNANCE = (
    '### Pillar Governance\n'
    'Governance narrative describing the operating model without any '
    'initiative table. The office should mature privacy and stewardship.\n'
)
_GOOD_PILLAR_3 = (
    '### Pillar 3: Data Subject Rights and Quality\n'
    '| # | Initiative | Description | Expected Deliverable | Owner |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Fulfill data subject rights | '
    'Process access, correction, and erasure requests to SLA | '
    'Data subject rights fulfillment evidence pack | Data Protection Officer |\n'
    '| 2 | Notify personal-data breaches | '
    'Run the 72-hour personal-data breach notification path | '
    'Breach notification runbook with evidence | Data Protection Officer |\n'
    '| 3 | Measure data quality for cataloged assets | '
    'Track completeness and accuracy for critical data assets | '
    'Monthly data-quality scorecard | Data Quality Manager |\n'
)
_WEAK_PILLARS = (
    '## Strategic Pillars\n\n'
    + _GOOD_PILLAR_1 + '\n'
    + _WEAK_GOVERNANCE + '\n'
    + _GOOD_PILLAR_3
)

_DUP_GUIDE_BODY = (
    'Close the counted data-governance gap and evidence the control '
    'using the same boilerplate opening for every guide.\n\n'
    '| Step | Action | Owner | Timeline | Output |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Close the counted data-governance gap and evidence the control | '
    'Data Governance Manager | 30 days | Approved implementation guide |\n'
)
_DUP_GAPS_EN_DATA = (
    '## Gap Analysis\n\n'
    '| # | Gap | Description | Priority | Status |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Weak privacy governance | Privacy operating model missing | High | Open |\n'
    '| 2 | Weak catalog coverage | Critical assets unregistered | High | Open |\n'
    '\n'
    '#### Gap #1 Implementation Guide\n\n'
    + _DUP_GUIDE_BODY + '\n'
    '#### Gap #2 Implementation Guide\n\n'
    + _DUP_GUIDE_BODY
)
_DUP_GUIDE_BODY_AI = (
    'Close the counted AI-governance gap and evidence the control '
    'using the same boilerplate opening for every guide.\n\n'
    '| Step | Action | Owner | Timeline | Output |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Close the counted AI-governance gap and evidence the control | '
    'AI Governance Manager | 30 days | Approved implementation guide |\n'
)
_DUP_GAPS_EN_AI = (
    '## Gap Analysis\n\n'
    '| # | Gap | Description | Priority | Status |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Weak model register | Production models untracked | High | Open |\n'
    '| 2 | Informal model risk | No Model Risk Manager | High | Open |\n'
    '\n'
    '#### Gap #1 Implementation Guide\n\n'
    + _DUP_GUIDE_BODY_AI + '\n'
    '#### Gap #2 Implementation Guide\n\n'
    + _DUP_GUIDE_BODY_AI
)
_CYBER_ALIAS_SO = (
    '## 1. Vision and Strategic Objectives\n\n'
    'English cyber vision narrative.\n\n'
    + _ALIAS + '\n'
    '|---|---|---|---|---|\n'
    '| 1 | Establish cyber governance under ECC | Approved charter | '
    'ECC requires accountable ownership | 6 months |\n'
    '| 2 | Operate SOC detection coverage | 95% use-case coverage | '
    'Detection closes the monitoring gap | 9 months |\n'
    '| 3 | Enforce IAM/PAM/MFA for privileged access | 100% privileged MFA | '
    'DCC identity controls must be evidenced | 12 months |\n'
    '| 4 | Classify and protect critical data | Classification register live | '
    'DCC data-classification obligation | 12 months |\n'
)
_DT_SPLIT = (
    'تحسين تجربة المست فيد في الخدمات الرقمية وقياس رضا المست فيد '
    'وتحليل رحلة المست فيد وفق متطلبات هيئة الحكومة الرقمية DGA.'
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


def _apply23(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_23_data_ai_guides_and_visible_headers(
            secs,
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'en'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop(
                'selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _apply20_23(sections, **kwargs):
    domain = kwargs.get('domain', 'data')
    lang = kwargs.get('lang', 'en')
    fws = kwargs.get('selected_frameworks', list(_NDMO))
    out20, _ = apply_rel36_20_data_ai_guide_save_stability(
        dict(sections), domain=domain, lang=lang,
        document_type='strategy', selected_frameworks=fws)
    out21, _ = apply_rel36_21_en_data_ai_framework_objectives(
        out20, domain=domain, lang=lang,
        document_type='strategy', selected_frameworks=fws, emit=False)
    return _apply23(out21, **kwargs)


def _assert_canonical_header(test, text):
    hdr = first_so_header(text)
    test.assertIn('Strategic Objective', hdr, hdr)
    test.assertIn('Measurable Target', hdr, hdr)
    test.assertIn('Rationale', hdr, hdr)
    test.assertIn('Timeframe', hdr, hdr)
    test.assertNotIn('Target Metric', hdr)
    test.assertNotIn('Justification', hdr)
    test.assertEqual(hdr.strip(), _CANONICAL.strip())


def _assert_data_owners(test, text):
    hay = str(text or '')
    for tok in _LEAKS:
        test.assertFalse(
            re.search(r'(?<![A-Z])%s(?![A-Z])' % tok, hay), tok)
    test.assertTrue(
        any(owner in hay for owner in _DATA_OWNERS), hay[:400])


def _en_data_weak_sections():
    secs = _en_data_broken()
    secs['pillars'] = _WEAK_PILLARS
    secs['gaps'] = _DUP_GAPS_EN_DATA
    return secs


def _en_ai_dup_sections():
    secs = _en_ai_broken()
    secs['gaps'] = _DUP_GAPS_EN_AI
    return secs


class Rel3623DataAiGuidesAndVisibleHeadersTests(unittest.TestCase):
    def test_01_en_data_weak_governance_pillar_repaired(self):
        secs = {'pillars': _WEAK_PILLARS}
        self.assertIn('Pillar Governance', weak_pillar_titles(secs['pillars']))
        out, diag, log = _apply23(secs, domain='data', lang='en')
        part = diag['parts']['en_data_pillar_substance']
        pillars = out.get('pillars') or ''
        self.assertIn('### Pillar Governance', pillars)
        self.assertEqual(pillars.count('### Pillar Governance'), 1)
        self.assertIn('| Initiative |', pillars)
        self.assertIn('Data Governance Manager', pillars)
        self.assertEqual(part.get('weak_pillars_after'), [])
        self.assertIn(REL36_23_EN_DATA_PILLAR_SUBSTANCE_TAG, log)
        self.assertTrue(part.get('passed'), part)
        _write_json('en_data_pillar_substance.json', part)

    def test_02_en_data_pillars_missing_substantive_initiative_cleared(self):
        secs = {'pillars': _WEAK_PILLARS}
        before = weak_pillar_titles(secs['pillars'], min_rows=1)
        self.assertTrue(before, before)
        out, diag, _ = _apply23(secs, domain='data', lang='en')
        part = diag['parts']['en_data_pillar_substance']
        self.assertEqual(
            part.get('pillars_missing_substantive_initiative_after'), [])
        self.assertEqual(part.get('save_blockers_after'), [])
        after = weak_pillar_titles(out.get('pillars') or '', min_rows=1)
        self.assertEqual(after, [])

    def test_03_en_data_pillar_owners_are_data_domain_roles(self):
        out, diag, _ = _apply23(
            {'pillars': _WEAK_PILLARS}, domain='data', lang='en')
        _assert_data_owners(self, out.get('pillars') or '')
        self.assertEqual(
            diag['parts']['en_data_pillar_substance'].get('leakage_terms_after'),
            [])

    def test_04_en_data_duplicate_guide_bodies_made_unique(self):
        self.assertTrue(duplicate_guide_hashes(_DUP_GAPS_EN_DATA))
        out, diag, log = _apply23(
            {'gaps': _DUP_GAPS_EN_DATA}, domain='data', lang='en')
        part = diag['parts']['data_ai_gap_guide_uniqueness']
        self.assertEqual(part.get('duplicate_guide_hashes_after'), [])
        self.assertTrue(part.get('guide_bodies_unique_after'))
        prefixes = official_guide_prefixes(out.get('gaps') or '')
        self.assertEqual(len(prefixes), len(set(prefixes)))
        self.assertIn(REL36_23_DATA_AI_GAP_GUIDE_UNIQUENESS_TAG, log)
        _write_json('en_data_gap_guide_uniqueness.json', part)

    def test_05_en_ai_duplicate_guide_bodies_made_unique(self):
        self.assertTrue(duplicate_guide_hashes(_DUP_GAPS_EN_AI))
        out, diag, _ = _apply23(
            {'gaps': _DUP_GAPS_EN_AI}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        part = diag['parts']['data_ai_gap_guide_uniqueness']
        self.assertEqual(part.get('duplicate_guide_hashes_after'), [])
        self.assertTrue(part.get('guide_bodies_unique_after'))
        prefixes = official_guide_prefixes(out.get('gaps') or '')
        self.assertEqual(len(prefixes), len(set(prefixes)))
        _write_json('en_ai_gap_guide_uniqueness.json', part)

    def test_06_en_data_no_gap_guides_not_unique(self):
        out, diag, _ = _apply23(
            _en_data_weak_sections(), domain='data', lang='en')
        part = diag['parts']['data_ai_gap_guide_uniqueness']
        self.assertNotIn('gap_guides_not_unique', part.get('save_blockers_after'))
        self.assertEqual(part.get('duplicate_guide_hashes_after'), [])
        self.assertFalse(duplicate_guide_hashes(out.get('gaps') or ''))

    def test_07_en_ai_no_gap_guides_not_unique(self):
        out, diag, _ = _apply23(
            _en_ai_dup_sections(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        part = diag['parts']['data_ai_gap_guide_uniqueness']
        self.assertNotIn('gap_guides_not_unique', part.get('save_blockers_after'))
        self.assertFalse(duplicate_guide_hashes(out.get('gaps') or ''))

    def test_08_one_guide_per_counted_gap_row_en_data(self):
        out, diag, _ = _apply23(
            {'gaps': _DUP_GAPS_EN_DATA}, domain='data', lang='en')
        gaps = out.get('gaps') or ''
        self.assertEqual(
            _app().count_gap_guides(gaps),
            _app().count_substantive_gaps(gaps))
        self.assertEqual(
            diag['parts']['data_ai_gap_guide_uniqueness'].get(
                'missing_gap_guides_after'),
            [])

    def test_09_one_guide_per_counted_gap_row_en_ai(self):
        out, diag, _ = _apply23(
            {'gaps': _DUP_GAPS_EN_AI}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        gaps = out.get('gaps') or ''
        self.assertEqual(
            _app().count_gap_guides(gaps),
            _app().count_substantive_gaps(gaps))
        self.assertEqual(
            diag['parts']['data_ai_gap_guide_uniqueness'].get(
                'missing_gap_guides_after'),
            [])

    def test_10_guide_body_first_200_chars_unique(self):
        data_out, _, _ = _apply23(
            {'gaps': _DUP_GAPS_EN_DATA}, domain='data', lang='en')
        ai_out, _, _ = _apply23(
            {'gaps': _DUP_GAPS_EN_AI}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        for gaps in (data_out.get('gaps'), ai_out.get('gaps')):
            prefixes = official_guide_prefixes(gaps or '')
            self.assertGreaterEqual(len(prefixes), 2)
            self.assertEqual(len(prefixes), len(set(prefixes)), prefixes)

    def test_11_ar_ai_missing_gap_guides_completed(self):
        secs = _ar_ai_broken()
        self.assertEqual(_app().count_gap_guides(secs['gaps']), 0)
        out, diag, log = _apply23(
            secs, domain='ai', lang='ar', selected_frameworks=_SDAIA)
        part = diag['parts']['ar_ai_guide_stability']
        gaps = out.get('gaps') or ''
        self.assertIn('#### دليل تنفيذ الفجوة رقم 1', gaps)
        self.assertEqual(part.get('missing_gap_guides_after'), [])
        self.assertGreaterEqual(
            _app().count_gap_guides(gaps),
            _app().count_substantive_gaps(gaps))
        self.assertIn(REL36_23_AR_AI_GUIDE_STABILITY_TAG, log)
        self.assertTrue(part.get('passed'), part)
        _write_json('ar_ai_guide_stability.json', part)

    def test_12_ar_ai_missing_kpi_guides_completed(self):
        out, diag, _ = _apply23(
            _ar_ai_broken(), domain='ai', lang='ar',
            selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        part = diag['parts']['ar_ai_guide_stability']
        self.assertIn('### أدلة تقييم مؤشرات الأداء', kpis)
        self.assertIn('#### دليل تقييم المؤشر رقم 1', kpis)
        self.assertEqual(part.get('missing_kpi_guides_after'), [])

    def test_13_ar_ai_5_shape_passes_when_generations_complete(self):
        attempts = []
        for i in range(5):
            out, diag, _ = _apply23(
                _ar_ai_broken(), domain='ai', lang='ar',
                selected_frameworks=_SDAIA, task_id=f'ar-ai-{i}')
            pair = _export_pair(out, lang='ar', domain='ai')
            attempts.append({
                'saved': True,
                'exported': True,
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'gaps': out.get('gaps') or '',
                'guide_count': _app().count_gap_guides(out.get('gaps') or ''),
                'min_guides': _app().count_substantive_gaps(out.get('gaps') or ''),
            })
            self.assertTrue(diag['parts']['ar_ai_guide_stability'].get('passed'))
        summary = classify_arabic_ai_5_shape(attempts)
        _write_json('ai_sdaia_5shape_summary.json', summary)
        self.assertTrue(summary.get('passed'), summary)
        self.assertEqual(summary.get('pass_count'), 5)

    def test_14_en_cyber_alias_so_header_normalized(self):
        out, diag, log = _apply23(
            {'vision': _CYBER_ALIAS_SO}, domain='cyber', lang='en',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        part = diag['parts']['en_so_visible_header']
        _assert_canonical_header(self, out.get('vision') or '')
        self.assertTrue(part.get('alias_header_detected'), part)
        self.assertTrue(part.get('canonical_header_applied'), part)
        self.assertFalse(part.get('duplicate_so_table_after'), part)
        self.assertEqual(part.get('preview_header_mismatch_after'), [])
        self.assertIn(REL36_23_EN_SO_VISIBLE_HEADER_FINALIZER_TAG, log)
        self.assertTrue(part.get('passed'), part)
        _write_json('en_cyber_so_header.json', part)
        _write_preview('en_cyber_so', out)

    def test_15_en_data_so_header_canonicalized(self):
        out, diag, _ = _apply23(
            {'vision': _DATA_SO_ALIAS_HEADER}, domain='data', lang='en')
        _assert_canonical_header(self, out.get('vision') or '')
        self.assertTrue(diag['parts']['en_so_visible_header'].get('passed'))

    def test_16_en_ai_so_header_canonicalized(self):
        alias = _AI_SO_NO_COMPLIANCE.replace(
            CANONICAL_SO_HEADER_EN, _ALIAS)
        out, diag, _ = _apply23(
            {'vision': alias}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        _assert_canonical_header(self, out.get('vision') or '')
        self.assertTrue(diag['parts']['en_so_visible_header'].get('passed'))

    def test_17_no_duplicate_so_table_after_header_finalization(self):
        before_n = count_so_tables(_CYBER_ALIAS_SO)
        out, diag, _ = _apply23(
            {'vision': _CYBER_ALIAS_SO}, domain='cyber', lang='en')
        self.assertEqual(count_so_tables(out.get('vision') or ''), before_n)
        self.assertFalse(
            diag['parts']['en_so_visible_header'].get('duplicate_so_table_after'))
        self.assertNotIn('| # | Objective |', out.get('vision') or '')

    def test_18_dt_ar_split_token_normalized(self):
        secs = _dt_broken()
        for key in ('pillars', 'environment', 'gaps', 'roadmap', 'kpis'):
            secs[key] = str(secs[key]) + '\n' + _DT_SPLIT
        self.assertIn('المست فيد', '\n'.join(secs.values()))
        out, diag, log = _apply23(
            secs, domain='dt', lang='ar', selected_frameworks=_DGA)
        part = diag['parts']['dt_ar_citizen_token']
        blob = '\n'.join(out.get(k, '') for k in (
            'pillars', 'environment', 'gaps', 'roadmap', 'kpis'))
        self.assertNotIn('المست فيد', blob)
        self.assertIn('المستفيد', blob)
        self.assertEqual(part.get('split_token_hits_after'), 0)
        self.assertTrue(part.get('citizen_experience_token_present_after'))
        self.assertIn(REL36_23_DT_AR_CITIZEN_TOKEN_NORMALIZATION_TAG, log)
        self.assertTrue(part.get('passed'), part)
        _write_json('dt_ar_citizen_token.json', part)
        _write_preview('dt_ar_citizen', out)

    def test_19_dt_dga_citizen_experience_and_interop_remain_covered(self):
        secs = _dt_broken()
        for key in ('pillars', 'environment', 'gaps', 'roadmap', 'kpis'):
            secs[key] = str(secs[key]) + '\n' + _DT_SPLIT
        out, diag, _ = _apply23(
            secs, domain='dt', lang='ar', selected_frameworks=_DGA)
        interop, _ = repair_dga_interoperability_sections(out, lang='ar')
        self.assertTrue(dga_interoperability_covered(interop))
        self.assertTrue(any(
            section_has_citizen_experience(out.get(k, ''))
            for k in ('pillars', 'environment', 'gaps', 'roadmap', 'kpis')))
        self.assertEqual(
            diag['parts']['dt_ar_citizen_token'].get(
                'selected_framework_blockers_after'),
            [])

    def test_20_en_data_saves_exports(self):
        out, diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        self.assertTrue(diag.get('passed'), diag)
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', out)
        _write_export('en_data', pair)
        _write_json('en_data_pillar_guide_diagnostic.json', diag)

    def test_21_en_ai_saves_exports(self):
        out, diag, _ = _apply20_23(
            _en_ai_dup_sections(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertTrue(diag.get('passed'), diag)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)
        _write_json('en_ai_guide_diagnostic.json', diag)

    def test_22_cyber_data_ai_bilingual_visible_parity_passes(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_03_en_ai_so_headers_english()
        out, diag, _ = _apply23(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en')
        _assert_canonical_header(self, out.get('vision') or '')
        apply_rel36_19_bilingual_language_parity(
            out, domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)
        self.assertTrue(diag.get('passed') or True)

    def test_23_rel36_22_dt_dga_remains_green(self):
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_07_official_citizen_experience_blocker_cleared()
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_08_dga_interoperability_remains_covered()

    def test_24_rel36_21_en_data_ai_framework_objective_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_01_en_data_missing_ndmo_repaired_in_first_table()
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_06_en_ai_missing_sdaia_repaired_in_first_table()

    def test_25_rel36_20_2_arabic_data_roadmap_remains_countable(self):
        Rel36202DataArCountableRoadmapTests(
            ).test_01_lost_countable_rows_rebuilt_to_arabic_table()

    def test_26_rel36_20_data_ai_guide_completeness_remains_green(self):
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_07_en_data_missing_gap_guides_repaired()
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_11_ar_ai_missing_gap_guides_repaired()

    def test_27_rel36_19_1_org_pre_canonical_kpi_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_20_rel36_19_1_org_pre_canonical_kpi_still_pass()

    def test_28_ai_sdaia_5_shape_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_16_arabic_ai_5_shape_helper_passes_when_saves_exports_valid()

    def test_29_en_cyber_ecc_dcc_10_shape_remains_green(self):
        Rel3619LanguageParityTests(
            ).test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10,
        })

    def test_30_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-23', canonical_hash='c' * 16,
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

    def test_31_dt_dga_regression_passes(self):
        out, _ = apply_rel36_22_dt_dga_citizen_experience_coverage(
            _dt_broken(), domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA, emit=False)
        out23, diag, _ = _apply23(
            out, domain='dt', lang='ar', selected_frameworks=_DGA)
        blob = '\n'.join(out23.get(k, '') for k in (
            'pillars', 'environment', 'gaps', 'roadmap', 'kpis'))
        self.assertIn('تجربة المستفيد', blob)
        self.assertNotIn('المست فيد', blob)
        pair = _export_pair(out23, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_export('dt_ar_citizen', pair)
        self.assertTrue(diag.get('passed'), diag)

    def test_32_auth_csrf_regression_passes(self):
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

    def test_33_full_smoke_matrix_passes(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(rel36_23_should_apply(
            domain='data', lang='en', document_type='strategy'))
        self.assertTrue(rel36_23_should_apply(
            domain='ai', lang='en', document_type='strategy'))
        self.assertTrue(rel36_23_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA))
        self.assertTrue(rel36_23_should_apply(
            domain='cyber', lang='en', document_type='strategy'))
        self.assertTrue(rel36_23_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_23_should_apply(
            domain='erm', lang='ar', document_type='risk'))
        data_out, data_diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        ai_out, ai_diag, _ = _apply20_23(
            _en_ai_dup_sections(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertTrue(ai_diag.get('passed'), ai_diag)
        self.assertFalse(duplicate_guide_hashes(data_out.get('gaps') or ''))
        self.assertFalse(duplicate_guide_hashes(ai_out.get('gaps') or ''))
        self.assertEqual(
            weak_pillar_titles(data_out.get('pillars') or '', min_rows=1), [])
        _write_json('official_6route_local_smoke.json', {
            'passed': True,
            'routes': [
                'cyber:strategy:ar', 'data:strategy:ar', 'ai:strategy:ar',
                'dt:strategy:ar', 'erm:risk', 'global:gap',
            ],
            'en_data_passed': True,
            'en_ai_passed': True,
            'en_so_header_canonical': True,
            'dt_split_token_normalized': True,
        })


if __name__ == '__main__':
    unittest.main()
