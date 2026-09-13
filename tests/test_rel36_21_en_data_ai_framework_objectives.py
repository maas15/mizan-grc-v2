"""REL36.21 — English Data/AI selected-framework objective coverage."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_21_')
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
from release_engine_v3.rel36_19_bilingual_language_parity import (
    apply_rel36_19_bilingual_language_parity,
    count_kpi_main_tables,
)
from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
    apply_rel36_20_data_ai_guide_save_stability,
)
from release_engine_v3.rel36_21_en_data_ai_framework_objectives import (
    ARABIC_GAP_GUIDE_PHRASES,
    CANONICAL_SO_HEADER_EN,
    REL36_21_EN_DATA_AI_FRAMEWORK_OBJECTIVE_COVERAGE_TAG,
    apply_rel36_21_en_data_ai_framework_objectives,
    classify_arabic_ai_5_shape,
    count_accepted_arabic_gap_guides,
    count_so_tables,
    first_so_header,
    rel36_21_should_apply,
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
    Rel3620DataAiGuideSaveStabilityTests,
    _en_ai_broken,
    _en_data_broken,
)
from tests.test_rel36_20_1_data_roadmap_family_integrity import (
    Rel36201DataRoadmapFamilyIntegrityTests,
)
from tests.test_rel36_20_2_data_ar_countable_roadmap import (
    Rel36202DataArCountableRoadmapTests,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_21_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_21_samples'
_QA.mkdir(parents=True, exist_ok=True)

_AR_RE = re.compile(r'[\u0600-\u06FF]')
_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']
_DATA_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_AI_LEAKS = _DATA_LEAKS + ('IAM', 'PAM', 'MFA')

_DATA_SO_NO_COMPLIANCE = (
    '## 1. Vision and Strategic Objectives\n\n'
    'English data vision narrative covering the operating model.\n\n'
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Publish the enterprise data catalog covering critical assets | '
    '100% of critical data assets cataloged | '
    'NDMO requires a governed catalog as the system of record | 12 months |\n'
    '| 2 | Operationalize personal data protection and privacy governance | '
    'Approved privacy governance charter and DPO operating model | '
    'PDPL requires a named privacy governance owner | 9 months |\n'
    '| 3 | Classify personal data and enforce consent management | '
    'All personal-data processing activities classified and consented | '
    'PDPL consent and classification controls must be evidenced | 12 months |\n'
    '| 4 | Fulfill data subject rights within published SLAs | '
    '95% of data-subject requests closed within the SLA | '
    'PDPL data-subject rights require a measurable fulfillment path | 12 months |\n'
)

_DATA_SO_ALIAS_HEADER = (
    '## 1. Vision and Strategic Objectives\n\n'
    'English data vision narrative.\n\n'
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Publish the enterprise data catalog | '
    '100% of critical assets cataloged | NDMO catalog obligation | 12 months |\n'
    '| 2 | Operationalize privacy governance | '
    'Approved privacy charter | PDPL owner obligation | 9 months |\n'
    '| 3 | Classify personal data | All processing classified | '
    'PDPL classification evidence | 12 months |\n'
    '| 4 | Fulfill data subject rights | 95% SLA | PDPL fulfillment path | 12 months |\n'
)

_DATA_SO_OUTSIDE_ONLY = (
    '## 1. Vision and Strategic Objectives\n\n'
    'The operating environment must satisfy NDMO and PDPL obligations.\n\n'
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Publish the enterprise data catalog | 100% cataloged | '
    'Catalog is the system of record | 12 months |\n'
    '| 2 | Raise data-quality coverage | 90% quality rules | '
    'Quality closes the integrity gap | 9 months |\n'
    '| 3 | Govern data lifecycle and retention | Approved schedules | '
    'Lifecycle closes the retention gap | 12 months |\n'
    '| 4 | Stand up stewardship operating model | Named stewards | '
    'Stewardship closes the ownership gap | 8 months |\n'
    '\n## Environment\n\nNDMO data governance and PDPL personal data protection apply.\n'
)

_DATA_SO_PLUS_LATER = (
    _DATA_SO_NO_COMPLIANCE
    + '\n### Later ignored objectives\n\n'
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Later NDMO mention only | 50% | NDMO text outside first table | 18 months |\n'
)

_AI_SO_NO_COMPLIANCE = (
    '## 1. Vision and Strategic Objectives\n\n'
    'English AI vision narrative for the operating model.\n\n'
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Establish AI governance under SDAIA | '
    'Approved AI policy and governance charter | '
    'Governance closes the SDAIA accountability gap | 6 months |\n'
    '| 2 | Register production AI models | '
    '100% of production models recorded | '
    'Registration closes the inventory gap | 8 months |\n'
    '| 3 | Operationalize AI risk and human oversight | '
    'Human-oversight logs complete | '
    'Oversight closes the SDAIA risk-control gap | 9 months |\n'
    '| 4 | Stand up MLOps quality controls | '
    'MLOps pipeline covering production models | '
    'MLOps closes the lifecycle-quality gap | 10 months |\n'
)

_AI_SO_OUTSIDE_ONLY = (
    '## 1. Vision and Strategic Objectives\n\n'
    'SDAIA responsible AI is named in the environment only.\n\n'
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Register production AI models | 100% recorded | '
    'Registration closes the inventory gap | 8 months |\n'
    '| 2 | Operationalize human oversight | Oversight logs complete | '
    'Oversight closes the risk-control gap | 9 months |\n'
    '| 3 | Stand up MLOps quality controls | Pipeline live | '
    'MLOps closes the lifecycle-quality gap | 10 months |\n'
    '| 4 | Publish AI transparency artifacts | Model cards issued | '
    'Transparency closes the disclosure gap | 12 months |\n'
    '\n## Environment\n\nSDAIA responsible AI requirements apply to high-impact use cases.\n'
)

_AI_SO_PLUS_LATER = (
    _AI_SO_NO_COMPLIANCE
    + '\n### Later ignored objectives\n\n'
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Later SDAIA mention only | 50% | SDAIA text outside first table | 18 months |\n'
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


def _apply21(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_21_en_data_ai_framework_objectives(
            secs,
            domain=kwargs.pop('domain', 'data'),
            lang=kwargs.pop('lang', 'en'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop(
                'selected_frameworks', list(_NDMO)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _apply20_21(sections, **kwargs):
    _TLS.depth = 0
    domain = kwargs.get('domain', 'data')
    lang = kwargs.get('lang', 'en')
    fws = kwargs.get('selected_frameworks', list(_NDMO))
    out20, _ = apply_rel36_20_data_ai_guide_save_stability(
        dict(sections), domain=domain, lang=lang,
        document_type='strategy', selected_frameworks=fws)
    return _apply21(out20, **kwargs)


_FW_DOMAIN = {
    'data': 'Data Management',
    'ai': 'Artificial Intelligence',
    'cyber': 'Cyber Security',
}


def _official_missing(sections, fws, domain, lang='en'):
    return list(_app()._compute_missing_compliance_objective(
        sections, fws, domain=_FW_DOMAIN.get(domain, domain), lang=lang) or [])


def _first_table_block(text):
    header = first_so_header(text)
    if not header:
        return text or ''
    idx = (text or '').find(header)
    rest = (text or '')[idx:]
    cut = re.search(r'\n### |\n## ', rest[len(header):])
    if cut:
        return rest[:len(header) + cut.start()]
    return rest


def _assert_canonical_header(test, text):
    hdr = first_so_header(text)
    test.assertIn('Strategic Objective', hdr, hdr)
    test.assertIn('Measurable Target', hdr, hdr)
    test.assertIn('Rationale', hdr, hdr)
    test.assertIn('Timeframe', hdr, hdr)
    test.assertNotIn('Target Metric', hdr)
    test.assertNotIn('Justification', hdr)


def _assert_no_leaks(test, text, extra=()):
    hay = str(text or '')
    for tok in list(_DATA_LEAKS) + list(extra):
        if tok == 'NCA' or tok in {'IAM', 'PAM', 'MFA'}:
            test.assertFalse(
                re.search(r'(?<![A-Z])%s(?![A-Z])' % tok, hay), tok)
            continue
        test.assertNotIn(tok, hay, tok)


class Rel3621EnDataAiFrameworkObjectivesTests(unittest.TestCase):
    def test_01_en_data_missing_ndmo_repaired_in_first_table(self):
        secs = {'vision': _DATA_SO_NO_COMPLIANCE}
        before = _official_missing(secs, _NDMO, 'data')
        self.assertIn('NDMO', before, before)
        out, diag, log = _apply21(secs, domain='data', lang='en')
        vision = out.get('vision') or ''
        first = _first_table_block(vision)
        self.assertIn('Align enterprise data governance with NDMO', first)
        self.assertIn('compliance and alignment with NDMO', first)
        after = _official_missing(out, _NDMO, 'data')
        self.assertNotIn('NDMO', after, after)
        self.assertIn('NDMO', diag.get('inserted_framework_objectives'), diag)
        self.assertIn(REL36_21_EN_DATA_AI_FRAMEWORK_OBJECTIVE_COVERAGE_TAG, log)
        self.assertEqual(diag.get('missing_framework_objectives_after'), [])
        self.assertTrue(diag.get('passed'), diag)
        _write_json('en_data_framework_objective_diagnostic.json', diag)

    def test_02_en_data_missing_pdpl_repaired_in_first_table(self):
        secs = {'vision': _DATA_SO_NO_COMPLIANCE}
        before = _official_missing(secs, _NDMO, 'data')
        self.assertIn('PDPL', before, before)
        out, diag, _ = _apply21(secs, domain='data', lang='en')
        first = _first_table_block(out.get('vision') or '')
        self.assertIn('Achieve PDPL compliance for personal data protection', first)
        self.assertIn('compliance and alignment with PDPL', first)
        after = _official_missing(out, _NDMO, 'data')
        self.assertNotIn('PDPL', after, after)
        self.assertIn('PDPL', diag.get('inserted_framework_objectives'), diag)

    def test_03_en_data_outside_so_table_still_gets_counted_objectives(self):
        secs = {
            'vision': _DATA_SO_OUTSIDE_ONLY,
            'environment': 'NDMO and PDPL regulatory context.',
            'roadmap': '| Phase | Initiative | Framework |\n|---|---|---|\n'
                       '| 1 | Catalog | NDMO |\n| 2 | Consent | PDPL |\n',
        }
        before = _official_missing(secs, _NDMO, 'data')
        self.assertTrue(before, before)
        out, diag, _ = _apply21(secs, domain='data', lang='en')
        after = _official_missing(out, _NDMO, 'data')
        self.assertEqual(after, [], after)
        first = _first_table_block(out.get('vision') or '')
        self.assertIn('NDMO', first)
        self.assertIn('PDPL', first)
        self.assertIn('compliance', first.lower())
        self.assertEqual(diag.get('missing_framework_objectives_after'), [])

    def test_04_en_data_does_not_append_second_ignored_so_table(self):
        before_n = count_so_tables(_DATA_SO_PLUS_LATER)
        self.assertGreaterEqual(before_n, 2)
        out, diag, _ = _apply21(
            {'vision': _DATA_SO_PLUS_LATER}, domain='data', lang='en')
        after_n = count_so_tables(out.get('vision') or '')
        self.assertEqual(after_n, before_n, out.get('vision'))
        self.assertFalse(diag.get('duplicate_so_table_after'), diag)
        first = _first_table_block(out.get('vision') or '')
        self.assertIn('Align enterprise data governance with NDMO', first)

    def test_05_en_data_saves_exports_after_repair(self):
        out, diag, _ = _apply20_21(_en_data_broken(), domain='data', lang='en')
        missing = _official_missing(out, _NDMO, 'data')
        self.assertEqual(missing, [], missing)
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        diag['docx_allowed'] = True
        diag['pdf_allowed'] = True
        _write_preview('en_data', out)
        _write_export('en_data', pair)
        _write_json('en_data_framework_objective_diagnostic.json', diag)

    def test_06_en_ai_missing_sdaia_repaired_in_first_table(self):
        secs = {'vision': _AI_SO_NO_COMPLIANCE}
        before = _official_missing(secs, _SDAIA, 'ai')
        self.assertIn('SDAIA', before, before)
        out, diag, log = _apply21(
            secs, domain='ai', lang='en', selected_frameworks=_SDAIA)
        first = _first_table_block(out.get('vision') or '')
        self.assertIn('Align artificial intelligence governance with SDAIA', first)
        self.assertIn('compliance and alignment with SDAIA', first)
        self.assertIn('responsible AI', first)
        after = _official_missing(out, _SDAIA, 'ai')
        self.assertNotIn('SDAIA', after, after)
        self.assertEqual(diag.get('missing_framework_objectives_after'), [])
        self.assertTrue(diag.get('passed'), diag)
        self.assertIn(REL36_21_EN_DATA_AI_FRAMEWORK_OBJECTIVE_COVERAGE_TAG, log)
        _write_json('en_ai_framework_objective_diagnostic.json', diag)

    def test_07_en_ai_outside_so_table_still_gets_counted_objective(self):
        secs = {
            'vision': _AI_SO_OUTSIDE_ONLY,
            'environment': 'SDAIA responsible AI requirements.',
        }
        before = _official_missing(secs, _SDAIA, 'ai')
        self.assertIn('SDAIA', before, before)
        out, _, _ = _apply21(
            secs, domain='ai', lang='en', selected_frameworks=_SDAIA)
        after = _official_missing(out, _SDAIA, 'ai')
        self.assertEqual(after, [], after)
        first = _first_table_block(out.get('vision') or '')
        self.assertIn('SDAIA', first)
        self.assertIn('compliance', first.lower())

    def test_08_en_ai_does_not_append_second_ignored_so_table(self):
        before_n = count_so_tables(_AI_SO_PLUS_LATER)
        out, diag, _ = _apply21(
            {'vision': _AI_SO_PLUS_LATER}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        after_n = count_so_tables(out.get('vision') or '')
        self.assertEqual(after_n, before_n)
        self.assertFalse(diag.get('duplicate_so_table_after'), diag)

    def test_09_en_ai_saves_exports_after_repair(self):
        out, diag, _ = _apply20_21(
            _en_ai_broken(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        missing = _official_missing(out, _SDAIA, 'ai')
        self.assertEqual(missing, [], missing)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)
        _write_json('en_ai_framework_objective_diagnostic.json', diag)

    def test_10_canonical_english_so_header_used(self):
        out, diag, _ = _apply21(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en')
        _assert_canonical_header(self, out.get('vision') or '')
        self.assertIn('Strategic Objective', diag.get('first_so_header_after'))
        self.assertIn(CANONICAL_SO_HEADER_EN, (out.get('vision') or ''))

    def test_11_alias_headers_normalized_without_duplicate_tables(self):
        before_n = count_so_tables(_DATA_SO_ALIAS_HEADER)
        self.assertEqual(before_n, 1)
        out, diag, _ = _apply21(
            {'vision': _DATA_SO_ALIAS_HEADER}, domain='data', lang='en')
        _assert_canonical_header(self, out.get('vision') or '')
        self.assertEqual(count_so_tables(out.get('vision') or ''), 1)
        self.assertFalse(diag.get('duplicate_so_table_after'), diag)
        self.assertNotIn('| # | Objective |', out.get('vision') or '')

    def test_12_no_arabic_generated_prose_or_headers_in_en_data_ai(self):
        data_out, data_diag, _ = _apply21(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en')
        ai_out, ai_diag, _ = _apply21(
            {'vision': _AI_SO_NO_COMPLIANCE}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        for blob, diag in (
                (data_out.get('vision') or '', data_diag),
                (ai_out.get('vision') or '', ai_diag)):
            self.assertFalse(_AR_RE.search(blob), blob[:300])
            self.assertEqual(diag.get('arabic_header_hits_after'), [])
            self.assertEqual(diag.get('arabic_prose_hits_after'), [])

    def test_13_en_data_no_cyber_leakage(self):
        out, diag, _ = _apply21(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en')
        _assert_no_leaks(self, out.get('vision') or '')
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_14_en_ai_no_cyber_leakage(self):
        out, diag, _ = _apply21(
            {'vision': _AI_SO_NO_COMPLIANCE}, domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        _assert_no_leaks(self, out.get('vision') or '', extra=('IAM', 'PAM', 'MFA'))
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_15_arabic_ai_helper_accepts_guide_heading_aliases(self):
        apply_text = '#### دليل تطبيق الفجوة رقم 1\nstep\n'
        tanfith_text = '#### دليل تنفيذ الفجوة رقم 1\nstep\n'
        self.assertGreaterEqual(count_accepted_arabic_gap_guides(apply_text), 1)
        self.assertGreaterEqual(count_accepted_arabic_gap_guides(tanfith_text), 1)
        self.assertIn('دليل تطبيق الفجوة', ARABIC_GAP_GUIDE_PHRASES)
        self.assertIn('دليل تنفيذ الفجوة', ARABIC_GAP_GUIDE_PHRASES)
        # Save-gate counter is unchanged: تنفيذ still counts.
        self.assertGreaterEqual(_app().count_gap_guides(tanfith_text), 1)

    def test_16_arabic_ai_5_shape_helper_passes_when_saves_exports_valid(self):
        attempts = []
        for i in range(1, 6):
            attempts.append({
                'saved': True,
                'exported': True,
                'docx_allowed': True,
                'pdf_allowed': True,
                'gaps': (
                    f'#### دليل تطبيق الفجوة رقم {i}\n'
                    f'#### دليل تقييم المؤشر رقم {i}\n'
                    '### أدلة تقييم مؤشرات الأداء\n'
                ),
                'min_guides': 1,
            })
        payload = classify_arabic_ai_5_shape(attempts)
        self.assertEqual(payload['pass_count'], 5, payload)
        self.assertTrue(payload['passed'], payload)
        failed = classify_arabic_ai_5_shape([
            {**attempts[0], 'saved': False},
            *attempts[1:],
        ])
        self.assertFalse(failed['passed'], failed)
        _write_json('ar_ai_5shape_summary.json', payload)

    def test_17_rel36_20_2_arabic_data_roadmap_remains_countable(self):
        Rel36202DataArCountableRoadmapTests(
            ).test_01_lost_countable_rows_rebuilt_to_arabic_table()
        _write_json('ar_data_countable_roadmap_diagnostic.json', {'passed': True})

    def test_18_rel36_20_1_family_duplicate_restart_cleared(self):
        Rel36201DataRoadmapFamilyIntegrityTests(
            ).test_01_arabic_duplicated_family_repaired()

    def test_19_rel36_20_en_data_ai_guide_completion_still_passes(self):
        Rel3620DataAiGuideSaveStabilityTests().test_07_en_data_missing_gap_guides_repaired()
        Rel3620DataAiGuideSaveStabilityTests().test_09_en_ai_missing_gap_guides_repaired()

    def test_20_rel36_19_1_org_pre_canonical_kpi_still_pass(self):
        Rel36191CodexGuardTests().test_01_en_cyber_arabic_org_preserved()
        Rel36191CodexGuardTests().test_08_repair_runs_before_canonical_artifact()
        Rel36191CodexGuardTests().test_13_valid_alias_kpi_no_second_seed()
        _write_json('rel36_19_1_org_preservation.json', {'passed': True})
        _write_json('rel36_19_1_pre_canonical.json', {'passed': True})
        _write_json('rel36_19_1_kpi_duplicate.json', {'passed': True})

    def test_21_cyber_data_ai_bilingual_parity_still_passes(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_04_en_ai_objective_rows_have_no_arabic()

    def test_22_ai_sdaia_5_shape_still_passes(self):
        Rel3619LanguageParityTests().test_27_rel36_18_ai_sdaia_5_shape_regression()

    def test_23_en_cyber_ecc_dcc_10_shape_still_passes(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10,
        })

    def test_24_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-21', canonical_hash='c' * 16,
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

    def test_25_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)

    def test_26_auth_csrf_regression_passes(self):
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

    def test_27_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(rel36_21_should_apply(
            domain='data', lang='en', document_type='strategy'))
        self.assertTrue(rel36_21_should_apply(
            domain='ai', lang='en', document_type='strategy'))
        self.assertFalse(rel36_21_should_apply(
            domain='data', lang='ar', document_type='strategy'))
        self.assertFalse(rel36_21_should_apply(
            domain='cyber', lang='en', document_type='strategy'))
        self.assertTrue(rel36_21_should_apply(
            domain='cyber', lang='en', document_type='strategy',
            header_only=True))


if __name__ == '__main__':
    unittest.main()
