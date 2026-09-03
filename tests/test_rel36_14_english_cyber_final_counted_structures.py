"""REL36.14 — English Cyber final counted-structure stabilization."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_14_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.rel23_finalize import (
    apply_rel23_cyber_finalize,
    rel23_blocking_errors,
)
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
    missing_families,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _TLS,
    _owner_binding_inventory,
    _rel2_pillars_blockers,
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
)
from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
    REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG,
    apply_rel36_14_en_cyber_final_counted_structures,
    evaluate_rel36_14_en_cyber_final_counted_structures,
    rel36_14_should_apply,
    repair_first_csf_table,
    repair_gap_guide_uniqueness,
    repair_roadmap_balance,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _dt_sections,
)
from tests.test_rel36_7_data_roadmap_balance import _data_generated_missing_three
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
)
from tests.test_rel36_9_english_cyber_live_stability import (
    _en_sections,
    _headingless_roadmap,
    _invisible_export_roadmap,
    _roadmap_heading_variant,
    _valid_en_cyber_vision,
)
from tests.test_rel36_10_data_catalog_roadmap_balance import (
    _DATA_STAGING_MISSING_CATALOG,
)
from tests.test_rel36_13_english_cyber_core_completeness import (
    _WEAK_CONF,
    _WEAK_ENV,
    _WEAK_GAPS,
    _WEAK_KPI,
    _WEAK_VISION,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_14_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_14_samples'
_QA.mkdir(parents=True, exist_ok=True)


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


def _imbalanced_roadmap_ecc2_dcc8() -> str:
    """Attempt-3 shape: two ECC rows, eight DCC-classified rows."""
    ecc = [
        '| Phase 1 | 1-6 months | Appoint a CISO | CISO | CISO charter | NCA ECC |',
        '| Phase 2 | 7-18 months | Operate SOC/SIEM | SOC Manager | SIEM coverage | NCA ECC |',
    ]
    dcc = [
        '| Phase 1 | 1-6 months | Classify customer records | Data Protection Officer | Register | NCA DCC |',
        '| Phase 1 | 1-6 months | Inventory personal files | Data Protection Officer | Inventory | NCA DCC |',
        '| Phase 2 | 7-18 months | Encrypt file shares | Data Protection Officer | Encryption | NCA DCC |',
        '| Phase 2 | 7-18 months | Rotate encryption keys | Data Protection Officer | Key ceremony | NCA DCC |',
        '| Phase 2 | 7-18 months | Enable DLP on email | Data Protection Officer | DLP rules | NCA DCC |',
        '| Phase 2 | 7-18 months | Tune DLP false positives | Data Protection Officer | DLP tuning | NCA DCC |',
        '| Phase 3 | 19-24 months | Handle sensitive data | Data Protection Officer | Handling SOP | NCA DCC |',
        '| Phase 3 | 19-24 months | Protect data in transit | Data Protection Officer | Transit controls | NCA DCC |',
    ]
    return (
        '## 5. Implementation Roadmap\n\n'
        '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |\n'
        '|---|---|---|---|---|---|\n'
        + '\n'.join(ecc + dcc)
        + '\n'
    )


def _duplicate_gap_guides() -> str:
    """Attempt-7 shape: ten gaps, two identical guide bodies."""
    rows = []
    for i, (name, desc, prio, owner) in enumerate((
            ('Governance operating model', 'No CISO model', 'High', 'CISO'),
            ('SOC/SIEM monitoring', 'No 24x7 SOC', 'High', 'SOC Manager'),
            ('IAM/PAM/MFA', 'MFA incomplete', 'High', 'IAM/PAM Manager'),
            ('Incident response / CSIRT', 'No CSIRT', 'High', 'CSIRT Lead'),
            ('Vulnerability management', 'No SLA', 'High', 'Vulnerability Manager'),
            ('Data classification', 'No register', 'High', 'Data Protection Officer'),
            ('Encryption and key management', 'No keys', 'High', 'Data Protection Officer'),
            ('DLP', 'No DLP', 'Medium', 'Data Protection Officer'),
            ('Backup and disaster recovery', 'No DR test', 'High', 'Business Continuity Manager'),
            ('Security awareness', 'No phishing program', 'Medium', 'Security Awareness Manager'),
    ), start=1):
        rows.append(f'| {i} | {name} | {desc} | {prio} | {owner} |')
    same = (
        'This guide closes the gap for English Cyber NCA ECC/DCC scope. '
        'Current issue: repeated boilerplate. The owner owns the work.'
    )
    guides = []
    for i in range(1, 11):
        body = same if i in (3, 7) else (
            f'Unique guide {i} closes a distinct family with evidence pack {i} '
            f'and a named owner so the first two hundred characters differ.'
        )
        guides.append(f'#### Gap #{i} Implementation Guide:\n{body}\n')
    return (
        '## 4. Gap Analysis\n\n### Identified Gaps\n\n'
        '| # | Gap | Description | Priority | Owner |\n'
        '|---|---|---|---|---|\n'
        + '\n'.join(rows)
        + '\n\n### Gap Implementation Guidance\n\n'
        + '\n'.join(guides)
    )


def _empty_first_csf_plus_second_table() -> str:
    """Attempts 8–10 shape: first Factor table is 0/4.

    REL36.13 appended valid catalog rows after Key Risks without a new
    Factor header, so ``_count_csf_rows`` never saw them.
    """
    return (
        '## 7. Confidence Assessment\n\n'
        '**Confidence Score:** 72%\n\n'
        '### Score Justification\n'
        'The score is a conservative rationale for current readiness.\n\n'
        '### Critical Success Factors\n\n'
        '| # | Factor | Description | Importance |\n'
        '|---|---|---|---|\n'
        '| 1 | TBD | TBD | TBD |\n'
        '| 2 | — | — | — |\n'
        '| 3 | TBA | TBA | TBA |\n'
        '| 4 | placeholder | placeholder | placeholder |\n\n'
        '### Key Risks\n\n'
        '| # | Risk | Likelihood | Impact | Treatment Plan | Owner |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | Undetected intrusion against unmonitored critical assets | High | High | Expand SOC/SIEM use cases | SOC Manager |\n'
        '| 2 | Privileged account takeover due to incomplete MFA and PAM | High | High | Enforce IAM/PAM/MFA | IAM/PAM Manager |\n'
        '| 3 | Sensitive-data leakage from unclassified NCA DCC information | Medium | High | Classify data and enable DLP | Data Protection Officer |\n'
        '| 4 | Prolonged outage after a cyber incident without tested recovery | Medium | High | Test backups and DR | Business Continuity Manager |\n\n'
        '| 1 | Governance maturity | CISO owns NCA ECC decisions | Critical |\n'
        '| 2 | Control implementation coverage | ECC baseline is implemented | Critical |\n'
        '| 3 | Detection and response readiness | SOC and CSIRT are ready | High |\n'
        '| 4 | Data protection maturity | DCC classification is live | High |\n'
    )


def _apply14(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _seed_sections(
        environment=_WEAK_ENV, gaps=_WEAK_GAPS,
        confidence=_WEAK_CONF, kpis=_WEAK_KPI,
        roadmap=_imbalanced_roadmap_ecc2_dcc8()))
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_14_en_cyber_final_counted_structures(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-14'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _apply13_then_14(sections=None, **kwargs):
    secs = dict(sections or _seed_sections())
    buf = io.StringIO()
    with redirect_stdout(buf):
        out13, _d13 = apply_rel36_13_en_cyber_core_completeness(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id=kwargs.get('task_id', 'local-rel36-14'),
            attempt_id=kwargs.get('attempt_id', 't1'),
            generation_mode=kwargs.get('generation_mode', 'drafting'),
            emit=False,
        )
        out, diag = apply_rel36_14_en_cyber_final_counted_structures(
            out13,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id=kwargs.get('task_id', 'local-rel36-14'),
            attempt_id=kwargs.get('attempt_id', 't1'),
            generation_mode=kwargs.get('generation_mode', 'drafting'),
            emit=True,
        )
    return out, diag, buf.getvalue()


def _finalize_art(sections, task_id='local-rel36-14-save'):
    art = {
        'sections': dict(sections),
        'final_markdown': sections.get('pillars') or '',
        'domain': 'cyber',
        'task_id': task_id,
        'contract_meta': {
            'lang': 'en',
            'domain': 'cyber',
            'document_type': 'strategy',
            'selected_frameworks': _NCA_FWS,
        },
        'selected_frameworks': _NCA_FWS,
    }
    buf = io.StringIO()
    with redirect_stdout(buf):
        merged, repairs, diags = apply_rel23_cyber_finalize(
            art, domain='cyber', lang='en', backend=_backend())
    return merged, repairs, diags, buf.getvalue()


def _assert_counted_pass(test, out, diag):
    test.assertTrue(diag.get('applied'), diag)
    test.assertEqual(diag.get('roadmap_balance_blockers_after'), [], diag)
    test.assertGreaterEqual(diag.get('roadmap_ecc_after') or 0, 3, diag)
    test.assertGreaterEqual(diag.get('roadmap_dcc_after') or 0, 3, diag)
    test.assertEqual(diag.get('gap_guides_duplicate_count_after'), 0, diag)
    test.assertTrue(diag.get('gap_guides_unique_after'), diag)
    test.assertGreaterEqual(diag.get('confidence_csf_rows_after') or 0, 4, diag)
    test.assertGreaterEqual(
        diag.get('confidence_first_table_rows_after') or 0, 4, diag)
    test.assertEqual(diag.get('confidence_csf_blockers_after'), [], diag)
    test.assertEqual(diag.get('save_blockers_after'), [], diag)
    test.assertTrue(diag.get('passed'), diag)
    app = _app()
    dcc, ecc = app._prcy68_count_roadmap_framework_rows(out.get('roadmap') or '')
    test.assertGreaterEqual(ecc, 3, (ecc, dcc, out.get('roadmap')))
    test.assertGreaterEqual(dcc, 3, (ecc, dcc, out.get('roadmap')))
    test.assertGreaterEqual(app._count_csf_rows(out.get('confidence') or ''), 4)
    richness = app.validate_arabic_strategy_semantic_richness(
        out, 'en', doc_subtype='technical', generation_mode='drafting',
        domain='cyber') or []
    test.assertFalse(
        any(str(item[0]) == 'gap_guides_not_unique' for item in richness),
        richness)
    test.assertFalse(
        any('prcy74_roadmap_framework_balance_invalid' in str(b)
            for b in (diag.get('save_blockers_after') or [])))


class Rel3614CountedRepairTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_01_roadmap_ecc2_dcc8_repaired_to_pass_prcy74(self):
        app = _app()
        before = _imbalanced_roadmap_ecc2_dcc8()
        dcc_b, ecc_b = app._prcy68_count_roadmap_framework_rows(before)
        self.assertEqual((ecc_b, dcc_b), (2, 8), (ecc_b, dcc_b))
        out, diag, log = _apply14(_seed_sections(roadmap=before))
        self.assertIn('roadmap', diag.get('repaired_sections') or [], diag)
        self.assertGreaterEqual(diag.get('roadmap_ecc_after'), 3, diag)
        self.assertGreaterEqual(diag.get('roadmap_dcc_after'), 3, diag)
        self.assertEqual(diag.get('roadmap_balance_blockers_after'), [], diag)
        dcc_a, ecc_a = app._prcy68_count_roadmap_framework_rows(
            out.get('roadmap') or '')
        self.assertGreaterEqual(ecc_a, 3, (ecc_a, dcc_a))
        self.assertGreaterEqual(dcc_a, 3, (ecc_a, dcc_a))
        self.assertIn(REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG, log)
        _assert_counted_pass(self, out, diag)

    def test_02_roadmap_repair_keeps_visible_implementation_rows(self):
        out, diag, _ = _apply14(_seed_sections(
            roadmap=_imbalanced_roadmap_ecc2_dcc8()))
        road = out.get('roadmap') or ''
        self.assertIn('Implementation Roadmap', road)
        self.assertGreater(diag.get('roadmap_ecc_after') + diag.get(
            'roadmap_dcc_after'), 0, diag)
        self.assertNotIn(
            'roadmap_visible_row_count:0',
            str(diag.get('save_blockers_after')))
        self.assertIn('SOC', road)
        self.assertIn('NCA DCC', road)

    def test_03_gap_guide_duplicates_are_made_unique(self):
        app = _app()
        gaps = _duplicate_gap_guides()
        richness = app.validate_arabic_strategy_semantic_richness(
            {'gaps': gaps}, 'en', doc_subtype='technical',
            generation_mode='drafting', domain='cyber') or []
        self.assertTrue(
            any(str(item[0]) == 'gap_guides_not_unique' for item in richness),
            richness)
        out, diag, _ = _apply14(_seed_sections(gaps=gaps))
        self.assertIn('gaps', diag.get('repaired_sections') or [], diag)
        self.assertEqual(diag.get('gap_guides_duplicate_count_after'), 0, diag)
        self.assertTrue(diag.get('gap_guides_unique_after'), diag)
        after = app.validate_arabic_strategy_semantic_richness(
            out, 'en', doc_subtype='technical', generation_mode='drafting',
            domain='cyber') or []
        self.assertFalse(
            any(str(item[0]) == 'gap_guides_not_unique' for item in after),
            after)

    def test_04_gap_guide_uniqueness_gate_passes_after_repair(self):
        repaired, added = repair_gap_guide_uniqueness(_duplicate_gap_guides())
        self.assertGreaterEqual(added, 10)
        after = _app().validate_arabic_strategy_semantic_richness(
            {'gaps': repaired}, 'en', doc_subtype='technical',
            generation_mode='drafting', domain='cyber') or []
        self.assertFalse(
            any(str(item[0]) == 'gap_guides_not_unique' for item in after),
            after)
        for fam in (
                'Governance and CISO', 'SOC and SIEM', 'IAM, PAM and MFA',
                'CSIRT incident response', 'Vulnerability management',
                'Data classification', 'Encryption and key management',
                'DLP and leakage', 'Backup and disaster',
                'Workforce awareness'):
            self.assertIn(fam.split()[0], repaired)

    def test_05_first_counted_csf_table_rebuilt_to_satisfy_count(self):
        app = _app()
        conf = _empty_first_csf_plus_second_table()
        self.assertEqual(app._count_csf_rows(conf), 0, conf)
        out, diag, _ = _apply14(_seed_sections(confidence=conf))
        self.assertIn('confidence', diag.get('repaired_sections') or [], diag)
        self.assertGreaterEqual(diag.get('confidence_first_table_rows_after'), 4, diag)
        self.assertGreaterEqual(diag.get('confidence_csf_rows_after'), 4, diag)
        self.assertEqual(diag.get('confidence_csf_blockers_after'), [], diag)
        self.assertGreaterEqual(
            app._count_csf_rows(out.get('confidence') or ''), 4)
        richness = app.validate_confidence_richness(
            {'confidence': out.get('confidence') or ''}, 'en',
            generation_mode='drafting')
        self.assertFalse(
            any(str(item[0]) == 'confidence_csf_insufficient' for item in richness),
            richness)

    def test_06_repair_does_not_merely_append_a_second_ignored_table(self):
        conf = _empty_first_csf_plus_second_table()
        repaired, _ = repair_first_csf_table(conf)
        app = _app()
        first = re.search(
            r'(\|\s*#\s*\|\s*Factor\s*\|[^\n]*\n(?:\|[^\n]*\n)+)',
            repaired, re.IGNORECASE)
        self.assertIsNotNone(first, repaired)
        first_table = first.group(1)
        self.assertGreaterEqual(app._count_csf_rows(first_table), 4, first_table)
        self.assertIn('Governance maturity', first_table)
        # A later Factor table must not be the only counted source.
        self.assertGreaterEqual(app._count_csf_rows(repaired), 4, repaired)
        self.assertNotIn('| 1 | TBD |', first_table)

    def test_07_all_three_defects_repaired_in_one_pass(self):
        secs = _seed_sections(
            roadmap=_imbalanced_roadmap_ecc2_dcc8(),
            gaps=_duplicate_gap_guides(),
            confidence=_empty_first_csf_plus_second_table(),
        )
        out, diag, log = _apply14(secs)
        repaired = set(diag.get('repaired_sections') or [])
        for key in ('roadmap', 'gaps', 'confidence'):
            self.assertIn(key, repaired, diag)
        self.assertIn(REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG, log)
        _assert_counted_pass(self, out, diag)

    def test_08_diagnostic_passed_false_if_roadmap_balance_still_fails(self):
        diag = evaluate_rel36_14_en_cyber_final_counted_structures(
            task_id='fail-road',
            selected_frameworks=_NCA_FWS,
            roadmap_ecc_after=2,
            roadmap_dcc_after=8,
            roadmap_balance_blockers_after=[
                'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=8'],
            gap_guides_unique_after=True,
            confidence_csf_rows_after=6,
            confidence_first_table_rows_after=6,
            save_blockers_after=[
                'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=8'],
        )
        self.assertFalse(diag.get('passed'), diag)
        self.assertFalse(diag.get('docx_allowed'), diag)

    def test_09_diagnostic_passed_false_if_duplicate_gap_guides_remain(self):
        diag = evaluate_rel36_14_en_cyber_final_counted_structures(
            task_id='fail-gaps',
            selected_frameworks=_NCA_FWS,
            roadmap_ecc_after=7,
            roadmap_dcc_after=5,
            gap_guides_duplicate_count_after=2,
            gap_guides_unique_after=False,
            confidence_csf_rows_after=6,
            confidence_first_table_rows_after=6,
            save_blockers_after=['gap_guides_not_unique:2'],
        )
        self.assertFalse(diag.get('passed'), diag)

    def test_10_diagnostic_passed_false_if_first_csf_table_still_fails(self):
        diag = evaluate_rel36_14_en_cyber_final_counted_structures(
            task_id='fail-csf',
            selected_frameworks=_NCA_FWS,
            roadmap_ecc_after=7,
            roadmap_dcc_after=5,
            gap_guides_unique_after=True,
            confidence_first_table_rows_after=0,
            confidence_csf_rows_after=0,
            confidence_csf_blockers_after=[
                'confidence_csf_insufficient:0/4 critical success factors'],
            save_blockers_after=[
                'confidence_csf_insufficient:0/4 critical success factors'],
        )
        self.assertFalse(diag.get('passed'), diag)

    def test_11_english_cyber_docx_pdf_allowed(self):
        out, diag, _ = _apply13_then_14(_seed_sections(
            roadmap=_imbalanced_roadmap_ecc2_dcc8(),
            gaps=_duplicate_gap_guides(),
            confidence=_empty_first_csf_plus_second_table(),
            pillars=_malformed_en_cyber_pillars(),
        ))
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        self.assertTrue(diag.get('docx_allowed'), diag)
        self.assertTrue(diag.get('pdf_allowed'), diag)
        _write_export('en_cyber_ecc_dcc', pair)


class Rel3614TenShapeAndRegressionTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_12_english_cyber_10_seeded_shapes_pass(self):
        shapes = [
            ('shape-01-ecc2-dcc8', _seed_sections(
                roadmap=_imbalanced_roadmap_ecc2_dcc8())),
            ('shape-02-dup-guides', _seed_sections(
                gaps=_duplicate_gap_guides())),
            ('shape-03-empty-first-csf', _seed_sections(
                confidence=_empty_first_csf_plus_second_table())),
            ('shape-04-all-three', _seed_sections(
                roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table())),
            ('shape-05-empty-core', _seed_sections(
                vision='', environment='', gaps='', roadmap='',
                confidence='', kpis='')),
            ('shape-06-weak-so-imbalance', _seed_sections(
                vision=_WEAK_VISION, roadmap=_imbalanced_roadmap_ecc2_dcc8())),
            ('shape-07-malformed-pillars-dup-guides', _seed_sections(
                pillars=_malformed_en_cyber_pillars(),
                gaps=_duplicate_gap_guides())),
            ('shape-08-invisible-roadmap-empty-csf', _seed_sections(
                roadmap=_invisible_export_roadmap(),
                confidence=_empty_first_csf_plus_second_table())),
            ('shape-09-heading-variant-roadmap', _seed_sections(
                roadmap=_roadmap_heading_variant(),
                gaps=_duplicate_gap_guides())),
            ('shape-10-attempt3-7-8-combo', _seed_sections(
                vision=_WEAK_VISION, environment=_WEAK_ENV,
                roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table(),
                kpis=_WEAK_KPI, pillars=_malformed_en_cyber_pillars())),
        ]
        summary = []
        last_diag = None
        last_pair = None
        for attempt_id, secs in shapes:
            out, diag, log = _apply13_then_14(
                secs, attempt_id=attempt_id, task_id=attempt_id)
            merged, _rep, diags, _ = _finalize_art(secs, task_id=attempt_id)
            blockers = rel23_blocking_errors(diags)
            pair = _export_pair(merged['sections'], lang='en', domain='cyber')
            app = _app()
            dcc, ecc = app._prcy68_count_roadmap_framework_rows(
                out.get('roadmap') or merged['sections'].get('roadmap') or '')
            rec = {
                'attempt_id': attempt_id,
                'roadmap_ecc_after': diag.get('roadmap_ecc_after'),
                'roadmap_dcc_after': diag.get('roadmap_dcc_after'),
                'prcy74_ecc': ecc,
                'prcy74_dcc': dcc,
                'gap_guides_duplicate_count_after': diag.get(
                    'gap_guides_duplicate_count_after'),
                'confidence_first_table_rows_after': diag.get(
                    'confidence_first_table_rows_after'),
                'confidence_csf_rows_after': diag.get(
                    'confidence_csf_rows_after'),
                'save_blockers_after': diag.get('save_blockers_after'),
                'rel2_pillars_blockers': _rel2_pillars_blockers(
                    out.get('pillars') or ''),
                'rel23_blockers': blockers,
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'log_has_tag': REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG in log,
                'passed': (
                    bool(diag.get('passed'))
                    and ecc >= 3 and dcc >= 3
                    and not diag.get('save_blockers_after')
                    and not any(
                        str(b).startswith('rel2_pillars_failed')
                        or 'roadmap_visible_row_count:0' in str(b)
                        or 'prcy74_roadmap_framework_balance_invalid' in str(b)
                        for b in blockers)
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
            last_diag = diag
            last_pair = pair
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
            'root_cause': {
                'prcy74': (
                    'REL36.13 only repaired empty/short roadmaps. Attempt 3 '
                    'already had enough rows (ECC=2, DCC=8) so PR-CY74 still '
                    'saw an unbalanced counted table.'
                ),
                'gap_guides_not_unique': (
                    'REL36.13 appended catalog-cycled guide bodies. The '
                    'uniqueness gate compares the first 200 characters, so '
                    'two guides shared the same boilerplate prefix.'
                ),
                'confidence_csf_insufficient': (
                    '_count_csf_rows reads the first | # | Factor | table. '
                    'REL36.13 appended a second table while the first table '
                    'still had 0 valid rows.'
                ),
            },
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        _write_json(
            'en_cyber_final_counted_structures_diagnostic.json', last_diag or {})
        if last_pair is not None:
            _write_export('en_cyber_ecc_dcc', last_pair)
        self.assertEqual(len(summary), 10)
        self.assertEqual(payload['pass_count'], 10)

    def test_13_data_ndmo_pdpl_regression_passes(self):
        secs = dict(_data_generated_missing_three())
        secs['roadmap'] = _DATA_STAGING_MISSING_CATALOG
        repaired, d367 = apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        repaired, d3610 = apply_rel36_10_data_catalog_roadmap_balance(
            repaired, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(missing_families(repaired.get('roadmap') or ''), [])
        self.assertTrue(d367.get('passed') or d3610.get('passed'))
        self.assertFalse(rel36_14_should_apply(
            lang='ar', domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL']))
        pair = _export_pair(repaired, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_14_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        self.assertFalse(rel36_14_should_apply(
            lang='ar', domain='cyber', document_type='strategy',
            selected_frameworks=_NCA_FWS))
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_15_erm_risk_regression_passes(self):
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
        tree = RenderTree(
            artifact_id='risk-rel36-14', canonical_hash='c' * 16,
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

    def test_16_ai_sdaia_regression_passes(self):
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

    def test_18_auth_csrf_regression_passes(self):
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

    def test_19_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
