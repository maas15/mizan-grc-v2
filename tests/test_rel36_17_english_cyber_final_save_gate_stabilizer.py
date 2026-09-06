"""REL36.17 — English Cyber board-ready SO and synth-gate stabilizer."""

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

_TMP = tempfile.mkdtemp(prefix='test_rel36_17_')
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
    apply_rel36_14_en_cyber_final_counted_structures,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    apply_rel36_15_final_registry_stability,
    official_cyber_missing_families,
)
from release_engine_v3.rel36_16_en_cyber_vision_pillars_objectives import (
    apply_rel36_16_en_cyber_vision_pillars_objectives,
)
from release_engine_v3.rel36_17_en_cyber_final_save_gate_stabilizer import (
    REL36_17_EN_CYBER_FINAL_SAVE_GATE_STABILIZER_TAG,
    apply_rel36_17_en_cyber_final_save_gate_stabilizer,
    evaluate_rel36_17_en_cyber_final_save_gate_stabilizer,
    repair_confidence_for_synth,
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
from tests.test_rel36_15_final_registry_stability import (
    _DATA_MISSING_LIFECYCLE,
    _NO_CLASSIFICATION_ROADMAP,
    _REL3613_KPI,
)
from tests.test_rel36_16_english_cyber_vision_pillars_objectives import (
    _empty_so_vision,
    _malformed_first_so_plus_later,
    _no_fw_compliance_vision,
    _residue_pillars,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_17_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_17_samples'
_QA.mkdir(parents=True, exist_ok=True)

_SO_HDR = (
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|\n'
)


def _duplicate_gov_so() -> str:
    """Attempts 2/3 shape: two governance titles + target-like DCC cell."""
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Build a resilient cybersecurity operating model.\n\n'
        '### Strategic Objectives\n\n'
        + _SO_HDR
        + '| 1 | Establish cybersecurity governance and CISO operating model | '
        'Approved CISO charter | Accountability | 6 months |\n'
        '| 2 | Establish cybersecurity governance and CISO committee | '
        'Approved committee charter | Accountability | 6 months |\n'
        '| 3 | Establish SOC/SIEM monitoring and incident response readiness | '
        '24x7 SOC | Detection | 12 months |\n'
        '| 4 | Strengthen IAM, PAM, and MFA access governance | '
        'MFA 100% | Identity | 12 months |\n'
        '| 5 | Protect sensitive data through NCA DCC classification | '
        'NCA DCC register | Data protection | 12 months |\n'
        '| 6 | Institutionalize vulnerability and patch management | '
        '95% closed | Exposure | 12 months |\n'
    )


def _target_like_so() -> str:
    """Target-like objectives plus REL36.16 ECC/DCC targets without %."""
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Protect digital services for the organization.\n\n'
        '### Strategic Objectives\n\n'
        + _SO_HDR
        + '| 1 | 95% ECC compliance | NCA ECC baseline controls implemented '
        'for in-scope systems | Mandatory | 12 months |\n'
        '| 2 | ≥90% DCC coverage | NCA DCC baseline | Mandatory | 12 months |\n'
        '| 3 | Establish SOC/SIEM monitoring and incident response | '
        '24x7 SOC | Detection | 12 months |\n'
        '| 4 | Strengthen IAM/PAM/MFA coverage | MFA 100% | Identity | 12 months |\n'
        '| 5 | Improve cyber resilience, backup, recovery, and continuity | '
        'Annual DR test | Resilience | 18 months |\n'
        '| 6 | Institutionalize vulnerability and patch management | '
        'NCA ECC patch SLA | Exposure | 12 months |\n'
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


def _prior_repairs(sections):
    out13, _ = apply_rel36_13_en_cyber_core_completeness(
        sections, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    out14, _ = apply_rel36_14_en_cyber_final_counted_structures(
        out13, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    out15, _ = apply_rel36_15_final_registry_stability(
        out14, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    out16, _ = apply_rel36_16_en_cyber_vision_pillars_objectives(
        out15, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    return out16


def _apply17(sections=None, **kwargs):
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
        out, diag = apply_rel36_17_en_cyber_final_save_gate_stabilizer(
            secs,
            domain=domain,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-17'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _official_so_gate(vision, lang='en'):
    from cyber_board_ready_prcy88 import baseline_strategic_objectives
    _secs, diag = baseline_strategic_objectives(
        _app(), {'vision': vision or ''}, lang, _NCA_FWS)
    return diag


def _first_csf_slice(text: str) -> str:
    matches = list(re.finditer(
        r'(?im)^\|\s*#\s*\|\s*(?:Factor|العامل)\s*\|', text or ''))
    if not matches:
        return text or ''
    end = matches[1].start() if len(matches) > 1 else len(text or '')
    return (text or '')[:end]


def _assert_synth_noop(testcase, sections, keys):
    app = _app()
    os.environ['OPENAI_API_KEY'] = ''
    before = {k: sections.get(k) for k in keys}
    if 'gaps' in keys:
        summary = app.synthesize_gaps_depth(
            sections, 'en', domain='Cyber Security', fw_short='NCA ECC',
            generation_mode='drafting')
        testcase.assertFalse(summary.get('rebuilt'), summary)
    if 'pillars' in keys:
        summary = app.synthesize_pillars_depth(
            sections, 'en', domain='Cyber Security', fw_short='NCA ECC',
            generation_mode='drafting')
        testcase.assertFalse(summary.get('rebuilt'), summary)
    if 'confidence' in keys:
        summary = app.synthesize_confidence_depth(
            sections, 'en', domain='Cyber Security', fw_short='NCA ECC',
            generation_mode='drafting')
        testcase.assertEqual(summary.get('csf_added'), 0, summary)
        testcase.assertEqual(summary.get('risks_added'), 0, summary)
    for k in keys:
        testcase.assertEqual(sections.get(k), before[k], k)


def _assert_save_clean(testcase, out, diag):
    testcase.assertTrue(diag.get('passed'), diag)
    testcase.assertEqual(diag.get('board_ready_so_blockers_after'), [], diag)
    testcase.assertEqual(diag.get('gaps_synth_blockers_after'), [], diag)
    testcase.assertEqual(diag.get('pillars_synth_blockers_after'), [], diag)
    testcase.assertEqual(diag.get('confidence_synth_blockers_after'), [], diag)
    testcase.assertEqual(diag.get('all_save_blockers_after'), [], diag)
    blob = ' '.join(diag.get('all_save_blockers_after') or [])
    for token in (
            'cyber_board_ready_so_failed',
            'so_count_or_duplicates_or_target_like',
            'synth_failed:gaps',
            'synth_failed:pillars',
            'synth_failed:confidence',
            'synth_failed:vision',
            'synth_failed:kpis',
            'selected_framework_compliance_objective_missing',
            'cyber_roadmap_balance_missing',
            'data_roadmap_balance_missing',
            'rel2_pillars_failed',
            'roadmap_visible_row_count:0'):
        testcase.assertNotIn(token, blob)


class Rel3617BoardReadySoTests(unittest.TestCase):
    def test_01_board_ready_duplicate_rows_repaired(self):
        vision = _duplicate_gov_so()
        before = _official_so_gate(vision)
        self.assertFalse(before.get('gate_passed'), before)
        secs = _seed_sections(vision=vision)
        out, diag, log = _apply17(secs)
        after = _official_so_gate(out.get('vision') or '')
        self.assertTrue(after.get('gate_passed'), after)
        self.assertEqual(after.get('duplicate_governance_rows_after'), 0, after)
        self.assertEqual(diag.get('so_duplicates_after'), 0, diag)
        self.assertEqual(diag.get('board_ready_so_blockers_after'), [], diag)
        self.assertIn(REL36_17_EN_CYBER_FINAL_SAVE_GATE_STABILIZER_TAG, log)
        _write_json('en_cyber_final_save_gate_stabilizer_diagnostic.json', diag)

    def test_02_board_ready_target_like_rows_repaired(self):
        vision = _target_like_so()
        self.assertGreater(_app()._prcy87_count_shifted_so_fields(vision, 'en'), 0)
        before = _official_so_gate(vision)
        self.assertFalse(before.get('gate_passed'), before)
        out, diag, _ = _apply17(_seed_sections(vision=vision))
        self.assertEqual(_app()._prcy87_count_shifted_so_fields(
            out.get('vision') or '', 'en'), 0)
        after = _official_so_gate(out.get('vision') or '')
        self.assertTrue(after.get('gate_passed'), after)
        self.assertEqual(after.get('target_like_objectives_after'), 0, after)
        self.assertEqual(diag.get('so_target_like_after'), 0, diag)
        blob = out.get('vision') or ''
        self.assertNotRegex(
            blob, r'(?m)^\|\s*\d+\s*\|\s*(?:95%|≥90%)')

    def test_03_so_count_remains_above_real_minimum(self):
        out, diag, _ = _apply17(_seed_sections(vision=_empty_so_vision()))
        self.assertGreaterEqual(diag.get('so_rows_after'), 6, diag)
        self.assertGreaterEqual(
            _app().count_valid_objective_rows(out.get('vision') or ''), 6)
        after = _official_so_gate(out.get('vision') or '')
        self.assertGreaterEqual(after.get('rows_after'), 6, after)
        self.assertLessEqual(after.get('rows_after'), 8, after)

    def test_04_ecc_objective_remains_present(self):
        out, diag, _ = _apply17(_seed_sections(vision=_no_fw_compliance_vision()))
        missing = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertNotIn('ECC', missing, missing)
        blob = out.get('vision') or ''
        self.assertTrue(
            'NCA ECC' in blob or 'Essential Cybersecurity Controls' in blob, blob)

    def test_05_dcc_objective_remains_present(self):
        out, diag, _ = _apply17(_seed_sections(vision=_no_fw_compliance_vision()))
        missing = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertNotIn('DCC', missing, missing)
        blob = out.get('vision') or ''
        self.assertTrue(
            'NCA DCC' in blob or 'Data Cybersecurity Controls' in blob, blob)


class Rel3617SynthGateTests(unittest.TestCase):
    def test_06_gaps_synth_shape_repaired_before_gate(self):
        secs = _seed_sections(gaps=_WEAK_GAPS)
        self.assertLess(_app().count_substantive_gaps(secs['gaps']), 2)
        out, diag, _ = _apply17(secs)
        self.assertGreaterEqual(
            _app().count_substantive_gaps(out.get('gaps') or ''), 2)
        self.assertGreaterEqual(
            _app().count_gap_guides(out.get('gaps') or ''),
            _app().count_substantive_gaps(out.get('gaps') or ''))
        self.assertEqual(diag.get('gaps_synth_blockers_after'), [], diag)
        _assert_synth_noop(self, out, ['gaps'])
        gaps = out.get('gaps') or ''
        for token in (
                'Governance', 'SOC', 'IAM', 'CSIRT', 'Vulnerability',
                'classification', 'Encryption', 'DLP', 'Backup', 'awareness'):
            self.assertIn(token.lower(), gaps.lower(), token)

    def test_07_pillars_synth_shape_repaired_before_gate(self):
        secs = _seed_sections(pillars=_malformed_en_cyber_pillars())
        out, diag, _ = _apply17(secs)
        self.assertEqual(
            _rel2_pillars_blockers(out.get('pillars') or ''), [], diag)
        self.assertEqual(diag.get('pillars_synth_blockers_after'), [], diag)
        self.assertNotIn('family:', out.get('pillars') or '')
        _assert_synth_noop(self, out, ['pillars'])

    def test_08_confidence_synth_shape_repaired_before_gate(self):
        secs = _seed_sections(confidence=_WEAK_CONF)
        out, diag, _ = _apply17(secs)
        conf = out.get('confidence') or ''
        self.assertGreaterEqual(_app()._count_csf_rows(conf), 4)
        self.assertGreaterEqual(
            _app()._count_risk_rows_with_mitigation(conf), 4)
        self.assertEqual(diag.get('confidence_synth_blockers_after'), [], diag)
        _assert_synth_noop(self, out, ['confidence'])

    def test_09_first_counted_confidence_table_repaired_not_second(self):
        conf = _empty_first_csf_plus_second_table()
        self.assertEqual(_app()._count_csf_rows(_first_csf_slice(conf)), 0)
        repaired = repair_confidence_for_synth(conf)
        first = _first_csf_slice(repaired)
        self.assertGreaterEqual(_app()._count_csf_rows(first), 4, first)
        self.assertGreaterEqual(_app()._count_csf_rows(repaired), 4)
        self.assertNotIn('| 1 | TBD |', first)
        factor_headers = re.findall(
            r'(?im)^\|\s*#\s*\|\s*(?:Factor|العامل)\s*\|', repaired)
        self.assertEqual(len(factor_headers), 1, factor_headers)

    def test_10_all_four_defects_repaired_in_one_pass(self):
        secs = _seed_sections(
            vision=_duplicate_gov_so(),
            gaps=_WEAK_GAPS,
            pillars=_malformed_en_cyber_pillars(),
            confidence=_empty_first_csf_plus_second_table(),
            kpis=_REL3613_KPI,
            roadmap=_NO_CLASSIFICATION_ROADMAP)
        prior = _prior_repairs(secs)
        out, diag, _ = _apply17(prior)
        _assert_save_clean(self, out, diag)
        self.assertTrue(_official_so_gate(out.get('vision') or '').get('gate_passed'))
        _assert_synth_noop(self, dict(out), ['gaps', 'pillars', 'confidence'])
        missing = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertEqual(missing, [], missing)


class Rel3617DiagnosticFailClosedTests(unittest.TestCase):
    def test_11_diagnostic_passed_false_if_board_ready_so_blocker_remains(self):
        diag = evaluate_rel36_17_en_cyber_final_save_gate_stabilizer(
            selected_frameworks=_NCA_FWS,
            board_ready_so_blockers_after=[
                'cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like'],
            gaps_synth_blockers_after=[],
            pillars_synth_blockers_after=[],
            confidence_synth_blockers_after=[],
            all_save_blockers_after=[
                'cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like'],
            docx_allowed=True,
            pdf_allowed=True,
        )
        self.assertFalse(diag.get('passed'), diag)
        self.assertFalse(diag.get('docx_allowed'))
        self.assertFalse(diag.get('pdf_allowed'))

    def test_12_diagnostic_passed_false_if_synth_failed_blocker_remains(self):
        diag = evaluate_rel36_17_en_cyber_final_save_gate_stabilizer(
            selected_frameworks=_NCA_FWS,
            board_ready_so_blockers_after=[],
            gaps_synth_blockers_after=['synth_failed:gaps'],
            pillars_synth_blockers_after=['synth_failed:pillars'],
            confidence_synth_blockers_after=['synth_failed:confidence'],
            all_save_blockers_after=[
                'synth_failed:gaps',
                'synth_failed:pillars',
                'synth_failed:confidence'],
        )
        self.assertFalse(diag.get('passed'), diag)


class Rel3617ExportAndShapeTests(unittest.TestCase):
    def test_13_english_cyber_docx_pdf_allowed(self):
        secs = _seed_sections(
            vision=_duplicate_gov_so(),
            pillars=_malformed_en_cyber_pillars(),
            environment=_WEAK_ENV, gaps=_WEAK_GAPS,
            confidence=_empty_first_csf_plus_second_table(),
            kpis=_REL3613_KPI,
            roadmap=_NO_CLASSIFICATION_ROADMAP)
        prior = _prior_repairs(secs)
        out, diag, _ = _apply17(prior)
        _assert_save_clean(self, out, diag)
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('en_cyber_ecc_dcc', pair)
        _write_json('en_cyber_final_stability_diagnostic.json', diag)

    def test_14_english_cyber_10_seeded_shapes_pass(self):
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
            out, diag, _ = _apply17(
                prior, attempt_id=attempt_id, task_id=attempt_id)
            pair = _export_pair(out, lang='en', domain='cyber')
            so_gate = _official_so_gate(out.get('vision') or '')
            missing_fw = _app()._compute_missing_compliance_objective(
                out, _NCA_FWS, domain='Cyber Security', lang='en')
            missing_fam = official_cyber_missing_families(
                out.get('roadmap') or '', _NCA_FWS)
            residue = _app().detect_arabic_prompt_residue(out, 'en') or []
            rec = {
                'attempt_id': attempt_id,
                'so_rows': _app().count_valid_objective_rows(
                    out.get('vision') or ''),
                'so_gate_passed': bool(so_gate.get('gate_passed')),
                'so_gate_error': so_gate.get('blocking_error_if_any'),
                'board_ready_so_blockers_after': diag.get(
                    'board_ready_so_blockers_after'),
                'gaps_synth_blockers_after': diag.get(
                    'gaps_synth_blockers_after'),
                'pillars_synth_blockers_after': diag.get(
                    'pillars_synth_blockers_after'),
                'confidence_synth_blockers_after': diag.get(
                    'confidence_synth_blockers_after'),
                'all_save_blockers_after': diag.get('all_save_blockers_after'),
                'missing_fw': missing_fw,
                'missing_families': missing_fam,
                'residue': [t for t, _ in residue],
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'passed': (
                    bool(diag.get('passed'))
                    and bool(so_gate.get('gate_passed'))
                    and not (diag.get('board_ready_so_blockers_after') or [])
                    and not (diag.get('gaps_synth_blockers_after') or [])
                    and not (diag.get('pillars_synth_blockers_after') or [])
                    and not (diag.get('confidence_synth_blockers_after') or [])
                    and not missing_fw
                    and 'data_classification' not in missing_fam
                    and not residue
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
            _assert_synth_noop(self, dict(out), ['gaps', 'pillars', 'confidence'])
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        self.assertEqual(payload['pass_count'], 10)


class Rel3617RegressionTests(unittest.TestCase):
    def test_15_data_ndmo_pdpl_regression_passes(self):
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
        out, diag, _ = _apply17(
            out15, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        self.assertFalse(diag.get('applied'), diag)
        official = _app()._compute_missing_data_roadmap_balance_topics(
            out15.get('roadmap') or '',
            ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(official, [], official)
        pair = _export_pair(out15, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_16_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        out, diag, _ = _apply17(
            sections, domain='cyber', lang='ar', selected_frameworks=_NCA_FWS)
        self.assertFalse(diag.get('applied'), diag)
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_17_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-17', canonical_hash='c' * 16,
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

    def test_18_ai_sdaia_regression_passes(self):
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

    def test_19_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_20_auth_csrf_regression_passes(self):
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

    def test_21_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
