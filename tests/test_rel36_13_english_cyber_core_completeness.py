"""REL36.13 — English Cyber technical core-completeness stabilization."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_13_')
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
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    REL36_13_EN_CYBER_CORE_COMPLETENESS_TAG,
    apply_rel36_13_en_cyber_core_completeness,
    collect_core_blockers,
    evaluate_rel36_13_en_cyber_core_completeness,
    inspect_english_cyber_core,
    rel36_13_should_apply,
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
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_13_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_13_samples'
_QA.mkdir(parents=True, exist_ok=True)

_WEAK_VISION = (
    '## 1. Vision and Strategic Objectives\n\n'
    'Protect the organization.\n'
)
_WEAK_ENV = '## 3. Environment\n\nShort note.\n'
_WEAK_GAPS = '## 4. Gap Analysis\n\nNo structured gaps.\n'
_WEAK_CONF = '## 6. Confidence\n\nNarrative only.\n'
_WEAK_KPI = '## 6. Key Performance Indicators\n\n| # | KPI | Target |\n|---|---|---|\n| 1 | TBD | TBD |\n'


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


def _apply13(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _seed_sections(
        environment=_WEAK_ENV, gaps=_WEAK_GAPS,
        confidence=_WEAK_CONF, kpis=_WEAK_KPI))
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_13_en_cyber_core_completeness(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-13'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _finalize_art(sections, task_id='local-rel36-13-save'):
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


def _assert_core_pass(test, out, diag):
    test.assertTrue(diag.get('applied'), diag)
    test.assertGreaterEqual(diag.get('so_rows_after') or 0, 4, diag)
    test.assertTrue(diag.get('environment_present_after'), diag)
    test.assertGreaterEqual(diag.get('gaps_rows_after') or 0, 2, diag)
    test.assertGreater(diag.get('roadmap_rows_after') or 0, 0, diag)
    test.assertGreaterEqual(diag.get('confidence_rows_after') or 0, 4, diag)
    test.assertEqual(diag.get('core_blockers_after'), [], diag)
    test.assertTrue(diag.get('save_allowed_after'), diag)
    test.assertTrue(diag.get('passed'), diag)
    test.assertEqual(_rel2_pillars_blockers(out.get('pillars') or ''), [])
    test.assertNotIn('family:', (out.get('pillars') or '').lower())
    test.assertNotIn('family:', (out.get('roadmap') or '').lower())
    empty, in_deliv = _owner_binding_inventory(out.get('pillars') or '')
    test.assertEqual(empty, [], empty)
    test.assertEqual(in_deliv, [], in_deliv)


class Rel3613CoreRepairTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_01_insufficient_strategic_objectives_topped_up_before_save(self):
        before = inspect_english_cyber_core(
            _seed_sections(vision=_WEAK_VISION))
        self.assertLess(before['so_rows'], 4, before)
        out, diag, log = _apply13(_seed_sections(
            vision=_WEAK_VISION, environment=_WEAK_ENV, gaps=_WEAK_GAPS,
            confidence=_WEAK_CONF, kpis=_WEAK_KPI))
        self.assertIn('vision', diag.get('repaired_sections') or [], diag)
        self.assertGreaterEqual(diag.get('so_rows_after'), 4, diag)
        self.assertIn('Establish cybersecurity governance', out.get('vision') or '')
        self.assertIn('NCA ECC', out.get('vision') or '')
        self.assertIn(REL36_13_EN_CYBER_CORE_COMPLETENESS_TAG, log)
        _assert_core_pass(self, out, diag)

    def test_02_empty_environment_repaired_before_save(self):
        out, diag, _ = _apply13(_seed_sections(environment=''))
        self.assertIn('environment', diag.get('repaired_sections') or [], diag)
        self.assertTrue(diag.get('environment_present_after'), diag)
        env = out.get('environment') or ''
        self.assertIn('Regulatory context', env)
        self.assertIn('SOC / SIEM', env)
        self.assertIn('NCA ECC', env)
        _assert_core_pass(self, out, diag)

    def test_03_empty_gaps_repaired_before_save(self):
        out, diag, _ = _apply13(_seed_sections(gaps=''))
        self.assertIn('gaps', diag.get('repaired_sections') or [], diag)
        self.assertGreaterEqual(diag.get('gaps_rows_after'), 2, diag)
        gaps = out.get('gaps') or ''
        self.assertIn('SOC/SIEM', gaps)
        self.assertIn('IAM/PAM/MFA', gaps)
        self.assertIn('#### Gap #1 Implementation Guide', gaps)
        _assert_core_pass(self, out, diag)

    def test_04_empty_roadmap_repaired_before_save(self):
        out, diag, _ = _apply13(_seed_sections(roadmap=''))
        self.assertIn('roadmap', diag.get('repaired_sections') or [], diag)
        self.assertGreater(diag.get('roadmap_rows_after') or 0, 0, diag)
        road = out.get('roadmap') or ''
        self.assertIn('Implementation Roadmap', road)
        self.assertIn('SOC', road)
        self.assertIn('IAM/PAM/MFA', road)
        self.assertNotIn('roadmap_visible_row_count:0',
                         str(diag.get('core_blockers_after')))
        _assert_core_pass(self, out, diag)

    def test_05_empty_confidence_repaired_before_save(self):
        out, diag, _ = _apply13(_seed_sections(confidence=''))
        self.assertIn('confidence', diag.get('repaired_sections') or [], diag)
        self.assertGreaterEqual(diag.get('confidence_rows_after'), 4, diag)
        conf = out.get('confidence') or ''
        self.assertIn('Confidence Score', conf)
        self.assertIn('## 7.', conf)
        self.assertIn('Treatment Plan', conf)
        _assert_core_pass(self, out, diag)

    def test_06_multiple_empty_core_sections_repaired_in_one_pass(self):
        secs = _seed_sections(
            vision='', environment='', gaps='', roadmap='',
            confidence='', kpis='')
        before = inspect_english_cyber_core(secs)
        self.assertEqual(before['so_rows'], 0, before)
        self.assertFalse(before['environment_present'], before)
        out, diag, _ = _apply13(secs)
        repaired = set(diag.get('repaired_sections') or [])
        for key in ('vision', 'environment', 'gaps', 'roadmap', 'confidence'):
            self.assertIn(key, repaired, diag)
        _assert_core_pass(self, out, diag)

    def test_07_valid_existing_section_content_is_preserved(self):
        out_base, _diag_base, _ = _apply13(_seed_sections(
            vision=_WEAK_VISION, environment=_WEAK_ENV, gaps=_WEAK_GAPS,
            confidence=_WEAK_CONF, kpis=_WEAK_KPI))
        marker = (
            'UNIQUE_VALID_ENV_MARKER_REL36_13 documents the current-state '
            'assessment already accepted by the environment richness gate '
            'and must survive a later completeness pass without rewrite.')
        secs = dict(out_base)
        secs['environment'] = (
            str(secs.get('environment') or '').rstrip()
            + '\n\n' + marker + '\n')
        before = inspect_english_cyber_core(secs)
        self.assertTrue(before['environment_present'], before)
        out, diag, _ = _apply13(secs)
        self.assertIn(marker, out.get('environment') or '')
        self.assertNotIn('environment', diag.get('repaired_sections') or [])
        self.assertIn('Establish cybersecurity governance', out.get('vision') or '')
        _assert_core_pass(self, out, diag)

    def test_08_core_completeness_blockers_cleared_after_repair(self):
        secs = _seed_sections(
            vision=_WEAK_VISION, environment='', gaps='',
            confidence=_WEAK_CONF, kpis=_WEAK_KPI)
        before_flags = collect_core_blockers(secs, generation_mode='drafting')
        self.assertTrue(before_flags, before_flags)
        out, diag, _ = _apply13(secs)
        self.assertTrue(diag.get('core_blockers_before'), diag)
        self.assertEqual(diag.get('core_blockers_after'), [], diag)
        self.assertEqual(
            collect_core_blockers(out, generation_mode='drafting'), [])
        _assert_core_pass(self, out, diag)

    def test_09_diagnostic_passed_false_if_any_core_section_remains_insufficient(self):
        diag = evaluate_rel36_13_en_cyber_core_completeness(
            task_id='local-fail',
            attempt_id='insufficient',
            selected_frameworks=_NCA_FWS,
            so_rows_after=0,
            environment_present_after=False,
            gaps_rows_after=0,
            roadmap_rows_after=0,
            confidence_rows_after=0,
            core_blockers_after=['so_rows_insufficient:0/4'],
            save_allowed_after=True,
            docx_allowed=True,
            pdf_allowed=True,
        )
        self.assertFalse(diag.get('passed'), diag)
        self.assertFalse(diag.get('save_allowed_after'), diag)
        self.assertFalse(diag.get('docx_allowed'), diag)
        self.assertEqual(
            diag.get('core_blockers_after'), ['so_rows_insufficient:0/4'])

    def test_10_diagnostic_passed_true_only_when_all_real_gate_counters_pass(self):
        out, diag, _ = _apply13(_seed_sections(
            vision=_WEAK_VISION, environment='', gaps='',
            roadmap='', confidence='', kpis=_WEAK_KPI))
        self.assertGreaterEqual(diag.get('so_rows_after'), 4, diag)
        self.assertTrue(diag.get('environment_present_after'), diag)
        self.assertGreaterEqual(diag.get('gaps_rows_after'), 2, diag)
        self.assertGreater(diag.get('roadmap_rows_after'), 0, diag)
        self.assertGreaterEqual(diag.get('confidence_rows_after'), 4, diag)
        self.assertEqual(diag.get('core_blockers_after'), [], diag)
        self.assertTrue(diag.get('save_allowed_after'), diag)
        self.assertTrue(diag.get('passed'), diag)
        snap = inspect_english_cyber_core(out)
        self.assertGreaterEqual(snap['so_rows'], 4, snap)
        self.assertTrue(snap['environment_present'], snap)

    def test_11_repaired_strategy_saves_successfully(self):
        secs = _seed_sections(
            vision=_WEAK_VISION, environment='', gaps='',
            confidence=_WEAK_CONF, kpis=_WEAK_KPI,
            pillars=_malformed_en_cyber_pillars())
        out, diag, _ = _apply13(secs)
        merged, repairs, diags, log = _finalize_art(out)
        blockers = rel23_blocking_errors(diags)
        self.assertFalse(
            any(str(b).startswith('rel2_pillars_failed') for b in blockers),
            (blockers, diags.get('rel36_13')))
        self.assertEqual(
            collect_core_blockers(
                merged['sections'], generation_mode='drafting'), [])
        self.assertTrue(diag.get('save_allowed_after'), diag)
        self.assertIn('rel36_13', str(diags.keys()) + log + str(repairs))

    def test_12_repaired_strategy_docx_pdf_export_allowed(self):
        out, diag, _ = _apply13()
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        self.assertTrue(diag.get('docx_allowed'), diag)
        self.assertTrue(diag.get('pdf_allowed'), diag)
        _write_export('en_cyber_ecc_dcc', pair)

    def test_13_no_rel2_pillars_failed_after_repair(self):
        out, diag, _ = _apply13(_seed_sections(
            pillars=_malformed_en_cyber_pillars()))
        self.assertEqual(diag.get('rel2_pillars_blockers_after'), [], diag)
        self.assertEqual(_rel2_pillars_blockers(out.get('pillars') or ''), [])
        merged, _rep, diags, _ = _finalize_art(_seed_sections(
            pillars=_malformed_en_cyber_pillars()))
        blockers = rel23_blocking_errors(diags)
        self.assertFalse(
            any(str(b).startswith('rel2_pillars_failed') for b in blockers),
            blockers)

    def test_14_no_roadmap_visible_row_count_zero_after_repair(self):
        out, diag, _ = _apply13(_seed_sections(
            roadmap=_invisible_export_roadmap()))
        self.assertGreater(diag.get('roadmap_rows_after') or 0, 0, diag)
        self.assertEqual(diag.get('roadmap_model_drift_after'), [], diag)
        self.assertNotIn(
            'roadmap_visible_row_count:0',
            str(diag.get('core_blockers_after')))
        self.assertIn('Implementation Roadmap', out.get('roadmap') or '')

    def test_15_no_vision_contains_prompt_residue_after_repair(self):
        residue_vision = (
            'Here is a draft of the cybersecurity strategy as requested.\n'
            'Please include at least NCA ECC controls.\n'
        )
        out, diag, _ = _apply13(_seed_sections(vision=residue_vision))
        residue = diag.get('prompt_residue_after') or []
        self.assertFalse(
            any('vision_contains_prompt_residue' in str(x) for x in residue),
            residue)
        self.assertNotIn('Here is a draft', out.get('vision') or '')
        flags = collect_core_blockers(out, generation_mode='drafting')
        self.assertFalse(
            any('vision_contains_prompt_residue' in str(f) for f in flags),
            flags)


class Rel3613TenShapeAndRegressionTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_16_english_cyber_10_seeded_shapes_pass(self):
        shapes = [
            ('shape-01-weak-so', _seed_sections(vision=_WEAK_VISION)),
            ('shape-02-empty-env', _seed_sections(environment='')),
            ('shape-03-empty-gaps', _seed_sections(gaps='')),
            ('shape-04-empty-roadmap', _seed_sections(roadmap='')),
            ('shape-05-empty-confidence', _seed_sections(confidence='')),
            ('shape-06-all-empty-core', _seed_sections(
                vision='', environment='', gaps='', roadmap='',
                confidence='', kpis='')),
            ('shape-07-valid-vision-empty-rest', _seed_sections(
                vision=_valid_en_cyber_vision(), environment='',
                gaps='', confidence=_WEAK_CONF)),
            ('shape-08-malformed-pillars', _seed_sections(
                pillars=_malformed_en_cyber_pillars(),
                roadmap=_roadmap_heading_variant())),
            ('shape-09-invisible-roadmap', _seed_sections(
                roadmap=_invisible_export_roadmap(),
                environment=_WEAK_ENV)),
            ('shape-10-attempt7-like', _seed_sections(
                vision=_WEAK_VISION, environment=_WEAK_ENV, gaps=_WEAK_GAPS,
                confidence=_WEAK_CONF, kpis=_WEAK_KPI,
                pillars=_malformed_en_cyber_pillars(),
                roadmap='')),
        ]
        summary = []
        last_diag = None
        last_pair = None
        for attempt_id, secs in shapes:
            out, diag, log = _apply13(
                secs, attempt_id=attempt_id, task_id=attempt_id)
            merged, _rep, diags, _ = _finalize_art(secs, task_id=attempt_id)
            blockers = rel23_blocking_errors(diags)
            pair = _export_pair(merged['sections'], lang='en', domain='cyber')
            rec = {
                'attempt_id': attempt_id,
                'so_rows_after': diag.get('so_rows_after'),
                'environment_present_after': diag.get(
                    'environment_present_after'),
                'gaps_rows_after': diag.get('gaps_rows_after'),
                'roadmap_rows_after': diag.get('roadmap_rows_after'),
                'confidence_rows_after': diag.get('confidence_rows_after'),
                'core_blockers_after': diag.get('core_blockers_after'),
                'save_allowed_after': diag.get('save_allowed_after'),
                'rel2_pillars_blockers_after': diag.get(
                    'rel2_pillars_blockers_after'),
                'rel23_blockers': blockers,
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'log_has_tag': REL36_13_EN_CYBER_CORE_COMPLETENESS_TAG in log,
                'passed': (
                    bool(diag.get('passed'))
                    and not diag.get('core_blockers_after')
                    and not any(
                        str(b).startswith('rel2_pillars_failed')
                        or 'roadmap_visible_row_count:0' in str(b)
                        for b in blockers)
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
            self.assertTrue(rec['log_has_tag'], rec)
            last_diag = diag
            last_pair = pair
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
            'root_cause': (
                'English Cyber technical path had no deterministic final '
                'core-completeness fallback. Warning-bypass ran real SO / '
                'environment / gaps / roadmap / confidence counters while '
                'structure was still broken; REL33 top-up is AI-first and '
                'does not fill environment, gaps or English roadmap before '
                'that 422.'
            ),
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        _write_json(
            'en_cyber_core_completeness_diagnostic.json', last_diag or {})
        if last_pair is not None:
            _write_export('en_cyber_ecc_dcc', last_pair)
        self.assertEqual(len(summary), 10)
        self.assertEqual(payload['pass_count'], 10)

    def test_17_data_ndmo_pdpl_regression_passes(self):
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
        self.assertFalse(rel36_13_should_apply(
            lang='ar', domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL']))
        pair = _export_pair(repaired, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_18_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        self.assertFalse(rel36_13_should_apply(
            lang='ar', domain='cyber', document_type='strategy',
            selected_frameworks=_NCA_FWS))
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_19_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-13', canonical_hash='c' * 16,
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
        (_OUT / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
        (_OUT / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        (_QA / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
        (_QA / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_20_ai_sdaia_regression_passes(self):
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

    def test_21_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_22_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
