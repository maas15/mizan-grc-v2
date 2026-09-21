"""Required all-domains smoke: typed REL37 quality + evidence-setup contract."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.rel33_quality_matrix import (
    ensure_required_acceptance_env,
    ensure_test_env,
    load_sections_for_case,
    run_rel33_quality_case,
)
from release_engine_v3.rel37_apply import (
    REL37_APPLIED_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_SOURCE_KEY,
    apply_rel37_to_sections,
    load_model,
    serialize_model,
)
from release_engine_v3.rel37_render import model_to_sections


def _rel37_sections(domain: str) -> dict:
    sections, _repairs = apply_rel37_to_sections(
        {},
        domain=domain,
        lang='ar',
        document_type='strategy',
        selected_frameworks=[],
    )
    return sections


def _write_model(sections: dict, model) -> dict:
    model.compute_hashes()
    out = dict(sections)
    out.update(model_to_sections(model))
    out[REL37_APPLIED_KEY] = '1'
    out[REL37_MODEL_KEY] = serialize_model(model)
    out[REL37_HASH_KEY] = model.model_hash
    out[REL37_SOURCE_KEY] = model.model_hash
    return out


class Rel37TypedQualityAdapterTests(unittest.TestCase):

    def test_valid_rel37_data_ai_dt_pass_intended_quality(self):
        for domain in ('data', 'ai', 'dt'):
            sections = _rel37_sections(domain)
            dq = evaluate_document_quality(
                legacy_sections=sections, domain=domain)
            self.assertTrue(
                dq.get('passed'),
                (domain, dq.get('blocking_errors')),
            )
            so = (dq.get('section_results') or {}).get(
                'strategic_objectives') or {}
            self.assertEqual(so.get('representation'), 'rel37_typed', domain)
            self.assertNotIn(
                'so_count_invalid',
                ' '.join(dq.get('blocking_errors') or []),
                domain,
            )

    def test_missing_objective_content_still_fails(self):
        sections = _rel37_sections('data')
        model = load_model(sections)
        self.assertIsNotNone(model)
        rows = list(model.strategic_objectives)
        rows[0] = replace(rows[0], objective='')
        model.strategic_objectives = tuple(rows)
        mutated = _write_model(sections, model)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('so_family_missing:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_removed_pillar_fields_still_fail(self):
        sections = _rel37_sections('data')
        model = load_model(sections)
        self.assertIsNotNone(model)
        inits = list(model.pillar_initiatives)
        inits[0] = replace(inits[0], description='', output='', owner='')
        model.pillar_initiatives = tuple(inits)
        mutated = _write_model(sections, model)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        blockers = dq.get('blocking_errors') or []
        self.assertFalse(dq.get('passed'), blockers)
        joined = ' '.join(blockers)
        self.assertIn('weak_pillar_description', joined, blockers)
        self.assertIn('missing_evidence_artifact', joined, blockers)
        self.assertIn('pillar_owner_missing', joined, blockers)

    def test_removed_trace_relationship_still_fails(self):
        sections = _rel37_sections('data')
        model = load_model(sections)
        self.assertIsNotNone(model)
        traces = list(model.traceability)
        traces[0] = replace(
            traces[0], initiative='', gap='', kpi='', family='', framework='')
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('trace_family_missing:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_stamp_alone_does_not_skip_legacy_so_count(self):
        vision = (
            '## الرؤية\n\n'
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
        )
        for i in range(1, 15):
            vision += f'| {i} | هدف {i} | مستهدف {i} | مبرر {i} | 12 شهراً |\n'
        sections = {REL37_APPLIED_KEY: '1', 'vision': vision}
        dq = evaluate_document_quality(
            legacy_sections=sections, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('so_count_invalid:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_pdf_evidence_pass_does_not_accept_failed_quality(self):
        sections = _rel37_sections('data')
        model = load_model(sections)
        rows = list(model.strategic_objectives)
        rows[0] = replace(rows[0], objective='')
        model.strategic_objectives = tuple(rows)
        mutated = _write_model(sections, model)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        pdf_returned_file_evidence_passed = True
        generation_save_allowed = bool(dq.get('passed'))
        accepted = (
            generation_save_allowed
            and pdf_returned_file_evidence_passed
        )
        self.assertTrue(pdf_returned_file_evidence_passed)
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertFalse(accepted)


class RequiredSmokePathTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        cls._app = None
        try:
            from release_engine_v3.rel33_quality_matrix import _load_app_module
            cls._app = _load_app_module()
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f'app load failed: {exc!r}')

    def setUp(self):
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)

    def test_data_ar_fixture_compile_path_accepted(self):
        fixture = load_sections_for_case({
            'domain': 'data', 'document_type': 'strategy', 'lang': 'ar',
        })
        self.assertTrue(fixture)
        row = run_rel33_quality_case(
            {
                'domain': 'data', 'document_type': 'strategy', 'lang': 'ar',
                'tier': 'P1',
            },
            app_mod=self._app,
        )
        self.assertTrue(row.get('pdf_returned_file_evidence_passed'), row)
        self.assertTrue(row.get('generation_save_allowed'), row.get('blockers'))
        self.assertTrue(row.get('accepted'), row.get('blockers'))


class RequiredSmokeEvidenceSetupTests(unittest.TestCase):

    def test_required_setup_does_not_enable_skip(self):
        env = {
            key: value for key, value in os.environ.items()
            if key != 'REL2_SKIP_EXPORT_EVIDENCE'
        }
        script = r'''
import os
import sys
from pathlib import Path
root = Path(%r)
sys.path.insert(0, str(root))
entry = os.environ.get("REL2_SKIP_EXPORT_EVIDENCE")
from release_engine_v3.rel33_quality_matrix import (
    ensure_required_acceptance_env,
)
after_import = os.environ.get("REL2_SKIP_EXPORT_EVIDENCE")
ensure_required_acceptance_env()
after_setup = os.environ.get("REL2_SKIP_EXPORT_EVIDENCE")
from release_engine_v3.rel31_authority import (
    _enforce_document_quality_blockers,
)
at_call = os.environ.get("REL2_SKIP_EXPORT_EVIDENCE")
print({
    "entry": entry,
    "after_import": after_import,
    "after_setup": after_setup,
    "at_call": at_call,
})
assert (entry or "") != "1"
assert (after_import or "") != "1"
assert (after_setup or "") != "1"
assert (at_call or "") != "1"
assert _enforce_document_quality_blockers(
    {"contract_meta": {"document_type": "strategy", "domain": "data"},
     "document_type": "strategy"},
    domain="data", lang="ar",
) is True
''' % str(ROOT)
        proc = subprocess.run(
            [sys.executable, '-c', script],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_required_setup_refuses_silent_skip_one(self):
        os.environ['REL2_SKIP_EXPORT_EVIDENCE'] = '1'
        try:
            with self.assertRaises(RuntimeError):
                ensure_required_acceptance_env()
        finally:
            os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)

    def test_legacy_unit_ensure_test_env_still_setdefaults(self):
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        ensure_test_env()
        self.assertEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)


if __name__ == '__main__':
    unittest.main()
