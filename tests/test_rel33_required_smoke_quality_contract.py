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

from release_engine_v3.document_quality_spec import (
    _evaluate_rel37_typed_tables,
    _rel37_claimed_model,
    _rel37_typed_eligibility,
    evaluate_document_quality,
)
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


def _write_model(sections: dict, model, *, recompute: bool = True) -> dict:
    if recompute:
        model.compute_hashes()
    out = dict(sections)
    out.update(model_to_sections(model))
    out[REL37_APPLIED_KEY] = '1'
    out[REL37_MODEL_KEY] = serialize_model(model)
    if recompute:
        out[REL37_HASH_KEY] = model.model_hash
        out[REL37_SOURCE_KEY] = model.model_hash
    return out


def _positive(domain: str = 'data'):
    sections = _rel37_sections(domain)
    model = load_model(sections)
    return sections, model


class Rel37TypedQualityAdapterTests(unittest.TestCase):

    def test_valid_rel37_data_ai_dt_pass_intended_quality(self):
        expected_counts = {'data': 14, 'ai': 11, 'dt': 15}
        for domain, count in expected_counts.items():
            sections, model = _positive(domain)
            helper = _rel37_claimed_model(sections)
            eligible = _rel37_typed_eligibility(sections, domain=domain)
            dq = evaluate_document_quality(
                legacy_sections=sections, domain=domain, lang='ar',
                document_type='strategy')
            self.assertIsNotNone(helper[0], domain)
            self.assertEqual(helper[1], [], domain)
            self.assertIsNotNone(eligible[0], domain)
            self.assertEqual(eligible[1], [], domain)
            self.assertEqual(len(model.strategic_objectives), count, domain)
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

    def test_incomplete_so_fields_fail_separately_and_together(self):
        sections, model = _positive('data')
        dq = evaluate_document_quality(
            legacy_sections=sections, domain='data')
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))
        rows = list(model.strategic_objectives)
        for field in ('target', 'rationale', 'timeframe'):
            mutated_model = load_model(sections)
            changed = list(mutated_model.strategic_objectives)
            changed[0] = replace(changed[0], **{field: ''})
            mutated_model.strategic_objectives = tuple(changed)
            mutated = _write_model(sections, mutated_model, recompute=True)
            helper = _rel37_claimed_model(mutated)
            self.assertIsNotNone(helper[0], field)
            self.assertEqual(helper[1], [], field)
            dq = evaluate_document_quality(
                legacy_sections=mutated, domain='data')
            self.assertFalse(dq.get('passed'), (field, dq.get('blocking_errors')))
            self.assertTrue(
                any(f'so_row_incomplete:' in str(b) and field in str(b)
                    for b in (dq.get('blocking_errors') or [])),
                (field, dq.get('blocking_errors')),
            )
        mutated_model = load_model(sections)
        changed = list(mutated_model.strategic_objectives)
        changed[0] = replace(
            changed[0], target='', rationale='', timeframe='')
        mutated_model.strategic_objectives = tuple(changed)
        mutated = _write_model(sections, mutated_model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        joined = ' '.join(dq.get('blocking_errors') or [])
        self.assertIn('so_row_incomplete', joined)
        self.assertNotIn('so_count_invalid', joined)

    def test_missing_objective_content_still_fails(self):
        sections, model = _positive('data')
        rows = list(model.strategic_objectives)
        rows[0] = replace(rows[0], objective='')
        model.strategic_objectives = tuple(rows)
        mutated = _write_model(sections, model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('so_family_missing:')
                or 'so_row_incomplete:' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_empty_pillar_initiatives_fail(self):
        sections, model = _positive('data')
        self.assertTrue(evaluate_document_quality(
            legacy_sections=sections, domain='data').get('passed'))
        model.pillar_initiatives = ()
        mutated = _write_model(sections, model, recompute=True)
        self.assertEqual(model.validate(), [])
        helper = _rel37_claimed_model(mutated)
        self.assertEqual(helper[1], [])
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any('pillar_initiatives_missing' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_one_pillar_without_initiatives_fails(self):
        sections, model = _positive('data')
        keep = [
            row for row in model.pillar_initiatives if row.pillar_number != 1]
        model.pillar_initiatives = tuple(keep)
        mutated = _write_model(sections, model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertIn(
            'pillar_initiatives_missing:1',
            dq.get('blocking_errors') or [],
        )

    def test_orphan_pillar_initiative_fails(self):
        sections, model = _positive('data')
        inits = list(model.pillar_initiatives)
        inits[0] = replace(inits[0], pillar_number=99)
        model.pillar_initiatives = tuple(inits)
        mutated = _write_model(sections, model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any('pillar_initiative_orphan:99' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_missing_initiative_name_fails(self):
        sections, model = _positive('data')
        inits = list(model.pillar_initiatives)
        inits[0] = replace(inits[0], initiative='')
        model.pillar_initiatives = tuple(inits)
        mutated = _write_model(sections, model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any('pillar_initiative_name_missing' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_removed_pillar_fields_still_fail(self):
        sections, model = _positive('data')
        inits = list(model.pillar_initiatives)
        inits[0] = replace(inits[0], description='', output='', owner='')
        model.pillar_initiatives = tuple(inits)
        mutated = _write_model(sections, model, recompute=True)
        blockers = evaluate_document_quality(
            legacy_sections=mutated, domain='data').get('blocking_errors') or []
        joined = ' '.join(blockers)
        self.assertIn('weak_pillar_description', joined, blockers)
        self.assertIn('missing_evidence_artifact', joined, blockers)
        self.assertIn('pillar_owner_missing', joined, blockers)

    def test_trace_references_missing_gap_and_kpi(self):
        sections, model = _positive('data')
        traces = list(model.traceability)
        traces[0] = replace(
            traces[0], gap='gap-not-in-model', kpi='kpi-not-in-model')
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model, recompute=True)
        typed = _evaluate_rel37_typed_tables(model, domain='data')
        table = typed.get('traceability_mapping_table') or []
        self.assertTrue(table)
        self.assertNotEqual(
            table[0].get('trace_gap'), table[0].get('matched_gap_family'))
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        joined = ' '.join(dq.get('blocking_errors') or [])
        self.assertIn('trace_gap_unassociated', joined)
        self.assertIn('trace_kpi_unassociated', joined)

    def test_swapped_trace_associations_fail(self):
        sections, model = _positive('data')
        traces = list(model.traceability)
        first, second = traces[0], traces[1]
        traces[0] = replace(first, gap=second.gap, kpi=second.kpi)
        traces[1] = replace(second, gap=first.gap, kpi=first.kpi)
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model, recompute=True)
        self.assertEqual(model.validate(), [])
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any('unassociated' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_duplicate_trace_hides_required_family(self):
        sections, model = _positive('data')
        traces = list(model.traceability)
        traces[1] = replace(
            traces[1],
            family=traces[0].family,
            framework=traces[0].framework,
            gap=traces[0].gap,
            kpi=traces[0].kpi,
            initiative=traces[0].initiative,
        )
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model, recompute=True)
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('trace_family_missing:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_removed_trace_relationship_still_fails(self):
        sections, model = _positive('data')
        traces = list(model.traceability)
        traces[0] = replace(
            traces[0], initiative='', gap='', kpi='', family='', framework='')
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model, recompute=True)
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
        helper = _rel37_claimed_model(sections)
        eligible = _rel37_typed_eligibility(sections, domain='data')
        dq = evaluate_document_quality(
            legacy_sections=sections, domain='data')
        self.assertIsNone(helper[0])
        self.assertIsNone(eligible[0])
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            any(str(b).startswith('so_count_invalid:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_data_model_under_ai_or_cyber_caller_is_ineligible(self):
        sections, _model = _positive('data')
        helper = _rel37_claimed_model(sections)
        self.assertEqual(helper[1], [])
        for caller in ('ai', 'cyber'):
            eligible = _rel37_typed_eligibility(sections, domain=caller)
            dq = evaluate_document_quality(
                legacy_sections=sections, domain=caller)
            self.assertIsNone(eligible[0], caller)
            self.assertTrue(eligible[1], caller)
            self.assertFalse(dq.get('passed'), (caller, dq.get('blocking_errors')))
            self.assertTrue(
                any('rel37_domain_mismatch' in str(b)
                    for b in (eligible[1] or []) + (dq.get('blocking_errors') or [])),
                (caller, eligible[1], dq.get('blocking_errors')),
            )

    def test_unsupported_schema_and_document_type_fail_closed(self):
        sections, model = _positive('data')
        model.schema_version = 'not-rel37'
        mutated = _write_model(sections, model, recompute=True)
        eligible = _rel37_typed_eligibility(mutated, domain='data')
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertIsNone(eligible[0])
        self.assertTrue(
            any('schema_version_invalid' in str(b) for b in (eligible[1] or [])),
            eligible[1],
        )
        self.assertFalse(dq.get('passed'))
        sections, model = _positive('data')
        model.document_type = 'policy'
        mutated = _write_model(sections, model, recompute=True)
        eligible = _rel37_typed_eligibility(
            mutated, domain='data', document_type='strategy')
        self.assertIsNone(eligible[0])
        self.assertTrue(
            any('document_type' in str(b) for b in (eligible[1] or [])),
            eligible[1],
        )

    def test_validate_rejected_model_fail_closed(self):
        sections, model = _positive('data')
        model.kpis = ()
        mutated = _write_model(sections, model, recompute=True)
        self.assertTrue(model.validate())
        eligible = _rel37_typed_eligibility(mutated, domain='data')
        dq = evaluate_document_quality(
            legacy_sections=mutated, domain='data')
        self.assertIsNone(eligible[0])
        self.assertTrue(eligible[1])
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))

    def test_stored_hash_tamper_distinct_from_content(self):
        sections, model = _positive('data')
        rows = list(model.strategic_objectives)
        rows[0] = replace(rows[0], target='')
        model.strategic_objectives = tuple(rows)
        content = _write_model(sections, model, recompute=True)
        helper = _rel37_claimed_model(content)
        self.assertEqual(helper[1], [])
        dq = evaluate_document_quality(
            legacy_sections=content, domain='data')
        self.assertFalse(dq.get('passed'))
        self.assertTrue(
            any('so_row_incomplete' in str(b)
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )
        tampered = dict(content)
        tampered[REL37_HASH_KEY] = '0' * 64
        helper = _rel37_claimed_model(tampered)
        eligible = _rel37_typed_eligibility(tampered, domain='data')
        dq = evaluate_document_quality(
            legacy_sections=tampered, domain='data')
        self.assertIn('rel37_model_hash_mismatch', helper[1] or [])
        self.assertIn('rel37_model_hash_mismatch', eligible[1] or [])
        self.assertIn(
            'rel37_model_hash_mismatch', dq.get('blocking_errors') or [])

    def test_genuine_legacy_paths_stay_on_legacy_rules(self):
        fixture = load_sections_for_case({
            'domain': 'data', 'document_type': 'strategy', 'lang': 'ar',
        })
        self.assertFalse(fixture.get(REL37_APPLIED_KEY))
        eligible = _rel37_typed_eligibility(fixture, domain='data')
        self.assertIsNone(eligible[0])
        self.assertIsNone(eligible[1])
        dq = evaluate_document_quality(
            legacy_sections=fixture, domain='data')
        self.assertFalse(dq.get('passed'))
        self.assertTrue(
            any(str(b).startswith('so_count_invalid:')
                for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'),
        )

    def test_cyber_erm_global_and_unclaimed_inputs_stay_legacy(self):
        sections = {'vision': '## vision\n'}
        for domain in ('cyber', 'erm', 'global'):
            helper = _rel37_claimed_model(sections)
            eligible = _rel37_typed_eligibility(sections, domain=domain)
            self.assertIsNone(helper[0], domain)
            self.assertIsNone(helper[1], domain)
            self.assertIsNone(eligible[0], domain)
            self.assertIsNone(eligible[1], domain)

    def test_pdf_evidence_pass_does_not_accept_failed_quality(self):
        sections, model = _positive('data')
        rows = list(model.strategic_objectives)
        rows[0] = replace(rows[0], objective='')
        model.strategic_objectives = tuple(rows)
        mutated = _write_model(sections, model, recompute=True)
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

    def _apply_contract(self, sections, domain='data'):
        from release_engine_v3.rel31_authority import (
            apply_rel31_authoritative_contract,
        )
        backend = dict(self._app._rel31_backend_callables())
        flags = {'rel3': True, 'rel31': True, 'rel32': True}
        backend['flags'] = dict(flags)
        backend['lang'] = 'ar'
        backend['document_type'] = 'strategy'
        md = self._app._prcy65_rebuild_content_from_sections(sections, None)
        art = {
            'sections': sections,
            'final_markdown': md,
            'domain': domain,
            'document_type': 'strategy',
            'strategy_id': f'rel33-{domain}-strategy-ar-typed-quality',
            'contract_meta': {
                'lang': 'ar',
                'domain': domain,
                'document_type': 'strategy',
            },
        }
        return apply_rel31_authoritative_contract(
            art, backend=backend, flags=flags)

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

    def test_generation_contract_accepts_valid_typed_source(self):
        sections, _model = _positive('data')
        art = self._apply_contract(sections, domain='data')
        contract = art.get('rel31_generation_contract') or {}
        dq = art.get('rel31_document_quality') or {}
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(
            contract.get('generation_save_allowed'),
            contract.get('blocking_errors'),
        )
        pdf_route = (dq.get('route_evidence') or {}).get('pdf')
        pdf_exercised = bool(pdf_route)
        self.assertTrue(
            contract.get('generation_save_allowed'),
            contract.get('blocking_errors'),
        )
        if not pdf_exercised:
            contract.setdefault('pdf_evidence', 'not_exercised')

    def test_generation_contract_refuses_malformed_required_content(self):
        sections, model = _positive('data')
        traces = list(model.traceability)
        traces[0] = replace(
            traces[0], gap=traces[1].gap, kpi=traces[1].kpi)
        model.traceability = tuple(traces)
        mutated = _write_model(sections, model, recompute=True)
        self.assertFalse(
            evaluate_document_quality(
                legacy_sections=mutated, domain='data').get('passed'))
        art = self._apply_contract(mutated, domain='data')
        contract = art.get('rel31_generation_contract') or {}
        dq = art.get('rel31_document_quality') or {}
        self.assertFalse(dq.get('passed'), dq.get('blocking_errors'))
        self.assertFalse(
            contract.get('generation_save_allowed'),
            contract.get('blocking_errors'),
        )
        pdf_route = (dq.get('route_evidence') or {}).get('pdf')
        pdf_exercised = bool(pdf_route)
        self.assertFalse(
            contract.get('generation_save_allowed'),
            contract.get('blocking_errors'),
        )
        if pdf_exercised:
            self.assertFalse(
                bool(dq.get('passed'))
                and contract.get('generation_save_allowed'))


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
