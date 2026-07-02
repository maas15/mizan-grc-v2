"""PR-REL3.1 — save authority wiring (legacy PRCY audit-only under REL3)."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from release_engine_v3.rel31_authority import (
    collect_legacy_audit_blockers,
    evaluate_rel31_pre_save_assertion,
    finalize_rel31_save_authority,
    is_legacy_audit_only_blocker,
    rel31_contract_guard_passed,
)


def _passing_rel31_contract(**overrides):
    base = {
        'artifact_id': 'hash-abc123',
        'task_id': 'task-1',
        'domain': 'cyber',
        'lang': 'ar',
        'document_type': 'strategy',
        'canonical_hash': 'canon-hash-111',
        'render_tree_hash': 'tree-hash-222',
        'generation_save_allowed': True,
        'preview_allowed': True,
        'docx_allowed': True,
        'pdf_allowed': True,
        'blocking_errors': [],
        'legacy_audit_blockers': [],
    }
    base.update(overrides)
    return base


class Rel31SaveAuthorityTests(unittest.TestCase):

    def test_01_prcy74_imbalance_is_legacy_audit_only(self):
        blocker = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        self.assertTrue(is_legacy_audit_only_blocker(blocker))

    def test_02_rel3_passes_while_legacy_prcy74_present(self):
        legacy = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        contract = _passing_rel31_contract(
            legacy_audit_blockers=[legacy])
        art = {
            'rel31_generation_contract': contract,
            'rel3_canonical_hash': contract['canonical_hash'],
            'rel3_render_tree_hash': contract['render_tree_hash'],
            'final_contract_result': {
                'final_hash': contract['canonical_hash'],
                'blocking_errors': [legacy],
            },
            'blocking_errors': [],
        }
        buf = StringIO()
        with redirect_stdout(buf):
            passed, errors, diag = evaluate_rel31_pre_save_assertion(art)
        self.assertTrue(passed, errors)
        self.assertEqual(errors, [])
        self.assertEqual(diag['save_decision'], 'ALLOWED')
        self.assertIn(legacy, diag['legacy_audit_blockers'])
        self.assertIn('[REL3-SAVE-AUTHORITY-CHECK]', buf.getvalue())
        self.assertIn('[REL3-LEGACY-AUDIT-BLOCKERS]', buf.getvalue())

    def test_03_assertion_blocks_on_rel3_not_legacy(self):
        contract = _passing_rel31_contract(
            generation_save_allowed=False,
            blocking_errors=['rel3_document_quality_failed:arabic_residue'],
        )
        art = {'rel31_generation_contract': contract}
        passed, errors, _ = evaluate_rel31_pre_save_assertion(art)
        self.assertFalse(passed)
        self.assertTrue(any('arabic' in e for e in errors))

    def test_04_finalize_demotes_legacy_to_audit_not_blocking(self):
        legacy = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        contract = _passing_rel31_contract()
        art = {
            'blocking_errors': [legacy],
            'final_contract_result': {
                'blocking_errors': [legacy],
                'final_hash': 'old-hash',
            },
            'contract_meta': {'blocking_errors': [legacy]},
        }
        out = finalize_rel31_save_authority(art, contract)
        self.assertEqual(out['blocking_errors'], [])
        self.assertEqual(
            (out['final_contract_result'] or {}).get('blocking_errors'), [])
        rel31 = out['rel31_generation_contract']
        self.assertIn(legacy, rel31['legacy_audit_blockers'])
        self.assertEqual(rel31['blocking_errors'], [])
        self.assertEqual(out['final_hash'], contract['canonical_hash'])

    def test_05_legacy_blocker_after_freeze_in_audit_not_blocking(self):
        legacy = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        art = {
            'final_contract_result': {'blocking_errors': [legacy]},
            'contract_meta': {},
        }
        found = collect_legacy_audit_blockers(art)
        self.assertIn(legacy, found)

    def test_06_pdf_legacy_source_blocked_under_rel3_guard(self):
        from release_engine_v3.rel31_authority import emit_rel3_source_authority_check
        payload = emit_rel3_source_authority_check(
            route_name='pdf',
            source_used='cyber_final_export_contract.final_markdown',
            cyber_final_export_contract_used=True,
            blocking_error_if_any=(
                'rel3_legacy_export_path_blocked:pdf:'
                'cyber_final_export_contract_final_markdown'),
        )
        self.assertFalse(payload['source_authority_valid'])
        self.assertIn('rel3_legacy_export_path_blocked', (
            payload.get('blocking_error_if_any') or ''))

    def test_07_pdf_rel3_render_tree_passes_source_authority(self):
        from release_engine_v3.rel31_authority import emit_rel3_source_authority_check
        payload = emit_rel3_source_authority_check(
            route_name='pdf',
            source_used='rel3_render_tree',
            sealed_artifact_used=True,
            render_tree_hash='tree',
            canonical_hash='canon',
        )
        self.assertTrue(payload['source_authority_valid'])

    def test_08_post_contract_mutation_detected(self):
        from release_engine_v3.rel31_authority import emit_rel3_post_contract_hash_check
        payload = emit_rel3_post_contract_hash_check(
            canonical_hash='aaa',
            render_tree_hash='bbb',
            saved_content_hash='ccc',
            derived_from_rel3=True,
        )
        self.assertTrue(payload['mutation_after_contract_detected'])

    def test_09_valid_rel3_no_mutation(self):
        from release_engine_v3.rel31_authority import emit_rel3_post_contract_hash_check
        payload = emit_rel3_post_contract_hash_check(
            canonical_hash='same',
            render_tree_hash='tree',
            saved_content_hash='same',
            derived_from_rel3=True,
        )
        self.assertFalse(payload['mutation_after_contract_detected'])

    def test_10_failing_log_fixture_allows_save(self):
        """Regression for live staging save_allowed_before_contract_pass:PRCY74."""
        legacy = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        contract = _passing_rel31_contract()
        cy28 = {
            'rel31_authoritative': True,
            'rel31_generation_contract': contract,
            'rel3_canonical_hash': contract['canonical_hash'],
            'rel3_render_tree_hash': contract['render_tree_hash'],
            'blocking_errors': [],
            'final_contract_result': {
                'blocking_errors': [legacy],
                'final_hash': 'stale-legacy-hash',
            },
        }
        art = {
            'rel31_generation_contract': contract,
            'rel3_canonical_hash': contract['canonical_hash'],
            'rel3_render_tree_hash': contract['render_tree_hash'],
            'final_contract_result': cy28['final_contract_result'],
        }
        passed, errors, diag = evaluate_rel31_pre_save_assertion(
            art, cy28_contract=cy28)
        self.assertTrue(passed)
        self.assertEqual(diag['final_save_decision'] if 'final_save_decision' in diag else 'ALLOWED',
                         diag.get('save_decision', 'ALLOWED'))
        self.assertEqual(diag['save_decision'], 'ALLOWED')
        self.assertNotIn(legacy, errors)

    def test_11_rel31_contract_guard_passed(self):
        cy28 = {
            'rel31_authoritative': True,
            'rel31_generation_contract': _passing_rel31_contract(),
            'content_hash': 'canon-hash-111',
        }
        ok, blocker, fh = rel31_contract_guard_passed(cy28)
        self.assertTrue(ok)
        self.assertIsNone(blocker)
        self.assertEqual(fh, 'canon-hash-111')

    def test_12_save_authority_check_final_allow(self):
        from release_engine_v3.rel31_authority import emit_rel3_save_authority_check
        buf = StringIO()
        legacy = (
            'final_quality_gate_failed:'
            'prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=9')
        contract = _passing_rel31_contract(
            legacy_audit_blockers=[legacy])
        with redirect_stdout(buf):
            payload = emit_rel3_save_authority_check(
                contract=contract,
                legacy_blockers_demoted_to_audit=True,
                final_save_decision='ALLOW',
            )
        self.assertEqual(payload['final_save_decision'], 'ALLOW')
        self.assertEqual(payload['blocking_errors'], [])
        self.assertIn(legacy, payload['legacy_audit_blockers'])
        line = [
            ln for ln in buf.getvalue().splitlines()
            if '[REL3-SAVE-AUTHORITY-CHECK]' in ln][0]
        data = json.loads(line.split(']', 1)[1].strip())
        self.assertTrue(data['generation_save_allowed_from_rel3'])


if __name__ == '__main__':
    unittest.main()
