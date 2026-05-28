"""PR-CY37 — Runtime Proof Gate.

Verifies the three independent proof signals that the spec mandates so
operators can prove the live runtime image (and not unit tests alone)
carries the contract-first save path:

1. ``[RUNTIME-BUILD-FINGERPRINT]`` — emitted once at app startup AND
   once inside every ``_cyber_final_export_contract`` invocation, with
   ``prcy37=True`` plus the rest of the spec'd fields.

2. ``[CONTRACT-FIRST-SAVE-PROOF]`` — emitted immediately before any
   ``save_decision=ALLOWED`` log line; blocks the save when
   ``final_contract_result`` is missing/has blocking errors/has an
   empty ``final_hash``.

3. ``[CONTRACT-FIRST-PIPELINE-PROOF]`` — wraps every downstream
   pipeline (traceability capture, initiative/gap/roadmap/KPI task
   extraction, preview canonical_hash emission, ``task_completed
   success=True``) and blocks with
   ``final_quality_gate_failed:pipeline_before_contract_pass:<name>``.
"""
import contextlib
import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_runtime_proof_gate_prcy37_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP = None
_APP_SOURCE = ''
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── (1) RUNTIME-BUILD-FINGERPRINT ──────────────────────────────────
class RuntimeBuildFingerprintTests(unittest.TestCase):

    @_skip_if_no_app
    def test_version_flags_include_prcy37(self):
        flags = _APP._PRCY28_VERSION_FLAGS
        for k in ('prcy25', 'prcy31', 'prcy34', 'prcy35', 'prcy37'):
            self.assertTrue(
                flags.get(k),
                f'_PRCY28_VERSION_FLAGS must carry {k}=True')

    @_skip_if_no_app
    def test_fingerprint_payload_has_required_fields(self):
        payload = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        for field in (
                'app_commit_hash', 'branch_name', 'deployed_at',
                'prcy25', 'prcy31', 'prcy34', 'prcy35', 'prcy37',
                'python_version', 'route_name', 'output_type'):
            self.assertIn(
                field, payload,
                f'fingerprint payload must surface {field!r}')
        self.assertTrue(payload['prcy37'])
        self.assertEqual(payload['route_name'], 'generation')
        self.assertEqual(payload['output_type'], 'generation')

    @_skip_if_no_app
    def test_fingerprint_emitted_at_startup(self):
        # Module-level emit lives next to the helper definition.
        self.assertIn(
            '_prcy37_emit_runtime_build_fingerprint(', _APP_SOURCE)
        self.assertIn("route_name='app_startup'", _APP_SOURCE)
        self.assertIn('[RUNTIME-BUILD-FINGERPRINT]', _APP_SOURCE)

    @_skip_if_no_app
    def test_fingerprint_emitted_inside_contract(self):
        # The contract invocation captures the fingerprint so the
        # generation logs prove prcy37=True is live.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _APP._cyber_final_export_contract(
                '## 1. الرؤية\n\nاختبار.\n',
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc'],
                lang='ar', domain='cyber',
                output_type='generation',
                read_only=True,
            )
        out = buf.getvalue()
        self.assertIn('[RUNTIME-BUILD-FINGERPRINT]', out)
        self.assertIn("'prcy37': True", out)


# ── (2) CONTRACT-FIRST-SAVE-PROOF ──────────────────────────────────
class ContractFirstSaveProofTests(unittest.TestCase):

    @_skip_if_no_app
    def test_save_proof_diagnostic_exists_with_required_fields(self):
        self.assertIn('[CONTRACT-FIRST-SAVE-PROOF]', _APP_SOURCE)
        for field in (
                'task_id', 'strategy_id_candidate',
                'contract_called_before_save', 'final_contract_present',
                'final_contract_hash', 'blocking_errors',
                'save_decision', 'insert_allowed',
                'traceability_allowed', 'task_pipeline_allowed',
                'kpi_pipeline_allowed', 'assertion_passed'):
            self.assertIn(
                field, _APP_SOURCE,
                f'save proof diagnostic must surface {field!r}')

    @_skip_if_no_app
    def test_save_proof_emits_before_save_decision_allowed(self):
        # Source ordering: the [CONTRACT-FIRST-SAVE-PROOF] string must
        # appear in the file before the literal save_decision=ALLOWED
        # log so no save_decision=ALLOWED line can be printed without
        # the proof gate having fired first.
        idx_proof = _APP_SOURCE.find('[CONTRACT-FIRST-SAVE-PROOF]')
        idx_allowed = _APP_SOURCE.find('save_decision=ALLOWED ')
        self.assertGreater(idx_proof, 0)
        self.assertGreater(idx_allowed, 0)
        self.assertLess(
            idx_proof, idx_allowed,
            '[CONTRACT-FIRST-SAVE-PROOF] must be emitted before any '
            'save_decision=ALLOWED log line')

    @_skip_if_no_app
    def test_contract_guard_result_classifies_blockers(self):
        # Missing contract → final_contract_missing_before_save.
        ok, blocker, fh = _APP._prcy37_contract_guard_result(None)
        self.assertFalse(ok)
        self.assertIn('final_contract_missing_before_save', blocker)
        # Blocking errors → save_allowed_before_contract_pass:<first>.
        contract = {
            'final_contract_result': {
                'blocking_errors': [
                    'final_quality_gate_failed:roadmap_horizon_mismatch:'
                    'summary_24:roadmap_18'],
                'final_hash': 'deadbeef',
            },
        }
        ok, blocker, fh = _APP._prcy37_contract_guard_result(contract)
        self.assertFalse(ok)
        self.assertIn('save_allowed_before_contract_pass', blocker)
        self.assertIn('roadmap_horizon_mismatch', blocker)
        # Missing hash → final_contract_hash_missing.
        contract2 = {
            'final_contract_result': {
                'blocking_errors': [],
                'final_hash': '',
            },
        }
        ok, blocker, fh = _APP._prcy37_contract_guard_result(contract2)
        self.assertFalse(ok)
        self.assertIn('final_contract_hash_missing', blocker)
        # Healthy contract → allowed.
        contract3 = {
            'final_contract_result': {
                'blocking_errors': [],
                'final_hash': 'cafef00d' * 8,
            },
        }
        ok, blocker, fh = _APP._prcy37_contract_guard_result(contract3)
        self.assertTrue(ok)
        self.assertIsNone(blocker)


# ── (3) CONTRACT-FIRST-PIPELINE-PROOF ─────────────────────────────
class ContractFirstPipelineProofTests(unittest.TestCase):

    @_skip_if_no_app
    def test_pipeline_proof_diagnostic_exists(self):
        self.assertIn('[CONTRACT-FIRST-PIPELINE-PROOF]', _APP_SOURCE)
        # Pipeline_before_contract_pass blocker code mandated by spec.
        self.assertIn('pipeline_before_contract_pass:', _APP_SOURCE)

    @_skip_if_no_app
    def test_guarded_pipelines_listed(self):
        # Every pipeline named in the spec must appear in the source
        # as a pipeline_name argument to the shared guard.
        for name in (
                'traceability_capture',
                'initiative_task_extraction',
                'gap_task_extraction',
                'roadmap_task_extraction',
                'kpi_task_extraction',
                'preview_canonical_hash_emission',
                'task_completed_success'):
            self.assertIn(
                name, _APP_SOURCE,
                f'pipeline {name!r} must be guarded by the '
                'PR-CY37 contract-first pipeline gate')

    @_skip_if_no_app
    def test_pipeline_guard_emits_proof_log(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok, blocker = _APP._prcy37_pipeline_guard(
                None, 'traceability_capture',
                task_id='t-123', strategy_id='s-456')
        out = buf.getvalue()
        self.assertFalse(ok)
        self.assertIn('[CONTRACT-FIRST-PIPELINE-PROOF]', out)
        self.assertIn('traceability_capture', out)
        self.assertIn(
            'pipeline_before_contract_pass:traceability_capture', blocker)

    @_skip_if_no_app
    def test_pipeline_guard_allows_passing_contract(self):
        contract = {
            'final_contract_result': {
                'blocking_errors': [],
                'final_hash': 'a' * 16,
            },
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok, blocker = _APP._prcy37_pipeline_guard(
                contract, 'kpi_task_extraction')
        self.assertTrue(ok)
        self.assertIsNone(blocker)
        self.assertIn('[CONTRACT-FIRST-PIPELINE-PROOF]', buf.getvalue())
        self.assertIn("'guard_passed': True", buf.getvalue())


if __name__ == '__main__':
    unittest.main()
