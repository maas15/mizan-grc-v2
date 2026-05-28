"""PR-CY43 — Async ``task_completed_success`` contract guard scope fix.

Reproduces and guards against the live async failure where a Cyber
generation passed the final contract and saved successfully, yet the
background task was marked failed at the ``task_completed_success``
guard with::

    NameError("name 'task' is not defined")
    final_quality_gate_failed:pipeline_before_contract_pass:task_completed_success

Root cause: the async finisher re-read the saved strategy with
``task['user_id']`` — there is no ``task`` variable in
``_run_strategy_generation_task(task_id, user_id, data)``. The
``NameError`` was swallowed, which forced the read-only contract to
``None`` and the guard to fail-closed.

These tests verify:
  * the finisher uses ``user_id`` (no out-of-scope ``task``);
  * the PR-CY43 guard allows completion when the final contract passed;
  * the guard allows completion via the saved sealed-artifact DB
    fallback when the re-run contract is absent;
  * the guard blocks on the precise fail-closed conditions only.
"""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_async_guard_prcy43_')
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
except Exception as _e:  # noqa: BLE001
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_CYBER_CONTENT = (
    '## 1. الرؤية الاستراتيجية\n\n'
    + ('تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني ' * 8)
    + '\n\n## 5. خارطة الطريق\n\n'
    '| # | البند | الشهر | المالك |\n|---|---|---|---|\n'
    '| 1 | حوكمة | 1-6 | CISO |\n'
)


def _mock_db_row(content, *, sealed=True, final_hash=None,
                 domain='cyber'):
    """Build a strategies row dict as returned by ``get_db_direct``."""
    import json as _json
    cj = {'vision': 'x'}
    if sealed:
        meta = {'prcy39': True, 'sealed': True}
        if final_hash is not None:
            meta['final_hash'] = final_hash
        cj['_contract_meta'] = meta
    return {
        'content': content,
        'content_json': _json.dumps(cj, ensure_ascii=False),
        'domain': domain,
        'language': 'ar',
    }


def _patch_db_returning(row):
    """Return a ``mock.patch`` for ``get_db_direct`` yielding ``row``."""
    conn = mock.MagicMock()
    conn.execute.return_value.fetchone.return_value = row
    conn.close = mock.MagicMock()
    patcher = mock.patch.object(_APP, 'get_db_direct')
    started = patcher.start()
    started.return_value = conn
    return patcher


def _passing_contract(final_hash='abc123'):
    return {
        'final_contract_result': {
            'blocking_errors': [],
            'final_hash': final_hash,
        }
    }


class ScopeSafetyTests(unittest.TestCase):
    """Clause B — no out-of-scope ``task`` reference in the finisher."""

    @_skip_if_no_app
    def test_prcy43_guard_helpers_exist(self):
        self.assertTrue(hasattr(_APP, '_prcy43_task_completed_guard'))
        self.assertTrue(hasattr(_APP, '_prcy43_verify_saved_sealed_artifact'))

    @_skip_if_no_app
    def test_finisher_does_not_reference_undefined_task(self):
        idx = _APP_SOURCE.find('def _run_strategy_generation_task')
        self.assertGreater(idx, 0)
        end = _APP_SOURCE.find('\ndef ', idx + 1)
        body = _APP_SOURCE[idx:end if end > 0 else idx + 30000]
        # The bug was a SELECT scoped with ``task['user_id']``.
        self.assertNotIn("task['user_id']", body)
        # The finisher must use the function-scoped ``user_id`` and the
        # PR-CY43 guard.
        self.assertIn('AND user_id = ?', body)
        self.assertIn('_prcy43_task_completed_guard(', body)

    @_skip_if_no_app
    def test_guard_callable_does_not_raise_nameerror(self):
        # A direct call must never raise (it returns a tuple) — proving
        # there is no undefined-name path inside the guard.
        ok, blocker, proof = _APP._prcy43_task_completed_guard(
            _passing_contract(), 'task-abc', 7, 1, 'cyber')
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(proof, dict)


class GuardAllowTests(unittest.TestCase):

    @_skip_if_no_app
    def test_passes_with_final_contract_result(self):
        ok, blocker, proof = _APP._prcy43_task_completed_guard(
            _passing_contract('hash_ok'), 'task-1', 42, 1, 'cyber')
        self.assertTrue(ok)
        self.assertIsNone(blocker)
        self.assertTrue(proof['guard_passed'])
        self.assertEqual(proof['action_taken'], 'allow_pipeline')
        self.assertEqual(proof['fallback_source'], 'final_contract_result')
        self.assertEqual(proof['final_contract_hash'], 'hash_ok')
        self.assertEqual(proof['blocking_errors'], [])

    @_skip_if_no_app
    def test_passes_with_saved_sealed_artifact_when_contract_absent(self):
        h = _APP._prcy25_compute_content_hash(_CYBER_CONTENT)
        row = _mock_db_row(_CYBER_CONTENT, sealed=True, final_hash=h)
        patcher = _patch_db_returning(row)
        try:
            ok, blocker, proof = _APP._prcy43_task_completed_guard(
                None, 'task-2', 99, 5, 'cyber')
        finally:
            patcher.stop()
        self.assertTrue(ok, proof)
        self.assertIsNone(blocker)
        self.assertEqual(proof['fallback_source'], 'saved_sealed_artifact')
        self.assertTrue(proof['saved_artifact_verified'])
        self.assertEqual(proof['final_contract_hash'], h)

    @_skip_if_no_app
    def test_non_cyber_is_passthrough(self):
        ok, blocker, proof = _APP._prcy43_task_completed_guard(
            None, 'task-3', None, 1, 'erm')
        self.assertTrue(ok)
        self.assertIsNone(blocker)
        self.assertEqual(proof['fallback_source'], 'non_cyber_passthrough')


class GuardBlockTests(unittest.TestCase):

    @_skip_if_no_app
    def test_blocks_when_no_strategy_id(self):
        ok, blocker, proof = _APP._prcy43_task_completed_guard(
            _passing_contract(), 'task-4', None, 1, 'cyber')
        self.assertFalse(ok)
        self.assertEqual(
            blocker,
            'final_quality_gate_failed:'
            'pipeline_before_contract_pass:task_completed_success')
        self.assertIn('no_saved_strategy_id', proof['blocking_errors'])

    @_skip_if_no_app
    def test_blocks_on_saved_hash_mismatch(self):
        row = _mock_db_row(
            _CYBER_CONTENT, sealed=True, final_hash='not_the_real_hash')
        patcher = _patch_db_returning(row)
        try:
            ok, blocker, proof = _APP._prcy43_task_completed_guard(
                None, 'task-5', 99, 5, 'cyber')
        finally:
            patcher.stop()
        self.assertFalse(ok, proof)
        self.assertIsNotNone(blocker)
        self.assertFalse(proof['saved_artifact_verified'])
        self.assertIn('saved_hash_mismatch', proof['blocking_errors'])

    @_skip_if_no_app
    def test_blocks_when_final_hash_missing(self):
        row = _mock_db_row(_CYBER_CONTENT, sealed=True, final_hash=None)
        patcher = _patch_db_returning(row)
        try:
            ok, blocker, proof = _APP._prcy43_task_completed_guard(
                None, 'task-6', 99, 5, 'cyber')
        finally:
            patcher.stop()
        self.assertFalse(ok, proof)
        self.assertIsNotNone(blocker)
        self.assertIn('final_hash_missing', proof['blocking_errors'])

    @_skip_if_no_app
    def test_blocks_when_saved_artifact_missing(self):
        patcher = _patch_db_returning(None)
        try:
            ok, blocker, proof = _APP._prcy43_task_completed_guard(
                None, 'task-7', 99, 5, 'cyber')
        finally:
            patcher.stop()
        self.assertFalse(ok, proof)
        self.assertIn('saved_artifact_missing', proof['blocking_errors'])


class VerifyHelperTests(unittest.TestCase):

    @_skip_if_no_app
    def test_verify_ok_for_sealed_matching_hash(self):
        h = _APP._prcy25_compute_content_hash(_CYBER_CONTENT)
        row = _mock_db_row(_CYBER_CONTENT, sealed=True, final_hash=h)
        patcher = _patch_db_returning(row)
        try:
            info = _APP._prcy43_verify_saved_sealed_artifact(99, 5)
        finally:
            patcher.stop()
        self.assertTrue(info['verified'])
        self.assertEqual(info['reason'], 'ok')
        self.assertEqual(info['contract_meta_hash'], h)
        self.assertEqual(info['saved_content_hash'], h)

    @_skip_if_no_app
    def test_verify_no_strategy_id(self):
        info = _APP._prcy43_verify_saved_sealed_artifact(None, 5)
        self.assertFalse(info['verified'])
        self.assertEqual(info['reason'], 'no_saved_strategy_id')

    @_skip_if_no_app
    def test_verify_not_sealed(self):
        row = _mock_db_row(_CYBER_CONTENT, sealed=False)
        patcher = _patch_db_returning(row)
        try:
            info = _APP._prcy43_verify_saved_sealed_artifact(99, 5)
        finally:
            patcher.stop()
        self.assertFalse(info['verified'])
        self.assertEqual(info['reason'], 'artifact_not_sealed')


class DiagnosticsTests(unittest.TestCase):
    """Clause E — extended [CONTRACT-FIRST-PIPELINE-PROOF] fields."""

    @_skip_if_no_app
    def test_pipeline_proof_emits_required_fields(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._prcy43_task_completed_guard(
                _passing_contract('h'), 'task-8', 42, 1, 'cyber')
        out = buf.getvalue()
        self.assertIn('[CONTRACT-FIRST-PIPELINE-PROOF]', out)
        for field in (
            'task_id', 'strategy_id', 'pipeline_name',
            'final_contract_present', 'final_contract_hash',
            'saved_artifact_verified', 'saved_content_hash',
            'contract_meta_hash', 'blocking_errors', 'guard_passed',
            'action_taken', 'fallback_source',
        ):
            self.assertIn(field, out)
        self.assertIn("'pipeline_name': 'task_completed_success'", out)
        self.assertIn("'guard_passed': True", out)
        self.assertIn("'action_taken': 'allow_pipeline'", out)


if __name__ == '__main__':
    unittest.main()
