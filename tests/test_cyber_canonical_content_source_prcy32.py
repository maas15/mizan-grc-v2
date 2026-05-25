"""PR-CY32 — Enforce PR-CY31 final canonical output across every Cyber
render route.

Verifies:

A. Runtime version stamp now exposes ``prcy29 / prcy30 / prcy31 / prcy32
   = True`` plus ``route_name`` / ``async_task_id`` / ``strategy_id``.
B. ``_prcy32_runtime_version_gate`` returns an empty list when the flag
   map is healthy, and the matching ``prcy31_not_active_in_runtime``
   blocking-error code when the flag is missing.
C. ``_cyber_final_export_contract`` returns ``pre_contract_hash`` and
   ``post_contract_hash`` fields and propagates them on re-invocation
   (idempotency, so Preview / Save / PDF / DOCX all see the same bytes).
D. ``_prcy32_emit_content_source_diag`` flags a hash mismatch between
   the post-contract bytes and a later route hash.
"""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_prcy32_')
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
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:  # noqa: BLE001
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


class PRVersionStampTests(unittest.TestCase):

    @_skip_if_no_app
    def test_version_stamp_carries_prcy29_30_31_32_flags(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy29'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy30'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy31'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy32'))

    @_skip_if_no_app
    def test_version_stamp_emits_correlation_fields(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._cyber_final_export_contract(
                '# Strategy\n\nbody', metadata={'domain': 'cyber'},
                selected_frameworks=['ECC'], lang='en', domain='cyber',
                output_type='preview',
                request_context={
                    'route_name': 'preview',
                    'async_task_id': 'TASK-XYZ',
                    'strategy_id': 4242,
                },
            )
        out = buf.getvalue()
        self.assertIn('[CYBER-PR-VERSION]', out)
        for token in (
            "'prcy29': True", "'prcy30': True",
            "'prcy31': True", "'prcy32': True",
            "'route_name': 'preview'",
            "'async_task_id': 'TASK-XYZ'",
            "'strategy_id': '4242'",
        ):
            self.assertIn(token, out, f'missing token {token!r}')


class RuntimeVersionGateTests(unittest.TestCase):

    @_skip_if_no_app
    def test_gate_passes_when_all_flags_true(self):
        self.assertEqual(_APP._prcy32_runtime_version_gate(), [])

    @_skip_if_no_app
    def test_gate_blocks_when_prcy31_missing(self):
        original = dict(_APP._PRCY28_VERSION_FLAGS)
        try:
            _APP._PRCY28_VERSION_FLAGS['prcy31'] = False
            errors = _APP._prcy32_runtime_version_gate()
            self.assertTrue(any(
                e.endswith('prcy31_not_active_in_runtime') for e in errors),
                f'gate failed to flag missing prcy31: {errors}')
        finally:
            _APP._PRCY28_VERSION_FLAGS.clear()
            _APP._PRCY28_VERSION_FLAGS.update(original)

    @_skip_if_no_app
    def test_contract_surfaces_prcy31_blocker_when_flag_missing(self):
        original = dict(_APP._PRCY28_VERSION_FLAGS)
        try:
            _APP._PRCY28_VERSION_FLAGS['prcy31'] = False
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = _APP._cyber_final_export_contract(
                    '# Strategy\n\nbody', metadata={'domain': 'cyber'},
                    selected_frameworks=['ECC'], lang='en', domain='cyber',
                    output_type='preview',
                )
            blockers = result.get('blocking_errors') or []
            self.assertTrue(any(
                'prcy31_not_active_in_runtime' in e for e in blockers),
                f'contract failed to block on missing prcy31: {blockers}')
        finally:
            _APP._PRCY28_VERSION_FLAGS.clear()
            _APP._PRCY28_VERSION_FLAGS.update(original)


class ContractHashFieldsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_returns_pre_and_post_hashes(self):
        result = _APP._cyber_final_export_contract(
            '# Strategy\n\nbody', metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'], lang='en', domain='cyber',
            output_type='preview',
        )
        self.assertTrue(result.get('pre_contract_hash'))
        self.assertTrue(result.get('post_contract_hash'))

    @_skip_if_no_app
    def test_contract_is_idempotent_on_clean_input(self):
        clean_md = '# Strategy\n\nbody'
        r1 = _APP._cyber_final_export_contract(
            clean_md, metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'], lang='en', domain='cyber',
            output_type='preview')
        r2 = _APP._cyber_final_export_contract(
            r1.get('final_markdown'), metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'], lang='en', domain='cyber',
            output_type='preview')
        self.assertEqual(
            r1.get('post_contract_hash'), r2.get('post_contract_hash'))


class ContentSourceDiagnosticTests(unittest.TestCase):

    @_skip_if_no_app
    def test_emit_flags_hash_mismatch_as_mutation(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            hashes_match, mutation = _APP._prcy32_emit_content_source_diag(
                output_type='preview', route_name='preview',
                pre_contract_hash='a' * 64, post_contract_hash='b' * 64,
                preview_hash='c' * 64,
                source_used_by_preview='preview_source',
            )
        out = buf.getvalue()
        self.assertFalse(hashes_match)
        self.assertTrue(mutation)
        self.assertIn('[CYBER-FINAL-CONTENT-SOURCE]', out)
        self.assertIn("'hashes_match': False", out)
        self.assertIn("'mutation_after_contract_detected': True", out)

    @_skip_if_no_app
    def test_emit_flags_matched_hashes(self):
        buf = io.StringIO()
        h = 'd' * 64
        with redirect_stdout(buf):
            hashes_match, mutation = _APP._prcy32_emit_content_source_diag(
                output_type='preview', route_name='preview',
                pre_contract_hash='1' * 64, post_contract_hash=h,
                preview_hash=h, saved_content_hash=h,
            )
        out = buf.getvalue()
        self.assertTrue(hashes_match)
        self.assertFalse(mutation)
        self.assertIn("'hashes_match': True", out)


if __name__ == '__main__':
    unittest.main()
