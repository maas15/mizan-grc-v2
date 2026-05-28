"""PR-CY45 — Strategy load / preview validation must not surface raw
diagnostics.

Live symptom: loading a generated Cyber strategy produced a UI toast that
dumped the raw PDF quality-gate diagnostic dict
(``arabic_spacing_issues_count``, ``markdown_residue_count``,
``required_sections``, ``blockers``). Root cause: the async PDF export
worker copies the PDF route's error JSON body verbatim into the task
``error`` field, and that body included the full ``quality_gate`` dict.

This suite verifies:
  * the read-only load/preview path logs full diagnostics to
    ``[STRATEGY-LOAD-VALIDATION]`` but surfaces only a concise
    ``strategy_preview_validation_failed:<reason>`` message;
  * empty blockers ⇒ success (zero diagnostic counters never block);
  * the PDF route no longer returns the raw ``quality_gate`` dict;
  * the load endpoints never run the PDF-only quality gate;
  * the load/preview contract stays read-only (no mutating gate).

Run:
    python -m pytest tests/test_cyber_strategy_load_validation_prcy45.py -v
"""
import contextlib
import functools
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_load_validation_prcy45_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'))
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


# A sealed-cyber row body long enough to satisfy _strategy_row_is_sealed_cyber.
_SEALED_MD = (
    '## 1. الرؤية الاستراتيجية\n\n'
    + ('تستهدف الاستراتيجية إرساء برنامج متكامل للأمن السيبراني ' * 10)
    + '\n'
)

# The raw diagnostic keys that must NEVER appear in a client-facing error.
_RAW_DIAG_KEYS = (
    'arabic_spacing_issues_count',
    'markdown_residue_count',
    'raw_markdown_residue_count',
    'required_sections_present',
    'quality_gate',
)


def _sealed_row(**overrides):
    cj = {'vision': 'x', '_contract_meta': {'prcy39': True, 'sealed': True}}
    row = {
        'id': 901,
        'sections_json': json.dumps({'vision': 'reassembled'},
                                    ensure_ascii=False),
        'content_json': json.dumps(cj, ensure_ascii=False),
        'content': _SEALED_MD,
        'domain': 'cyber',
        'language': 'ar',
        'document_title': 'Cyber Strategy',
    }
    row.update(overrides)
    return row


class SafeReasonTests(unittest.TestCase):
    """``_prcy45_safe_preview_reason`` reduces blocker codes to a concise
    token and never emits raw payloads."""

    @_skip_if_no_app
    def test_strips_prefix_and_caps_segments(self):
        r = _APP._prcy45_safe_preview_reason(
            'final_quality_gate_failed:strategic_objectives_schema_compose_'
            'failed:missing_specialized_cyber_objective:row_6')
        # Prefix stripped; at most two reason segments retained.
        self.assertFalse(r.startswith('final_quality_gate_failed'))
        self.assertEqual(
            r,
            'strategic_objectives_schema_compose_failed:'
            'missing_specialized_cyber_objective')

    @_skip_if_no_app
    def test_empty_blocker_yields_default(self):
        self.assertEqual(
            _APP._prcy45_safe_preview_reason(''), 'validation_failed')
        self.assertEqual(
            _APP._prcy45_safe_preview_reason(None), 'validation_failed')

    @_skip_if_no_app
    def test_reason_has_no_raw_dict_chars(self):
        # Even a malformed blocker that embedded a dict fragment must be
        # reduced to a safe token with no JSON/dict structural characters.
        r = _APP._prcy45_safe_preview_reason(
            "final_quality_gate_failed:{'arabic_spacing_issues_count': 0}")
        for ch in ('{', '}', "'", '"', '\n', ' ', ','):
            self.assertNotIn(ch, r)


class EmitDiagnosticTests(unittest.TestCase):
    """``_prcy45_emit_strategy_load_validation`` — logging vs. surfacing."""

    @_skip_if_no_app
    def test_empty_blockers_returns_none_and_success(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            msg = _APP._prcy45_emit_strategy_load_validation(
                strategy_id=1, domain='cyber', sealed_artifact_used=True,
                read_only_contract=True, blockers=[],
                contract={'diag': {'arabic_spacing_issues_count': 0,
                                   'markdown_residue_count': 0}})
        out = buf.getvalue()
        self.assertIsNone(msg)
        self.assertIn('[STRATEGY-LOAD-VALIDATION]', out)
        self.assertIn("'api_success': True", out)

    @_skip_if_no_app
    def test_zero_counters_do_not_block(self):
        # Counters present with zero values must not produce a blocking msg.
        msg = _APP._prcy45_emit_strategy_load_validation(
            strategy_id=1, domain='cyber', sealed_artifact_used=True,
            read_only_contract=True, blockers=[],
            contract={'diag': {'arabic_spacing_issues_count': 0,
                               'raw_markdown_residue_count': 0,
                               'required_sections_present': {'vision': True}}})
        self.assertIsNone(msg)

    @_skip_if_no_app
    def test_blockers_return_concise_message_and_log_full_diag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            msg = _APP._prcy45_emit_strategy_load_validation(
                strategy_id=2, domain='cyber', sealed_artifact_used=True,
                read_only_contract=True,
                blockers=['final_quality_gate_failed:'
                          'strategic_objectives_schema_compose_failed:'
                          'missing_framework_compliance_objective'],
                contract={'diag': {'arabic_spacing_issues_count': 3}})
        out = buf.getvalue()
        # Concise user-facing message.
        self.assertEqual(
            msg,
            'strategy_preview_validation_failed:'
            'strategic_objectives_schema_compose_failed:'
            'missing_framework_compliance_objective')
        # Full diagnostics logged (server-side only).
        self.assertIn('[STRATEGY-LOAD-VALIDATION]', out)
        self.assertIn('arabic_spacing_issues_count', out)
        self.assertIn("'blockers_count': 1", out)


class LatestLoadBehaviourTests(unittest.TestCase):
    """End-to-end ``/api/strategy/latest`` behaviour for sealed cyber rows."""

    @classmethod
    def setUpClass(cls):
        cls.app = _APP.app
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False

    def _login(self, client):
        with client.session_transaction() as s:
            s['user_id'] = 4242
            s['user_email'] = 'prcy45@example.com'
            s['user_name'] = 'PR-CY45 tester'

    @contextlib.contextmanager
    def _patched(self, row, contract_result):
        orig_rec = _APP.ensure_latest_strategy_recoverable
        _APP.ensure_latest_strategy_recoverable = lambda *a, **kw: (row, 1)
        try:
            with mock.patch.object(
                    _APP, '_cyber_final_export_contract',
                    return_value=contract_result) as _m:
                yield _m
        finally:
            _APP.ensure_latest_strategy_recoverable = orig_rec

    @_skip_if_no_app
    def test_success_when_blockers_empty(self):
        contract = {
            'blocking_errors': [],
            'post_contract_hash': 'deadbeef',
            'sections': {'vision': _SEALED_MD},
            'diag': {'arabic_spacing_issues_count': 0,
                     'raw_markdown_residue_count': 0},
        }
        with self._patched(_sealed_row(), contract):
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                body_text = r.get_data(as_text=True)
                self.assertEqual(r.status_code, 200, body_text)
                body = r.get_json()
                self.assertTrue(body.get('success'))
                self.assertTrue(body.get('content'))
                # No raw diagnostic keys anywhere in the response.
                for k in _RAW_DIAG_KEYS:
                    self.assertNotIn(k, body_text)

    @_skip_if_no_app
    def test_blockers_return_concise_safe_error(self):
        contract = {
            'blocking_errors': [
                'final_quality_gate_failed:'
                'strategic_objectives_schema_compose_failed:'
                'missing_specialized_cyber_objective'],
            'post_contract_hash': 'cafe',
            'diag': {'arabic_spacing_issues_count': 0,
                     'raw_markdown_residue_count': 0,
                     'required_sections_present': {'vision': True}},
        }
        with self._patched(_sealed_row(), contract):
            with self.app.test_client() as c:
                self._login(c)
                r = c.get('/api/strategy/latest?domain=Cyber%20Security')
                self.assertEqual(r.status_code, 422)
                body_text = r.get_data(as_text=True)
                body = r.get_json()
                self.assertFalse(body.get('success'))
                self.assertEqual(
                    body.get('error'),
                    'strategy_preview_validation_failed:'
                    'strategic_objectives_schema_compose_failed:'
                    'missing_specialized_cyber_objective')
                # Raw diagnostics must NOT leak to the client.
                for k in _RAW_DIAG_KEYS:
                    self.assertNotIn(k, body_text)

    @_skip_if_no_app
    def test_preview_load_uses_read_only_contract(self):
        contract = {'blocking_errors': [], 'post_contract_hash': 'x',
                    'sections': {'vision': _SEALED_MD}, 'diag': {}}
        with self._patched(_sealed_row(), contract) as _m:
            with self.app.test_client() as c:
                self._login(c)
                c.get('/api/strategy/latest?domain=Cyber%20Security')
            # The sealed-load contract call must be read-only (no mutation).
            self.assertTrue(_m.called)
            _, kwargs = _m.call_args
            self.assertTrue(kwargs.get('read_only'),
                            'load path must call the contract read-only')


class SourceContractTests(unittest.TestCase):
    """Source-level guarantees that survive refactors."""

    @_skip_if_no_app
    def test_pdf_route_does_not_return_raw_quality_gate_dict(self):
        # The PDF quality-gate failure response must not include the raw
        # ``quality_gate`` dict (it leaks via the async export worker).
        self.assertNotIn("'quality_gate': _p41_gate", _APP_SOURCE)
        # It must still log the diagnostics server-side.
        self.assertIn('[PDF-QUALITY-GATE] export_blocked', _APP_SOURCE)
        # And keep the concise reason code.
        self.assertIn("'reason': 'pdf_render_failed'", _APP_SOURCE)

    @_skip_if_no_app
    def test_load_endpoints_do_not_run_pdf_quality_gate(self):
        for fn_name in ('api_strategy_latest', 'api_strategy_status'):
            idx = _APP_SOURCE.find(f'def {fn_name}')
            self.assertGreater(idx, 0, fn_name)
            end = _APP_SOURCE.find('\n@app.route', idx + 1)
            body = _APP_SOURCE[idx:end if end > 0 else idx + 40000]
            self.assertNotIn('run_pdf_quality_gate', body,
                             f'{fn_name} must not run the PDF-only gate')
            self.assertNotIn('run_visual_quality_gate', body,
                             f'{fn_name} must not run the PDF-only gate')

    @_skip_if_no_app
    def test_load_path_emits_load_validation_diagnostic(self):
        self.assertIn('_prcy45_emit_strategy_load_validation(', _APP_SOURCE)
        self.assertIn('[STRATEGY-LOAD-VALIDATION]', _APP_SOURCE)
        # The concise surfaced code is the user-facing contract.
        self.assertIn('strategy_preview_validation_failed:', _APP_SOURCE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
