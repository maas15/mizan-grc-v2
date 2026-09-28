"""Official runner evidence capture: success, failure, timeout, redaction."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        'rel33_official_runner',
        ROOT / 'scripts' / '_rel33_all_domain_staging_acceptance.py',
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OfficialRunnerCaptureTests(unittest.TestCase):
    def test_six_routes_retained(self):
        mod = _load_runner()
        self.assertEqual(len(mod.P1_ROUTES), 6)
        keys = [mod._route_key(case) for case in mod.P1_ROUTES]
        self.assertEqual(keys, [
            'cyber:strategy:ar:technical',
            'data:strategy:ar',
            'ai:strategy:ar',
            'dt:strategy:ar',
            'erm:risk:ar',
            'global:gap_assessment:ar',
        ])

    def test_sanitize_redacts_secrets_and_content(self):
        mod = _load_runner()
        out = mod._sanitize_runner_payload({
            'org_name': 'REL33 P1 Data Management Org',
            'password': 'super-secret',
            'content': 'x' * 500,
            'cookie': 'abc',
            'strategy_id': 12,
        })
        self.assertEqual(out['org_name'], 'REL33 P1 Data Management Org')
        self.assertEqual(out['password'], 'redacted')
        self.assertEqual(out['cookie'], 'redacted')
        self.assertEqual(out['content_chars'], 500)
        self.assertNotIn('content', out)
        self.assertEqual(out['strategy_id'], 12)
        auth = mod._sanitize_runner_payload({
            'Authorization': 'Bearer secret-token',
            'csrf_token': 'csrf-secret',
        })
        self.assertEqual(auth['Authorization'], 'redacted')
        self.assertEqual(auth['csrf_token'], 'redacted')

    def test_session_cookie_is_label_only(self):
        mod = _load_runner()
        session = MagicMock()
        session.cookies = {'session': 'raw-secret-value'}
        ident = mod._auth_identity_ref(session)
        self.assertEqual(ident['authenticated_identity_ref'], 'session_cookie')
        self.assertEqual(ident['session_cookie'], 'present')
        blob = str(ident)
        self.assertNotIn('raw-secret-value', blob)

    def test_export_org_matches_generation_suffix(self):
        mod = _load_runner()
        case = {'domain': 'data', 'document_type': 'strategy'}
        gen = mod._base_payload(case)
        self.assertTrue(gen['org_name'].endswith(' Org'))
        self.assertEqual(
            gen['org_name'],
            f"REL33 P1 {mod.DOMAIN_LABELS['data']} Org")

    def test_success_failure_timeout_capture(self):
        mod = _load_runner()
        case = {'domain': 'data', 'document_type': 'strategy'}
        ops = []
        session = MagicMock()
        create = MagicMock(status_code=200)
        create.json.return_value = {
            'task_id': '11111111-2222-3333-4444-555555555555'}
        terminal = MagicMock(status_code=200)
        terminal.json.return_value = {'status': 'done', 'progress_percent': 100}
        session.post.return_value = create
        session.get.return_value = terminal
        out = mod._generate_live(session, case, ops=ops)
        self.assertEqual(out.get('status'), 'done')
        kinds = [item['kind'] for item in ops]
        self.assertIn('generate_request', kinds)
        self.assertIn('generate_create_response', kinds)
        self.assertIn('generate_poll_terminal', kinds)
        created = [item for item in ops if item['kind'] == 'generate_create_response'][0]
        self.assertEqual(
            created['task_id'], '11111111-2222-3333-4444-555555555555')
        self.assertNotIn('password', json_blob(ops))

        fail_ops = []
        fail_create = MagicMock(status_code=200)
        fail_create.json.return_value = {
            'task_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}
        fail_term = MagicMock(status_code=200)
        fail_term.json.return_value = {'status': 'error', 'error': 'boom'}
        session.post.return_value = fail_create
        session.get.return_value = fail_term
        failed = mod._generate_live(session, case, ops=fail_ops)
        self.assertEqual(failed.get('status'), 'error')
        self.assertEqual(
            fail_ops[-1]['task_id'],
            'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')

        timeout_ops = []
        session.post.return_value = create
        create.json.return_value = {
            'task_id': '00000000-1111-2222-3333-444444444444'}
        with patch.object(mod, '_poll_gen', side_effect=TimeoutError('generation timeout')):
            with self.assertRaises(TimeoutError):
                mod._generate_live(session, case, ops=timeout_ops)
        self.assertEqual(
            timeout_ops[1]['task_id'],
            '00000000-1111-2222-3333-444444444444')

    def test_local_replay_restores_skip_env(self):
        mod = _load_runner()
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
        os.environ['SECRET_KEY'] = 'test-secret-key'
        with patch.object(
                mod.importlib.util, 'spec_from_file_location',
                side_effect=RuntimeError('stop')):
            with self.assertRaises(RuntimeError):
                mod._local_hash_lock(
                    {}, 'x', '1',
                    {'domain': 'data', 'document_type': 'strategy'})
        self.assertNotEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')
        self.assertIsNone(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'))
        self.assertEqual(os.environ.get('ADMIN_PASSWORD'), 'test-admin-password')

    def test_import_does_not_set_skip(self):
        os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
        _load_runner()
        self.assertNotEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')


def json_blob(value):
    import json
    return json.dumps(value, ensure_ascii=False)


if __name__ == '__main__':
    unittest.main()
