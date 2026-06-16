"""PR-REL3.1 — source authority checks."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

_TMP = tempfile.mkdtemp(prefix='test_rel31_source_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine_v3.rel31_authority import emit_rel3_source_authority_check


class Rel31SourceAuthorityTests(unittest.TestCase):

    def test_01_valid_rel3_render_tree_source(self):
        buf = StringIO()
        with redirect_stdout(buf):
            payload = emit_rel3_source_authority_check(
                route_name='docx',
                artifact_id='a1',
                strategy_id='s1',
                render_tree_hash='abc',
                canonical_hash='def',
            )
        self.assertTrue(payload['source_authority_valid'])
        self.assertEqual(payload['source_used'], 'rel3_render_tree')
        self.assertTrue(payload['sealed_artifact_used'])
        self.assertFalse(payload['raw_markdown_used'])
        self.assertFalse(payload['client_content_used'])
        self.assertFalse(payload['cyber_final_export_contract_used'])
        self.assertIn('[REL3-SOURCE-AUTHORITY-CHECK]', buf.getvalue())

    def test_02_client_content_fails_authority(self):
        payload = emit_rel3_source_authority_check(
            route_name='docx',
            client_content_used=True,
            blocking_error_if_any='rel3_legacy_route_blocked:docx:client_content',
        )
        self.assertFalse(payload['source_authority_valid'])

    def test_03_cyber_final_contract_used_fails(self):
        payload = emit_rel3_source_authority_check(
            route_name='pdf',
            cyber_final_export_contract_used=True,
        )
        self.assertFalse(payload['source_authority_valid'])

    def test_04_raw_markdown_used_fails(self):
        payload = emit_rel3_source_authority_check(
            route_name='preview',
            raw_markdown_used=True,
        )
        self.assertFalse(payload['source_authority_valid'])

    def test_05_app_emit_helper(self):
        buf = StringIO()
        with redirect_stdout(buf):
            _APP._rel31_emit_source_authority(
                'generation',
                artifact_dict={
                    'domain': 'cyber',
                    'contract_meta': {'lang': 'ar'},
                    'rel3_render_tree_hash': 'h1',
                    'rel3_canonical_hash': 'h2',
                },
                render_tree_hash='h1',
                canonical_hash='h2',
            )
        self.assertIn('[REL3-SOURCE-AUTHORITY-CHECK]', buf.getvalue())
        line = buf.getvalue().strip()
        data = json.loads(line.split(']', 1)[1].strip())
        self.assertTrue(data['source_authority_valid'])


if __name__ == '__main__':
    unittest.main()
