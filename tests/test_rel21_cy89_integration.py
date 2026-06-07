"""PR-REL2.1 — CY89 runs before REL2; integration diagnostic."""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

_TMP = tempfile.mkdtemp(prefix='test_rel21_cy89_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


class Rel21Cy89IntegrationTests(unittest.TestCase):

    def test_flags_and_pipeline_order(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy89'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel2'))
        from domains.cyber.fixtures_ar import technical_sections
        sections = technical_sections()
        order = ('vision', 'pillars', 'environment', 'gaps',
                 'roadmap', 'kpis', 'confidence')
        content = '\n\n'.join(sections[k] for k in order if sections.get(k))
        buf = io.StringIO()
        with redirect_stdout(buf):
            art = _APP._build_cyber_final_strategy_artifact(
                content,
                sections=dict(sections),
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar',
                domain='cyber',
                output_type='generation',
                doc_subtype='technical',
            )
        self.assertIn('[REL2-CY89-INTEGRATION-CHECK]', buf.getvalue())
        self.assertTrue((art.get('diagnostics') or {}).get('prcy89'))
        self.assertTrue((art.get('diagnostics') or {}).get('rel2'))
        self.assertTrue(art.get('release_ready_final_passed'))


if __name__ == '__main__':
    unittest.main()
