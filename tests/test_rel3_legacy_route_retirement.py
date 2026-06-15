"""PR-REL3 — legacy export route retirement."""

import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel3_legacy_')
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
    raise SystemExit(f'Cannot load app module: {_e!r}')

from release_engine_v3.orchestrator import rel3_block_legacy_export_path


class Rel3LegacyRouteRetirementTests(unittest.TestCase):

    def test_01_legacy_cyber_final_export_contract_blocked(self):
        ok, err = rel3_block_legacy_export_path(
            'legacy_cyber_final_export_contract')
        self.assertFalse(ok)
        self.assertIn('rel3_legacy_export_path_blocked', err)

    def test_02_legacy_professional_render_blocked(self):
        ok, err = rel3_block_legacy_export_path(
            'legacy_professional_strategy_render_raw')
        self.assertFalse(ok)

    def test_03_app_rel3_should_use_cyber_ar(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel3'))
        self.assertTrue(
            _APP._rel3_should_use_unified_engine('cyber', 'ar'))

    def test_04_app_rel3_not_used_for_non_cyber(self):
        self.assertFalse(
            _APP._rel3_should_use_unified_engine('data', 'en'))

    def test_05_block_legacy_raw_markdown_after_seal(self):
        err = _APP._rel3_block_legacy_raw_markdown_export(
            'docx', sealed=True, source='raw_markdown')
        self.assertIn('rel3_legacy_export_path_blocked', err)

    def test_06_rel3_flag_enabled(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel3'))

    def test_07_unified_export_returns_none_when_disabled(self):
        flags = _APP._PRCY28_VERSION_FLAGS
        old = flags.get('rel3')
        flags['rel3'] = False
        try:
            result = _APP._rel3_unified_export_route(
                'docx',
                artifact_dict={'sections': {}, 'domain': 'cyber'},
                domain='cyber',
                lang='ar',
            )
            self.assertIsNone(result)
        finally:
            flags['rel3'] = old

    def test_08_post_seal_mutation_guard(self):
        from release_engine_v3.orchestrator import rel3_guard_post_seal_mutation
        from release_engine_v3.contracts import FinalDocumentArtifact, ExportManifest
        art = FinalDocumentArtifact(
            artifact_id='test-frozen',
            domain='cyber',
            language='ar',
            document_type='strategy',
            strategy_type='technical',
            selected_frameworks=[],
            canonical_sections={},
            quality_repairs=[],
            quality_results={},
            frozen=True,
            canonical_hash='abc',
            render_tree_hash='',
            export_manifest=ExportManifest(),
            blocking_errors=[],
            release_ready_final_passed=True,
        )
        err = rel3_guard_post_seal_mutation(art, 'vision')
        self.assertTrue(err.startswith('rel3_post_seal_mutation_blocked'))


if __name__ == '__main__':
    unittest.main()
