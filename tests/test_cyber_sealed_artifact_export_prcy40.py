"""PR-CY40 — Sealed cyber artifact export / latest / canonical parity.

Verifies that saved post-contract ``strategies.content`` is the source of
truth for preview parity routes, that PDF/DOCX/latest use read-only
contract verification (no mutating repair chain), and that hash
diagnostics prove byte-level parity across routes.
"""
import functools
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from unittest import mock


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_sealed_prcy40_')
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


_SEALED_MARKDOWN = (
    '## 1. الرؤية الاستراتيجية\n\n'
    + ('تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني ' * 8)
    + '\n\n## 5. خارطة الطريق\n\n'
    '| # | البند | الشهر | المالك |\n|---|---|---|---|\n'
    '| 1 | حوكمة | 1-6 | CISO |\n\n'
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | ≥ 95% | (x/y)*100 | إدارة الثغرات | شهري |\n\n'
    '## 7. تقييم الثقة\n\n**درجة الثقة:** 82%\n'
)


def _sealed_row(content=None, *, prcy39_meta=True):
    import json as _json
    cj = {'vision': 'x'}
    if prcy39_meta:
        cj['_contract_meta'] = {'prcy39': True, 'sealed': True}
    return {
        'domain': 'cyber',
        'language': 'ar',
        'content': content if content is not None else _SEALED_MARKDOWN,
        'content_json': _json.dumps(cj, ensure_ascii=False),
        'sections_json': _json.dumps({'vision': 'reassembled'}, ensure_ascii=False),
    }


class SealedCyberHelpersTests(unittest.TestCase):

    @_skip_if_no_app
    def test_strategy_row_is_sealed_cyber_with_meta(self):
        self.assertTrue(_APP._strategy_row_is_sealed_cyber(_sealed_row()))

    @_skip_if_no_app
    def test_strategy_row_is_sealed_cyber_without_meta_long_content(self):
        row = _sealed_row(prcy39_meta=False)
        self.assertTrue(_APP._strategy_row_is_sealed_cyber(row))

    @_skip_if_no_app
    def test_cyber_export_is_sealed_artifact_requires_strategy_id(self):
        self.assertTrue(_APP._cyber_export_is_sealed_artifact(
            'strategy', 42, 'cyber'))
        self.assertFalse(_APP._cyber_export_is_sealed_artifact(
            'strategy', None, 'cyber'))
        self.assertFalse(_APP._cyber_export_is_sealed_artifact(
            'strategy', 42, 'erm'))

    @_skip_if_no_app
    def test_fingerprint_includes_prcy38_and_prcy39(self):
        payload = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='test', output_type='test')
        self.assertTrue(payload.get('prcy38'))
        self.assertTrue(payload.get('prcy39'))


class CanonicalContentFromDbTests(unittest.TestCase):

    @_skip_if_no_app
    def test_canonical_prefers_sealed_content_over_sections_json(self):
        row = _sealed_row()
        with mock.patch.object(_APP, 'get_db_direct') as _gdb:
            conn = mock.MagicMock()
            conn.execute.return_value.fetchone.return_value = row
            conn.close = mock.MagicMock()
            _gdb.return_value = conn
            with mock.patch.object(
                    _APP, '_assemble_canonical_from_sections') as _asm:
                out = _APP._canonical_content_from_db(
                    'strategy', 99, user_id=1)
                _asm.assert_not_called()
        self.assertEqual(out.strip(), row['content'].strip())
        self.assertNotIn('reassembled', out)

    @_skip_if_no_app
    def test_canonical_skips_ensure_markdown_formatting_for_sealed(self):
        row = _sealed_row()
        with mock.patch.object(_APP, 'get_db_direct') as _gdb:
            conn = mock.MagicMock()
            conn.execute.return_value.fetchone.return_value = row
            conn.close = mock.MagicMock()
            _gdb.return_value = conn
            with mock.patch.object(
                    _APP, 'ensure_markdown_formatting') as _fmt:
                _APP._canonical_content_from_db('strategy', 99, user_id=1)
                _fmt.assert_not_called()


class ExportContractReadOnlyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_build_docx_bytes_passes_read_only_for_sealed(self):
        self.assertIn('cyber_sealed_artifact', _APP_SOURCE)
        self.assertIn('read_only=bool(cyber_sealed_artifact)', _APP_SOURCE)

    @_skip_if_no_app
    def test_api_generate_pdf_sets_sealed_flag(self):
        self.assertIn('_cyber_sealed_pdf = _cyber_export_is_sealed_artifact',
                      _APP_SOURCE)
        self.assertRegex(
            _APP_SOURCE,
            r"read_only=bool\(\s+locals\(\)\.get\('_cyber_sealed_pdf', False\)\)",
        )

    @_skip_if_no_app
    def test_docx_contract_read_only_when_sealed_artifact(self):
        self.assertRegex(
            _APP_SOURCE,
            r'read_only=bool\(cyber_sealed_artifact\)',
        )

    @_skip_if_no_app
    def test_read_only_contract_does_not_mutate_bytes(self):
        before = _SEALED_MARKDOWN
        out = _APP._cyber_final_export_contract(
            before,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            read_only=True,
        )
        self.assertEqual(out.get('final_markdown'), before)
        self.assertEqual(out.get('repair_actions'), [])
        self.assertTrue(out.get('read_only'))


class LatestRouteSourceTests(unittest.TestCase):

    @_skip_if_no_app
    def test_latest_uses_read_only_contract_for_sealed(self):
        self.assertIn('_strategy_row_is_sealed_cyber(row)', _APP_SOURCE)
        self.assertIn("output_type='latest'", _APP_SOURCE)
        self.assertIn('read_only=True', _APP_SOURCE)
        idx = _APP_SOURCE.find('def api_strategy_latest')
        block = _APP_SOURCE[idx:idx + 12000]
        self.assertNotIn('ensure_markdown_formatting(_row_content)',
                          block.split('_strategy_row_is_sealed_cyber')[1])


class HashProofDiagnosticsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_final_artifact_source_diag_fields(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        h = _APP._prcy25_compute_content_hash(_SEALED_MARKDOWN)
        with redirect_stdout(buf):
            _APP._prcy40_emit_final_artifact_source_diag(
                strategy_id=1,
                saved_content_hash=h,
                latest_hash=h,
                preview_hash=h,
                sealed_artifact_used=True,
                read_only_contract=True,
            )
        out = buf.getvalue()
        self.assertIn('[CYBER-FINAL-ARTIFACT-SOURCE]', out)
        for field in (
            'saved_content_hash', 'latest_hash', 'preview_hash',
            'sealed_artifact_used', 'read_only_contract', 'hashes_match',
        ):
            self.assertIn(field, out)

    @_skip_if_no_app
    def test_saved_preview_latest_hashes_match_on_read_only(self):
        h = _APP._prcy25_compute_content_hash(_SEALED_MARKDOWN)
        out = _APP._cyber_final_export_contract(
            _SEALED_MARKDOWN,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='latest',
            read_only=True,
        )
        self.assertEqual(out.get('post_contract_hash'), h)


class SavePathContractMetaTests(unittest.TestCase):

    @_skip_if_no_app
    def test_save_path_stamps_contract_meta_prcy39(self):
        self.assertIn("'_contract_meta'", _APP_SOURCE)
        self.assertIn("'prcy39': True", _APP_SOURCE)

    @_skip_if_no_app
    def test_schema_first_compose_compat_log(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._prcy38_emit_schema_first_compose_compat(
                {'final_compose_marker_clean': True})
        self.assertIn(
            '[CYBER-SCHEMA-FIRST-COMPOSE] markers_in_output=0',
            buf.getvalue(),
        )


class RegressionGuardTests(unittest.TestCase):

    @_skip_if_no_app
    def test_prcy37_read_only_preview_still_present(self):
        self.assertIn('[CYBER-PREVIEW-READONLY-CHECK]', _APP_SOURCE)

    @_skip_if_no_app
    def test_prcy38_strategic_objectives_compose_log_preserved(self):
        self.assertIn(
            '[STRATEGIC-OBJECTIVES-SCHEMA-FIRST-COMPOSE]',
            _APP_SOURCE,
        )

    @_skip_if_no_app
    def test_no_mutating_contract_keyword_on_sealed_docx_path(self):
        block = re.search(
            r'read_only=bool\(cyber_sealed_artifact\).*?if _cy25_docx_blockers',
            _APP_SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(block)


if __name__ == '__main__':
    unittest.main()
