"""REL3.3 — gated staging-only export evidence diagnostics + settle guard.

These are diagnostic-only surfaces: they must never alter export pass/fail,
never bypass the evidence gate, never expose internals by default, and never
appear in production. They also verify the staging acceptance script waits for
Python worker settle instead of probing immediately after deploy.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_staging_diag_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402


class DebugGateTests(unittest.TestCase):
    """Gating: off by default; on only in staging/dev/debug with the flag."""

    def _allowed(self, data, *, base_url, flask_env=None, diag_env=None):
        prev_env = os.environ.get('FLASK_ENV')
        prev_diag = os.environ.get('REL33_STAGING_EXPORT_DIAG')
        try:
            if flask_env is None:
                os.environ.pop('FLASK_ENV', None)
            else:
                os.environ['FLASK_ENV'] = flask_env
            if diag_env is None:
                os.environ.pop('REL33_STAGING_EXPORT_DIAG', None)
            else:
                os.environ['REL33_STAGING_EXPORT_DIAG'] = diag_env
            with app.app.test_request_context(base_url=base_url):
                return app._rel33_debug_export_allowed(data)
        finally:
            if prev_env is None:
                os.environ.pop('FLASK_ENV', None)
            else:
                os.environ['FLASK_ENV'] = prev_env
            if prev_diag is None:
                os.environ.pop('REL33_STAGING_EXPORT_DIAG', None)
            else:
                os.environ['REL33_STAGING_EXPORT_DIAG'] = prev_diag

    def test_off_by_default_no_flag(self):
        self.assertFalse(self._allowed(
            {}, base_url='https://mizan-grc-rel21-staging.onrender.com',
            flask_env='production'))

    def test_on_in_staging_host_with_flag(self):
        self.assertTrue(self._allowed(
            {'rel33_debug_export_evidence': True},
            base_url='https://mizan-grc-rel21-staging.onrender.com',
            flask_env='production'))

    def test_production_host_not_exposed_even_with_flag(self):
        # Production-like: production host, FLASK_ENV=production, no diag env.
        self.assertFalse(self._allowed(
            {'rel33_debug_export_evidence': True},
            base_url='https://mizan-grc.onrender.com',
            flask_env='production'))

    def test_enabled_by_explicit_diag_env(self):
        self.assertTrue(self._allowed(
            {'rel33_debug_export_evidence': True},
            base_url='https://mizan-grc.onrender.com',
            flask_env='production', diag_env='1'))

    def test_enabled_in_development(self):
        self.assertTrue(self._allowed(
            {'rel33_debug_export_evidence': True},
            base_url='https://mizan-grc.example.com',
            flask_env='development'))

    def test_localhost_allowed_with_flag(self):
        self.assertTrue(self._allowed(
            {'rel33_debug_export_evidence': True},
            base_url='http://localhost:5000', flask_env=None))


class PdfEvidenceDiagBuilderTests(unittest.TestCase):
    """The diagnostic builder is pure, preserves blockers, never bypasses."""

    _SECTIONS = {
        'register': (
            '## سجل المخاطر\n| المخاطرة | المالك |\n|---|---|\n'
            '| الوصول غير المصرح به | مدير المخاطر |\n'),
        'treatments': (
            '## خطة المعالجة\n| الضابط | المالك |\n|---|---|\n'
            '| مراجعة الصلاحيات | مدير المخاطر |\n'),
    }

    def test_has_all_required_fields(self):
        diag = app.build_rel33_erm_pdf_evidence_diag(
            pdf_bytes=b'', domain='erm', document_type='risk',
            artifact_type='risk', risk_id=1, route='pdf',
            sections=self._SECTIONS,
            blocking_errors=['rel3_export_evidence_failed:pdf'])
        for field in (
                'route', 'domain', 'document_type', 'artifact_type', 'risk_id',
                'output_type', 'pdf_bytes_len', 'pdf_text_len',
                'pdf_text_extract_source', 'pdf_text_has_null_bytes',
                'arabic_font_registered', 'arabic_font_is_kufi',
                'evidence_gate_name', 'blocking_errors',
                'treatment_section_present', 'treatment_rows_expected',
                'treatment_rows_extracted', 'treatment_headers_detected',
                'treatment_keywords_detected', 'risk_register_rows_expected',
                'risk_register_rows_extracted', 'risk_owner_rows_extracted',
                'kri_rows_extracted', 'extraction_method',
                'structured_table_count', 'fallback_text_scan_used',
                'normalized_arabic_scan_used', 'passed'):
            self.assertIn(field, diag, f'missing field {field}')

    def test_preserves_blocking_errors_and_marks_failed(self):
        blk = ['rel3_export_evidence_failed:pdf', 'empty_risk_treatment']
        diag = app.build_rel33_erm_pdf_evidence_diag(
            pdf_bytes=b'', domain='erm', document_type='risk',
            artifact_type='risk', risk_id=1, sections=self._SECTIONS,
            blocking_errors=blk)
        # Never suppresses or clears blockers; reflects failed state.
        self.assertEqual(diag['blocking_errors'], blk)
        self.assertFalse(diag['passed'])

    def test_does_not_mutate_inputs(self):
        secs = dict(self._SECTIONS)
        blk = ['x']
        app.build_rel33_erm_pdf_evidence_diag(
            pdf_bytes=b'', domain='erm', document_type='risk',
            artifact_type='risk', risk_id=1, sections=secs, blocking_errors=blk)
        self.assertEqual(secs, self._SECTIONS)
        self.assertEqual(blk, ['x'])

    def test_treatment_rows_expected_counted(self):
        diag = app.build_rel33_erm_pdf_evidence_diag(
            pdf_bytes=b'', domain='erm', document_type='risk',
            artifact_type='risk', risk_id=1, sections=self._SECTIONS,
            blocking_errors=[])
        self.assertGreaterEqual(diag['treatment_rows_expected'], 1)
        self.assertTrue(diag['passed'])


class SettleGuardScriptTests(unittest.TestCase):
    """The staging acceptance script waits for worker settle after deploy."""

    def test_acceptance_script_has_settle_guard(self):
        src = (ROOT / 'scripts'
               / '_rel33_all_domain_staging_acceptance.py').read_text(
                   encoding='utf-8')
        self.assertIn('STAGING_DEPLOY_SETTLE_SECONDS', src)
        self.assertIn('deploy-settle', src)
        self.assertIn('deploy_verify_post_settle', src)
        # Default settle window is a multi-minute wait, not immediate probing.
        self.assertIn("'480'", src)


if __name__ == '__main__':
    unittest.main()
