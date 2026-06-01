"""PR-CY74 — roadmap schema normalization before PR-CY71/73 parity checks."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy74_')
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
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


_MALFORMED_ROADMAP = (
    '## 5. \u062e\u0627\u0631\u0637\u0629 \u0627\u0644\u0637\u0631\u064a\u0642\n\n'
    '| # | \u0627\u0644\u0646\u0634\u0627\u0637 | \u0627\u0644\u0645\u0633\u0624\u0648\u0644 | '
    '\u0627\u0644\u0625\u0637\u0627\u0631 \u0627\u0644\u0632\u0645\u0646\u064a | \u0627\u0644\u0645\u062e\u0631\u062c |\n'
    '|---|---|---|---|---|\n'
    '| 1 | \u062a\u0623\u0633\u064a\u0633 \u062d\u0648\u0643\u0645\u0629 \u0627\u0644\u0623\u0645\u0646 \u0648\u062a\u0639\u064a\u064a\u0646 CISO | '
    '\u0627\u0644\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u062a\u0646\u0641\u064a\u0630\u064a\u0629 | 1-6 \u0623\u0634\u0647\u0631 | '
    '\u0647\u064a\u0643\u0644 \u062d\u0648\u0643\u0645\u0629 \u0645\u0639\u062a\u0645\u062f |\n'
    '| 2 | \u062a\u0623\u0633\u064a\u0633 SOC/SIEM \u0648\u062a\u0634\u063a\u064a\u0644 \u0627\u0644\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0623\u0645\u0646\u064a\u0629 | '
    'CISO | 6-12 \u0634\u0647\u0631 | SOC \u0645\u0634\u063a\u0651\u0644 |\n'
    '| 3 | \u062a\u0637\u0628\u064a\u0642 IAM/PAM/MFA \u0644\u0644\u062d\u0633\u0627\u0628\u0627\u062a \u0627\u0644\u0645\u0645\u064a\u0632\u0629 | '
    'CISO | 6-12 \u0634\u0647\u0631 | MFA \u0645\u0641\u0639\u0651\u0644 |\n'
    '| 4 | \u0628\u0646\u0627\u0621 \u0642\u062f\u0631\u0627\u062a CSIRT \u0648\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u062b\u063a\u0631\u0627\u062a | '
    'CISO | 7-18 \u0634\u0647\u0631 | CSIRT \u0645\u0634\u063a\u0651\u0644 |\n'
    '| 5 | \u062a\u0635\u0646\u064a\u0641 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u062d\u0633\u0627\u0633\u0629 | '
    '\u0645\u062f\u064a\u0631 \u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a | 1-6 \u0623\u0634\u0647\u0631 | '
    '\u0633\u062c\u0644 \u0628\u064a\u0627\u0646\u0627\u062a |\n'
)

_VISION_STUB = (
    '## 1. \u0627\u0644\u0631\u0624\u064a\u0629\n\n### \u0627\u0644\u0623\u0647\u062f\u0627\u0641\n\n'
    '| # | \u0627\u0644\u0647\u062f\u0641 | \u0627\u0644\u0645\u0642\u064a\u0627\u0633 | '
    '\u0627\u0644\u0645\u0628\u0631\u0631 | \u0627\u0644\u0625\u0637\u0627\u0631 |\n'
    '|---|---|---|---|---|\n'
    '| 1 | \u0625\u0646\u0634\u0627\u0621 \u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u0623\u0645\u0646 | '
    '100% | q | 6m |\n'
    '| 2 | \u062a\u0639\u0632\u064a\u0632 \u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a | '
    '90% | q | 12m |\n'
)

_KPI_STUB = (
    '## 6. KPI\n\n'
    '| # | \u0648\u0635\u0641 \u0627\u0644\u0645\u0624\u0634\u0631 | \u0627\u0644\u0642\u064a\u0645\u0629 | \u0635\u064a\u063a\u0629 | '
    '\u0645\u0635\u062f\u0631 | \u062a\u0648\u0627\u062a\u0631 |\n'
    '|---|---|---|---|---|\n'
    '| 1 | MTTR | 4h | f | SIEM | \u0634\u0647\u0631\u064a |\n'
)

_CONF = '## 7. \u0627\u0644\u062b\u0642\u0629\n\n**\u062f\u0631\u062c\u0629:** 82%\n'


def _sections(**kw):
    base = {
        'vision': _VISION_STUB,
        'pillars': '## 2.\n',
        'environment': '## 3.\n',
        'gaps': '## 4.\n',
        'roadmap': _MALFORMED_ROADMAP,
        'kpis': _KPI_STUB,
        'confidence': _CONF,
    }
    base.update(kw)
    return base


class Prcy74RoadmapSchemaTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy74_normalize_roadmap_schema'))
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy74'))

    @_skip
    def test_malformed_header_normalized_to_canonical_6_col(self):
        sections = _sections()
        out, diag, actions = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        roadmap = out.get('roadmap', '')
        self.assertTrue(diag.get('normalized_to_canonical'))
        self.assertIn('\u0627\u0644\u0645\u0628\u0627\u062f\u0631\u0629', roadmap)
        self.assertIn('\u0627\u0644\u0625\u0637\u0627\u0631 \u0627\u0644\u0645\u0631\u062a\u0628\u0637', roadmap)
        hdr = None
        for r in _APP._prcy19_strip_md_table_rows(roadmap):
            if r.get('kind') == 'header':
                hdr = r['cells']
                break
        self.assertTrue(_APP._prcy74_is_canonical_roadmap_header(hdr))
        self.assertIn('prcy74:roadmap_schema_normalized', actions)

    @_skip
    def test_owner_values_not_used_as_initiative_preview(self):
        sections = _sections()
        out, _, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        preview = _APP._prcy71_final_dcc_rows_preview(out)
        joined = ' '.join(preview)
        self.assertNotIn('CISO', joined)
        self.assertNotIn('\u0627\u0644\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u062a\u0646\u0641\u064a\u0630\u064a\u0629', joined)

    @_skip
    def test_governance_soc_iam_csirt_classify_as_ecc(self):
        sections = _sections()
        out, _, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        dcc, ecc = _APP._prcy68_count_roadmap_framework_rows(
            out.get('roadmap', ''))
        self.assertGreaterEqual(ecc, 3)
        for ln in out.get('roadmap', '').split('\n'):
            if 'SOC' in ln and ln.strip().startswith('|'):
                self.assertIn('NCA ECC', ln.upper())

    @_skip
    def test_data_classification_classifies_as_dcc(self):
        sections = _sections()
        out, _, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        fams = _APP._prcy71_present_dcc_roadmap_families(out.get('roadmap', ''))
        self.assertIn('data_classification', fams)

    @_skip
    def test_missing_dlp_row_inserted_after_normalization(self):
        sections = _sections()
        out, diag, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        self.assertTrue(diag.get('standalone_dlp_row_present'))
        self.assertTrue(_APP._prcy73_standalone_dlp_roadmap_row_present(
            out.get('roadmap', '')))

    @_skip
    def test_missing_encryption_row_inserted(self):
        sections = _sections(roadmap=_MALFORMED_ROADMAP)
        out, diag, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        fams = _APP._prcy71_present_dcc_roadmap_families(out.get('roadmap', ''))
        self.assertIn('encryption', fams)
        self.assertTrue(diag.get('required_dcc_families_present'))

    @_skip
    def test_missing_data_classification_row_inserted_if_absent(self):
        minimal = (
            '## 5.\n\n| # | \u0627\u0644\u0646\u0634\u0627\u0637 | \u0627\u0644\u0645\u0633\u0624\u0648\u0644 | '
            '\u0627\u0644\u0625\u0637\u0627\u0631 \u0627\u0644\u0632\u0645\u0646\u064a | \u0627\u0644\u0645\u062e\u0631\u062c |\n'
            '|---|---|---|---|---|\n'
            '| 1 | \u062a\u0623\u0633\u064a\u0633 SOC | CISO | 6-12 \u0634\u0647\u0631 | SOC |\n'
            '| 2 | IAM/MFA | CISO | 6-12 \u0634\u0647\u0631 | MFA |\n'
            '| 3 | CSIRT | CISO | 7-18 \u0634\u0647\u0631 | CSIRT |\n'
        )
        out, _, _ = _APP._prcy74_normalize_roadmap_schema(
            _sections(roadmap=minimal), 'ar', ['nca_ecc', 'nca_dcc'])
        fams = _APP._prcy71_present_dcc_roadmap_families(out.get('roadmap', ''))
        self.assertIn('data_classification', fams)

    @_skip
    def test_parity_passes_after_schema_normalization(self):
        sections = _sections()
        out, _, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        val = _APP._prcy69_validate_final_artifact(
            '', out, ['nca_ecc', 'nca_dcc'], 'ar', 'cyber', strict=True)
        blockers = '|'.join(val.get('blockers') or [])
        self.assertNotIn('prcy71_final_artifact_missing_required_dcc', blockers)
        self.assertNotIn('prcy73_missing_standalone_dlp', blockers)

    @_skip
    def test_framework_balance_after_normalization(self):
        sections = _sections()
        out, diag, _ = _APP._prcy74_normalize_roadmap_schema(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        dcc, ecc = _APP._prcy68_count_roadmap_framework_rows(
            out.get('roadmap', ''))
        self.assertGreaterEqual(dcc, 3)
        self.assertGreaterEqual(ecc, 3)
        self.assertGreaterEqual(diag.get('dcc_rows_after', 0), 3)
        self.assertGreaterEqual(diag.get('ecc_rows_after', 0), 3)


if __name__ == '__main__':
    unittest.main()
