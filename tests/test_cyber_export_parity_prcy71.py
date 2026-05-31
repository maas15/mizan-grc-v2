"""PR-CY71 — DCC roadmap/KPI parity and Arabic residue cleanup."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy71_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
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


_ROADMAP_ONE_DCC_AR = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | المدة | النشاط | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تطبيق تصنيف ووسم البيانات الحساسة | '
    'CISO | سجل | NCA DCC |\n'
    '| المرحلة 1 | 1-6 أشهر | تأسيس SOC | CISO | SOC | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | IAM/MFA | CISO | MFA | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | CSIRT | CISO | CSIRT | NCA ECC |\n'
)

_VISION_GOV = (
    '## 1. الرؤية\n\n### الأهداف\n\n'
    '| # | الهدف | المقياس | المبرr | الإطار |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن | 100% | q | 6m |\n'
)

_KPI_STUB = (
    '## 6. KPI\n\n'
    '| # | المؤشر | النوع | القيمة | صيغة | مصدر | مالك | تكرar | إطار |\n'
    '|---|---|---|---|---|---|---|---|---|\n'
    '| 1 | MTTR | KPI | 4h | f | SIEM | CISO | شهري | 12m |\n'
)

_CONF = '## 7. الثقة\n\n**درجة:** 82%\n'


def _sections(**kw):
    base = {
        'vision': _VISION_GOV,
        'pillars': '## 2.\n',
        'environment': '## 3.\n',
        'gaps': '## 4.\nGap guide.\n',
        'roadmap': _ROADMAP_ONE_DCC_AR,
        'kpis': _KPI_STUB,
        'confidence': _CONF,
    }
    base.update(kw)
    return base


class Prcy71DccParityTests(unittest.TestCase):

    @_skip
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy71_ensure_required_dcc_roadmap_rows'))
        self.assertTrue(hasattr(_APP, '_prcy71_ensure_dcc_kpi_row'))

    @_skip
    def test_three_required_dcc_roadmap_rows_inserted(self):
        sections = _sections()
        out, actions = _APP._prcy71_ensure_required_dcc_roadmap_rows(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        fams = _APP._prcy71_present_dcc_roadmap_families(out.get('roadmap', ''))
        self.assertIn('data_classification', fams)
        self.assertIn('encryption', fams)
        self.assertIn('dlp', fams)
        self.assertTrue(actions)

    @_skip
    def test_ecc_roadmap_rows_preserved(self):
        sections = _sections()
        before_ecc = _APP._prcy68_count_roadmap_framework_rows(
            sections['roadmap'])[1]
        out, _ = _APP._prcy71_ensure_required_dcc_roadmap_rows(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        after_ecc = _APP._prcy68_count_roadmap_framework_rows(
            out.get('roadmap', ''))[1]
        self.assertGreaterEqual(after_ecc, before_ecc)

    @_skip
    def test_dcc_kpi_row_inserted(self):
        sections = _sections()
        out, actions = _APP._prcy71_ensure_dcc_kpi_row(
            sections, 'ar', ['nca_ecc', 'nca_dcc'])
        self.assertTrue(_APP._prcy71_dcc_kpi_present(out.get('kpis', ''), 'ar'))
        self.assertIn('prcy71:dcc_kpi_row_inserted', actions)

    @_skip
    def test_arabic_residue_masoul_hokuma_cleaned(self):
        dirty = 'المسؤولحوكمة السيبرانية يشرف على البرنامج'
        clean, _ = _APP._prcy71_apply_arabic_residue_cleanup(dirty, 'ar')
        self.assertNotIn('المسؤولحوكمة', clean)
        self.assertIn('مسؤول حوكمة', clean)

    @_skip
    def test_ciso_duplicate_normalized(self):
        dirty = 'تعيين CISO CISO للإدارة'
        clean, samples = _APP._prcy71_apply_arabic_residue_cleanup(dirty, 'ar')
        self.assertNotIn('CISO CISO', clean)
        self.assertIn('CISO', clean)

    @_skip
    def test_pam_iam_normalized_in_render(self):
        text = 'تطبيق PAM/IAM للحسابات المميزة'
        clean = _PSR.normalize_arabic_for_render(text)
        self.assertIn('IAM/PAM', clean)
        self.assertNotIn('PAM/IAM', clean)

    @_skip
    def test_parity_fails_when_dcc_roadmap_under_three(self):
        sections = _sections()
        val = _APP._prcy69_validate_final_artifact(
            '', sections, ['nca_ecc', 'nca_dcc'], 'ar', 'cyber', strict=True)
        self.assertFalse(val.get('parity_valid'))
        blockers = '|'.join(val.get('blockers') or [])
        self.assertTrue(
            'prcy69_final_artifact_missing_dcc_roadmap_rows' in blockers
            or 'prcy71_final_artifact_missing_required_dcc_roadmap_rows'
            in blockers)

    @_skip
    def test_enforce_parity_inserts_dcc_rows_and_kpi(self):
        from tests.test_cyber_export_parity_prcy70 import _minimal_sections
        sections = _minimal_sections(roadmap=_ROADMAP_ONE_DCC_AR)
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='docx')
        diag = result.get('diag') or {}
        self.assertTrue(diag.get('dcc_roadmap_required_rows_present'))
        self.assertTrue(diag.get('dcc_kpi_present_in_final_artifact'))
        self.assertGreaterEqual(
            diag.get('dcc_roadmap_rows_count_in_final_artifact', 0), 3)
        ecc_before = _APP._prcy68_count_roadmap_framework_rows(
            _ROADMAP_ONE_DCC_AR)[1]
        md = result.get('final_markdown') or ''
        self.assertGreaterEqual(
            _APP._prcy68_count_roadmap_framework_rows(md)[1], ecc_before)


if __name__ == '__main__':
    unittest.main()
