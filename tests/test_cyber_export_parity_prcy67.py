"""PR-CY67 — Ensure sufficient Cyber strategic objective rows before save."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy67_')
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
except Exception as _e:  # pragma: no cover
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_VISION_TWO_VALID_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO |'
    ' تأسيس الهيكل 100% | قيادة وحوكمة | 6 أشهر |\n'
    '| 2 | تحقيق الالتزام بضوابط NCA ECC و NCA DCC |'
    ' امتثال 90% | تنظيمي | 12 شهر |\n'
    '|  |  |  |  |  |\n'
    '| - | - | - | - | - |\n'
)

_VISION_GOV_ONLY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين رئيس الأمن السيبراني CISO |'
    ' تأسيس الهيكل 100% | قيادة | 6 أشهر |\n'
)

_VISION_FW_ONLY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تحقيق الالتزام بضوابط NCA ECC و NCA DCC |'
    ' امتثال 90% | تنظيمي | 12 شهر |\n'
)

_KPI_STUB = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية | ≥ 95% | (x/y)*100 | VM | شهري |\n'
)

_CONF_STUB = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص.\n'
)


def _minimal_sections(vision):
    return {
        'vision': vision,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nنص.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': '## 5. خارطة الطريق\n\nنص.\n',
        'kpis': _KPI_STUB,
        'confidence': _CONF_STUB,
    }


def _run_cy67(sections, content=None, quality_issues=None, **kwargs):
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = _APP._prcy67_presave_ensure_sufficient_objective_rows(
            sections=dict(sections),
            content=content,
            domain='cyber',
            lang='ar',
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase='test',
            generation_mode='consulting',
            quality_issues=quality_issues or [],
            **kwargs,
        )
    return result, buf.getvalue()


class StrategicObjectivesRowSufficiencyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(
            _APP, '_prcy67_presave_ensure_sufficient_objective_rows'))
        self.assertTrue(hasattr(_APP, '_prcy67_detect_objective_families'))
        self.assertTrue(hasattr(_APP, '_prcy67_count_valid_so_rows'))

    @_skip_if_no_app
    def test_two_valid_rows_topped_up_to_minimum(self):
        sections = _minimal_sections(_VISION_TWO_VALID_AR)
        valid_before, _ = _APP._prcy67_count_valid_so_rows(
            sections['vision'])
        self.assertEqual(valid_before, 2)
        result, log = _run_cy67(sections)
        diag = result.get('diag') or {}
        self.assertGreaterEqual(
            diag.get('valid_rows_after', 0),
            _APP._prcy67_required_min_rows('cyber'))
        self.assertTrue(diag.get('rows_sufficient_after_repair'))
        self.assertIn(
            '[PRE-SAVE-STRATEGIC-OBJECTIVES-ROW-SUFFICIENCY-REPAIR]', log)

    @_skip_if_no_app
    def test_existing_valid_rows_preserved(self):
        sections = _minimal_sections(_VISION_TWO_VALID_AR)
        result, _log = _run_cy67(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('CISO', vision)
        self.assertIn('NCA ECC', vision)

    @_skip_if_no_app
    def test_governance_ciso_not_duplicated(self):
        sections = _minimal_sections(_VISION_GOV_ONLY_AR)
        result, _log = _run_cy67(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertEqual(vision.lower().count('ciso'), 1)

    @_skip_if_no_app
    def test_framework_compliance_not_duplicated(self):
        sections = _minimal_sections(_VISION_FW_ONLY_AR)
        result, _log = _run_cy67(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertEqual(vision.count('NCA ECC'), 1)

    @_skip_if_no_app
    def test_soc_csirt_inserted_when_missing(self):
        vision = _VISION_GOV_ONLY_AR
        fam = _APP._prcy67_detect_objective_families(vision)
        self.assertFalse(fam.get('soc_csirt'))
        result, _log = _run_cy67(_minimal_sections(vision))
        vision_after = (result.get('sections') or {}).get('vision', '')
        fam_after = _APP._prcy67_detect_objective_families(vision_after)
        self.assertTrue(fam_after.get('soc_csirt'))
        inserted = (result.get('diag') or {}).get('inserted_families') or []
        if 'soc_csirt' in inserted:
            self.assertIn('SOC', vision_after)

    @_skip_if_no_app
    def test_iam_pam_mfa_inserted_when_missing(self):
        result, _log = _run_cy67(_minimal_sections(_VISION_GOV_ONLY_AR))
        vision = (result.get('sections') or {}).get('vision', '')
        fam = _APP._prcy67_detect_objective_families(vision)
        self.assertTrue(fam.get('iam_pam_mfa'))

    @_skip_if_no_app
    def test_data_protection_dcc_inserted_when_missing(self):
        result, _log = _run_cy67(_minimal_sections(_VISION_GOV_ONLY_AR))
        vision = (result.get('sections') or {}).get('vision', '')
        fam = _APP._prcy67_detect_objective_families(vision)
        self.assertTrue(fam.get('data_protection_dcc'))

    @_skip_if_no_app
    def test_artifact_rows_do_not_count_as_valid(self):
        valid, _ = _APP._prcy67_count_valid_so_rows(_VISION_TWO_VALID_AR)
        self.assertEqual(valid, 2)
        sections = _minimal_sections(_VISION_TWO_VALID_AR)
        result, log = _run_cy67(sections, skip_bootstrap=True)
        diag = result.get('diag') or {}
        self.assertEqual(diag.get('valid_rows_before'), 2)
        self.assertGreaterEqual(diag.get('valid_rows_after', 0), 5)
        self.assertIn('[STRATEGIC-OBJECTIVES-ROWS-SUFFICIENCY-DIAG]', log)

    @_skip_if_no_app
    def test_rows_insufficient_cleared_after_repair(self):
        sections = _minimal_sections(_VISION_TWO_VALID_AR)
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        self.assertIn('strategic_objectives_rows_insufficient', pre_issues)
        result, _log = _run_cy67(
            sections, quality_issues=pre_issues)
        diag = result.get('diag') or {}
        self.assertTrue(diag.get('rows_sufficient_after_repair'))
        refined = _APP._prcy67_refine_rows_insufficient_issues(
            pre_issues, diag)
        self.assertNotIn(
            'strategic_objectives_rows_insufficient', refined)

    @_skip_if_no_app
    def test_precise_blocker_when_still_insufficient(self):
        diag = {
            'rows_sufficient_after_repair': False,
            'valid_rows_after': 1,
            'required_min_rows': 5,
            'missing_families_after': ['soc_csirt', 'iam_pam_mfa'],
        }
        refined = _APP._prcy67_refine_rows_insufficient_issues(
            ['strategic_objectives_rows_insufficient'], diag)
        self.assertIn(
            'strategic_objectives_rows_insufficient_after_repair:1/5',
            refined)
        self.assertTrue(
            any(i.startswith(
                'strategic_objectives_missing_families_after_repair:')
                for i in refined))

    @_skip_if_no_app
    def test_prcy66_pipeline_invariant_still_valid(self):
        sections = _minimal_sections(_VISION_TWO_VALID_AR)
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = _APP._prcy66_presave_canonical_repair_pipeline(
                sections=dict(sections),
                content=None,
                domain='cyber',
                lang='ar',
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                phase='test',
                generation_mode='consulting',
                quality_issues=['strategic_objectives_rows_insufficient'],
            )
        issues = result.get('quality_issues') or []
        inv = result.get('diag') or {}
        self.assertNotIn('strategic_objectives_rows_insufficient', issues)
        self.assertIn('[PRE-SAVE-REPAIR-ORDER-INVARIANT]', buf.getvalue())
        self.assertTrue(
            inv.get('so_valid_after_final_recheck')
            or not _APP._prcy63_critical_so_issue_tags(issues))


if __name__ == '__main__':
    unittest.main()
