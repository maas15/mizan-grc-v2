"""PR-CY63 — Strategic objectives pre-save schema composer alignment.

Pre-save SO validation must run the same PR-CY39 schema-first composer
used by ``_cyber_final_export_contract`` before the row-schema blocker
fires. Artifact rows (empty / dash-only / pipe-only) must be removed;
CY18 specialized and CY20 framework-compliance rows must be preserved;
residual failures must surface precise blockers instead of the legacy
generic ``strategic_objectives_row_schema_violation``.
"""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_export_parity_prcy63_')
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
except Exception as _e:  # pragma: no cover
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_VISION_NOISY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'رؤية الأمن السيبراني للمؤسسة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
    ' تعيين CISO خلال 6 أشهر |'
    ' ضرورة وجود هيكل تنظيمي متخصص لقيادة برنامج الأمن السيبراني |'
    ' 6 أشهر |\n'
    '| 2 | الامتثال لمتطلبات NCA ECC الأساسية |'
    ' تحقيق نضج 3 على 5 ضوابط ECC الأساسية |'
    ' الامتثال التنظيمي لـ NCA ECC | 12 شهر |\n'
    '| 3 | الامتثال لمتطلبات NCA DCC لحماية البيانات |'
    ' تطبيق ضوابط DCC على 100% من البيانات الحساسة |'
    ' الامتثال التنظيمي لـ NCA DCC | 18 شهر |\n'
    '|  |  |  |  |  |\n'
    '| - | - | - | - | - |\n'
    '|   |   |   |   |   |\n'
    '| bad | orphan | fragment | row | 12 months |\n'
    '\n'
)

_VISION_INCOMPLETE_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | | | | |\n'
)

_KPI_STUB = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | ≥ 95% | (x/y)*100 | VM | شهري |\n'
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
        'gaps': '## 4. الفجوات\n\nنص.\n',
        'roadmap': '## 5. خارطة الطريق\n\nنص.\n',
        'kpis': _KPI_STUB,
        'confidence': _CONF_STUB,
    }


class PreSaveStrategicObjectivesComposeTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(_APP, '_prcy63_presave_compose_strategic_objectives'))
        self.assertTrue(hasattr(_APP, '_prcy63_critical_so_issue_tags'))

    @_skip_if_no_app
    def test_artifact_rows_removed_before_presave_validation(self):
        sections = _minimal_sections(_VISION_NOISY_AR)
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        self.assertIn('strategic_objectives_row_schema_violation', pre_issues)

        result = _APP._prcy63_presave_compose_strategic_objectives(
            sections=dict(sections),
            content=None,
            domain='cyber',
            lang='ar',
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase='test',
            generation_mode='consulting',
            quality_issues=pre_issues,
        )
        post_issues = result.get('quality_issues') or []
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', post_issues)
        diag = result.get('diag') or {}
        self.assertGreaterEqual(diag.get('rows_after', 0), 5)
        self.assertTrue(diag.get('schema_valid_after_compose'))
        self.assertLessEqual(diag.get('rows_before', 99), diag.get('rows_after', 0))

    @_skip_if_no_app
    def test_cy18_specialized_row_preserved(self):
        result = _APP._prcy63_presave_compose_strategic_objectives(
            sections=_minimal_sections(_VISION_NOISY_AR),
            content=None,
            domain='cyber',
            lang='ar',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase='test',
        )
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('CISO', vision)
        self.assertIn('إدارة الأمن السيبراني', vision)
        self.assertTrue(
            (result.get('diag') or {}).get('mandatory_specialized_present'))

    @_skip_if_no_app
    def test_cy20_framework_compliance_rows_preserved(self):
        result = _APP._prcy63_presave_compose_strategic_objectives(
            sections=_minimal_sections(_VISION_NOISY_AR),
            content=None,
            domain='cyber',
            lang='ar',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase='test',
        )
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('NCA ECC', vision)
        self.assertIn('NCA DCC', vision)
        self.assertTrue(
            (result.get('diag') or {}).get(
                'mandatory_framework_compliance_present'))

    @_skip_if_no_app
    def test_presave_does_not_emit_generic_schema_violation_for_artifacts(self):
        sections = _minimal_sections(_VISION_NOISY_AR)
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        result = _APP._prcy63_presave_compose_strategic_objectives(
            sections=sections,
            content=None,
            domain='cyber',
            lang='ar',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            quality_issues=pre_issues,
        )
        issues = result.get('quality_issues') or []
        legacy = [
            i for i in issues
            if i in (
                'strategic_objectives_row_schema_violation',
                'strategic_objectives_row_schema_validation',
            )
        ]
        self.assertEqual(legacy, [])

    @_skip_if_no_app
    def test_presave_emits_precise_blocker_for_real_incomplete_row(self):
        sections = _minimal_sections(_VISION_INCOMPLETE_AR)
        result = _APP._prcy63_presave_compose_strategic_objectives(
            sections=sections,
            content=None,
            domain='cyber',
            lang='ar',
            selected_frameworks=['nca_ecc'],
            phase='test',
        )
        issues = result.get('quality_issues') or []
        so_issues = _APP._prcy63_critical_so_issue_tags(issues)
        diag = result.get('diag') or {}
        # Empty-row artifacts are removed and composed to a valid table;
        # residual SO blockers should not include generic violations.
        self.assertFalse(so_issues, f'unexpected SO blockers: {so_issues!r}')
        self.assertTrue(diag.get('schema_valid_after_compose'))
        self.assertGreaterEqual(diag.get('rows_after', 0), 5)

    @_skip_if_no_app
    def test_composer_runs_before_presave_blocker_in_source(self):
        post_idx = _APP_SOURCE.find('phase=\'pre_save_post_norm\'')
        gate_idx = _APP_SOURCE.find(
            'reason=strategic_objectives_malformed_post_normalization')
        self.assertGreater(post_idx, 0)
        self.assertGreater(gate_idx, post_idx)

    @_skip_if_no_app
    def test_final_export_contract_still_blocks_real_defects(self):
        bad_md = (
            '## 1. الرؤية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
            ' المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | | | | |\n'
        )
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(
            {'vision': bad_md}, 'ar')
        self.assertTrue(
            any(i.startswith('strategic_objectives_incomplete_row:')
                for i in issues),
            msg=f'canonical incomplete row must be detected: {issues!r}')


if __name__ == '__main__':
    unittest.main()
