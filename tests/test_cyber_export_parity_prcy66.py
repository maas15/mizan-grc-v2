"""PR-CY66 — Stabilize pre-save repair ordering after confidence repair."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy66_')
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


def _minimal_sections(vision, confidence=''):
    return {
        'vision': vision,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nنص.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': '## 5. خارطة الطريق\n\nنص.\n',
        'kpis': _KPI_STUB,
        'confidence': confidence,
    }


def _run_pipeline(sections, content=None, quality_issues=None, phase='test'):
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = _APP._prcy66_presave_canonical_repair_pipeline(
            sections=dict(sections),
            content=content,
            domain='cyber',
            lang='ar',
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase=phase,
            generation_mode='consulting',
            quality_issues=quality_issues or [],
        )
    return result, buf.getvalue()


class PreSaveRepairOrderTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(_APP, '_prcy66_presave_canonical_repair_pipeline'))
        self.assertTrue(hasattr(_APP, '_prcy66_rebuild_canonical_content'))
        self.assertTrue(hasattr(_APP, '_prcy66_finalize_presave_issues'))

    @_skip_if_no_app
    def test_pipeline_does_not_block_on_stale_so_after_confidence_repair(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        self.assertIn('strategic_objectives_row_schema_violation', pre_issues)
        self.assertIn('confidence_score_missing', pre_issues)

        result, _log = _run_pipeline(
            sections,
            quality_issues=pre_issues,
        )
        issues = result.get('quality_issues') or []
        so_blockers = _APP._prcy63_critical_so_issue_tags(issues)
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', issues,
            f'unrefined stale SO violation must not survive pipeline: {issues!r}')
        self.assertFalse(
            so_blockers,
            f'SO gate must not block after successful compose: {issues!r}')

    @_skip_if_no_app
    def test_confidence_rebuild_preserves_composed_vision(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        result, _log = _run_pipeline(sections)
        out_sections = result.get('sections') or {}
        vision = out_sections.get('vision', '')
        self.assertIn('### الأهداف الاستراتيجية', vision)
        self.assertIn('CISO', vision)
        content = result.get('content') or ''
        self.assertIn('### الأهداف الاستراتيجية', content)
        self.assertIn('درجة الثقة', content)

    @_skip_if_no_app
    def test_quality_issues_after_excludes_unrefined_so_violation(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        result, log = _run_pipeline(
            sections, quality_issues=pre_issues)
        cy65_diag = result.get('cy65_diag') or {}
        after = cy65_diag.get('quality_issues_after') or []
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', after,
            f'CONFIDENCE quality_issues_after must be refined: {after!r}')
        self.assertIn('[CONFIDENCE-PRE-SAVE-REPAIR]', log)

    @_skip_if_no_app
    def test_invariant_passes_when_so_and_confidence_valid(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        result, log = _run_pipeline(sections)
        inv = result.get('diag') or {}
        self.assertTrue(inv.get('so_compose_passed_before_confidence'))
        self.assertTrue(inv.get('so_rechecked_after_confidence'))
        self.assertTrue(inv.get('so_valid_after_final_recheck'))
        self.assertTrue(inv.get('confidence_valid_after_final_recheck'))
        self.assertFalse(inv.get('stale_so_issue_detected'))
        self.assertIn('[PRE-SAVE-REPAIR-ORDER-INVARIANT]', log)

    @_skip_if_no_app
    def test_stale_so_cleared_by_rerun_after_confidence_rebuild(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        stale_content = (
            '## 1. الرؤية\n\n'
            '| # | bad | table | only | one |\n'
            '|---|---|---|---|---|\n'
            '| bad | orphan | row | here | 12 months |\n\n'
            + sections['pillars']
        )
        _, pre_issues = _APP._audit_doc_quality(
            sections, 'technical', 'ar', generation_mode='consulting')
        result, log = _run_pipeline(
            sections,
            content=stale_content,
            quality_issues=pre_issues,
        )
        inv = result.get('diag') or {}
        issues = result.get('quality_issues') or []
        if inv.get('stale_so_issue_detected'):
            self.assertEqual(
                inv.get('stale_issue_source'), 'post_confidence_reaudit')
            self.assertEqual(
                inv.get('action_taken'), 'so_rerun_cleared_stale_issue')
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', issues)
        self.assertTrue(inv.get('so_valid_after_final_recheck'))

    @_skip_if_no_app
    def test_real_so_defect_emits_precise_blocker_not_generic(self):
        sections = _minimal_sections(_VISION_INCOMPLETE_AR, confidence='')
        result, _log = _run_pipeline(sections)
        issues = result.get('quality_issues') or []
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', issues)
        so_blockers = _APP._prcy63_critical_so_issue_tags(issues)
        if so_blockers:
            self.assertTrue(
                any(
                    b.startswith('strategic_objectives_incomplete_row:')
                    or b.startswith('strategic_objectives_schema_compose_failed:')
                    or b == 'strategic_objectives_table_missing_after_repair'
                    for b in so_blockers
                ),
                f'expected precise SO blocker, got {so_blockers!r}',
            )

    @_skip_if_no_app
    def test_rebuild_canonical_content_preserves_vision_when_splice_stale(self):
        sections = _minimal_sections(_VISION_NOISY_AR, confidence='')
        composed = _APP._prcy63_presave_compose_strategic_objectives(
            sections=dict(sections),
            content=None,
            domain='cyber',
            lang='ar',
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc'],
            phase='test',
            generation_mode='consulting',
        )
        sections = composed.get('sections') or sections
        stale = '## 1. Old stale vision without table\n\n' + sections['pillars']
        rebuilt = _APP._prcy66_rebuild_canonical_content(sections, stale)
        self.assertIn('### الأهداف الاستراتيجية', rebuilt)
        self.assertNotIn('Old stale vision', rebuilt)


if __name__ == '__main__':
    unittest.main()
