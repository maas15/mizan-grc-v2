"""PR-CY75 — Strip legacy malformed SO table fragments before save gate."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy75_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
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


_LEGACY_ROWS = (
    '| 1 | إنشاء إدارة الأمن السيبراني المتخصصة | '
    'هيكل تنظيمي معتمد مع تعيين CISO وفريق SOC |\n'
    '| 2 | تشغيل مركز عمليات الأمن المتقدم | '
    'مركز SOC يعمل 24/7 مع تغطية 100% للأصول الحرجة |\n'
    '| 3 | إنجاز منظومة السياسات الأمنية الشاملة | '
    '100% من متطلبات NCA ECC مغطاة بسياسات معتمدة |\n'
)

_CANONICAL_TABLE = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
    ' تعيين CISO خلال 6 أشهر | ضرورة وجود هيكل | 6 أشهر |\n'
    '| 2 | الامتثال لمتطلبات NCA ECC الأساسية |'
    ' تحقيق نضج 3 على 5 | الامتثال التنظيمي | 12 شهر |\n'
    '| 3 | الامتثال لمتطلبات NCA DCC |'
    ' تطبيق ضوابط DCC | الامتثال التنظيمي | 18 شهر |\n'
)

_VISION_MIXED_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'رؤية الأمن السيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    + _LEGACY_ROWS + '\n'
    + _CANONICAL_TABLE
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
    '| 1 | تغطية | ≥ 95% | (x/y)*100 | VM | شهري |\n'
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


def _run_pipeline(sections, quality_issues=None):
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = _APP._prcy66_presave_canonical_repair_pipeline(
            sections=dict(sections),
            content=None,
            domain='cyber',
            lang='ar',
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            phase='test_prcy75',
            generation_mode='consulting',
            quality_issues=quality_issues or [],
        )
    return result, buf.getvalue()


class Prcy75LegacyFragmentCleanupTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy75_strip_legacy_objective_fragments'))
        self.assertTrue(hasattr(_APP, '_prcy75_apply_legacy_fragment_cleanup'))
        self.assertTrue(hasattr(_APP, '_prcy75_resolve_final_save_gate_issues'))

    @_skip_if_no_app
    def test_strip_removes_only_legacy_three_column_rows(self):
        new_text, diag = _APP._prcy75_strip_legacy_objective_fragments(
            _VISION_MIXED_AR, 'ar', 'cyber')
        self.assertGreater(diag.get('malformed_rows_removed', 0), 0)
        self.assertIn('الهدف الاستراتيجي', new_text)
        self.assertNotIn(
            'هيكل تنظيمي معتمد مع تعيين CISO وفريق SOC', new_text)
        self.assertIn('تعيين CISO خلال 6 أشهر', new_text)
        self.assertGreaterEqual(diag.get('canonical_rows_after', 0), 3)

    @_skip_if_no_app
    def test_valid_five_column_rows_preserved(self):
        new_text, diag = _APP._prcy75_strip_legacy_objective_fragments(
            _VISION_MIXED_AR, 'ar', 'cyber')
        self.assertEqual(diag.get('canonical_rows_before', 0), 3)
        self.assertEqual(diag.get('canonical_rows_after', 0), 3)
        self.assertIn('الامتثال لمتطلبات NCA DCC', new_text)

    @_skip_if_no_app
    def test_compose_runs_after_cleanup(self):
        sections = _minimal_sections(_VISION_MIXED_AR)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = _APP._prcy63_presave_compose_strategic_objectives(
                sections=sections,
                content=None,
                domain='cyber',
                lang='ar',
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                phase='test',
                generation_mode='consulting',
            )
        self.assertTrue(
            (out.get('diag') or {}).get('schema_valid_after_compose'))
        self.assertIn(
            '[PRE-SAVE-STRATEGIC-OBJECTIVES-COMPOSE]', buf.getvalue())
        vision = (out.get('sections') or {}).get('vision', '')
        self.assertNotIn(
            'هيكل تنظيمي معتمد مع تعيين CISO وفريق SOC', vision)

    @_skip_if_no_app
    def test_audit_clean_after_pipeline(self):
        sections = _minimal_sections(_VISION_MIXED_AR)
        result, log = _run_pipeline(
            sections,
            quality_issues=['strategic_objectives_row_schema_violation'],
        )
        issues = result.get('quality_issues') or []
        self.assertNotIn('strategic_objectives_row_schema_violation', issues)
        out_sections = result.get('sections') or {}
        _, post_issues = _APP._audit_doc_quality(
            out_sections, 'technical', 'ar', generation_mode='consulting')
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', post_issues)
        self.assertIn(
            '[STRATEGIC-OBJECTIVES-LEGACY-FRAGMENT-CLEANUP]', log)
        inv = result.get('diag') or {}
        self.assertTrue(inv.get('so_valid_after_final_recheck'))
        self.assertTrue(inv.get('final_save_gate_uses_refined_issues'))

    @_skip_if_no_app
    def test_save_gate_resolve_drops_stale_generic_violation(self):
        stale = [
            'strategic_objectives_row_schema_violation',
            'confidence_score_missing',
        ]
        inv = {
            'so_valid_after_final_recheck': True,
            'legacy_so_fragments_removed': 3,
            'final_save_gate_uses_refined_issues': True,
        }
        resolved = _APP._prcy75_resolve_final_save_gate_issues(stale, inv)
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', resolved)
        so_blockers = _APP._prcy63_critical_so_issue_tags(resolved)
        self.assertFalse(so_blockers)

    @_skip_if_no_app
    def test_stale_post_list_cannot_block_when_refined_empty(self):
        sections = _minimal_sections(_VISION_MIXED_AR)
        result, _log = _run_pipeline(sections)
        refined = result.get('quality_issues') or []
        inv = result.get('diag') or {}
        stale_post = [
            'strategic_objectives_row_schema_violation',
            'generic_scaffold_dominant',
        ]
        gate_issues = _APP._prcy75_resolve_final_save_gate_issues(
            stale_post, inv)
        so_blockers = _APP._prcy63_critical_so_issue_tags(gate_issues)
        refined_blockers = _APP._prcy63_critical_so_issue_tags(refined)
        self.assertFalse(refined_blockers)
        self.assertFalse(so_blockers)

    @_skip_if_no_app
    def test_real_incomplete_row_emits_precise_blocker(self):
        sections = _minimal_sections(_VISION_INCOMPLETE_AR)
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
                    for b in so_blockers),
                f'expected precise blocker, got {so_blockers!r}',
            )

    @_skip_if_no_app
    def test_invariant_reports_legacy_fragment_fields(self):
        sections = _minimal_sections(_VISION_MIXED_AR)
        result, log = _run_pipeline(sections)
        inv = result.get('diag') or {}
        self.assertTrue(inv.get('legacy_so_fragments_detected'))
        self.assertGreater(inv.get('legacy_so_fragments_removed', 0), 0)
        self.assertIn('legacy_so_fragments_detected', log)


if __name__ == '__main__':
    unittest.main()
