"""PR-CY76 — Re-run SO row sufficiency after PR-CY75 legacy cleanup."""

import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy76_')
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

_SPARSE_CANONICAL = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO |'
    ' تأسيس الهيكل 100% | قيادة وحوكمة | 6 أشهر |\n'
    '| 2 | تحقيق الالتزام بضوابط NCA ECC و NCA DCC |'
    ' امتثال 90% | تنظيمي | 12 شهر |\n'
)

_VISION_LEGACY_PLUS_SPARSE = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    + _LEGACY_ROWS + '\n'
    + _SPARSE_CANONICAL
)

_VISION_GOV_ONLY = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO |'
    ' تأسيس الهيكل 100% | قيادة | 6 أشهر |\n'
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
            phase='test_prcy76',
            generation_mode='consulting',
            quality_issues=quality_issues or [],
        )
    return result, buf.getvalue()


class Prcy76PostCleanupSufficiencyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helpers_present(self):
        self.assertTrue(hasattr(_APP, '_prcy76_post_cleanup_sufficiency_repair'))
        self.assertTrue(hasattr(_APP, '_prcy76_emit_post_cleanup_sufficiency_diag'))

    @_skip_if_no_app
    def test_prcy75_cleanup_then_prcy67_tops_up_rows(self):
        sections = _minimal_sections(_VISION_LEGACY_PLUS_SPARSE)
        result, log = _run_pipeline(
            sections,
            quality_issues=['strategic_objectives_rows_insufficient'],
        )
        inv = result.get('diag') or {}
        issues = result.get('quality_issues') or []
        vision = (result.get('sections') or {}).get('vision', '')
        valid, _ = _APP._prcy67_count_valid_so_rows(vision)
        self.assertGreaterEqual(valid, 5)
        self.assertTrue(inv.get('prcy67_reran_after_prcy75_cleanup'))
        self.assertTrue(inv.get('so_rows_sufficient_after_final_recheck'))
        self.assertNotIn('strategic_objectives_rows_insufficient', issues)
        self.assertIn('[STRATEGIC-OBJECTIVES-POST-CLEANUP-SUFFICIENCY]', log)

    @_skip_if_no_app
    def test_sparse_table_repaired_to_five_plus_rows(self):
        sections = _minimal_sections(_VISION_LEGACY_PLUS_SPARSE)
        result, _log = _run_pipeline(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        valid, _ = _APP._prcy67_count_valid_so_rows(vision)
        self.assertGreaterEqual(valid, 5)

    @_skip_if_no_app
    def test_existing_valid_rows_preserved(self):
        sections = _minimal_sections(_VISION_LEGACY_PLUS_SPARSE)
        result, _log = _run_pipeline(sections)
        vision = (result.get('sections') or {}).get('vision', '')
        self.assertIn('إنشاء إدارة الأمن السيبراني', vision)
        self.assertIn('NCA ECC', vision)

    @_skip_if_no_app
    def test_missing_iam_pam_mfa_inserted_after_cleanup(self):
        sections = _minimal_sections(_VISION_GOV_ONLY)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = _APP._prcy76_post_cleanup_sufficiency_repair(
                sections=dict(sections),
                content=None,
                domain='cyber',
                lang='ar',
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                phase='test_iam',
                generation_mode='consulting',
            )
        _diag = out[7]
        vision = out[0].get('vision', '')
        fam = _APP._prcy67_detect_objective_families(vision)
        self.assertTrue(fam.get('iam_pam_mfa'))
        self.assertIn('iam_pam_mfa', _diag.get('inserted_families') or [])

    @_skip_if_no_app
    def test_missing_data_protection_dcc_inserted_after_cleanup(self):
        sections = _minimal_sections(_VISION_GOV_ONLY)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = _APP._prcy76_post_cleanup_sufficiency_repair(
                sections=dict(sections),
                content=None,
                domain='cyber',
                lang='ar',
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                phase='test_dcc',
                generation_mode='consulting',
            )
        vision = out[0].get('vision', '')
        fam = _APP._prcy67_detect_objective_families(vision)
        self.assertTrue(fam.get('data_protection_dcc'))

    @_skip_if_no_app
    def test_rows_insufficient_not_emitted_after_successful_repair(self):
        sections = _minimal_sections(_VISION_LEGACY_PLUS_SPARSE)
        result, _log = _run_pipeline(
            sections,
            quality_issues=['strategic_objectives_rows_insufficient'],
        )
        issues = result.get('quality_issues') or []
        self.assertNotIn('strategic_objectives_rows_insufficient', issues)
        so_blockers = _APP._prcy63_critical_so_issue_tags(issues)
        self.assertFalse(
            any('rows_insufficient' in b for b in so_blockers))

    @_skip_if_no_app
    def test_save_gate_uses_refined_issues_only(self):
        sections = _minimal_sections(_VISION_LEGACY_PLUS_SPARSE)
        result, _log = _run_pipeline(sections)
        inv = result.get('diag') or {}
        stale = [
            'strategic_objectives_rows_insufficient',
            'strategic_objectives_row_schema_violation',
        ]
        resolved = _APP._prcy75_resolve_final_save_gate_issues(stale, inv)
        self.assertNotIn('strategic_objectives_rows_insufficient', resolved)
        self.assertNotIn(
            'strategic_objectives_row_schema_violation', resolved)
        self.assertTrue(inv.get('final_save_gate_uses_refined_issues'))


if __name__ == '__main__':
    unittest.main()
