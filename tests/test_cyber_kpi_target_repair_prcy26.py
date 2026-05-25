"""PR-CY26 — Targeted KPI target marker repair tests.

Verifies that ``_repair_kpi_target_marker`` resolves
``[REQUIRES_AI_TARGET_REPAIR]`` markers in the KPI table per the
PR-CY26 deterministic catalog (IAM/PAM, MFA, MTTR/MTTD, vulnerability
remediation, backup, awareness, phishing, encryption) BEFORE the
PR-CY25 final blocking gate fires, while leaving unrecognised KPIs
unresolved so the hard gate still blocks rendering.

Constraints:
* PR-CY18 specialised-objective preservation, PR-CY20 framework-
  compliance preservation, PR-CY22 final export audit, PR-CY23 final
  quality gate, PR-CY24 strategic-objectives sanitiser and PR-CY25
  final export contract / hard blocking gate remain untouched.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_kpi_target_repair_prcy26_')
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
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_KPI_HEADER = (
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
)


def _kpi_table(rows):
    return _KPI_HEADER + '\n'.join(rows) + '\n'


# ── A. Helper signature and catalog matches ────────────────────────
class HelperCatalogTests(unittest.TestCase):

    @_skip_if_no_app
    def test_iam_pam_compliance(self):
        md = _kpi_table([
            '| 1 | الامتثال في إدارة الوصول المميز (PAM) |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' PAM Tool | ربعي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1,
            lang='ar', metadata=None, selected_frameworks=['ECC'])
        self.assertEqual(diag['repaired_target'], '≥ 90%')
        self.assertEqual(diag['confidence'], 'high')
        self.assertIn('iam_pam_compliance', diag['action_taken'])
        self.assertIn('≥ 90%', new_md)
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)

    @_skip_if_no_app
    def test_mfa_coverage(self):
        md = _kpi_table([
            '| 1 | تغطية MFA للحسابات المميزة |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' IdP | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertIn('100% للحسابات المميزة', diag['repaired_target'])
        self.assertIn('≥ 95%', new_md)

    @_skip_if_no_app
    def test_mttr_incident_response(self):
        md = _kpi_table([
            '| 1 | متوسط زمن الاستجابة للحوادث الأمنية الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن من الكشف إلى بدء الاستجابة |'
            ' SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(
            diag['repaired_target'], 'أقل من 4 ساعات للحوادث الحرجة')
        self.assertIn('أقل من 4 ساعات', new_md)
        self.assertEqual(diag['confidence'], 'high')

    @_skip_if_no_app
    def test_mttd_detection(self):
        md = _kpi_table([
            '| 1 | متوسط زمن الكشف عن الحوادث (MTTD) |'
            ' [REQUIRES_AI_TARGET_REPAIR] | متوسط الزمن |'
            ' SIEM | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(
            diag['repaired_target'], 'أقل من 15 دقيقة للحوادث الحرجة')
        self.assertIn('15 دقيقة', new_md)

    @_skip_if_no_app
    def test_vulnerability_remediation(self):
        md = _kpi_table([
            '| 1 | معالجة الثغرات عالية الخطورة |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' VM Tool | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(
            diag['repaired_target'], '≥ 95% خلال 72 ساعة')
        self.assertIn('72 ساعة', new_md)

    @_skip_if_no_app
    def test_backup_success(self):
        md = _kpi_table([
            '| 1 | نسبة نجاح النسخ الاحتياطي |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' Backup System | يومي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(diag['repaired_target'], '≥ 99%')
        self.assertIn('≥ 99%', new_md)

    @_skip_if_no_app
    def test_awareness_training(self):
        md = _kpi_table([
            '| 1 | تغطية برنامج التوعية بالأمن السيبراني |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' LMS | سنوي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertIn('≥ 95% من الموظفين المستهدفين',
                      diag['repaired_target'])
        self.assertIn('الموظفين المستهدفين', new_md)

    @_skip_if_no_app
    def test_phishing_failure_rate(self):
        md = _kpi_table([
            '| 1 | معدل الوقوع في حملات محاكاة التصيد |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' Phishing Sim | ربعي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(diag['repaired_target'], 'أقل من 5%')
        self.assertIn('أقل من 5%', new_md)

    @_skip_if_no_app
    def test_encryption_sensitive_data(self):
        md = _kpi_table([
            '| 1 | تغطية تشفير البيانات الحساسة |'
            ' [REQUIRES_AI_TARGET_REPAIR] | (x/y)*100 |'
            ' DLP | ربعي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertIn('للبيانات الحساسة المصنفة',
                      diag['repaired_target'])
        self.assertIn('≥ 95%', new_md)


# ── B. Row_3 specific behaviour from the spec ─────────────────────
class RowThreeIncidentResponseTests(unittest.TestCase):

    @_skip_if_no_app
    def test_row_3_mttr_repaired_to_four_hours(self):
        md = _kpi_table([
            '| 1 | تغطية الترقيع | 95% | (x/y)*100 | VM | شهري |',
            '| 2 | تغطية MFA | 100% | (x/y)*100 | IdP | شهري |',
            '| 3 | زمن الاستجابة المتوسط للحوادث الأمنية الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن من الكشف إلى بدء الاستجابة |'
            ' SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 3, lang='ar')
        self.assertEqual(diag['row_ref'], 3)
        self.assertEqual(
            diag['repaired_target'], 'أقل من 4 ساعات للحوادث الحرجة')
        # Unchanged rows still present.
        self.assertIn('تغطية الترقيع', new_md)
        self.assertIn('تغطية MFA', new_md)
        # Marker removed and the row 3 target cell now contains the
        # repaired value.
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertIn('أقل من 4 ساعات للحوادث الحرجة', new_md)

    @_skip_if_no_app
    def test_row_3_initial_triage_variant(self):
        md = _kpi_table([
            '| 1 | x | 1 | f | s | شهري |',
            '| 2 | y | 2 | f | s | شهري |',
            '| 3 | زمن الاستجابة الأولية للحوادث الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] | فرز أولي | SOC | شهري |',
        ])
        _, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 3, lang='ar')
        self.assertEqual(
            diag['repaired_target'],
            'أقل من 30 دقيقة للاستجابة الأولية للحوادث الحرجة')

    @_skip_if_no_app
    def test_row_ref_zero_repairs_first_marker(self):
        md = _kpi_table([
            '| 1 | تغطية MFA | [REQUIRES_AI_TARGET_REPAIR] |'
            ' f | IdP | شهري |',
            '| 2 | y | 2 | f | s | شهري |',
        ])
        _, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 0, lang='ar')
        self.assertEqual(diag['row_ref'], 1)
        self.assertIsNotNone(diag['repaired_target'])


# ── C. Structural preservation ────────────────────────────────────
class StructuralPreservationTests(unittest.TestCase):

    @_skip_if_no_app
    def test_table_structure_preserved(self):
        md = _kpi_table([
            '| 1 | متوسط زمن الكشف MTTD |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن | SIEM | شهري |',
        ])
        new_md, _ = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        # Pipe count of the data row is unchanged.
        before_row = md.split('\n')[2]
        after_row = new_md.split('\n')[2]
        self.assertEqual(before_row.count('|'), after_row.count('|'))
        # Formula / source cells untouched.
        self.assertIn('متوسط الزمن', after_row)
        self.assertIn('SIEM', after_row)
        self.assertIn('شهري', after_row)

    @_skip_if_no_app
    def test_formula_and_source_not_overwritten(self):
        md = _kpi_table([
            '| 1 | نسبة نجاح النسخ الاحتياطي |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' (نسخ ناجحة / إجمالي النسخ) * 100 |'
            ' Backup System | يومي |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertIn('(نسخ ناجحة / إجمالي النسخ) * 100', new_md)
        self.assertIn('Backup System', new_md)
        self.assertEqual(diag['repaired_target'], '≥ 99%')


# ── D. Unresolvable KPIs fail closed ──────────────────────────────
class UnresolvableTargetTests(unittest.TestCase):

    @_skip_if_no_app
    def test_unknown_kpi_leaves_marker_in_place(self):
        md = _kpi_table([
            '| 1 | مؤشر تشغيلي مخصص غير قياسي |'
            ' [REQUIRES_AI_TARGET_REPAIR] | f | s | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1, lang='ar')
        self.assertEqual(new_md, md)
        self.assertIsNone(diag['repaired_target'])
        self.assertEqual(
            diag['action_taken'], 'unresolved_kpi_target_repair')
        self.assertGreaterEqual(diag['remaining_markers_count'], 1)


# ── E. End-to-end through the PR-CY25 contract ────────────────────
_CYBER_AR_WITH_ROW3_MARKER = (
    '## 1. الرؤية الاستراتيجية\n\n'
    'تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني خلال 24 شهرًا.\n\n'
    '## 5. خارطة الطريق\n\n'
    '### المرحلة 1\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | حوكمة | 1-6 | CISO |\n\n'
    '### المرحلة 2\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | SOC | 7-18 | SOC |\n\n'
    '### المرحلة 3\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | SOAR | 19-24 | SOC |\n\n'
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | 95% | (x/y)*100 | VM | شهري |\n'
    '| 2 | تغطية MFA | 100% | (x/y)*100 | IdP | شهري |\n'
    '| 3 | زمن الاستجابة المتوسط للحوادث الأمنية الحرجة |'
    ' [REQUIRES_AI_TARGET_REPAIR] |'
    ' متوسط الزمن من الكشف إلى بدء الاستجابة | SOC | شهري |\n\n'
    '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
    '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
    ' مصدر القياس | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الاستجابة | ≤ 4 ساعات | SOC | شهري |\n\n'
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n\n'
    '**درجة الثقة المُشتقة من العوامل:** 82%\n'
)


class ContractWiringTests(unittest.TestCase):

    @_skip_if_no_app
    def test_row_3_marker_repaired_before_final_gate(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_ROW3_MARKER,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        self.assertEqual(out['blocking_errors'], [])
        self.assertFalse(out['diag']['has_unresolved_markers'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         out['final_markdown'])
        self.assertIn('أقل من 4 ساعات للحوادث الحرجة',
                      out['final_markdown'])
        self.assertTrue(any(
            'kpi_target_repair' in a for a in out['repair_actions']))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
