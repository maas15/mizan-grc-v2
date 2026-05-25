"""PR-CY27 — Final KPI target repair routing & last-chance pass.

Verifies that the PR-CY27 fix eliminates the residual
``final_quality_gate_failed:unresolved_final_repair_marker:
[REQUIRES_AI_TARGET_REPAIR]:kpis:row_3`` diagnostic by:

  A. Routing every ``kpis`` / ``kpi`` / Arabic / ``kpi_table`` section
     alias to ``_repair_kpi_target_marker``.
  B. Running a last-chance marker repair on the final markdown
     immediately before the PR-CY25 hard blocking gate.
  C. Repairing markers directly on the final markdown string the
     blocking gate scans.
  D. Falling back to the marker-containing row when the diagnostic
     row index does not match the table's data-row numbering.
  E. Returning ``"أقل من 4 ساعات للحوادث الحرجة"`` for the canonical
     incident response row_3 example from the problem statement.
  F. Accepting Arabic KPI target values (``أقل من …``, ``لا يقل عن …``,
     ``≥ …``, percentage / duration / SLA targets) and rejecting
     pure-frequency tokens (``شهري``) in the target column.
  G. Not reinserting ``[REQUIRES_AI_TARGET_REPAIR]`` once the repaired
     target passes PR-CY23 schema validation.

Constraints: PR-CY18 specialised-objective preservation, PR-CY20
framework-compliance preservation, PR-CY22 final export audit, PR-CY23
final quality gate, PR-CY24 strategic-objectives sanitiser and
PR-CY25 hard blocking gate must remain functional.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_kpi_target_final_repair_prcy27_')
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


# ── A. Section alias router ─────────────────────────────────────────
class SectionAliasRouterTests(unittest.TestCase):

    @_skip_if_no_app
    def test_kpi_section_aliases_route_to_kpi_repair(self):
        for alias in ('kpi', 'kpis', 'KPI', 'KPIs', 'kpi_table',
                      'مؤشرات الأداء', 'مؤشرات الأداء الرئيسية',
                      'مؤشرات الأداء الرئيسية KPI',
                      'Key Performance Indicators'):
            self.assertTrue(
                _APP._prcy27_is_kpi_section_alias(alias),
                f'alias {alias!r} must route to KPI repair')

    @_skip_if_no_app
    def test_non_kpi_section_does_not_route(self):
        for alias in ('vision', 'roadmap', 'gaps', '', None):
            self.assertFalse(
                _APP._prcy27_is_kpi_section_alias(alias),
                f'alias {alias!r} must NOT route to KPI repair')


# ── B. Marker diagnostic parser ─────────────────────────────────────
class MarkerDiagnosticParserTests(unittest.TestCase):

    @_skip_if_no_app
    def test_parse_canonical_diagnostic(self):
        err = ('final_quality_gate_failed:unresolved_final_repair_marker:'
               '[REQUIRES_AI_TARGET_REPAIR]:kpis:row_3')
        marker, section, row_ref = _APP._prcy27_parse_marker_diagnostic(err)
        self.assertEqual(marker, '[REQUIRES_AI_TARGET_REPAIR]')
        self.assertEqual(section, 'kpis')
        self.assertEqual(row_ref, 3)

    @_skip_if_no_app
    def test_parse_marker_only(self):
        err = ('final_quality_gate_failed:unresolved_final_repair_marker:'
               '[REQUIRES_AI_TARGET_REPAIR]')
        marker, section, row_ref = _APP._prcy27_parse_marker_diagnostic(err)
        self.assertEqual(marker, '[REQUIRES_AI_TARGET_REPAIR]')
        self.assertEqual(section, '')
        self.assertEqual(row_ref, 0)


# ── C. Arabic target validator ──────────────────────────────────────
class ArabicTargetValidatorTests(unittest.TestCase):

    @_skip_if_no_app
    def test_arabic_thresholds_accepted(self):
        for v in (
                'أقل من 4 ساعات', 'أقل من 30 دقيقة', 'أقل من 15 دقيقة',
                'لا يقل عن 90%', 'لا يقل عن 95%',
                '≥ 90%', '≥ 95%',
                '100% للحسابات المميزة', '95% خلال 72 ساعة',
                '99% أو أكثر',
                'أقل من 4 ساعات للحوادث الحرجة',
                'أقل من 30 دقيقة للاستجابة الأولية للحوادث الحرجة',
        ):
            self.assertTrue(
                _APP._prcy27_is_valid_kpi_target(v),
                f'{v!r} must be accepted as a KPI target')

    @_skip_if_no_app
    def test_frequency_tokens_rejected_in_target_column(self):
        for v in ('شهري', 'monthly', 'أسبوعي', 'weekly', 'ربعي'):
            self.assertFalse(
                _APP._prcy27_is_valid_kpi_target(v, column_role='target'),
                f'{v!r} must NOT be accepted as a KPI target')

    @_skip_if_no_app
    def test_marker_token_rejected(self):
        self.assertFalse(_APP._prcy27_is_valid_kpi_target(
            '[REQUIRES_AI_TARGET_REPAIR]'))

    @_skip_if_no_app
    def test_dash_and_empty_rejected(self):
        for v in ('', '—', '-', '–', None):
            self.assertFalse(_APP._prcy27_is_valid_kpi_target(v))


# ── D. Row locator fallback ─────────────────────────────────────────
_KPI_HEADER = (
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
)


def _kpi_table(rows):
    return _KPI_HEADER + '\n'.join(rows) + '\n'


class RowLocatorFallbackTests(unittest.TestCase):

    @_skip_if_no_app
    def test_row_ref_miss_falls_back_to_marker_row(self):
        # Marker is in data row 2 but the diagnostic claims row 9.
        md = _kpi_table([
            '| 1 | تغطية MFA | 100% | (x/y)*100 | IdP | شهري |',
            '| 2 | متوسط زمن الاستجابة للحوادث |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن | SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 9, lang='ar')
        # Falls back to the marker-containing row (row 2) and repairs.
        self.assertEqual(diag['row_ref'], 2)
        self.assertEqual(
            diag['repaired_target'], 'أقل من 4 ساعات للحوادث الحرجة')
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)

    @_skip_if_no_app
    def test_row_ref_match_picks_correct_row_when_multiple_markers(self):
        md = _kpi_table([
            '| 1 | متوسط زمن الكشف MTTD |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن | SIEM | شهري |',
            '| 2 | متوسط زمن الاستجابة MTTR |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن | SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 2, lang='ar')
        self.assertEqual(diag['row_ref'], 2)
        self.assertEqual(
            diag['repaired_target'], 'أقل من 4 ساعات للحوادث الحرجة')
        # Row 1 marker still in place (only row 2 was targeted).
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertIn('متوسط زمن الكشف MTTD', new_md)


# ── E. Last-chance final-markdown repair API ────────────────────────
class LastChanceFinalMarkdownRepairTests(unittest.TestCase):

    @_skip_if_no_app
    def test_repair_routes_kpis_row_3_diagnostic(self):
        md = _kpi_table([
            '| 1 | تغطية الترقيع | 95% | (x/y)*100 | VM | شهري |',
            '| 2 | تغطية MFA | 100% | (x/y)*100 | IdP | شهري |',
            '| 3 | زمن الاستجابة المتوسط للحوادث الأمنية الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن من الكشف إلى بدء الاستجابة |'
            ' SOC | شهري |',
        ])
        blocking_errors = [
            'final_quality_gate_failed:unresolved_final_repair_marker:'
            '[REQUIRES_AI_TARGET_REPAIR]:kpis:row_3'
        ]
        new_md, actions = _APP._prcy27_repair_kpi_target_in_final_markdown(
            md, blocking_errors, lang='ar',
            selected_frameworks=['ECC'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertIn('أقل من 4 ساعات للحوادث الحرجة', new_md)
        self.assertTrue(any('kpi_target_repair' in a for a in actions),
                        f'expected kpi_target_repair action, got {actions}')

    @_skip_if_no_app
    def test_broad_fallback_when_no_diagnostic_provided(self):
        md = _kpi_table([
            '| 1 | تغطية MFA للحسابات المميزة |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' (x/y)*100 | IdP | شهري |',
        ])
        new_md, actions = _APP._prcy27_repair_kpi_target_in_final_markdown(
            md, [], lang='ar')
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertTrue(actions)

    @_skip_if_no_app
    def test_unresolvable_marker_left_in_place(self):
        md = _kpi_table([
            '| 1 | مؤشر تشغيلي مخصص غير قياسي |'
            ' [REQUIRES_AI_TARGET_REPAIR] | f | s | شهري |',
        ])
        blocking_errors = [
            'final_quality_gate_failed:unresolved_final_repair_marker:'
            '[REQUIRES_AI_TARGET_REPAIR]:kpis:row_1'
        ]
        new_md, actions = _APP._prcy27_repair_kpi_target_in_final_markdown(
            md, blocking_errors, lang='ar')
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertTrue(any('unresolved_kpi_target_repair' in a
                            for a in actions))


# ── F. End-to-end through the PR-CY25 contract ──────────────────────
# Reproduces the exact failure scenario from the PR-CY27 problem
# statement: final markdown carries a residual ``row_3`` KPI target
# marker that PR-CY26 section-level repair did not reach.

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
    '## 6. مؤشرات الأداء الرئيسية KPI\n\n'
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


class ContractEndToEndTests(unittest.TestCase):

    @_skip_if_no_app
    def test_row_3_marker_repaired_before_hard_gate(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_ROW3_MARKER,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        self.assertEqual(out['blocking_errors'], [],
                         f"unexpected blocking errors: {out['blocking_errors']}")
        self.assertFalse(out['diag']['has_unresolved_markers'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         out['final_markdown'])
        self.assertIn('أقل من 4 ساعات للحوادث الحرجة',
                      out['final_markdown'])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
