"""PR-CY24 — Strategic Objectives table sanitizer.

Verifies the Cyber-safe and domain-safe sanitizer that runs immediately
after the final quality repair (PR-CY22/PR-CY23 quality gate or
``_repair_and_revalidate`` in the save flow) and BEFORE the
``strategic_objectives_row_schema_violation`` check inside
``_audit_doc_quality``.

PR-CY18 specialized-objective preservation and PR-CY20 framework-
compliance preservation MUST remain intact and are explicitly
exercised here.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_strategic_objectives_sanitizer_prcy24_')
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
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
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


_HEADER_EN = (
    '| # | Objective | Target Metric | Justification | Timeframe |\n'
    '|---|---|---|---|---|'
)
_HEADER_AR = (
    '| # | الهدف الاستراتيجي | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|'
)


def _wrap_vision(table_lines):
    return '## 1. Vision and Strategic Objectives\n\n' + '\n'.join(
        table_lines) + '\n'


class StrategicObjectivesSanitizerTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_exists(self):
        self.assertTrue(hasattr(
            _APP, '_sanitize_strategic_objectives_table_rows'),
            'PR-CY24 sanitizer must be defined on app module')
        self.assertTrue(hasattr(
            _APP, '_strategic_objectives_schema_diag'),
            'PR-CY24 diagnostic helper must be defined on app module')

    @_skip_if_no_app
    def test_drops_fully_empty_rows(self):
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | Establish governance | 90% coverage | Closes critical gap | 12 months |',
            '|   |   |   |   |   |',
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        diag = _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertGreaterEqual(diag['removed_empty_rows'], 1)
        self.assertNotIn('|   |   |   |   |   |', sections['vision'])
        self.assertIn('Establish governance', sections['vision'])
        self.assertIn('Deploy SIEM', sections['vision'])

    @_skip_if_no_app
    def test_drops_dash_only_meaningful_rows(self):
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | Establish governance | 90% coverage | Closes gap | 12 months |',
            '| 2 | — | — | — | — |',
            '| 3 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        diag = _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertGreaterEqual(diag['removed_dash_only_rows'], 1)
        self.assertNotIn('| 2 | — | — | — | — |', sections['vision'])

    @_skip_if_no_app
    def test_merges_orphan_timeframe_continuation(self):
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | Establish governance | 90% coverage | Closes critical gap | — |',
            '| — | — | — | — | 12 months |',
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        diag = _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertGreaterEqual(diag['merged_continuation_rows'], 1)
        # The merged-into-prev row now carries the timeframe.
        self.assertIn('| 12 months |', sections['vision'])
        # The orphan one-cell row must not survive.
        self.assertNotIn('| — | — | — | — | 12 months |',
                         sections['vision'])

    @_skip_if_no_app
    def test_preserves_prcy18_specialized_objective_row(self):
        # Row carries the PR-CY18 CISO / governance-committee vocabulary.
        vision = _wrap_vision([
            _HEADER_EN,
            ('| 1 | Establish cybersecurity function led by CISO with a '
             'governance committee and clear reporting line | — | — | — |'),
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertIn('CISO', sections['vision'])
        self.assertIn('governance committee', sections['vision'])

    @_skip_if_no_app
    def test_preserves_prcy20_framework_compliance_row(self):
        # Row carries the PR-CY20 framework-compliance vocabulary.
        vision = _wrap_vision([
            _HEADER_EN,
            ('| 1 | Achieve framework compliance with ECC '
             'controls | — | — | — |'),
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertIn('ECC', sections['vision'])
        self.assertIn('framework compliance', sections['vision'])

    @_skip_if_no_app
    def test_partial_real_row_surfaces_incomplete_signal(self):
        vision = _wrap_vision([
            _HEADER_EN,
            # Real objective text but rationale + timeframe empty.
            '| 1 | Build SOC capability | 24x7 coverage | — | — |',
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
        ])
        sections = {'vision': vision}
        diag = _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        self.assertTrue(diag['incomplete_rows'],
                        'partial-but-real row must surface as incomplete')
        # Row must NOT be silently dropped.
        self.assertIn('Build SOC capability', sections['vision'])

    @_skip_if_no_app
    def test_resequences_after_row_removal(self):
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | A | a | ar | 12 months |',
            '| 2 | — | — | — | — |',
            '| 3 | B | b | br | 18 months |',
            '| 4 | C | c | cr | 24 months |',
        ])
        sections = {'vision': vision}
        _APP._sanitize_strategic_objectives_table_rows(
            sections, 'en', 'cyber')
        out = sections['vision']
        self.assertNotIn('| 2 | — | — | — | — |', out)
        # After the dash-only row removal, the survivors must be re-sequenced
        # 1, 2, 3 (was 1, 3, 4 originally).
        self.assertIn('| 1 | A ', out)
        self.assertIn('| 2 | B ', out)
        self.assertIn('| 3 | C ', out)

    @_skip_if_no_app
    def test_audit_emits_incomplete_row_flag(self):
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | Build SOC capability | 24x7 coverage | — | — |',
            '| 2 | Deploy SIEM | MTTD < 24h | Improves detection | 18 months |',
            '| 3 | Establish governance | 90% coverage | Closes gap | 12 months |',
        ])
        sections = {
            'vision': vision,
            'kpis': '',
            'confidence': '',
            'gaps': '',
            'pillars': '',
        }
        _quality_ok, issues = _APP._audit_doc_quality(
            sections, 'technical', 'en', generation_mode='drafting')
        self.assertIn('strategic_objectives_incomplete_row', issues)

    @_skip_if_no_app
    def test_audit_passes_after_sanitizing_blank_rows(self):
        # Three valid objective rows interleaved with empty / dash-only rows.
        vision = _wrap_vision([
            _HEADER_EN,
            '| 1 | A obj | a metric | a rationale | 12 months |',
            '|   |   |   |   |   |',
            '| 2 | B obj | b metric | b rationale | 18 months |',
            '| 3 | — | — | — | — |',
            '| 3 | C obj | c metric | c rationale | 24 months |',
        ])
        sections = {
            'vision': vision,
            'kpis': '',
            'confidence': '',
            'gaps': '',
            'pillars': '',
        }
        _quality_ok, issues = _APP._audit_doc_quality(
            sections, 'technical', 'en', generation_mode='drafting')
        self.assertNotIn('strategic_objectives_row_schema_violation', issues)
        self.assertNotIn('strategic_objectives_rows_insufficient', issues)
        self.assertNotIn('strategic_objectives_incomplete_row', issues)

    @_skip_if_no_app
    def test_arabic_table_sanitization(self):
        vision = '## 1. الرؤية والأهداف الاستراتيجية\n\n' + '\n'.join([
            _HEADER_AR,
            '| 1 | إرساء برنامج الحوكمة | 90% تغطية | يغلق الفجوة | 12 شهرا |',
            '|   |   |   |   |   |',
            '| 2 | نشر SIEM | MTTD أقل من 24 ساعة | يحسن الكشف | 18 شهرا |',
        ]) + '\n'
        sections = {'vision': vision}
        diag = _APP._sanitize_strategic_objectives_table_rows(
            sections, 'ar', 'cyber')
        self.assertGreaterEqual(diag['removed_empty_rows'], 1)
        self.assertIn('إرساء برنامج الحوكمة', sections['vision'])
        self.assertIn('نشر SIEM', sections['vision'])

    @_skip_if_no_app
    def test_diag_helper_is_safe(self):
        # Pure logging — must never raise even with None / bad inputs.
        _APP._strategic_objectives_schema_diag(
            None, None, None, None, None, None, None, None, None)


if __name__ == '__main__':
    unittest.main()
