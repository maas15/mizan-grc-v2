"""PR-CY39 — Schema-first Strategic Objectives composer.

After PR-CY35 the late-stage sanitizer removes empty / dash-only /
separator artifact rows from the Strategic Objectives table, but if
the upstream model produced a table that is structurally short (only
3 rows when Cyber technical strategy mandates ≥ 5) or missing one of
the two mandatory rows (specialized cyber + ECC/DCC compliance) the
final blocking gate still fails with::

    final_quality_gate_failed:
    strategic_objectives_row_schema_validation

PR-CY39 introduces ``_prcy39_compose_strategic_objectives_table`` —
a schema-first composer that runs inside
``_cyber_final_export_contract`` after every prior mutation, parses
existing objective rows into specs, preserves the two mandatory
rows, composes missing top-up rows from context (SOC / DLP /
awareness) and re-renders a canonical 5-column table.
"""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_strategic_objectives_schema_first_compose_prcy39_')
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


# A noisy Arabic vision containing: a valid CISO specialized row,
# a valid NCA ECC compliance row, a valid NCA DCC compliance row,
# and several artifact rows (empty / dash-only / pipe-only).
_VISION_NOISY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'رؤية الأمن السيبراني للمؤسسة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
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
    '\n'
)

# An Arabic vision that ONLY contains noise + the mandatory rows
# stripped — composer must reconstruct CISO + ECC/DCC compliance.
_VISION_MISSING_MANDATORY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'رؤية الأمن السيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تعزيز برنامج التوعية الأمنية |'
    ' خفض معدل النقر على رسائل التصيد إلى 5% |'
    ' بناء ثقافة الأمن السيبراني | 12 شهر |\n'
    '\n'
)

_ROADMAP_AR = (
    '## خارطة الطريق\n\n'
    '### المرحلة 1 — التأسيس (أشهر 1–6)\n\n'
    '| الشهر | المبادرة / النشاط | المالك |'
    ' المخرجات المتوقعة | الإطار المرتبط |\n'
    '|---|---|---|---|---|\n'
    '| الأشهر 1–6 | تعيين CISO | الإدارة التنفيذية |'
    ' دور CISO فعّال | NCA ECC |\n'
)

_SUMMARY_AR = (
    '## الملخص التنفيذي\n\n'
    'استراتيجية الأمن السيبراني تُنفّذ خلال 18 شهرًا.\n'
)


class StrategicObjectivesSchemaFirstComposeTests(unittest.TestCase):

    @_skip_if_no_app
    def test_helper_present(self):
        self.assertTrue(hasattr(
            _APP, '_prcy39_compose_strategic_objectives_table'),
            'PR-CY39 composer must be defined')

    @_skip_if_no_app
    def test_compose_produces_canonical_table_with_minimum_rows(self):
        """The composer must produce ≥ 5 rows for Cyber technical
        strategy, preserve CISO + NCA ECC/DCC, and run without
        emitting a strategic-objectives row-schema blocker."""
        markdown = (
            _SUMMARY_AR + '\n' + _VISION_NOISY_AR + '\n' + _ROADMAP_AR
            + '\n## مؤشرات الأداء الرئيسية\n\n(placeholder)\n')
        result = _APP._cyber_final_export_contract(
            markdown,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            request_context={'route_name': 'preview'},
        )

        blockers = result.get('blocking_errors') or []
        so_blockers = [
            b for b in blockers
            if 'strategic_objectives_row_schema' in (b or '')
            or 'strategic_objectives_rows_insufficient' in (b or '')
            or 'strategic_objectives_schema_compose_failed' in (b or '')
        ]
        self.assertEqual(
            so_blockers, [],
            msg=('PR-CY39 — composer must eliminate strategic '
                 f'objectives row-schema blockers. all={blockers!r}'))

        final_md = result.get('final_markdown') or ''
        # Preserved mandatory rows
        self.assertIn('CISO', final_md)
        self.assertIn('NCA ECC', final_md)
        self.assertIn('NCA DCC', final_md)
        # No artifact rows in the final markdown
        self.assertNotIn('|  |  |  |  |  |', final_md)
        self.assertNotIn('| - | - | - | - | - |', final_md)

    @_skip_if_no_app
    def test_repair_actions_records_prcy39_compose(self):
        markdown = (
            _SUMMARY_AR + '\n' + _VISION_NOISY_AR + '\n' + _ROADMAP_AR
            + '\n## مؤشرات الأداء الرئيسية\n\n(placeholder)\n')
        result = _APP._cyber_final_export_contract(
            markdown,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            request_context={'route_name': 'preview'},
        )
        actions = result.get('repair_actions') or []
        prcy39_actions = [
            a for a in actions
            if isinstance(a, str)
            and a.startswith(
                'prcy39:strategic_objectives_schema_first_compose:')
        ]
        # When the upstream rows are short of the 5-row minimum the
        # composer must record at least one schema-first compose
        # action (composed top-up rows).
        self.assertTrue(
            prcy39_actions,
            msg=('PR-CY39 — composer must record at least one '
                 'schema-first compose action when topping up rows. '
                 f'actions={actions!r}'))

    @_skip_if_no_app
    def test_compose_reconstructs_missing_mandatory_rows(self):
        """When the input vision is missing CISO + NCA ECC/DCC rows
        the composer must reconstruct them from defaults."""
        markdown = (
            _SUMMARY_AR + '\n' + _VISION_MISSING_MANDATORY_AR + '\n'
            + _ROADMAP_AR
            + '\n## مؤشرات الأداء الرئيسية\n\n(placeholder)\n')
        result = _APP._cyber_final_export_contract(
            markdown,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            request_context={'route_name': 'preview'},
        )

        final_md = result.get('final_markdown') or ''
        self.assertIn('CISO', final_md)
        # Default framework-compliance row references ECC + DCC.
        self.assertIn('NCA ECC', final_md)
        self.assertIn('NCA DCC', final_md)

        blockers = result.get('blocking_errors') or []
        so_blockers = [
            b for b in blockers
            if 'strategic_objectives_row_schema' in (b or '')
            or 'strategic_objectives_rows_insufficient' in (b or '')
            or 'strategic_objectives_schema_compose_failed' in (b or '')
        ]
        self.assertEqual(
            so_blockers, [],
            msg=('PR-CY39 — composer must reconstruct mandatory rows '
                 'and pass the final gate. '
                 f'all blockers={blockers!r}'))

    @_skip_if_no_app
    def test_arabic_concatenation_fixes_applied(self):
        """The PR-CY39 normalization map must repair known Arabic
        concatenation issues such as ``امتثاللا`` → ``امتثال لا``."""
        sample = (
            '## 1. الرؤية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
            ' المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تحقيق الامتثاللضوابط NCA ECC |'
            ' نسبة امتثاللا تقلعن 85% |'
            ' مواءمة برنامج الأمن السيبرانيمع التنظيمية | 12 شهر |\n'
        )
        info = _APP._prcy39_compose_strategic_objectives_table(
            sample,
            {'domain': 'cyber'},
            {'route_name': 'preview'},
            ['nca_ecc', 'nca_dcc'],
            'ar',
            'cyber',
        )
        new_vision = (info or {}).get('new_vision') or ''
        self.assertIn('امتثال لا', new_vision)
        self.assertIn('تقل عن', new_vision)
        self.assertIn('السيبراني', new_vision)
        # Should not contain the broken concatenations any more.
        self.assertNotIn('امتثاللا', new_vision)
        self.assertNotIn('تقلعن', new_vision)
        self.assertNotIn('السيبرانيمع', new_vision)

    @_skip_if_no_app
    def test_final_contract_invariant_fields_present(self):
        """The contract diagnostic must surface the four PR-CY39
        invariant fields used by the final blocking gate."""
        markdown = (
            _SUMMARY_AR + '\n' + _VISION_NOISY_AR + '\n' + _ROADMAP_AR
            + '\n## مؤشرات الأداء الرئيسية\n\n(placeholder)\n')
        result = _APP._cyber_final_export_contract(
            markdown,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='preview',
            request_context={'route_name': 'preview'},
        )
        diag = result.get('diag') or {}
        for k in (
            'strategic_objectives_valid',
            'strategic_objectives_rows',
            'strategic_objectives_schema',
            'strategic_objectives_mandatory_rows_present',
        ):
            self.assertIn(
                k, diag,
                msg=f'PR-CY39 invariant {k!r} missing from diag')
        self.assertTrue(diag['strategic_objectives_valid'])
        self.assertGreaterEqual(int(diag['strategic_objectives_rows']), 5)
        self.assertEqual(
            diag['strategic_objectives_schema'],
            'prcy39_canonical_5col')
        self.assertTrue(
            diag['strategic_objectives_mandatory_rows_present'])


if __name__ == '__main__':
    unittest.main()
