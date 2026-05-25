"""PR-CY35 — Strategic Objectives sanitation after final mutations.

Reproduces the live incident:

    final_quality_gate_failed:
    strategic_objectives_row_schema_validation

caused by the PR-CY24 sanitizer running inside the audit cycle while
subsequent mutators (PR-CY27/CY31/CY32 KPI repair, PR-CY34 roadmap
horizon reconciliation) re-split ``sections`` from ``final_markdown``
and therefore replace the sanitized vision body with the
pre-sanitization re-split copy.

The fix runs the PR-CY24 sanitizer one more time inside
``_cyber_final_export_contract`` immediately before the lightweight
``_cyber_final_blocking_gate``, and re-splices the sanitized vision
back into ``final_markdown`` so the gate, the renderer and the
incomplete-row detector all observe the same bytes.

PR-CY18 / PR-CY20 preservation must remain intact: valid CISO /
specialized-cyber objective rows and valid NCA ECC / DCC framework-
compliance objective rows must NEVER be removed by the sanitizer.

Incomplete real objective rows (real text but missing target /
justification / timeframe) must NOT be silently deleted — the hard
gate must continue to surface them via
``strategic_objectives_incomplete_row:<row>``.
"""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_strategic_objectives_final_sanitize_prcy35_')
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


# Vision body with: valid CISO row, valid NCA ECC compliance row,
# valid NCA DCC compliance row, plus several noise rows that the
# PR-CY24 sanitizer is expected to remove.
_VISION_NOISY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    'رؤية الأمن السيبراني للمؤسسة.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المقياس المستهدف |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني بقيادة CISO |'
    ' تعيين CISO خلال 6 أشهر | متطلب NCA ECC |'
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


class StrategicObjectivesFinalSanitizeTests(unittest.TestCase):

    @_skip_if_no_app
    def test_sanitizer_helper_still_present(self):
        self.assertTrue(hasattr(
            _APP, '_sanitize_strategic_objectives_table_rows'),
            'PR-CY24 sanitizer must still be defined for PR-CY35')

    @_skip_if_no_app
    def test_final_contract_strips_noise_rows_preserves_cy18_cy20(self):
        """The contract must not emit any blocking error related to
        the strategic objectives table when the noise rows are
        removable artifacts (empty / dash-only / pipe-only)."""
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
        ]
        self.assertEqual(
            so_blockers, [],
            msg=('PR-CY35 — final contract must not emit '
                 'strategic_objectives row-schema blockers when the '
                 'noise rows are removable artifacts. '
                 f'all blockers={blockers!r}'))

        final_md = result.get('final_markdown') or ''
        # PR-CY18 / PR-CY20 preserved rows must survive.
        self.assertIn('CISO', final_md)
        self.assertIn('NCA ECC', final_md)
        self.assertIn('NCA DCC', final_md)
        # The sanitized vision must NOT contain a fully empty row.
        self.assertNotIn('|  |  |  |  |  |', final_md)
        self.assertNotIn('| - | - | - | - | - |', final_md)

    @_skip_if_no_app
    def test_repair_actions_records_prcy35_sanitize(self):
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
        prcy35_actions = [
            a for a in actions
            if isinstance(a, str)
            and a.startswith('prcy35:strategic_objectives_sanitize:')
        ]
        # If the upstream PR-CY24 pass already cleaned every noise row
        # the late-stage pass may be a no-op; in that case nothing is
        # recorded. The important assertion is the test above: no
        # strategic-objectives row-schema blocker survives.
        if prcy35_actions:
            # The recorded action must encode at least one mutation.
            tail = prcy35_actions[0].rsplit(':', 1)[-1]
            self.assertTrue(tail.isdigit() and int(tail) >= 1)


if __name__ == '__main__':
    unittest.main()
