"""PR-CY34 — Roadmap horizon reconciliation.

Covers PR-CY34 spec section C:

  * ``_prcy34_reconcile_roadmap_horizon`` extends the roadmap to match
    the summary horizon when ``summary_horizon > roadmap_coverage`` and
    never reduces the summary horizon nor deletes valid roadmap rows.
  * ``_cyber_final_export_contract`` no longer emits
    ``final_quality_gate_failed:roadmap_horizon_mismatch:summary_18:
    roadmap_6`` when the summary horizon is 18 and the input roadmap
    only covers 6 months — the reconciliation block lands first.
"""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_roadmap_horizon_reconcile_prcy34_')
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


# A roadmap whose phase tables only cover months 1–6 (Phase 1: 1–2,
# Phase 2: 3–4, Phase 3: 5–6) — the live incident reproduction.
_ROADMAP_AR_6MO = (
    '## خارطة الطريق\n\n'
    '### المرحلة 1 — التأسيس (أشهر 1–2)\n\n'
    '| الشهر | المبادرة / النشاط | المالك | المخرجات المتوقعة |'
    ' الإطار المرتبط |\n'
    '|---|---|---|---|---|\n'
    '| الأشهر 1–2 | تعيين CISO | الإدارة التنفيذية |'
    ' دور CISO فعّال | NCA ECC |\n'
    '\n'
    '### المرحلة 2 — التوسع (أشهر 3–4)\n\n'
    '| الشهر | المبادرة / النشاط | المالك | المخرجات المتوقعة |'
    ' الإطار المرتبط |\n'
    '|---|---|---|---|---|\n'
    '| الأشهر 3–4 | تشغيل SOC | مدير SOC |'
    ' لوحات مراقبة فعّالة | NCA ECC |\n'
    '\n'
    '### المرحلة 3 — التحسين (أشهر 5–6)\n\n'
    '| الشهر | المبادرة / النشاط | المالك | المخرجات المتوقعة |'
    ' الإطار المرتبط |\n'
    '|---|---|---|---|---|\n'
    '| الأشهر 5–6 | تمارين Tabletop | CISO |'
    ' خطة تحسين | NCA ECC |\n'
)

_SUMMARY_AR_18MO = (
    '## الملخص التنفيذي\n\n'
    'استراتيجية الأمن السيبراني الوطنية تُنفّذ خلال 18 شهرًا.\n'
)


class RoadmapHorizonReconcileTests(unittest.TestCase):
    """PR-CY34 spec section C — reconciliation extends roadmap."""

    @_skip_if_no_app
    def test_extends_roadmap_when_summary_longer(self):
        sections = {
            'summary': _SUMMARY_AR_18MO,
            'roadmap': _ROADMAP_AR_6MO,
        }
        info = _APP._prcy34_reconcile_roadmap_horizon(
            None, sections, None, None,
            ['nca_ecc', 'nca_dcc'], 'ar')
        self.assertEqual(info['summary_horizon'], 18)
        self.assertEqual(info['roadmap_coverage_before'], 6)
        self.assertGreaterEqual(info['roadmap_coverage_after'], 18 - 2)
        self.assertTrue(info['reconciled'])
        # Existing roadmap rows must still be present.
        self.assertIn('تعيين CISO', sections['roadmap'])
        # Action taken must be a real repair, not a noop.
        self.assertNotIn('noop', info['action_taken'])

    @_skip_if_no_app
    def test_noop_when_within_tolerance(self):
        # Summary horizon 7 vs roadmap coverage 6 — within the 2-month
        # tolerance the blocking gate already grants.
        sections = {
            'summary': ('## الملخص التنفيذي\n\n'
                        'تُنفّذ خلال 7 شهر.\n'),
            'roadmap': _ROADMAP_AR_6MO,
        }
        info = _APP._prcy34_reconcile_roadmap_horizon(
            None, sections, None, None,
            ['nca_ecc'], 'ar')
        self.assertEqual(info['summary_horizon'], 7)
        self.assertIn('noop', info['action_taken'])

    @_skip_if_no_app
    def test_full_rebuild_when_roadmap_missing(self):
        sections = {
            'summary': _SUMMARY_AR_18MO,
            'roadmap': '',
        }
        info = _APP._prcy34_reconcile_roadmap_horizon(
            None, sections, None, None,
            ['nca_ecc'], 'ar')
        self.assertTrue(sections['roadmap'])
        self.assertGreaterEqual(info['roadmap_coverage_after'], 18 - 2)
        self.assertTrue(info['action_taken'].startswith('full_rebuild'))

    @_skip_if_no_app
    def test_never_reduces_summary_horizon(self):
        # The function must never write to summary/vision.
        sections = {
            'summary': _SUMMARY_AR_18MO,
            'roadmap': _ROADMAP_AR_6MO,
        }
        original_summary = sections['summary']
        _APP._prcy34_reconcile_roadmap_horizon(
            None, sections, None, None, ['nca_ecc'], 'ar')
        self.assertEqual(sections['summary'], original_summary)


class FinalExportContractReconcileTests(unittest.TestCase):
    """PR-CY34 — the final export contract no longer emits
    ``roadmap_horizon_mismatch`` when reconciliation can repair the
    gap."""

    @_skip_if_no_app
    def test_contract_does_not_block_on_horizon_mismatch(self):
        markdown = (
            _SUMMARY_AR_18MO + '\n' + _ROADMAP_AR_6MO + '\n'
            + '## مؤشرات الأداء الرئيسية\n\n(placeholder)\n')
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
        horizon_blockers = [
            b for b in blockers
            if 'roadmap_horizon_mismatch' in (b or '')
        ]
        self.assertEqual(horizon_blockers, [], msg=blockers)


if __name__ == '__main__':
    unittest.main()
