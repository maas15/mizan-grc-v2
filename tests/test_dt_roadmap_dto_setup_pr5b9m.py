"""PR-5B.9M — Digital Transformation roadmap governance-setup
regression guard.

Production observation: DT now includes ``غياب مكتب التحول الرقمي`` in
gaps and generates successfully, but the roadmap could still omit the
explicit governance-setup activity that establishes the Digital
Transformation Office.

Required behaviour (already enforced by
``_compute_missing_governance_setup_in_roadmap`` for DT —
``_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['dt']``):

When ``org_structure_is_none=True`` and ``domain=dt`` the roadmap MUST
include at least one of:
  * إنشاء مكتب التحول الرقمي
  * تعيين Chief Digital Officer
  * تشكيل لجنة التحول الرقمي
  * اعتماد نموذج تشغيل التحول الرقمي

This file is a regression guard — it does NOT block the PR if the
validator emits ``missing_governance_setup`` (the helper is the
contract, and is exercised by ``test_roadmap_governance_setup_pr5b9j``);
this file only locks the DT-specific accepted-concept families so a
future widening of the registry cannot accidentally drop the DT
``establish_dept`` family.

Run:
    python -m pytest tests/test_dt_roadmap_dto_setup_pr5b9m.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_dt_pr5b9m_')
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
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


class DtRoadmapGovernanceSetupRegressionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_dt_registry_contains_dto_concepts(self):
        """DT specialized-function registry must include the canonical
        accepted concepts the spec lists."""
        concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS.get('dt')
        self.assertIsNotNone(concepts, 'DT must be in the registry')
        all_tokens = []
        for fam_tokens in concepts.values():
            all_tokens.extend(t.lower() for t in fam_tokens)
        # Canonical accepted-concept families:
        self.assertTrue(
            any('مكتب التحول الرقمي' in t for t in all_tokens),
            'Expected "مكتب التحول الرقمي" in DT registry')
        self.assertTrue(
            any('chief digital officer' in t for t in all_tokens),
            'Expected "Chief Digital Officer" in DT registry')

    @_skip_if_no_app
    def test_dt_bare_roadmap_signals_missing_when_org_none(self):
        # Bare roadmap text + org_structure_is_none=True must signal
        # missing governance setup. The helper returns family ids that
        # are missing.
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            '## 5. خارطة الطريق\n\nنص عام دون نشاط محدد.\n',
            domain='dt',
            org_structure_is_none=True,
            lang='ar',
        )
        self.assertTrue(
            len(missing) > 0,
            f'expected non-empty missing list for bare DT roadmap, '
            f'got {missing!r}')

    @_skip_if_no_app
    def test_dt_roadmap_with_dto_setup_passes(self):
        # Roadmap with explicit "إنشاء مكتب التحول الرقمي" and
        # Chief Digital Officer must clear the helper.
        roadmap = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 1 | إنشاء مكتب التحول الرقمي وتعيين Chief Digital '
            'Officer وتشكيل لجنة التحول الرقمي | Q1 | 6 أشهر |\n'
        )
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            roadmap, domain='dt',
            org_structure_is_none=True, lang='ar',
        )
        self.assertEqual(
            missing, [],
            f'expected empty missing list for DT roadmap with DTO '
            f'setup, got {missing!r}')

    @_skip_if_no_app
    def test_dt_roadmap_with_cdo_appointment_passes(self):
        roadmap = (
            '## 5. خارطة الطريق\n\n'
            '| 1 | تعيين Chief Digital Officer (CDO) | Q1 | 6 أشهر |\n'
        )
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            roadmap, domain='dt',
            org_structure_is_none=True, lang='ar',
        )
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_dt_roadmap_org_structure_not_none_returns_empty(self):
        # When org structure already exists, helper returns [] even
        # for bare roadmap (the obligation does not apply).
        missing = _APP._compute_missing_governance_setup_in_roadmap(
            '## 5. خارطة الطريق\n\n', domain='dt',
            org_structure_is_none=False, lang='ar',
        )
        self.assertEqual(missing, [])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
