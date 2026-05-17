"""PR-5B.9S fix — convergence audit wiring + cross-domain regression.

Validates Part A of the PR-5B.9S enforcement fix: the
``converge_strategy_sections`` loop must thread ``selected_frameworks``
(from ``ctx['frameworks']``) and ``domain`` into every internal
``_final_strategy_audit`` call so the per-framework
``data_roadmap_balance_missing`` defect is visible during convergence
repair cycles — not only at the post-normalization save gate.

Also verifies that Cyber / AI / DT / ERM convergence audit behaviour
is unaffected (the new threading is purely additive).

Run:
    python -m pytest \
        tests/test_data_convergence_balance_wiring_pr5b9s_fix.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_conv_pr5b9s_fix_')
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


# Office-only Data Management roadmap — no balance topics.
_OFFICE_ONLY_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) | DMO |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | data governance committee |\n'
    '| 3 | اعتماد نموذج التشغيل وخطوط الرفع | operating model |\n'
)


class TestConvergenceSeesDataBalanceDefect(unittest.TestCase):
    """Part A — Convergence audit calls must thread selected_frameworks
    and domain so the Data Management roadmap-balance defect surfaces
    during repair cycles, not only at the post-normalization gate."""

    @_skip_if_no_app
    def test_initial_audit_records_balance_defect_during_convergence(self):
        # Use bare-minimum non-empty sections so other audit branches
        # are quiet enough that any synth failure (we expect them — no
        # AI keys here) is recorded but does not mask the visibility
        # of the balance defect in ``initial_defects``.
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _OFFICE_ONLY_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        log = _APP.converge_strategy_sections(
            sections, 'ar', 'Data Management', 'NDMO',
            ctx={'frameworks': ['NDMO', 'PDPL'],
                 'org_structure_is_none': False},
            doc_subtype=None, max_iter=1,
        )
        # The initial_defects list is captured BEFORE any repair pass
        # runs. Prior to the fix this list never contained a
        # ``data_roadmap_balance_missing:*`` entry because
        # selected_frameworks/domain defaulted to None inside the
        # convergence loop.
        initial_tags = [t for _s, t, _c, _m in log['initial_defects']]
        bal = [t for t in initial_tags
               if t.startswith('data_roadmap_balance_missing:')]
        self.assertEqual(
            len(bal), 1,
            f'expected balance defect in convergence initial_defects; '
            f'got tags={initial_tags}')
        # The tag must enumerate the uncovered families. We pick two
        # tokens that come from different frameworks (NDMO / PDPL) so
        # the assertion verifies both registry tuples were resolved.
        self.assertIn('data_quality', bal[0])
        self.assertIn('breach_notification', bal[0])

    @_skip_if_no_app
    def test_convergence_does_not_claim_success_with_balance_defect(self):
        # An empty roadmap cannot be repaired without AI (no API keys
        # in tests) — so the synth will mark synth_failed:roadmap or
        # the balance defect will remain. Either way, the loop must
        # NOT report ``converged=True``.
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _OFFICE_ONLY_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        log = _APP.converge_strategy_sections(
            sections, 'ar', 'Data Management', 'NDMO',
            ctx={'frameworks': ['NDMO', 'PDPL'],
                 'org_structure_is_none': False},
            doc_subtype=None, max_iter=1,
        )
        self.assertFalse(
            log['converged'],
            f'convergence wrongly claimed success while balance '
            f'defect remained; log={log}')


class TestCrossDomainConvergenceWiringUnchanged(unittest.TestCase):
    """Regression — Cyber / AI / DT / ERM convergence must not now emit
    a ``data_roadmap_balance_missing`` defect just because
    selected_frameworks is threaded through (the helper is guarded by
    domain == 'data' AND a registry framework match)."""

    @_skip_if_no_app
    def _initial_tags(self, domain, fws):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        log = _APP.converge_strategy_sections(
            sections, 'en', domain, fws[0] if fws else '',
            ctx={'frameworks': fws, 'org_structure_is_none': False},
            doc_subtype=None, max_iter=1,
        )
        return [t for _s, t, _c, _m in log['initial_defects']]

    @_skip_if_no_app
    def test_cyber_convergence_no_balance_defect(self):
        tags = self._initial_tags('Cyber Security', ['ECC'])
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:')
                for t in tags),
            f'Cyber convergence must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_ai_convergence_no_balance_defect(self):
        tags = self._initial_tags('Artificial Intelligence', ['SDAIA'])
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:')
                for t in tags),
            f'AI convergence must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_dt_convergence_no_balance_defect(self):
        tags = self._initial_tags('Digital Transformation', ['DGA'])
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:')
                for t in tags),
            f'DT convergence must not emit balance defect: {tags}')

    @_skip_if_no_app
    def test_erm_convergence_no_balance_defect(self):
        tags = self._initial_tags(
            'Enterprise Risk Management', ['ISO22301'])
        self.assertFalse(
            any(t.startswith('data_roadmap_balance_missing:')
                for t in tags),
            f'ERM convergence must not emit balance defect: {tags}')


class TestPDPLPersonalDataClassificationRegistered(unittest.TestCase):
    """PR-5B.9S fix — PDPL balance must require personal_data_
    classification as an explicit family (previously missing from
    ``_DATA_ROADMAP_BALANCE_BY_FRAMEWORK['PDPL']``)."""

    @_skip_if_no_app
    def test_pdpl_includes_personal_data_classification(self):
        fams = _APP._DATA_ROADMAP_BALANCE_BY_FRAMEWORK.get('PDPL') or ()
        self.assertIn(
            'personal_data_classification', fams,
            f'PDPL family tuple missing personal_data_classification: '
            f'{fams}')

    @_skip_if_no_app
    def test_classification_token_registered(self):
        tokens = _APP._DATA_ROADMAP_BALANCE_TOPICS.get(
            'personal_data_classification') or ()
        # Both Arabic and English forms must be recognised.
        joined = ' '.join(tokens).lower()
        self.assertIn('تصنيف البيانات الشخصية',
                      ' '.join(tokens))
        self.assertIn('personal data classification', joined)


if __name__ == '__main__':
    unittest.main()
