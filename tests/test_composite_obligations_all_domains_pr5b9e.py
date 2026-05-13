"""PR-5B.9E — Unified composite obligation coordinator.

Pins ``_compute_applicable_strategy_obligations`` for every supported
domain and the (frameworks, org_structure_is_none, generation_mode)
combinations that drive the runtime obligations.

Run:
    python -m pytest tests/test_composite_obligations_all_domains_pr5b9e.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_composite_obl_pr5b9e_')
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


class CompositeObligationsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_coordinator_helper_exists(self):
        self.assertTrue(
            hasattr(_APP, '_compute_applicable_strategy_obligations'),
            '_compute_applicable_strategy_obligations helper missing',
        )

    @_skip_if_no_app
    def test_consulting_min_objective_rows_is_six(self):
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertEqual(obl['min_objective_rows'], 6)

    @_skip_if_no_app
    def test_drafting_min_objective_rows_is_base(self):
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=False,
            generation_mode='drafting',
            lang='ar',
        )
        self.assertEqual(
            obl['min_objective_rows'], _APP._RICHNESS_MIN_SO_ROWS,
        )

    @_skip_if_no_app
    def test_consulting_min_gap_rows_is_five(self):
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Cyber Security',
            selected_frameworks=['ECC'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertEqual(obl['min_gap_rows'], 5)

    @_skip_if_no_app
    def test_org_structure_none_forces_min_gap_five(self):
        # Even in drafting mode, org_structure_is_none promotes the
        # gap floor to 5.
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Data Management',
            selected_frameworks=['NDMO'],
            org_structure_is_none=True,
            generation_mode='drafting',
            lang='ar',
        )
        self.assertEqual(obl['min_gap_rows'], 5)

    @_skip_if_no_app
    def test_specialized_function_flag_follows_org_structure(self):
        for domain, code in (
                ('Cyber Security', 'cyber'),
                ('Data Management', 'data'),
                ('Artificial Intelligence', 'ai'),
                ('Digital Transformation', 'dt'),
                ('Enterprise Risk Management', 'erm'),
        ):
            with self.subTest(domain=domain):
                obl_yes = _APP._compute_applicable_strategy_obligations(
                    domain=domain,
                    selected_frameworks=[],
                    org_structure_is_none=True,
                    generation_mode='consulting',
                    lang='ar',
                )
                obl_no = _APP._compute_applicable_strategy_obligations(
                    domain=domain,
                    selected_frameworks=[],
                    org_structure_is_none=False,
                    generation_mode='consulting',
                    lang='ar',
                )
                self.assertTrue(obl_yes['specialized_function_establishment'])
                self.assertFalse(obl_no['specialized_function_establishment'])
                self.assertEqual(
                    obl_yes['specialized_function_domain_code'], code,
                )

    @_skip_if_no_app
    def test_selected_framework_compliance_objectives_lists_resolved(self):
        # SAMA + ECC selected on a Cyber Security strategy must both
        # surface in the compliance-objectives obligation.
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Cyber Security',
            selected_frameworks=['SAMA', 'ECC'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        resolved = set(obl['selected_framework_compliance_objectives'])
        self.assertIn('SAMA', resolved)
        self.assertIn('ECC', resolved)

    @_skip_if_no_app
    def test_glossary_scope_lists_non_selected_registry(self):
        obl = _APP._compute_applicable_strategy_obligations(
            domain='Artificial Intelligence',
            selected_frameworks=['SDAIA'],
            org_structure_is_none=False,
            generation_mode='consulting',
            lang='ar',
        )
        scope = obl['glossary_scope']
        self.assertIn('SDAIA', scope['allowed_acronyms'])
        # NIST_AI_RMF is in the registry but NOT selected on this run —
        # the coordinator must surface it as such so the appendix can
        # drop it when content does not reference it.
        self.assertIn(
            'NIST_AI_RMF', scope['non_selected_registry_acronyms'],
        )

    @_skip_if_no_app
    def test_coordinator_is_side_effect_free(self):
        # Same inputs → same dict; never raises.
        a = _APP._compute_applicable_strategy_obligations(
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
        )
        b = _APP._compute_applicable_strategy_obligations(
            domain='Data Management',
            selected_frameworks=['NDMO', 'PDPL'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertEqual(a, b)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
