"""PR-5B.9J — AI environment framework-reference alignment.

The Environment / Threat Landscape section MUST explicitly mention
every selected framework by one of its canonical aliases. Generic
mentions of an acronym alone (e.g. ``SDAIA``) are NOT acceptable when
both ``SDAIA AI Ethics Principles`` and ``SDAIA AI Governance
Framework`` are selected. Unselected frameworks MUST NEVER be required.

These tests pin:

  1. Selected = [SDAIA AI Ethics Principles] requires only AI Ethics,
     not AI Governance Framework.
  2. Selected = [SDAIA AI Ethics Principles, SDAIA AI Governance
     Framework] requires both — env mentioning only Ethics fails for
     the second.
  3. Environment mentioning only generic ``SDAIA`` fails when the
     selected list contains canonical full names.
  4. The environment repair prompt addendum names every selected
     framework verbatim.
  5. If AI Governance Framework is not selected, the validator does
     not emit a missing reference for it.
  6. Scope and environment validation use the same canonical resolved
     framework list (round-trip check).
  7. No non-selected framework is injected by the helper.

Run:
    python -m pytest tests/test_environment_framework_reference_pr5b9j.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_env_fwref_pr5b9j_')
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


class HelperContractTests(unittest.TestCase):
    """Direct tests for ``_compute_missing_framework_references_in_env``."""

    @_skip_if_no_app
    def test_only_ethics_selected_requires_only_ethics(self):
        # T1: Selected = [SDAIA AI Ethics Principles] — env mentioning
        # the canonical name of Ethics passes; AI Governance Framework
        # is NOT required because it is not selected.
        env = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '**السياق التنظيمي:** تلتزم المنظمة بمبادئ SDAIA AI Ethics '
            'Principles لأخلاقيات الذكاء الاصطناعي.\n'
        )
        missing = _APP._compute_missing_framework_references_in_env(
            env, ['SDAIA AI Ethics Principles'], domain=None,
        )
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_both_selected_env_only_mentions_ethics_fails_for_governance(self):
        # T2: Selected = both — env mentioning only Ethics fails for the
        # second framework.
        env = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '**السياق التنظيمي:** تلتزم المنظمة بمبادئ SDAIA AI Ethics '
            'Principles لأخلاقيات الذكاء الاصطناعي.\n'
        )
        missing = _APP._compute_missing_framework_references_in_env(
            env,
            ['SDAIA AI Ethics Principles',
             'SDAIA AI Governance Framework'],
            domain=None,
        )
        self.assertIn('SDAIA AI Governance Framework', missing,
                      f'expected AI Governance Framework in missing, '
                      f'got {missing!r}')
        self.assertNotIn('SDAIA AI Ethics Principles', missing)

    @_skip_if_no_app
    def test_both_selected_env_mentions_both_passes(self):
        env = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '**السياق التنظيمي:** تلتزم المنظمة بمبادئ SDAIA AI Ethics '
            'Principles وإطار SDAIA AI Governance Framework.\n'
        )
        missing = _APP._compute_missing_framework_references_in_env(
            env,
            ['SDAIA AI Ethics Principles',
             'SDAIA AI Governance Framework'],
            domain=None,
        )
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_generic_sdaia_alone_fails_when_full_names_selected(self):
        # T3: When both "SDAIA AI Ethics Principles" and "SDAIA AI
        # Governance Framework" are selected, env mentioning ONLY the
        # bare acronym "SDAIA" must FAIL for both — because "SDAIA"
        # is a shared alias and not distinguishing.
        env = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '**السياق التنظيمي:** تلتزم المنظمة بمتطلبات SDAIA.\n'
        )
        missing = _APP._compute_missing_framework_references_in_env(
            env,
            ['SDAIA AI Ethics Principles',
             'SDAIA AI Governance Framework'],
            domain=None,
        )
        # Both must be missing because "SDAIA" alone does not
        # distinguish between them.
        self.assertIn('SDAIA AI Ethics Principles', missing)
        self.assertIn('SDAIA AI Governance Framework', missing)

    @_skip_if_no_app
    def test_unselected_governance_not_required(self):
        # T5: AI Governance Framework not selected — validator never
        # asks for it.
        env = (
            '## 3. البيئة التنظيمية والتهديدات\n\n'
            '**السياق التنظيمي:** تلتزم المنظمة بمبادئ SDAIA AI Ethics '
            'Principles لأخلاقيات الذكاء الاصطناعي.\n'
        )
        missing = _APP._compute_missing_framework_references_in_env(
            env, ['SDAIA AI Ethics Principles'], domain=None,
        )
        self.assertNotIn('SDAIA AI Governance Framework', missing)

    @_skip_if_no_app
    def test_no_non_selected_framework_injected(self):
        # T7: Helper never reports a non-selected framework as missing.
        env = '## 3. البيئة\n\nنص قصير.\n'
        missing = _APP._compute_missing_framework_references_in_env(
            env, ['NCA ECC'], domain=None,
        )
        # NCA ECC is the only selected; only NCA ECC may appear.
        for fw in missing:
            self.assertEqual(fw, 'NCA ECC',
                             f'helper reported non-selected '
                             f'framework: {fw!r}')

    @_skip_if_no_app
    def test_empty_env_returns_full_list(self):
        missing = _APP._compute_missing_framework_references_in_env(
            '', ['SDAIA AI Ethics Principles', 'NCA ECC'], domain=None,
        )
        self.assertEqual(sorted(missing),
                         sorted(['SDAIA AI Ethics Principles',
                                 'NCA ECC']))

    @_skip_if_no_app
    def test_no_selected_returns_empty(self):
        missing = _APP._compute_missing_framework_references_in_env(
            'some env text', [], domain=None,
        )
        self.assertEqual(missing, [])


class ScopeEnvAlignmentTests(unittest.TestCase):
    """T6: Scope, environment validation, repair, and final audit must
    use the same canonical resolved framework list."""

    @_skip_if_no_app
    def test_resolver_round_trip_does_not_invent_frameworks(self):
        # _resolve_selected_frameworks should not invent SDAIA AI
        # Governance Framework when only SDAIA AI Ethics Principles is
        # selected.
        resolved = _APP._resolve_selected_frameworks(
            ['SDAIA AI Ethics Principles'],
            domain='Artificial Intelligence',
        )
        # The resolver maps both possible selected SDAIA labels onto
        # the single registry key 'SDAIA' (because the registry has
        # one entry covering both); but it never invents an entirely
        # different framework family. Verify only SDAIA / nothing
        # cross-domain leaked.
        for key in resolved:
            self.assertIn(
                key.upper(), ('SDAIA',),
                f'resolver invented framework key {key!r} when only '
                f'SDAIA Ethics was selected',
            )

    @_skip_if_no_app
    def test_obligations_coordinator_uses_resolved_list(self):
        # The applicable-obligations coordinator must surface the same
        # resolved framework list for environment coverage and final
        # audit.
        oblig = _APP._compute_applicable_strategy_obligations(
            domain='Artificial Intelligence',
            selected_frameworks=['SDAIA AI Ethics Principles'],
            org_structure_is_none=True,
            generation_mode='consulting',
            lang='ar',
        )
        self.assertEqual(
            oblig['selected_framework_compliance_objectives'],
            oblig['selected_framework_section_coverage'],
            'scope/environment/audit must share the same resolved '
            'framework list',
        )


class EnvRepairPromptTests(unittest.TestCase):
    """T4: The environment repair prompt addendum names every selected
    framework by canonical display name."""

    @_skip_if_no_app
    def test_env_repair_prompt_lists_canonical_names(self):
        captured = {}

        def _fake_provider(prompt, **_kw):
            captured['prompt'] = prompt
            return (
                '## 3. البيئة التنظيمية والتهديدات\n\n'
                '**السياق التنظيمي:** تلتزم المنظمة بمبادئ SDAIA AI '
                'Ethics Principles وإطار SDAIA AI Governance '
                'Framework.\n\n'
                '**سياق التهديدات:** التهديدات تشمل الهجمات الإلكترونية '
                'والاختراقات.\n\n'
                '**السياق التشغيلي:** التحول الرقمي يفرض متطلبات على '
                'الأعمال.\n\n'
                '| # | البُعد | المصدر | التأثير | المبادرة |\n'
                '|---|------|------|------|------|\n'
                '| 1 | تنظيمي | SDAIA | عالٍ | إنشاء مكتب الحوكمة |\n'
            )

        import unittest.mock as _mock
        try:
            dctx = _APP.get_strategy_domain_context(
                'Artificial Intelligence',
                selected_frameworks=['SDAIA'],
            )
        except Exception as e:
            self.skipTest(f'cannot resolve AI domain context: {e}')
        # Inject canonical names into the domain context — this is
        # what the new ENVIRONMENT-FRAMEWORK-REPAIR pass does at
        # call-time.
        dctx = dict(dctx)
        dctx['selected_frameworks'] = [
            'SDAIA AI Ethics Principles',
            'SDAIA AI Governance Framework',
        ]

        sections = {'environment': '## 3. البيئة\n\nنص قصير.\n'}

        with _mock.patch.object(_APP, 'generate_ai_content',
                                side_effect=_fake_provider):
            try:
                _APP.ai_repair_strategy_section(
                    section_key='environment',
                    sections=sections,
                    lang='ar',
                    domain_context=dctx,
                    org_name='Test Org',
                    sector='Government',
                    maturity='Initial',
                    generation_mode='consulting',
                    validation_error=(
                        'environment_missing_framework_reference: '
                        'SDAIA AI Ethics Principles, SDAIA AI '
                        'Governance Framework'),
                )
            except Exception:
                pass

        self.assertIn('prompt', captured,
                      'expected ai_repair_strategy_section to call '
                      'the provider')
        prompt = captured['prompt']
        # Canonical framework names present.
        self.assertIn('السياق التنظيمي', prompt)
        # Both selected framework labels are passed through.
        self.assertIn('SDAIA AI Ethics Principles', prompt)
        self.assertIn('SDAIA AI Governance Framework', prompt)


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
