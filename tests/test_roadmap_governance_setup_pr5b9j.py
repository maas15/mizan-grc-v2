"""PR-5B.9J — Domain-specific governance-setup activity in the Roadmap.

When the diagnostic input flags ``org_structure_is_none=True`` the
**Roadmap** section MUST contain at least one explicit governance/setup
activity for the selected domain (e.g. DT →
``إنشاء مكتب التحول الرقمي``, AI →
``إنشاء مكتب حوكمة الذكاء الاصطناعي``). The diagnosis-grounding gate
downstream blocks the save with "roadmap does not include governance
setup" when this activity is absent — even after Vision and Gaps
already satisfy their respective specialized-function obligations.

These tests pin:

  1. ``_compute_missing_governance_setup_in_roadmap`` returns ``[]`` when
     ``org_structure_is_none=False`` regardless of roadmap content.
  2. The helper returns ``[]`` when the roadmap mentions the domain's
     specialized-function tokens (DT/AI/Data/Cyber/ERM examples).
  3. The helper returns the missing concept families when the roadmap
     does NOT mention any domain establishment tokens.
  4. The helper returns the full family list when the roadmap is empty.
  5. The roadmap repair prompt addendum (built by
     ``ai_repair_strategy_section`` for ``section_key='roadmap'`` +
     ``org_structure_is_none=True``) names the per-domain
     office/committee/chief-role tokens, requires Owner/Timeline/
     Deliverable, and forbids vague ``تعزيز الحوكمة`` phrasing.
  6. The roadmap repair prompt does NOT inject a deterministic roadmap
     row — it is a prompt addendum, not content.
  7. Cyber/Data/ERM existing governance-setup wording still passes.

Run:
    python -m pytest tests/test_roadmap_governance_setup_pr5b9j.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_roadmap_gov_pr5b9j_')
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


# Bare roadmap text — no specialized-function token for any domain.
_ROADMAP_BARE_AR = (
    '## 5. خارطة الطريق التنفيذية\n\n'
    '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تطوير القدرات | فريق العمليات | 6 أشهر | تقرير |\n'
    '| 2 | تحسين الأدوات | فريق التقنية | 9 أشهر | تقرير |\n'
    '| 3 | تدريب الفريق | الموارد البشرية | 12 شهراً | شهادات |\n'
    '| 4 | مراجعة الأداء | الإدارة | 18 شهراً | تقرير |\n'
)


# Per-domain "good" roadmap text — explicitly mentions the domain's
# specialized function so at least one concept family token matches.
_ROADMAP_GOOD_BY_DOMAIN = {
    'ai': _ROADMAP_BARE_AR + (
        '| 5 | إنشاء مكتب حوكمة الذكاء الاصطناعي وتشكيل لجنة الحوكمة '
        '| المدير التنفيذي | 6 أشهر | قرار إنشاء واعتماد ميثاق |\n'
    ),
    'dt': _ROADMAP_BARE_AR + (
        '| 5 | إنشاء مكتب التحول الرقمي وتعيين Chief Digital Officer '
        '| المدير التنفيذي | 6 أشهر | قرار إنشاء |\n'
    ),
    'data': _ROADMAP_BARE_AR + (
        '| 5 | إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة '
        'البيانات | المدير التنفيذي | 6 أشهر | قرار إنشاء |\n'
    ),
    'cyber': _ROADMAP_BARE_AR + (
        '| 5 | إنشاء إدارة الأمن السيبراني وتعيين CISO وتشكيل لجنة '
        'حوكمة الأمن السيبراني | المدير التنفيذي | 6 أشهر | قرار '
        'إنشاء |\n'
    ),
    'erm': _ROADMAP_BARE_AR + (
        '| 5 | إنشاء إدارة المخاطر المؤسسية وتعيين CRO وتشكيل لجنة '
        'المخاطر | المدير التنفيذي | 6 أشهر | قرار إنشاء |\n'
    ),
}


_DOMAINS = ('ai', 'dt', 'data', 'cyber', 'erm')


class HelperContractTests(unittest.TestCase):
    """Direct tests for ``_compute_missing_governance_setup_in_roadmap``."""

    @_skip_if_no_app
    def test_returns_empty_when_org_structure_is_none_false(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_setup_in_roadmap(
                        _ROADMAP_BARE_AR, d,
                        org_structure_is_none=False, lang='ar',
                    ))
                self.assertEqual(missing, [],
                                 f'expected [] for domain={d} when '
                                 f'org_structure_is_none=False')

    @_skip_if_no_app
    def test_returns_empty_for_unknown_domain_code(self):
        # Simulate an out-of-registry domain code by patching
        # normalize_domain to return ''.
        import unittest.mock as _mock
        with _mock.patch.object(_APP, 'normalize_domain',
                                return_value=''):
            missing = (
                _APP._compute_missing_governance_setup_in_roadmap(
                    _ROADMAP_BARE_AR, 'whatever',
                    org_structure_is_none=True, lang='ar',
                ))
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_dt_bare_roadmap_returns_missing(self):
        # T1: DT + org_structure_is_none roadmap WITHOUT
        # "إنشاء مكتب التحول الرقمي" should signal missing setup.
        missing = (
            _APP._compute_missing_governance_setup_in_roadmap(
                _ROADMAP_BARE_AR, 'Digital Transformation',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertTrue(
            len(missing) > 0,
            f'expected missing concept families for DT bare roadmap, '
            f'got {missing!r}')

    @_skip_if_no_app
    def test_dt_roadmap_with_dto_passes(self):
        # T2: DT roadmap WITH "إنشاء مكتب التحول الرقمي" passes.
        missing = (
            _APP._compute_missing_governance_setup_in_roadmap(
                _ROADMAP_GOOD_BY_DOMAIN['dt'], 'Digital Transformation',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_ai_bare_roadmap_returns_missing(self):
        # T3: AI + org_structure_is_none roadmap WITHOUT AI Governance
        # Office should signal missing setup.
        missing = (
            _APP._compute_missing_governance_setup_in_roadmap(
                _ROADMAP_BARE_AR, 'Artificial Intelligence',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertTrue(
            len(missing) > 0,
            f'expected missing concept families for AI bare roadmap, '
            f'got {missing!r}')

    @_skip_if_no_app
    def test_ai_roadmap_with_office_passes(self):
        # T4: AI roadmap WITH "إنشاء مكتب حوكمة الذكاء الاصطناعي" passes.
        missing = (
            _APP._compute_missing_governance_setup_in_roadmap(
                _ROADMAP_GOOD_BY_DOMAIN['ai'], 'Artificial Intelligence',
                org_structure_is_none=True, lang='ar',
            ))
        self.assertEqual(missing, [])

    @_skip_if_no_app
    def test_cyber_data_erm_existing_setup_passes(self):
        # T5: Cyber/Data/ERM existing governance-setup wording passes.
        for d in ('cyber', 'data', 'erm'):
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_setup_in_roadmap(
                        _ROADMAP_GOOD_BY_DOMAIN[d], d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertEqual(missing, [],
                                 f'expected [] for domain={d}, got '
                                 f'{missing!r}')

    @_skip_if_no_app
    def test_empty_roadmap_returns_full_missing_list(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_setup_in_roadmap(
                        '', d,
                        org_structure_is_none=True, lang='ar',
                    ))
                expected = list(
                    _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS[d].keys())
                self.assertEqual(sorted(missing), sorted(expected))


class RoadmapRepairPromptTests(unittest.TestCase):
    """Pin the roadmap repair prompt addendum content (T6, T7, T8).

    The prompt is built by ``ai_repair_strategy_section`` and we assert
    against the prompt body that would be sent to the AI provider. To
    avoid making a network call we monkey-patch ``call_provider`` to
    capture the prompt and return a stub Markdown response.
    """

    @_skip_if_no_app
    def test_roadmap_repair_prompt_includes_dt_setup_language(self):
        # T6: Roadmap repair prompt for DT + org_structure_is_none must
        # include the DT-specific setup language and the Owner/Timeline/
        # Deliverable + "تعزيز الحوكمة" rejection.
        captured = {}

        def _fake_provider(prompt, **_kw):
            captured['prompt'] = prompt
            return (
                '## 5. خارطة الطريق التنفيذية\n\n'
                '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
                '|---|------|------|------|------|\n'
                '| 1 | إنشاء مكتب التحول الرقمي وتعيين CDO وتشكيل '
                'لجنة التحول الرقمي | الرئيس التنفيذي | 6 أشهر | '
                'قرار إنشاء |\n'
                '| 2 | تطوير القدرات | فريق العمليات | 9 أشهر | '
                'تقرير |\n'
                '| 3 | تدريب الفريق | الموارد البشرية | 12 شهراً | '
                'شهادات |\n'
                '| 4 | مراجعة الأداء | الإدارة | 18 شهراً | تقرير |\n'
            )

        import unittest.mock as _mock
        # Resolve domain context for DT.
        try:
            dctx = _APP.get_strategy_domain_context(
                'Digital Transformation')
        except Exception as e:
            self.skipTest(f'cannot resolve DT domain context: {e}')

        sections = {'roadmap': _ROADMAP_BARE_AR}

        with _mock.patch.object(_APP, 'generate_ai_content',
                                side_effect=_fake_provider):
            try:
                _APP.ai_repair_strategy_section(
                    section_key='roadmap',
                    sections=sections,
                    lang='ar',
                    domain_context=dctx,
                    org_name='Test Org',
                    sector='Government',
                    maturity='Initial',
                    generation_mode='consulting',
                    validation_error='roadmap_governance_setup_missing',
                    org_structure_is_none=True,
                )
            except Exception:
                # We only need the captured prompt, not a successful
                # repair — downstream validation in some configurations
                # may reject the stub.
                pass

        self.assertIn('prompt', captured,
                      'expected ai_repair_strategy_section to call '
                      'the provider and capture the prompt')
        prompt = captured['prompt']
        # DT-specific setup language present.
        self.assertIn('مكتب التحول الرقمي', prompt)
        # Owner/Timeline/Deliverable required.
        self.assertIn('المالك', prompt)
        self.assertIn('الإطار الزمني', prompt)
        self.assertIn('المخرج', prompt)
        # Vague phrasing rejection.
        self.assertIn('تعزيز الحوكمة', prompt)

    @_skip_if_no_app
    def test_roadmap_repair_prompt_includes_ai_setup_language(self):
        # T6 (AI domain).
        captured = {}

        def _fake_provider(prompt, **_kw):
            captured['prompt'] = prompt
            return _ROADMAP_GOOD_BY_DOMAIN['ai']

        import unittest.mock as _mock
        try:
            dctx = _APP.get_strategy_domain_context(
                'Artificial Intelligence')
        except Exception as e:
            self.skipTest(f'cannot resolve AI domain context: {e}')

        sections = {'roadmap': _ROADMAP_BARE_AR}

        with _mock.patch.object(_APP, 'generate_ai_content',
                                side_effect=_fake_provider):
            try:
                _APP.ai_repair_strategy_section(
                    section_key='roadmap',
                    sections=sections,
                    lang='ar',
                    domain_context=dctx,
                    org_name='Test Org',
                    sector='Government',
                    maturity='Initial',
                    generation_mode='consulting',
                    validation_error='roadmap_governance_setup_missing',
                    org_structure_is_none=True,
                )
            except Exception:
                pass

        self.assertIn('prompt', captured)
        prompt = captured['prompt']
        # AI-specific setup language present.
        self.assertIn('حوكمة الذكاء الاصطناعي', prompt)

    @_skip_if_no_app
    def test_no_deterministic_roadmap_rows_inserted(self):
        # T8: The repair pathway is AI-first only; no deterministic
        # roadmap row is inserted into ``sections['roadmap']`` by the
        # helper. We verify by patching call_provider to return an
        # empty string — the pathway should NOT inject content.
        import unittest.mock as _mock
        try:
            dctx = _APP.get_strategy_domain_context(
                'Digital Transformation')
        except Exception as e:
            self.skipTest(f'cannot resolve DT domain context: {e}')

        sections = {'roadmap': _ROADMAP_BARE_AR}
        original = sections['roadmap']

        with _mock.patch.object(_APP, 'generate_ai_content',
                                return_value=''):
            try:
                _APP.ai_repair_strategy_section(
                    section_key='roadmap',
                    sections=sections,
                    lang='ar',
                    domain_context=dctx,
                    org_name='Test Org',
                    sector='Government',
                    maturity='Initial',
                    generation_mode='consulting',
                    validation_error='roadmap_governance_setup_missing',
                    org_structure_is_none=True,
                )
            except _APP.RepairError:
                # Expected when provider returns empty.
                pass
            except Exception:
                pass

        # ai_repair_strategy_section returns text but does not write
        # back to sections; the pathway-level repair (the new
        # ROADMAP-GOVERNANCE-SETUP-REPAIR pass) restores original on
        # failure. Either way, this helper alone never injects a
        # deterministic row into sections['roadmap'].
        self.assertEqual(sections['roadmap'], original,
                         'ai_repair_strategy_section must not mutate '
                         'sections; deterministic rows must not be '
                         'inserted')

    @_skip_if_no_app
    def test_vague_governance_phrasing_alone_does_not_satisfy(self):
        # T7: A roadmap that only contains vague "تعزيز الحوكمة"
        # without naming the domain office/committee/chief role
        # should still be flagged as missing the governance-setup
        # activity.
        vague_roadmap = (
            '## 5. خارطة الطريق التنفيذية\n\n'
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تعزيز الحوكمة | الإدارة | 6 أشهر | تقرير |\n'
            '| 2 | تطوير القدرات | فريق العمليات | 9 أشهر | تقرير |\n'
            '| 3 | تدريب الفريق | الموارد البشرية | 12 شهراً | شهادات |\n'
            '| 4 | مراجعة الأداء | الإدارة | 18 شهراً | تقرير |\n'
        )
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_setup_in_roadmap(
                        vague_roadmap, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertTrue(
                    len(missing) > 0,
                    f'vague "تعزيز الحوكمة" alone must NOT satisfy '
                    f'the governance-setup obligation for domain={d}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
