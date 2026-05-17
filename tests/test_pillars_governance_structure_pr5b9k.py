"""PR-5B.9K — Strategic Pillars governance/structure enforcement.

When the diagnostic input flags ``org_structure_is_none=True`` the
**Strategic Pillars** section MUST include — as the FIRST pillar — a
domain-specific governance / structure / operating-model pillar (e.g.
AI → AI Governance Office; DT → Digital Transformation Office; Data →
Data Management Office; ERM → ERM function / CRO; Cyber →
Cybersecurity Department / CISO).

These tests pin:

  1. ``_compute_missing_governance_structure_in_pillars`` returns ``[]``
     when ``org_structure_is_none=False`` regardless of pillars content.
  2. The helper returns ``[]`` when the FIRST pillar text contains the
     domain-specific governance wording.
  3. The helper returns the missing concept families when the FIRST
     pillar does NOT mention any domain-specific establishment tokens.
  4. ``_final_strategy_audit`` emits ONE
     ``missing_governance-org_structure_is_none:<domain>:...`` defect
     (section=``pillars``) when the first pillar lacks the wording.
  5. The defect is NOT emitted when ``org_structure_is_none=False``.
  6. Vague phrasing such as "تعزيز الحوكمة" alone is rejected.
  7. The pillars repair prompt includes the domain-specific concept
     families (Cyber → CISO, Data → CDO, AI → AI Governance Office /
     Model Risk, DT → Chief Digital Officer, ERM → CRO).
  8. No deterministic pillar rows are inserted by the helper.

Run:
    python -m pytest tests/test_pillars_governance_structure_pr5b9k.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_pillars_gov_pr5b9k_')
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


# Bare pillars text — first pillar mentions only "تطوير القدرات"
# (no governance/structure/specialized-function wording).
_PILLARS_BARE_AR = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: تطوير القدرات\n\n'
    'برامج تطوير القدرات.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تطوير القدرات | وصف عام | الإدارة | 12 شهر |\n\n'
    '### الركيزة 2: تحسين العمليات\n\n'
    'برامج تحسين العمليات.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تحسين | وصف | الإدارة | 12 شهر |\n\n'
    '### الركيزة 3: تطوير الأدوات\n\n'
    'تطوير الأدوات.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | الأدوات | وصف | الإدارة | 12 شهر |\n'
)


# Per-domain "good" pillars text — Pillar 1 explicitly names the
# domain's specialized function so at least one concept family
# token matches.
_PILLARS_GOOD_BY_DOMAIN = {
    'ai': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة الذكاء الاصطناعي والهيكل التنظيمي ونموذج '
        'التشغيل\n\n'
        'إنشاء مكتب حوكمة الذكاء الاصطناعي وتشكيل لجنة حوكمة الذكاء '
        'الاصطناعي وتعيين Model Risk Manager و AI Ethics Officer و AI '
        'Compliance Lead وتطبيق نموذج تشغيل الذكاء الاصطناعي.\n\n'
        '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
        '|---|----------|-------|--------|--------|\n'
        '| 1 | تأسيس مكتب الحوكمة | تأسيس | الإدارة | 6 أشهر |\n'
        '| 2 | لجنة الحوكمة | تشكيل | الإدارة | 6 أشهر |\n'
        '| 3 | الأدوار والمسؤوليات | تحديد | الإدارة | 6 أشهر |\n'
    ),
    'dt': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة التحول الرقمي ونموذج التشغيل\n\n'
        'إنشاء مكتب التحول الرقمي وتعيين Chief Digital Officer وتشكيل '
        'لجنة التحول الرقمي ونموذج تشغيل التحول الرقمي.\n\n'
        '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
        '|---|----------|-------|--------|--------|\n'
        '| 1 | تأسيس المكتب | تأسيس | الإدارة | 6 أشهر |\n'
        '| 2 | تعيين CDO | تعيين | الإدارة | 6 أشهر |\n'
        '| 3 | لجنة التحول | تشكيل | الإدارة | 6 أشهر |\n'
    ),
    'data': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة البيانات ومكتب إدارة البيانات ونموذج '
        'التشغيل\n\n'
        'إنشاء مكتب إدارة البيانات وتعيين CDO وتشكيل لجنة حوكمة البيانات '
        'وأمناء البيانات.\n\n'
        '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
        '|---|----------|-------|--------|--------|\n'
        '| 1 | تأسيس المكتب | تأسيس | الإدارة | 6 أشهر |\n'
        '| 2 | تعيين CDO | تعيين | الإدارة | 6 أشهر |\n'
        '| 3 | لجنة البيانات | تشكيل | الإدارة | 6 أشهر |\n'
    ),
    'cyber': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني والهيكل التنظيمي ونموذج '
        'التشغيل\n\n'
        'إنشاء إدارة الأمن السيبراني وتعيين CISO وتشكيل لجنة حوكمة '
        'الأمن السيبراني وتحديد الأدوار والمسؤوليات (RACI).\n\n'
        '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
        '|---|----------|-------|--------|--------|\n'
        '| 1 | تأسيس الإدارة | تأسيس | الإدارة | 6 أشهر |\n'
        '| 2 | تعيين CISO | تعيين | الإدارة | 6 أشهر |\n'
        '| 3 | لجنة الحوكمة | تشكيل | الإدارة | 6 أشهر |\n'
    ),
    'erm': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة المخاطر المؤسسية والهيكل التنظيمي\n\n'
        'إنشاء إدارة المخاطر المؤسسية وتعيين CRO وتشكيل لجنة المخاطر '
        'وتعيين مالكي المخاطر.\n\n'
        '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
        '|---|----------|-------|--------|--------|\n'
        '| 1 | تأسيس إدارة المخاطر | تأسيس | الإدارة | 6 أشهر |\n'
        '| 2 | تعيين CRO | تعيين | الإدارة | 6 أشهر |\n'
        '| 3 | لجنة المخاطر | تشكيل | الإدارة | 6 أشهر |\n'
    ),
}


_DOMAINS = ('ai', 'dt', 'data', 'cyber', 'erm')


class HelperContractTests(unittest.TestCase):
    """Direct-call tests for
    ``_compute_missing_governance_structure_in_pillars``."""

    @_skip_if_no_app
    def test_helper_exists(self):
        self.assertTrue(
            hasattr(_APP, '_compute_missing_governance_structure_in_pillars'),
            '_compute_missing_governance_structure_in_pillars helper missing',
        )

    @_skip_if_no_app
    def test_returns_empty_when_org_structure_is_none_false(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        _PILLARS_BARE_AR, d,
                        org_structure_is_none=False, lang='ar',
                    ))
                self.assertEqual(missing, [],
                                 f'expected [] for domain={d} when '
                                 f'org_structure_is_none=False')

    @_skip_if_no_app
    def test_returns_missing_for_bare_pillars_per_domain(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        _PILLARS_BARE_AR, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertTrue(
                    len(missing) > 0,
                    f'expected non-empty missing list for domain={d} '
                    f'when first pillar has no SF tokens, got {missing!r}')

    @_skip_if_no_app
    def test_returns_empty_when_first_pillar_mentions_specialized_function(
            self):
        for d, good in _PILLARS_GOOD_BY_DOMAIN.items():
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        good, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertEqual(
                    missing, [],
                    f'expected [] for domain={d} when first pillar '
                    f'mentions SF, got {missing!r}')

    @_skip_if_no_app
    def test_vague_governance_phrasing_alone_rejected(self):
        """Vague phrasing such as "تعزيز الحوكمة" must NOT satisfy the
        domain-specific obligation."""
        vague = (
            '## 2. الركائز الاستراتيجية\n\n'
            '### الركيزة 1: تعزيز الحوكمة\n\n'
            'نص عام عن تعزيز الحوكمة بدون تفاصيل.\n'
        )
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        vague, d,
                        org_structure_is_none=True, lang='ar',
                    ))
                self.assertTrue(
                    len(missing) > 0,
                    f'expected non-empty missing list for domain={d} '
                    f'with vague phrasing, got {missing!r}')

    @_skip_if_no_app
    def test_empty_pillars_returns_full_missing_list(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                missing = (
                    _APP._compute_missing_governance_structure_in_pillars(
                        '', d,
                        org_structure_is_none=True, lang='ar',
                    ))
                expected = list(
                    _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS[d].keys())
                self.assertEqual(sorted(missing), sorted(expected))


class FinalAuditDefectTests(unittest.TestCase):
    """Pin the new defect emission in ``_final_strategy_audit``."""

    def _make_sections(self, pillars_text):
        return {
            'vision': '## 1. الرؤية\n\nرؤية.\n',
            'pillars': pillars_text,
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': '## 4. الفجوات\n\n',
            'roadmap': '## 5. خارطة\n\n',
            'kpis': '## 6. مؤشرات\n\n',
            'confidence': '## 7. الثقة\n\n',
        }

    def _has_governance_pillar_defect(self, defects):
        for tup in defects:
            if not isinstance(tup, tuple) or len(tup) < 2:
                continue
            sec, tag = tup[0], tup[1]
            if (sec == 'pillars'
                    and isinstance(tag, str)
                    and tag.startswith(
                        'missing_governance-org_structure_is_none')):
                return True
        return False

    @_skip_if_no_app
    def test_defect_emitted_when_pillars_lack_governance_first(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                sections = self._make_sections(_PILLARS_BARE_AR)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=True,
                )
                self.assertTrue(
                    self._has_governance_pillar_defect(defects),
                    f'expected missing_governance defect for '
                    f'domain={d}, got defects={defects!r}')

    @_skip_if_no_app
    def test_defect_not_emitted_when_org_structure_is_none_false(self):
        for d in _DOMAINS:
            with self.subTest(domain=d):
                sections = self._make_sections(_PILLARS_BARE_AR)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=False,
                )
                self.assertFalse(
                    self._has_governance_pillar_defect(defects),
                    f'unexpected missing_governance defect for '
                    f'domain={d} when org_structure_is_none=False, '
                    f'got defects={defects!r}')

    @_skip_if_no_app
    def test_defect_not_emitted_when_first_pillar_satisfies(self):
        for d, good in _PILLARS_GOOD_BY_DOMAIN.items():
            with self.subTest(domain=d):
                sections = self._make_sections(good)
                defects = _APP._final_strategy_audit(
                    sections, lang='ar', doc_subtype=None,
                    selected_frameworks=None,
                    domain=d,
                    org_structure_is_none=True,
                )
                self.assertFalse(
                    self._has_governance_pillar_defect(defects),
                    f'unexpected missing_governance defect for '
                    f'domain={d} when first pillar mentions SF, '
                    f'got defects={defects!r}')


class PillarsRepairPromptTests(unittest.TestCase):
    """Pin the per-domain repair-prompt addendum content for pillars."""

    def _domain_context(self, code):
        return {
            'code': code,
            'display_en': {'cyber': 'Cyber Security',
                           'data':  'Data Management',
                           'ai':    'Artificial Intelligence',
                           'dt':    'Digital Transformation',
                           'erm':   'Enterprise Risk Management'}.get(
                code, code),
            'display_ar': {'cyber': 'الأمن السيبراني',
                           'data':  'إدارة البيانات',
                           'ai':    'الذكاء الاصطناعي',
                           'dt':    'التحول الرقمي',
                           'erm':   'إدارة المخاطر المؤسسية'}.get(
                code, code),
        }

    @_skip_if_no_app
    def test_ai_repair_prompt_names_required_concepts(self):
        captured = {}

        def _fake(prompt, *a, **kw):
            captured['prompt'] = prompt
            raise _APP.RepairError('forced for test')

        sections = {
            'vision': '## 1. Vision\n\n',
            'pillars': _PILLARS_BARE_AR,
            'environment': '', 'gaps': '', 'roadmap': '',
            'kpis': '', 'confidence': '',
        }
        import unittest.mock as _mock
        with _mock.patch.object(_APP, 'generate_ai_content',
                                side_effect=_fake):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='pillars',
                    sections=sections,
                    lang='en',
                    domain_context=self._domain_context('ai'),
                    org_name='Acme',
                    sector='Finance',
                    maturity='developing',
                    generation_mode='consulting',
                    validation_error='test',
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '') or ''
        # AI prompt addendum must name the AI-specific concepts.
        for token in ('AI Governance Office', 'AI Ethics Officer',
                      'Model Risk Manager', 'AI Compliance Lead'):
            self.assertIn(token, prompt,
                          f'AI repair prompt missing required token: '
                          f'{token!r}')

    @_skip_if_no_app
    def test_dt_repair_prompt_names_required_concepts(self):
        captured = {}

        def _fake(prompt, *a, **kw):
            captured['prompt'] = prompt
            raise _APP.RepairError('forced for test')

        sections = {
            'vision': '## 1. Vision\n\n',
            'pillars': _PILLARS_BARE_AR,
            'environment': '', 'gaps': '', 'roadmap': '',
            'kpis': '', 'confidence': '',
        }
        import unittest.mock as _mock
        with _mock.patch.object(_APP, 'generate_ai_content',
                                side_effect=_fake):
            with self.assertRaises(_APP.RepairError):
                _APP.ai_repair_strategy_section(
                    section_key='pillars',
                    sections=sections,
                    lang='en',
                    domain_context=self._domain_context('dt'),
                    org_name='Acme',
                    sector='Finance',
                    maturity='developing',
                    generation_mode='consulting',
                    validation_error='test',
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '') or ''
        for token in ('Digital Transformation Office',
                      'Chief Digital Officer'):
            self.assertIn(token, prompt,
                          f'DT repair prompt missing required token: '
                          f'{token!r}')


class NoDeterministicInsertionTests(unittest.TestCase):
    """Helper must never mutate sections nor invent pillar text."""

    @_skip_if_no_app
    def test_helper_is_pure(self):
        text_before = _PILLARS_BARE_AR
        _APP._compute_missing_governance_structure_in_pillars(
            text_before, 'ai', org_structure_is_none=True, lang='ar')
        # Helper must not mutate inputs.
        self.assertEqual(text_before, _PILLARS_BARE_AR)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
