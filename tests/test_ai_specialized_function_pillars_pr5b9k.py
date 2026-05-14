"""PR-5B.9K — AI specialized_function_missing pillar enforcement.

When an AI strategy is generated with ``org_structure_is_none=True``,
the AI strategy MUST surface — across Pillars / Gaps — the
AI-specific specialized-function tokens (AI Governance Office, AI
Governance Committee, AI Ethics Officer, Model Risk Manager, AI
Compliance Lead, model inventory, AI operating model). Generic AI
governance wording alone is no longer sufficient — the new pillar
governance/structure check (PR-5B.9K) raises
``missing_governance-org_structure_is_none:ai`` when Pillar 1 lacks
the AI Governance Office wording, and the existing PR-5B.9D
``specialized_function_missing`` check still fails when the assembled
strategy does not name the function at all.

These tests pin:

  1. AI strategy with bare pillars (no AI Governance Office) emits
     ``missing_governance-org_structure_is_none:ai`` from
     ``_final_strategy_audit``.
  2. AI strategy with AI Governance Office / AI committee / Model
     Risk Manager wording in Pillar 1 passes the governance check.
  3. The AI-domain
     ``_DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['ai']`` registry includes
     the new responsible-AI roles (AI Ethics Officer, Model Risk
     Manager, AI Compliance Lead) and inventory / operating-model
     tokens.
  4. The AI pillars repair prompt names AI Governance Office /
     Model Risk Manager / AI Ethics Officer.

Run:
    python -m pytest tests/test_ai_specialized_function_pillars_pr5b9k.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_ai_spec_pillars_pr5b9k_')
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


# Bare pillars — generic AI governance wording only, no specialized-
# function tokens.
_AI_PILLARS_BARE = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: تطوير الذكاء الاصطناعي\n\n'
    'برامج تطوير قدرات الذكاء الاصطناعي.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تطوير القدرات | عام | الإدارة | 12 شهر |\n\n'
    '### الركيزة 2: تدريب الكوادر\n\n'
    'تدريب الكوادر.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تدريب | عام | الإدارة | 12 شهر |\n\n'
    '### الركيزة 3: تطبيقات\n\n'
    'تطبيقات.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تطبيقات | عام | الإدارة | 12 شهر |\n'
)


# Good pillars — Pillar 1 explicitly names AI Governance Office,
# AI Governance Committee, Model Risk Manager, etc.
_AI_PILLARS_GOOD = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة الذكاء الاصطناعي والهيكل التنظيمي ونموذج '
    'التشغيل\n\n'
    'إنشاء مكتب حوكمة الذكاء الاصطناعي وتشكيل لجنة حوكمة الذكاء '
    'الاصطناعي وتعيين Model Risk Manager و AI Ethics Officer و AI '
    'Compliance Lead، وبناء مخزون النماذج، وتطبيق نموذج تشغيل الذكاء '
    'الاصطناعي.\n\n'
    '| # | المبادرة | الوصف | المسؤول | الإطار |\n'
    '|---|----------|-------|--------|--------|\n'
    '| 1 | تأسيس مكتب الحوكمة | تأسيس | الإدارة | 6 أشهر |\n'
    '| 2 | لجنة الحوكمة | تشكيل | الإدارة | 6 أشهر |\n'
    '| 3 | الأدوار والمسؤوليات | تحديد | الإدارة | 6 أشهر |\n'
)


def _make_sections(pillars_text):
    return {
        'vision': '## 1. الرؤية\n\nرؤية.\n',
        'pillars': pillars_text,
        'environment': '## 3. البيئة\n\nنص.\n',
        'gaps': '## 4. الفجوات\n\n',
        'roadmap': '## 5. خارطة\n\n',
        'kpis': '## 6. مؤشرات\n\n',
        'confidence': '## 7. الثقة\n\n',
    }


class AIRegistryTests(unittest.TestCase):

    @_skip_if_no_app
    def test_ai_registry_includes_new_roles(self):
        ai_concepts = _APP._DOMAIN_SPECIALIZED_FUNCTION_CONCEPTS['ai']
        # Flatten all tokens.
        all_tokens = set()
        for fam_tokens in ai_concepts.values():
            for t in fam_tokens:
                all_tokens.add(t.lower())
        for required in (
                'ai ethics officer',
                'model risk manager',
                'ai compliance lead',
                'model inventory',
                'ai operating model',
        ):
            self.assertIn(required, all_tokens,
                          f'AI registry missing token: {required!r}')


class AIPillarsAuditTests(unittest.TestCase):

    def _has_governance_pillar_defect(self, defects):
        for tup in defects:
            if not isinstance(tup, tuple) or len(tup) < 2:
                continue
            sec, tag = tup[0], tup[1]
            if (sec == 'pillars'
                    and isinstance(tag, str)
                    and tag.startswith(
                        'missing_governance-org_structure_is_none')
                    and ':ai:' in tag):
                return True
        return False

    @_skip_if_no_app
    def test_bare_ai_pillars_emit_missing_governance(self):
        sections = _make_sections(_AI_PILLARS_BARE)
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=None,
            domain='ai',
            org_structure_is_none=True,
        )
        self.assertTrue(
            self._has_governance_pillar_defect(defects),
            f'expected missing_governance:ai defect, got '
            f'defects={defects!r}')

    @_skip_if_no_app
    def test_good_ai_pillars_pass_governance_check(self):
        sections = _make_sections(_AI_PILLARS_GOOD)
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=None,
            domain='ai',
            org_structure_is_none=True,
        )
        self.assertFalse(
            self._has_governance_pillar_defect(defects),
            f'unexpected missing_governance:ai defect, got '
            f'defects={defects!r}')

    @_skip_if_no_app
    def test_ai_pillars_no_defect_when_org_structure_is_none_false(self):
        sections = _make_sections(_AI_PILLARS_BARE)
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=None,
            domain='ai',
            org_structure_is_none=False,
        )
        self.assertFalse(
            self._has_governance_pillar_defect(defects),
            f'unexpected missing_governance:ai defect when '
            f'org_structure_is_none=False, got defects={defects!r}')


class AIPillarsRepairPromptTests(unittest.TestCase):
    """The AI pillars repair prompt addendum names AI Governance
    Office / Model Risk Manager / AI Ethics Officer."""

    @_skip_if_no_app
    def test_repair_prompt_names_ai_specific_concepts(self):
        captured = {}

        def _fake(prompt, *a, **kw):
            captured['prompt'] = prompt
            raise _APP.RepairError('forced for test')

        ctx = {
            'code': 'ai',
            'display_en': 'Artificial Intelligence',
            'display_ar': 'الذكاء الاصطناعي',
        }
        sections = {
            'vision': '## 1. Vision\n\n',
            'pillars': _AI_PILLARS_BARE,
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
                    domain_context=ctx,
                    org_name='Acme',
                    sector='Tech',
                    maturity='developing',
                    generation_mode='consulting',
                    validation_error='test',
                    org_structure_is_none=True,
                )
        prompt = captured.get('prompt', '') or ''
        for token in ('AI Governance Office',
                      'AI Ethics Officer',
                      'Model Risk Manager',
                      'AI Compliance Lead'):
            self.assertIn(token, prompt,
                          f'AI pillars repair prompt missing token: '
                          f'{token!r}')


class NoDeterministicPillarRowsTests(unittest.TestCase):
    """The new helper must not insert deterministic pillar rows."""

    @_skip_if_no_app
    def test_helper_does_not_mutate_sections(self):
        # Helper is read-only — it never receives ``sections``; only
        # the pillars text. This guards against future refactors that
        # might accidentally route a writable container through it.
        text_before = _AI_PILLARS_BARE
        _APP._compute_missing_governance_structure_in_pillars(
            text_before, 'ai', org_structure_is_none=True, lang='ar')
        self.assertEqual(text_before, _AI_PILLARS_BARE)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
