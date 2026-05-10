"""PR-5B.8H: org_structure_is_none governance-pillar runtime contract.

Pins the alignment between the post-normalization save gate
(``diagnosis_pillars_missing_governance``) and the AI-first pillars
synthesizer / repair prompt:

  * When ``org_structure_is_none=True``, ``synthesize_pillars_depth``
    forwards the flag into ``ai_repair_strategy_section`` so the AI is
    told to make the FIRST pillar a governance/structure/operating-model
    pillar.
  * ``_AI_REPAIR_SECTION_SCHEMA["pillars"]`` plus the AR/EN
    governance-first clause appended by ``ai_repair_strategy_section``
    explicitly requires recognised governance/structure wording.
  * After AI repair, ``synthesize_pillars_depth`` re-checks the
    governance-pillar contract on the repaired markdown. AI-repaired
    pillars that still lack governance/structure wording in the FIRST
    pillar leave ``sections['pillars']`` UNCHANGED and raise
    ``RepairError(section='pillars')``.
  * No deterministic pillar bank or fallback content is added by this
    PR (AST scan).

Run:
  python -m pytest tests/test_pillars_org_structure_runtime_pr5b8h.py -q
"""

import ast
import importlib
import inspect
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///tmp/test_pillars_org_structure_runtime_pr5b8h.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper.
# ---------------------------------------------------------------------------

class _Patch:
    def __init__(self, target, name, value):
        self.target = target
        self.name = name
        self.value = value
        self._original = None
        self._had = False

    def __enter__(self):
        self._had = hasattr(self.target, self.name)
        if self._had:
            self._original = getattr(self.target, self.name)
        setattr(self.target, self.name, self.value)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._had:
            setattr(self.target, self.name, self._original)
        else:  # pragma: no cover
            try:
                delattr(self.target, self.name)
            except AttributeError:
                pass
        return False


# ---------------------------------------------------------------------------
# Fixtures: AR / EN pillars whose FIRST pillar IS a governance pillar
# (passes the contract) and corresponding non-governance variants
# (technical first pillar — fails the contract).
# ---------------------------------------------------------------------------

_AR_GOV_FIRST = (
    "## 2. الركائز الاستراتيجية\n\n"
    "### الركيزة 1: الحوكمة والهيكل التنظيمي\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | تأسيس اللجنة التوجيهية واعتماد الهيكل التنظيمي | "
    "تشكيل لجنة برئاسة تنفيذية واعتماد الهيكل التنظيمي وتعريف "
    "الأدوار والمسؤوليات وخطوط الرفع | "
    "ميثاق اللجنة + الهيكل التنظيمي المعتمد |\n\n"
    "### الركيزة 2: الحماية التقنية\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | إدارة الهوية والوصول | تطبيق المصادقة متعددة العوامل "
    "ومراجعة الصلاحيات | خطة نشر معتمدة + سجل المراجعة |\n\n"
    "### الركيزة 3: الكشف والاستجابة\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | بناء قدرات المراقبة | تكامل مصادر السجلات وتطوير حالات "
    "الاستخدام | كتالوج حالات + مصفوفة التصعيد |\n"
)

_AR_TECH_FIRST = (
    "## 2. الركائز الاستراتيجية\n\n"
    "### الركيزة 1: الحماية التقنية\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | إدارة الهوية والوصول | تطبيق المصادقة متعددة العوامل "
    "ومراجعة الصلاحيات | خطة نشر معتمدة + سجل المراجعة |\n\n"
    "### الركيزة 2: الكشف والاستجابة\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | بناء قدرات المراقبة | تكامل مصادر السجلات وتطوير حالات "
    "الاستخدام | كتالوج حالات + مصفوفة التصعيد |\n\n"
    "### الركيزة 3: التوعية والتدريب\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | برنامج التوعية | تنفيذ حملات توعوية ومحاكاة التصيد | "
    "تقارير قياس الوعي + خطة التدريب |\n"
)

_EN_GOV_FIRST = (
    "## 2. Strategic Pillars\n\n"
    "### Pillar 1: Governance and Organizational Structure\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Establish steering committee and operating model | "
    "Form an executive-chaired steering committee, approve the "
    "organizational structure, define roles, responsibilities, and "
    "reporting lines | Approved charter + organisational structure |\n\n"
    "### Pillar 2: Technical Protection\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Identity and access | Enforce multi-factor authentication "
    "and periodic access reviews | Deployment plan + access review log |\n\n"
    "### Pillar 3: Detection and Response\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Monitoring capability | Integrate log sources and develop "
    "detection use cases | Use-case catalogue + escalation matrix |\n"
)

_EN_TECH_FIRST = (
    "## 2. Strategic Pillars\n\n"
    "### Pillar 1: Technical Protection\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Identity and access | Enforce multi-factor authentication "
    "and periodic access reviews | Deployment plan + access review log |\n\n"
    "### Pillar 2: Detection and Response\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Monitoring capability | Integrate log sources and develop "
    "detection use cases | Use-case catalogue + escalation matrix |\n\n"
    "### Pillar 3: Awareness and Training\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Awareness programme | Run phishing simulations and "
    "training campaigns | Awareness measurement reports |\n"
)


# ---------------------------------------------------------------------------
# 1. Sufficient pillars with governance-first satisfied → no AI call.
# ---------------------------------------------------------------------------

class TestGovernanceFirstSatisfied(unittest.TestCase):

    def test_ar_governance_first_passes_no_ai(self):
        sections = {'pillars': _AR_GOV_FIRST}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _AR_GOV_FIRST

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                org_structure_is_none=True,
            )
        self.assertFalse(result.get('rebuilt'),
                         'governance-first-satisfied pillars must no-op')
        self.assertEqual(_ai_calls, [],
                         'AI repair must not be called when contract holds')

    def test_en_governance_first_passes_no_ai(self):
        sections = {'pillars': _EN_GOV_FIRST}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _EN_GOV_FIRST

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                org_structure_is_none=True,
            )
        self.assertFalse(result.get('rebuilt'))
        self.assertEqual(_ai_calls, [])


# ---------------------------------------------------------------------------
# 2. First pillar missing governance wording → AI repair invoked with
#    org_structure_is_none=True context AND governance_pillar_missing
#    surfaced in validation_error.
# ---------------------------------------------------------------------------

class TestGovernanceFirstMissingTriggersAI(unittest.TestCase):

    def test_ar_tech_first_triggers_ai_with_org_struct_context(self):
        sections = {'pillars': _AR_TECH_FIRST}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _AR_GOV_FIRST  # AI returns a contract-satisfying repair

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                org_structure_is_none=True,
            )
        self.assertEqual(len(_ai_calls), 1,
                         'expected exactly one AI repair call')
        call = _ai_calls[0]
        self.assertEqual(call.get('section_key'), 'pillars')
        self.assertTrue(call.get('org_structure_is_none'),
                        'org_structure_is_none must be forwarded to AI repair')
        self.assertIn('governance_pillar_missing',
                      call.get('validation_error') or '',
                      'validation_error must surface governance_pillar_missing')
        self.assertTrue(result.get('rebuilt'))
        self.assertEqual(sections['pillars'], _AR_GOV_FIRST)

    def test_en_tech_first_triggers_ai_with_org_struct_context(self):
        sections = {'pillars': _EN_TECH_FIRST}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _EN_GOV_FIRST

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                org_structure_is_none=True,
            )
        self.assertEqual(len(_ai_calls), 1)
        self.assertTrue(_ai_calls[0].get('org_structure_is_none'))
        self.assertIn('governance_pillar_missing',
                      _ai_calls[0].get('validation_error') or '')
        self.assertTrue(result.get('rebuilt'))


# ---------------------------------------------------------------------------
# 3. AI returns repaired pillars that STILL miss governance wording in the
#    first pillar → RepairError(section='pillars'); sections['pillars']
#    UNCHANGED; no deterministic fallback content inserted.
# ---------------------------------------------------------------------------

class TestRepairedPillarsStillMissingGovernance(unittest.TestCase):

    def test_ar_repaired_without_governance_first_raises(self):
        sections = {'pillars': _AR_TECH_FIRST}
        _original = sections['pillars']

        def _spy(**_kw):
            # AI returned 3 substantive pillars but FIRST one is technical.
            return _AR_TECH_FIRST

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_pillars_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    org_structure_is_none=True,
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'pillars',
                         'RepairError must be annotated with section="pillars"')
        self.assertEqual(sections['pillars'], _original,
                         "sections['pillars'] must remain unchanged on failure")

    def test_en_repaired_without_governance_first_raises(self):
        sections = {'pillars': _EN_TECH_FIRST}
        _original = sections['pillars']

        def _spy(**_kw):
            return _EN_TECH_FIRST

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.synthesize_pillars_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                    org_structure_is_none=True,
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'pillars')
        self.assertEqual(sections['pillars'], _original)


# ---------------------------------------------------------------------------
# 4. Schema/prompt: ai_repair_strategy_section accepts org_structure_is_none
#    AND emits AR/EN governance-first wording when pillars + flag set.
# ---------------------------------------------------------------------------

class TestPromptIncludesGovernanceClause(unittest.TestCase):

    def test_signature_accepts_org_structure_is_none_kwarg(self):
        sig = inspect.signature(_APP.ai_repair_strategy_section)
        self.assertIn('org_structure_is_none', sig.parameters,
                      'ai_repair_strategy_section must accept '
                      'org_structure_is_none kwarg')

    def test_ar_pillars_prompt_includes_governance_first_clause(self):
        captured = {}

        def _gen_spy(prompt, **_kw):
            captured['prompt'] = prompt
            # Return a contract-satisfying repaired AR pillars text so that
            # the post-repair governance contract re-check passes and the
            # function returns normally.
            return _AR_GOV_FIRST

        # Resolve a domain context and call AI repair directly.
        dctx = _APP.get_strategy_domain_context(
            'Cyber Security', 'ar',
            selected_frameworks=['NCA ECC'])
        with _Patch(_APP, 'generate_ai_content', _gen_spy):
            _APP.ai_repair_strategy_section(
                section_key='pillars',
                sections={'pillars': ''},
                lang='ar',
                domain_context=dctx,
                org_structure_is_none=True,
            )
        prompt = captured.get('prompt', '') or ''
        self.assertIn('الهيكل التنظيمي', prompt,
                      'AR pillars prompt must include الهيكل التنظيمي '
                      'when org_structure_is_none=True')
        self.assertIn('الحوكمة', prompt)
        self.assertIn('الركيزة', prompt)

    def test_en_pillars_prompt_includes_governance_first_clause(self):
        captured = {}

        def _gen_spy(prompt, **_kw):
            captured['prompt'] = prompt
            return _EN_GOV_FIRST

        dctx = _APP.get_strategy_domain_context(
            'Cyber Security', 'en',
            selected_frameworks=['NCA ECC'])
        with _Patch(_APP, 'generate_ai_content', _gen_spy):
            _APP.ai_repair_strategy_section(
                section_key='pillars',
                sections={'pillars': ''},
                lang='en',
                domain_context=dctx,
                org_structure_is_none=True,
            )
        prompt = captured.get('prompt', '') or ''
        self.assertIn('organizational structure', prompt.lower())
        self.assertIn('governance', prompt.lower())
        self.assertIn('first', prompt.lower())

    def test_pillars_prompt_omits_clause_when_flag_false(self):
        captured = {}

        def _gen_spy(prompt, **_kw):
            captured['prompt'] = prompt
            return _EN_GOV_FIRST

        dctx = _APP.get_strategy_domain_context(
            'Cyber Security', 'en',
            selected_frameworks=['NCA ECC'])
        with _Patch(_APP, 'generate_ai_content', _gen_spy):
            _APP.ai_repair_strategy_section(
                section_key='pillars',
                sections={'pillars': ''},
                lang='en',
                domain_context=dctx,
                org_structure_is_none=False,
            )
        prompt = captured.get('prompt', '') or ''
        self.assertNotIn('Missing organisational structure rule',
                         prompt,
                         'governance-first clause must NOT appear when '
                         'org_structure_is_none=False')


# ---------------------------------------------------------------------------
# 5. AST scan: PR did NOT introduce a deterministic governance pillar bank
#    or fallback content insertion in synthesize_pillars_depth.
# ---------------------------------------------------------------------------

class TestNoDeterministicPillarFallback(unittest.TestCase):

    def test_synthesize_pillars_depth_has_no_deterministic_bank(self):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as fh:
            src = fh.read()
        tree = ast.parse(src)
        target = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'synthesize_pillars_depth'):
                target = node
                break
        self.assertIsNotNone(target,
                             'synthesize_pillars_depth not found')
        body_src = ast.get_source_segment(src, target) or ''
        # No deterministic governance/structure pillar bank symbols may
        # appear inside the function body.
        forbidden = (
            'pillar_bank',
            'governance_pillar_template',
            'GOVERNANCE_PILLAR_FALLBACK',
            'DETERMINISTIC_PILLARS',
        )
        for sym in forbidden:
            self.assertNotIn(
                sym, body_src,
                f'synthesize_pillars_depth must not reference '
                f'deterministic-bank symbol {sym!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
