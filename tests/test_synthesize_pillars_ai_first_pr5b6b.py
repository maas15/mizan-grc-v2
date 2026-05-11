"""PR-5B.6B: AI-first ``synthesize_pillars_depth``.

This module pins down the post-migration contract for the pillars
synthesizer:

  * Sufficient pillars (count >= ``_RICHNESS_MIN_PILLARS_LOCAL``, every
    counted pillar has a substantive initiative table, and the
    ``org_structure_is_none`` governance-pillar contract is satisfied)
    do NOT trigger AI repair.
  * Insufficient / contract-failing pillars delegate to
    :func:`ai_repair_strategy_section` with ``section_key='pillars'``.
  * Strict domain resolution: no ``domain or 'Cyber Security'`` fallback;
    a :class:`DomainResolutionError` is converted to a
    :class:`RepairError` annotated with ``section='pillars'``.
  * On AI failure, AI :class:`RepairError`, or invalid repaired output,
    a :class:`RepairError` is raised with ``section='pillars'`` and
    ``sections['pillars']`` is left UNCHANGED — no deterministic
    cyber/governance/tech bank is ever consulted.
  * AST scan: ``synthesize_pillars_depth`` no longer references the
    deleted deterministic-bank vocabulary (SIEM / SOC / CISO / IAM /
    PAM / EDR / XDR / phishing / DLP literals; "Pillar 1: Cyber
    Security" hardcoded title; ``pillar_bank`` local).

Run:  python -m pytest tests/test_synthesize_pillars_ai_first_pr5b6b.py -q
"""

import ast
import importlib
import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_synthesize_pillars_ai_first_pr5b6b.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')

_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper (mirrors PR-5B.5F2 test pattern).
# ---------------------------------------------------------------------------

class _Patch:
    """Lightweight context manager that swaps a module attribute."""

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
        else:  # pragma: no cover - defensive
            try:
                delattr(self.target, self.name)
            except AttributeError:
                pass
        return False


# ---------------------------------------------------------------------------
# Canonical AR / EN repair fixtures (>= 3 substantive pillars, each with a
# substantive 4-column initiative table row).
# ---------------------------------------------------------------------------

_REPAIRED_AR_PILLARS = (
    "## 2. الركائز الاستراتيجية\n\n"
    "### الركيزة 1: الحوكمة والامتثال\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | تأسيس لجنة الحوكمة | تشكيل لجنة برئاسة تنفيذية مع اختصاصات معتمدة | "
    "ميثاق اللجنة + جدول الاجتماعات |\n"
    "| 2 | اعتماد سياسات الأمن | إصدار حزمة السياسات وآلية المراجعة الدورية | "
    "حزمة السياسات المعتمدة |\n"
    "| 3 | مصفوفة المسؤوليات | بناء مصفوفة RACI لجميع أدوار الحوكمة | "
    "مصفوفة RACI معتمدة |\n\n"
    "### الركيزة 2: الحماية التقنية\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | إدارة الهوية | تطبيق المصادقة متعددة العوامل ومراجعة الصلاحيات | "
    "خطة نشر معتمدة + سجل المراجعة |\n"
    "| 2 | حماية نقاط النهاية | نشر EDR على جميع الأجهزة الحرجة | "
    "تقارير التغطية + لوحة المتابعة |\n"
    "| 3 | تشفير البيانات | تطبيق تشفير البيانات أثناء النقل والتخزين | "
    "تقرير التغطية + سجل المفاتيح |\n\n"
    "### الركيزة 3: الكشف والاستجابة\n\n"
    "| # | المبادرة | الوصف | المخرج المتوقع |\n"
    "|---|---------|-------|----------------|\n"
    "| 1 | بناء قدرات المراقبة | تكامل مصادر السجلات وتطوير حالات الاستخدام | "
    "كتالوج حالات + مصفوفة التصعيد |\n"
    "| 2 | دليل الاستجابة | إعداد دليل استجابة للحوادث وتمارين دورية | "
    "دليل معتمد + تقارير التمارين |\n"
    "| 3 | إدارة الثغرات | فحص دوري للثغرات وإغلاقها وفق أولوية المخاطر | "
    "تقارير الفحص + سجل المعالجة |\n"
)

_REPAIRED_EN_PILLARS = (
    "## 2. Strategic Pillars\n\n"
    "### Pillar 1: Governance and Compliance\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Establish steering committee | Form an executive-chaired committee "
    "with approved terms of reference | Approved charter + meeting cadence |\n"
    "| 2 | Approve security policy set | Issue policy bundle and periodic review "
    "procedure | Approved policy bundle |\n"
    "| 3 | Responsibility matrix | Build a RACI matrix covering all governance "
    "roles | Approved RACI matrix |\n\n"
    "### Pillar 2: Technical Protection\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Identity and access | Enforce multi-factor authentication and "
    "periodic access reviews | Deployment plan + access review register |\n"
    "| 2 | Endpoint protection | Deploy EDR on all critical endpoints with "
    "centralised telemetry | Coverage report + monitoring dashboard |\n"
    "| 3 | Data encryption | Encrypt data in transit and at rest with managed "
    "keys | Coverage report + key inventory |\n\n"
    "### Pillar 3: Detection and Response\n\n"
    "| # | Initiative | Description | Expected Deliverable |\n"
    "|---|------------|-------------|----------------------|\n"
    "| 1 | Monitoring capability | Integrate log sources and develop detection "
    "use cases mapped to threats | Use-case catalogue + escalation matrix |\n"
    "| 2 | Response playbook | Author incident response playbook and run "
    "tabletop exercises | Approved playbook + exercise reports |\n"
    "| 3 | Vulnerability management | Periodic scanning and risk-prioritised "
    "remediation cycles | Scan reports + remediation register |\n"
)


# ---------------------------------------------------------------------------
# 1. Sufficient input → no AI call (rebuilt=False).
# ---------------------------------------------------------------------------

class TestSufficientPillarsNoOp(unittest.TestCase):

    def test_sufficient_pillars_skip_ai(self):
        sections = {'pillars': _REPAIRED_AR_PILLARS}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _REPAIRED_AR_PILLARS

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                org_structure_is_none=False,
            )
        self.assertFalse(result.get('rebuilt'))
        self.assertEqual(_ai_calls, [],
                         'AI repair must not be called for sufficient pillars')


# ---------------------------------------------------------------------------
# 2. Insufficient input → AI delegation with section_key='pillars'.
# ---------------------------------------------------------------------------

class TestInsufficientPillarsDelegateAI(unittest.TestCase):

    def test_empty_pillars_calls_ai_repair_section_pillars(self):
        sections = {'pillars': ''}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _REPAIRED_AR_PILLARS

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(len(_ai_calls), 1,
                         'Expected exactly one ai_repair_strategy_section call')
        call = _ai_calls[0]
        self.assertEqual(call.get('section_key'), 'pillars')
        self.assertEqual(call.get('lang'), 'ar')
        self.assertIn('domain_context', call)
        self.assertIsInstance(call.get('domain_context'), dict)
        # Successful repair populates the section and reports rebuilt=True.
        self.assertTrue(result.get('rebuilt'))
        self.assertEqual(sections['pillars'], _REPAIRED_AR_PILLARS)

    def test_english_empty_pillars_calls_ai_repair(self):
        sections = {'pillars': ''}
        _ai_calls = []

        def _spy(**kwargs):
            _ai_calls.append(kwargs)
            return _REPAIRED_EN_PILLARS

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.synthesize_pillars_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(len(_ai_calls), 1)
        self.assertEqual(_ai_calls[0].get('section_key'), 'pillars')
        self.assertTrue(result.get('rebuilt'))
        self.assertEqual(sections['pillars'], _REPAIRED_EN_PILLARS)


# ---------------------------------------------------------------------------
# 3. RepairError annotated with section='pillars' on AI failure.
# ---------------------------------------------------------------------------

class TestPillarsRepairErrorAnnotation(unittest.TestCase):

    def test_ai_repair_error_propagates_with_section_pillars(self):
        sections = {'pillars': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider available')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_pillars_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'pillars')
        # No deterministic content must have been injected on failure.
        self.assertEqual(sections.get('pillars', ''), '')

    def test_invalid_repair_output_raises_repair_error_pillars(self):
        sections = {'pillars': ''}

        def _bad(**_kw):
            # AI returns the heading but no substantive pillar tables.
            return '## 2. الركائز الاستراتيجية\n\nمحتوى نصي بدون جداول مبادرات.\n'

        with _Patch(_APP, 'ai_repair_strategy_section', _bad):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_pillars_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'pillars')
        # Invalid output must NOT be assigned to sections['pillars'].
        self.assertEqual(sections.get('pillars', ''), '')


# ---------------------------------------------------------------------------
# 4. DomainResolutionError → RepairError(section='pillars').
# ---------------------------------------------------------------------------

class TestDomainResolutionErrorWrapping(unittest.TestCase):

    def test_invalid_domain_raises_repair_error_pillars(self):
        sections = {'pillars': ''}

        def _raise(*_a, **_kw):
            raise _APP.DomainResolutionError('unknown domain')

        # The synth must NOT swallow / coerce / cyber-default the
        # invalid domain — it must raise RepairError with
        # section='pillars'.
        with _Patch(_APP, 'get_strategy_domain_context', _raise):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_pillars_depth(
                    sections, lang='ar',
                    domain='NotARealDomain', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'pillars')
        self.assertEqual(sections.get('pillars', ''), '')


# ---------------------------------------------------------------------------
# 5. AST scan: deterministic-bank vocabulary is gone from the function body.
# ---------------------------------------------------------------------------

class TestNoDeterministicBankInPillarsSynth(unittest.TestCase):
    """Static guarantee that the deterministic cyber/governance/tech
    pillar bank is no longer present inside ``synthesize_pillars_depth``.
    """

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        cls._fn_node = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'synthesize_pillars_depth'):
                cls._fn_node = node
                break
        assert cls._fn_node is not None, (
            'synthesize_pillars_depth function not found in app.py')
        cls._fn_src = ast.unparse(cls._fn_node)

    def test_no_pillar_bank_local(self):
        # The old implementation built a `pillar_bank = [...]` local.
        for node in ast.walk(self._fn_node):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == 'pillar_bank':
                        self.fail(
                            'pillar_bank local must be removed from '
                            'synthesize_pillars_depth (PR-5B.6B AI-first)')

    def test_no_cyber_literal_phrases(self):
        # Common deterministic phrases that must no longer appear in the
        # function body. We allow them in docstrings / comments stripped
        # by ast.unparse, but ast.unparse keeps docstrings — so we scan
        # only string literals INSIDE non-docstring expressions.
        forbidden = [
            'SIEM', 'SOC', 'CISO', 'IAM/PAM', 'EDR/XDR', 'MTTD', 'MTTR',
            'phishing', 'DLP', 'Pillar 1: Cyber Security',
            # AR cyber bank phrases
            'كتب الاستجابة', 'محاكاة التصيد',
        ]
        # Skip the function docstring (first statement if it is an
        # Expr(Constant(str))).
        body = list(self._fn_node.body)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]

        # Walk all string constants inside the remaining body.
        offending = []
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for phrase in forbidden:
                        if phrase in node.value:
                            offending.append(phrase)
        self.assertEqual(
            offending, [],
            f'Deterministic cyber-bank phrases must be removed from '
            f'synthesize_pillars_depth: {sorted(set(offending))}',
        )

    def test_no_governance_pillar_injection_block(self):
        # The old implementation set
        # summary['governance_pillar_injected'] = True after building a
        # gov_pillar dict. The AI-first version may still expose the
        # `governance_pillar_injected` key (defaulted False) but must
        # never assign True to it from a deterministic injection branch.
        # Any `Subscript` Assign whose value is `Constant(True)` and
        # whose subscript slice references 'governance_pillar_injected'
        # is a regression.
        for node in ast.walk(self._fn_node):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if (isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.slice, ast.Constant)
                            and tgt.slice.value
                                == 'governance_pillar_injected'
                            and isinstance(node.value, ast.Constant)
                            and node.value.value is True):
                        self.fail(
                            'synthesize_pillars_depth must not inject '
                            'a deterministic governance pillar '
                            '(PR-5B.6B AI-first)')

    def test_calls_ai_repair_strategy_section_with_pillars(self):
        # Static proof of delegation: the function body MUST contain a
        # Call to ai_repair_strategy_section with section_key='pillars'.
        found = False
        for node in ast.walk(self._fn_node):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'ai_repair_strategy_section'):
                for kw in node.keywords:
                    if (kw.arg == 'section_key'
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == 'pillars'):
                        found = True
                        break
                if found:
                    break
        self.assertTrue(
            found,
            'synthesize_pillars_depth must delegate to '
            'ai_repair_strategy_section(section_key="pillars", ...)')


# ---------------------------------------------------------------------------
# 6. Schema entry registered for "pillars".
# ---------------------------------------------------------------------------

class TestPillarsSchemaRegistered(unittest.TestCase):

    def test_schema_has_pillars_entry(self):
        schema = getattr(_APP, '_AI_REPAIR_SECTION_SCHEMA', None)
        self.assertIsInstance(schema, dict)
        self.assertIn('pillars', schema)
        self.assertIn('ar', schema['pillars'])
        self.assertIn('en', schema['pillars'])
        # The body must mention the canonical heading and the
        # 4-column table format.
        self.assertIn('## 2. الركائز الاستراتيجية', schema['pillars']['ar'])
        self.assertIn('## 2. Strategic Pillars', schema['pillars']['en'])
        self.assertIn('### الركيزة', schema['pillars']['ar'])
        self.assertIn('### Pillar', schema['pillars']['en'])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
