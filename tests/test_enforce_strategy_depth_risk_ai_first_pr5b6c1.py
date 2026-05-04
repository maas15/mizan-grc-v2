"""PR-5B.6C.1: AI-first Section D risk top-up in
``enforce_technical_strategy_depth``.

Section D used to maintain an AR/EN deterministic ``_risk_bank`` and
inject cyber-specific rows (SIEM Integration Failure, IAM/PAM Rollout
Resistance, Untested Backup/DR, Third-Party Cyber Exposure,
نقص الكفاءات السيبرانية, MSSP, …) into the Key Risks table whenever
the row count was below ``_MIN_RISK_DEPTH = 5``. PR-5B.6C.1 replaces
this with a single delegation to
``ai_repair_strategy_section(section_key='confidence', ...)`` using
strict-resolved domain context. On failure the section is left
UNCHANGED and a ``RepairError`` annotated with ``section='confidence'``
is raised so the post-normalization save gate (PR-5B.5F1) and the
final-audit ``synth_failed:confidence`` defect block the strategy.

This module pins:

  1. Sufficient risk rows → no AI call, summary['risk_rows_added'] == 0.
  2. Insufficient risk rows → ``ai_repair_strategy_section`` is called
     with ``section_key='confidence'``.
  3. Successful repair replaces ``sections['confidence']`` ONLY after
     the ≥ ``_MIN_RISK_DEPTH`` row count is validated.
  4. Old malformed (single-row) confidence is replaced wholesale, not
     merged with the AI-repaired output.
  5. Deterministic risk-bank phrases are not produced by Section D
     when the AI returns a generic (non-cyber) confidence section.
  6. Non-cyber domains do NOT receive a Cyber Security fallback —
     strict ``get_strategy_domain_context`` is used and any failure
     bubbles up as ``RepairError(section='confidence')``.
  7. ``ai_repair_strategy_section`` raising ``RepairError`` produces
     ``RepairError(section='confidence')`` and leaves the original
     section unchanged.
  8. AI-repaired confidence with too few risk rows is rejected; the
     original ``sections['confidence']`` is preserved verbatim.
  9. Final-audit defects emit ``synth_failed:confidence`` when the
     caller records the failure into ``_synth_status``.
 10. AST scan: Section D (the body of
     ``enforce_technical_strategy_depth`` after ``# ── D. Risk register
     depth ──``) no longer references ``_risk_bank`` or the deleted
     cyber risk-row literals.

Run:  python -m pytest tests/test_enforce_strategy_depth_risk_ai_first_pr5b6c1.py -q
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
    'DATABASE_URL', 'sqlite:///tmp/test_enforce_strategy_depth_risk_ai_first_pr5b6c1.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper (mirrors PR-5B.5F2 / PR-5B.6B test pattern).
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
# Canonical fixtures.
# ---------------------------------------------------------------------------

# A confidence section with EXACTLY 5 substantive risk rows. Used as the
# "sufficient" baseline (Section D must no-op).
_RICH_CONFIDENCE_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 65%\n\n"
    "### المخاطر الرئيسية:\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر اعتماد الحوكمة | متوسط | عالٍ | ورش تنفيذية مبكرة |\n"
    "| 2 | محدودية الميزانية | متوسط | عالٍ | جدولة متعددة السنوات |\n"
    "| 3 | عدم اكتمال جرد الأصول | متوسط | متوسط | جرد شامل قبل التطبيق |\n"
    "| 4 | فجوات الكفاءات | عالٍ | عالٍ | برامج تدريب وتوظيف |\n"
    "| 5 | تأخر تكامل الأنظمة | متوسط | عالٍ | تنفيذ مرحلي مع اختبار قبول |\n"
)

# Single, malformed-from-the-deterministic-bank-perspective row. Below
# ``_MIN_RISK_DEPTH = 5`` so Section D must invoke AI repair.
_THIN_CONFIDENCE_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 65%\n\n"
    "### المخاطر الرئيسية:\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر الميزانية | متوسط | عالٍ | جدولة المدفوعات مبكراً |\n"
)

# AI-repaired confidence (5 substantive rows, NONE matching the deleted
# deterministic risk-bank phrases).
_AI_REPAIRED_CONFIDENCE_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 70%\n\n"
    "### المخاطر الرئيسية:\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر اعتماد القرارات | متوسط | عالٍ | تشكيل لجنة توجيهية |\n"
    "| 2 | محدودية الموارد | متوسط | عالٍ | إعادة جدولة المخصصات |\n"
    "| 3 | فجوات في البيانات | متوسط | متوسط | جرد شامل وتصنيف |\n"
    "| 4 | فجوات الكفاءات | عالٍ | عالٍ | برامج تدريب |\n"
    "| 5 | تأخر تنفيذ المشاريع | متوسط | عالٍ | تنفيذ مرحلي |\n"
)

# AI-repaired confidence with TOO FEW risk rows (only 2). Must be rejected
# by the post-AI validation step.
_AI_INVALID_CONFIDENCE_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 70%\n\n"
    "### المخاطر الرئيسية:\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر القرارات | متوسط | عالٍ | لجنة توجيهية |\n"
    "| 2 | محدودية الموارد | متوسط | عالٍ | إعادة جدولة |\n"
)

# Sufficient SO and KPI fixtures so that Sections B and C of
# ``enforce_technical_strategy_depth`` do not delegate to the SO/KPI
# AI synthesizers during these Section-D-focused tests.
_SUFFICIENT_VISION_AR = (
    "### الأهداف الاستراتيجية:\n\n"
    "| # | الهدف الاستراتيجي | المؤشر المستهدف | المبرر | الإطار الزمني |\n"
    "|---|--------------------|-----------------|--------|----------------|\n"
    "| 1 | تعزيز الحوكمة | 100% | NCA ECC | 12 شهراً |\n"
    "| 2 | إدارة الهوية | 100% | NCA ECC | 12 شهراً |\n"
    "| 3 | المراقبة المستمرة | 24/7 | NCA ECC | 12 شهراً |\n"
    "| 4 | الاستجابة للحوادث | < 4 ساعات | NCA ECC | 12 شهراً |\n"
    "| 5 | حماية البيانات | 100% | NCA ECC | 12 شهراً |\n"
)
_SUFFICIENT_KPIS_AR = (
    "### مؤشرات الأداء الرئيسية:\n\n"
    "| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب |"
    " مصدر البيانات | المالك | التكرار | الإطار الزمني |\n"
    "|---|--------|---------------|-------------------|----------------|"
    "----------------|--------|---------|----------------|\n"
    "| 1 | تغطية NCA | KPI | 100% | (مطبق/إجمالي)x100 | GRC | CISO | شهري | سنة |\n"
    "| 2 | تأهيل الكوادر | KPI | 100% | المُدرَّبون/الإجمالي | HR | CISO | ربعي | سنة |\n"
    "| 3 | جاهزية الاستجابة | KPI | < 4س | متوسط زمن الاستجابة | SOC | CISO | شهري | سنة |\n"
    "| 4 | جاهزية النسخ | KPI | 100% | اختبارات/الإجمالي | DR | CIO | ربعي | سنة |\n"
    "| 5 | متوسط زمن التصحيح | KPI | 30 يوم | متوسط أيام التصحيح | VM | CISO | شهري | سنة |\n"
    "| 6 | تقييم الأطراف | KPI | 100% | المُقيّمون/الإجمالي | TPRM | CISO | ربعي | سنة |\n"
)


def _make_sections(*, confidence):
    """Build a sections dict that exercises Section D specifically."""
    return {
        'vision': _SUFFICIENT_VISION_AR,
        'pillars': '',  # Section A no-ops on empty pillars
        'environment': '',
        'gaps': '',
        'roadmap': '',
        'kpis': _SUFFICIENT_KPIS_AR,
        'confidence': confidence,
    }


# ---------------------------------------------------------------------------
# 1. Sufficient risk rows → no AI call, no row addition.
# ---------------------------------------------------------------------------

class TestSufficientRiskRowsNoOp(unittest.TestCase):

    def test_sufficient_risk_rows_skip_ai_repair(self):
        sections = _make_sections(confidence=_RICH_CONFIDENCE_AR)
        ai_calls = []

        def _spy(**kwargs):
            ai_calls.append(kwargs)
            return _AI_REPAIRED_CONFIDENCE_AR

        before = sections['confidence']
        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            summary = _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        self.assertEqual(
            ai_calls, [],
            'ai_repair_strategy_section must NOT be called when risk rows '
            'already meet _MIN_RISK_DEPTH')
        self.assertEqual(summary.get('risk_rows_added', 0), 0,
                         'risk_rows_added must remain 0 on no-op')
        self.assertEqual(sections['confidence'], before,
                         'confidence section must be left unchanged on no-op')


# ---------------------------------------------------------------------------
# 2. Insufficient → ai_repair_strategy_section called with section_key='confidence'.
# ---------------------------------------------------------------------------

class TestInsufficientRiskRowsDelegatesAI(unittest.TestCase):

    def test_insufficient_risk_rows_calls_ai_repair_with_confidence_key(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)
        ai_calls = []

        def _spy(**kwargs):
            ai_calls.append(kwargs)
            return _AI_REPAIRED_CONFIDENCE_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            summary = _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        self.assertEqual(
            len(ai_calls), 1,
            'Expected exactly one ai_repair_strategy_section call')
        call = ai_calls[0]
        self.assertEqual(call.get('section_key'), 'confidence')
        self.assertEqual(call.get('lang'), 'ar')
        self.assertIn('domain_context', call)
        self.assertIsInstance(call.get('domain_context'), dict)
        # min_rows must be passed and at the risk floor.
        self.assertGreaterEqual(call.get('min_rows', 0), 5)
        # validation_error must mention the risk shortfall.
        ve = call.get('validation_error', '') or ''
        self.assertIn('risk', ve.lower())
        # On success, summary reports rows added.
        self.assertGreaterEqual(summary.get('risk_rows_added', 0), 1)


# ---------------------------------------------------------------------------
# 3. AI-repaired confidence replaces the section ONLY after validation.
# ---------------------------------------------------------------------------

class TestRepairedConfidenceAssignedAfterValidation(unittest.TestCase):

    def test_valid_repair_replaces_confidence_after_validation(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)

        def _ok(**_kw):
            return _AI_REPAIRED_CONFIDENCE_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _ok):
            _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        self.assertEqual(
            sections['confidence'], _AI_REPAIRED_CONFIDENCE_AR,
            'Successfully validated AI-repaired confidence must replace '
            'sections[confidence] verbatim')
        self.assertGreaterEqual(
            _APP._count_risk_rows_with_mitigation(sections['confidence']), 5)


# ---------------------------------------------------------------------------
# 4. Old malformed risk rows are not merged into the AI-repaired output.
# ---------------------------------------------------------------------------

class TestOldMalformedRowsNotMerged(unittest.TestCase):

    def test_malformed_rows_replaced_not_merged(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)

        def _ok(**_kw):
            return _AI_REPAIRED_CONFIDENCE_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _ok):
            _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        # The single old row's mitigation phrase must NOT survive — Section D
        # replaces the section wholesale with the AI output.
        self.assertNotIn('جدولة المدفوعات مبكراً', sections['confidence'])


# ---------------------------------------------------------------------------
# 5. Deterministic risk-bank phrases are not produced by Section D.
# ---------------------------------------------------------------------------

_FORBIDDEN_DETERMINISTIC_RISK_PHRASES = [
    'SIEM Integration Failure',
    'IAM/PAM',
    'Third-Party Cyber Exposure',
    'Untested Backup/DR',
    'نقص الكفاءات السيبرانية',
    'MSSP',
    'فشل تكامل SIEM',
    'مقاومة نشر IAM/PAM',
    'مخاطر الأطراف الثالثة',
]


class TestNoDeterministicRiskBankPhrases(unittest.TestCase):

    def test_section_d_does_not_inject_deterministic_phrases(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)

        # AI returns a GENERIC confidence section with none of the
        # deleted deterministic phrases. Section D must not synthesise
        # them on its own.
        def _ok(**_kw):
            return _AI_REPAIRED_CONFIDENCE_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _ok):
            _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        for phrase in _FORBIDDEN_DETERMINISTIC_RISK_PHRASES:
            self.assertNotIn(
                phrase, sections['confidence'],
                f'Section D must not inject deleted deterministic risk-bank '
                f'phrase {phrase!r}')


# ---------------------------------------------------------------------------
# 6. Non-cyber domain → no Cyber Security fallback; strict domain context.
# ---------------------------------------------------------------------------

class TestNonCyberDomainStrict(unittest.TestCase):

    def test_non_cyber_domain_uses_strict_resolution_no_cyber_fallback(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)
        captured = []
        ai_calls = []

        def _spy_resolve(domain, lang='en', selected_frameworks=None):
            captured.append({'domain': domain, 'lang': lang,
                             'selected_frameworks': list(selected_frameworks or [])})
            # Delegate to the real resolver so we get a valid context dict.
            return _APP.get_strategy_domain_context.__wrapped__(  # type: ignore[attr-defined]
                domain, lang, selected_frameworks=selected_frameworks
            ) if hasattr(_APP.get_strategy_domain_context, '__wrapped__') else \
                _RESOLVE_REAL(domain, lang, selected_frameworks=selected_frameworks)

        def _ok(**kwargs):
            ai_calls.append(kwargs)
            return _AI_REPAIRED_CONFIDENCE_AR

        # Capture the real resolver before patching.
        global _RESOLVE_REAL
        _RESOLVE_REAL = _APP.get_strategy_domain_context
        with _Patch(_APP, 'get_strategy_domain_context', _spy_resolve), \
                _Patch(_APP, 'ai_repair_strategy_section', _ok):
            _APP.enforce_technical_strategy_depth(
                sections, lang='ar',
                domain='ERM', fw_short='COSO',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting',
            )
        # Section D must call get_strategy_domain_context with the ORIGINAL
        # (non-cyber) domain — never coerced to 'Cyber Security'.
        self.assertTrue(captured, 'get_strategy_domain_context was not called')
        self.assertEqual(captured[-1]['domain'], 'ERM',
                         'Section D must not coerce non-cyber domain to '
                         'Cyber Security fallback')
        self.assertNotIn('Cyber Security',
                         [c['domain'] for c in captured])
        self.assertEqual(captured[-1]['selected_frameworks'], ['COSO'])
        # And the AI repair call must carry the resolved (non-cyber) context.
        self.assertTrue(ai_calls)
        dctx = ai_calls[-1].get('domain_context') or {}
        self.assertNotEqual(dctx.get('code'), 'cyber',
                            'Resolved domain code must not be cyber for ERM input')


_RESOLVE_REAL = None  # populated inside the test above (kept for sanity)


# ---------------------------------------------------------------------------
# 7. AI failure → RepairError(section='confidence'), section unchanged.
# ---------------------------------------------------------------------------

class TestAIFailureRaisesRepairError(unittest.TestCase):

    def test_ai_repair_error_propagates_with_section_confidence(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)
        before = sections['confidence']

        def _raise(**_kw):
            raise _APP.RepairError('no provider available')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.enforce_technical_strategy_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'confidence')
        # No deterministic content must have been injected on failure.
        self.assertEqual(sections['confidence'], before,
                         'Original confidence section must be left UNCHANGED '
                         'on RepairError')

    def test_domain_resolution_error_raises_repair_error_confidence(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)
        before = sections['confidence']

        def _raise(*_a, **_kw):
            raise _APP.DomainResolutionError('unknown domain')

        with _Patch(_APP, 'get_strategy_domain_context', _raise):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.enforce_technical_strategy_depth(
                    sections, lang='ar',
                    domain='NotARealDomain', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'confidence')
        self.assertEqual(sections['confidence'], before)


# ---------------------------------------------------------------------------
# 8. Invalid AI-repaired confidence (too few rows) is rejected.
# ---------------------------------------------------------------------------

class TestInvalidRepairedConfidenceRejected(unittest.TestCase):

    def test_too_few_risk_rows_in_ai_output_raises_repair_error(self):
        sections = _make_sections(confidence=_THIN_CONFIDENCE_AR)
        before = sections['confidence']

        def _bad(**_kw):
            return _AI_INVALID_CONFIDENCE_AR  # only 2 risk rows

        with _Patch(_APP, 'ai_repair_strategy_section', _bad):
            with self.assertRaises(_APP.RepairError) as ctx:
                _APP.enforce_technical_strategy_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting',
                )
        self.assertEqual(getattr(ctx.exception, 'section', None), 'confidence')
        # Original section must NOT have been overwritten with the invalid
        # AI output.
        self.assertEqual(sections['confidence'], before,
                         'Invalid AI-repaired confidence must NOT be assigned '
                         'to sections[confidence]')


# ---------------------------------------------------------------------------
# 9. Final audit emits synth_failed:confidence when the failure is recorded.
# ---------------------------------------------------------------------------

class TestFinalAuditBlocksSynthFailedConfidence(unittest.TestCase):

    def test_synth_failed_confidence_recorded_via_mark_synth_failed(self):
        # Build a minimal container exactly like the production caller's
        # _synth_status dict and feed it the RepairError annotated by
        # Section D. _mark_synth_failed must record the failure under
        # the key 'confidence'.
        container = {}
        err = _APP.RepairError(
            'enforce_technical_strategy_depth[D]: AI provider unavailable')
        setattr(err, 'section', 'confidence')

        section = getattr(err, 'section', 'strategy')
        _APP._mark_synth_failed(container, section, err)
        self.assertEqual(container.get('synth_status', {}).get('confidence'),
                         'failed',
                         'final audit must see synth_status[confidence]=failed '
                         'so synth_failed:confidence defects are emitted')


# ---------------------------------------------------------------------------
# 10. AST scan: Section D no longer contains _risk_bank or cyber phrases.
# ---------------------------------------------------------------------------

class TestSectionDNoDeterministicRiskBank(unittest.TestCase):
    """Static guarantee that Section D inside
    ``enforce_technical_strategy_depth`` no longer references the
    deleted deterministic AR/EN ``_risk_bank`` or its cyber-specific
    row literals (PR-5B.6C.1).
    """

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        cls._fn_node = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'enforce_technical_strategy_depth'):
                cls._fn_node = node
                break
        assert cls._fn_node is not None, (
            'enforce_technical_strategy_depth function not found in app.py')

    def test_no_risk_bank_local_assigned_in_function(self):
        for node in ast.walk(self._fn_node):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == '_risk_bank':
                        self.fail(
                            '_risk_bank local must be removed from '
                            'enforce_technical_strategy_depth Section D '
                            '(PR-5B.6C.1 AI-first)')

    def test_no_cyber_risk_literal_phrases(self):
        forbidden = [
            'SIEM Integration Failure',
            'IAM/PAM',
            'Third-Party Cyber Exposure',
            'Untested Backup/DR',
            'فشل تكامل SIEM',
            'مقاومة نشر IAM/PAM',
            'مخاطر الأطراف الثالثة',
            'نقص الكفاءات السيبرانية',
            'MSSP',
        ]
        body = list(self._fn_node.body)
        # Skip the function docstring if present.
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        offending = []
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for phrase in forbidden:
                        if phrase in node.value:
                            offending.append(phrase)
        self.assertEqual(
            offending, [],
            'Deterministic cyber risk-bank phrases must be removed from '
            f'enforce_technical_strategy_depth: {sorted(set(offending))}')

    def test_section_d_calls_ai_repair_with_section_key_confidence(self):
        # Static proof of delegation: a Call to ai_repair_strategy_section
        # with section_key='confidence' must exist in the function body.
        found = False
        for node in ast.walk(self._fn_node):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'ai_repair_strategy_section'):
                for kw in node.keywords:
                    if (kw.arg == 'section_key'
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == 'confidence'):
                        found = True
                        break
            if found:
                break
        self.assertTrue(
            found,
            'enforce_technical_strategy_depth Section D must delegate to '
            'ai_repair_strategy_section(section_key="confidence", ...)')

    def test_section_d_annotates_repair_error_with_confidence(self):
        # Static proof of annotation: the function body must contain a
        # setattr(<err>, 'section', 'confidence') call.
        found = False
        for node in ast.walk(self._fn_node):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'setattr'
                    and len(node.args) >= 3
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == 'section'
                    and isinstance(node.args[2], ast.Constant)
                    and node.args[2].value == 'confidence'):
                found = True
                break
        self.assertTrue(
            found,
            "enforce_technical_strategy_depth Section D must "
            "setattr(err, 'section', 'confidence') on RepairError")


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
