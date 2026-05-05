"""PR-5B.6C.3: AI-first ``repair_confidence_risk_section``.

This module pins down the post-migration contract for the deterministic
confidence/risk REPAIR pass that runs in the production strategy
pipeline (``api_generate_strategy`` final repair pass):

  * Schema-only cleanup (duplicate '### المخاطر الرئيسية' / '### Key
    Risks' heading collapse) is preserved as a no-AI step.
  * Sufficient confidence (score + justification + ``>= _RICHNESS_MIN_CSF_ROWS``
    CSF rows + ``>= 6`` risk rows with mitigation + exactly one risk
    heading) is a no-op — AI is not called and the section is not
    mutated beyond the duplicate-heading collapse.
  * Insufficient / malformed confidence delegates to
    ``ai_repair_strategy_section(section_key='confidence', ...)`` for
    BOTH cyber and non-cyber domains.  No deterministic CSF / risk bank
    rows (CISO, SOC, SIEM, IAM/PAM/MFA, MSSP, DR/RTO, Tabletop
    Exercise, رئيس الأمن السيبراني, فريق SOC, …) are ever inserted.
  * On AI failure or invalid repaired output, ``RepairError`` is raised
    with ``setattr(err, 'section', 'confidence')`` and
    ``sections['confidence']`` is left UNCHANGED.
  * The production caller catches ``RepairError`` before generic
    ``Exception`` and routes through ``_mark_synth_failed`` so the
    post-normalization audit gate (``_final_strategy_audit``) blocks
    ``synth_failed:confidence``.

Run:
    python -m pytest tests/test_repair_confidence_ai_first_pr5b6c3.py -q
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
    'DATABASE_URL',
    'sqlite:///tmp/test_repair_confidence_ai_first_pr5b6c3.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper (mirrors PR-5B.6C.2 test pattern).
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
# Canonical AR / EN repair fixtures (score + justification + 4 CSF rows +
# 6 risk rows with mitigation, exactly one risk heading).
# ---------------------------------------------------------------------------

_REPAIRED_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 65%\n\n"
    "### مبررات التقييم\n\n"
    "تستند هذه الدرجة إلى مستوى النضج الحالي والفجوات المحددة. "
    "تأخذ في الاعتبار القدرة التنفيذية المتاحة.\n\n"
    "### عوامل النجاح الحرجة\n\n"
    "| # | العامل | الوصف | الأهمية |\n"
    "|---|-------|-------|--------|\n"
    "| 1 | دعم القيادة | رعاية تنفيذية فعّالة | حرج |\n"
    "| 2 | توفر الكفاءات | كوادر مؤهلة | عالٍ |\n"
    "| 3 | حوكمة قابلة للتشغيل | لجنة توجيه دورية | عالٍ |\n"
    "| 4 | تمويل مستقر | ميزانية متعددة السنوات | عالٍ |\n\n"
    "### المخاطر الرئيسية\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر اعتماد الحوكمة | متوسط | عالٍ | ورش تنفيذية مبكرة |\n"
    "| 2 | محدودية الميزانية | متوسط | عالٍ | جدولة متعددة السنوات |\n"
    "| 3 | فجوات الكفاءات | عالٍ | عالٍ | برامج تدريب وتوظيف |\n"
    "| 4 | تأخر تكامل الأنظمة | متوسط | عالٍ | تنفيذ مرحلي مع اختبار قبول |\n"
    "| 5 | تغيّر المتطلبات | متوسط | عالٍ | مراجعة ربع سنوية |\n"
    "| 6 | تأخر التمويل | متوسط | عالٍ | اعتماد ميزانية متعددة السنوات |\n"
)

_REPAIRED_EN = (
    "## 7. Confidence Assessment & Risks\n\n"
    "**Confidence Score:** 65%\n\n"
    "### Score Justification\n\n"
    "This score reflects the current maturity posture and the gaps "
    "identified. It accounts for the executive capacity available.\n\n"
    "### Critical Success Factors\n\n"
    "| # | Factor | Description | Importance |\n"
    "|---|--------|-------------|------------|\n"
    "| 1 | Executive Sponsorship | Active leadership support | Critical |\n"
    "| 2 | Skilled Resources | Qualified personnel | High |\n"
    "| 3 | Operable Governance | Standing steering committee | High |\n"
    "| 4 | Stable Funding | Multi-year budget plan | High |\n\n"
    "### Key Risks\n\n"
    "| # | Risk | Likelihood | Impact | Mitigation Plan |\n"
    "|---|------|------------|--------|-----------------|\n"
    "| 1 | Governance Delay | Medium | High | Early executive workshops |\n"
    "| 2 | Insufficient Budget | Medium | High | Multi-year budget plan |\n"
    "| 3 | Capability Gaps | High | High | Recruitment and training |\n"
    "| 4 | Integration Delay | Medium | High | Phased rollout with UAT |\n"
    "| 5 | Regulatory Change | Medium | High | Quarterly review cadence |\n"
    "| 6 | Funding Lag | Medium | High | Multi-year budget commitment |\n"
)


def _kwargs(domain='Cyber Security', org='Test Org', frameworks=None,
            sector='Government'):
    return dict(
        domain=domain,
        org_name=org,
        frameworks=frameworks or ['NCA ECC'],
        sector=sector,
    )


# ---------------------------------------------------------------------------
# 1. Sufficient confidence → no AI call, section unchanged.
# ---------------------------------------------------------------------------

class TestSufficientConfidenceNoOp(unittest.TestCase):

    def test_valid_confidence_skips_ai(self):
        sections = {'confidence': _REPAIRED_AR}
        original = sections['confidence']
        _calls = []

        def _spy(**kwargs):
            _calls.append(kwargs)
            return _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.repair_confidence_risk_section(
                sections, lang='ar', **_kwargs())
        self.assertEqual(_calls, [],
                         'AI repair must not be called for sufficient confidence')
        self.assertEqual(sections['confidence'], original,
                         'Sufficient confidence must remain byte-identical')
        self.assertEqual(result['csf_rows_added'], 0)
        self.assertEqual(result['risk_rows_added'], 0)
        self.assertFalse(result['score_added'])
        self.assertEqual(result['dup_headings_removed'], 0)


# ---------------------------------------------------------------------------
# 2-5. Insufficient inputs trigger AI repair (section_key='confidence').
# ---------------------------------------------------------------------------

class TestInsufficientTriggersAI(unittest.TestCase):

    def _run(self, conf, lang='ar', repaired=None, domain='Cyber Security'):
        sections = {'confidence': conf}
        _calls = []

        def _spy(**kwargs):
            _calls.append(kwargs)
            return repaired if repaired is not None else _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.repair_confidence_risk_section(
                sections, lang=lang, **_kwargs(domain=domain))
        return sections, _calls

    def test_insufficient_csf_rows_calls_ai(self):
        # Only 1 CSF row.
        conf = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | عالٍ | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
            "| 5 | هـ | متوسط | عالٍ | خطة |\n| 6 | و | متوسط | عالٍ | خطة |\n"
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_insufficient_risk_rows_calls_ai(self):
        conf = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n"
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_missing_score_calls_ai(self):
        conf = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "### مبررات التقييم\n\nنص.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | عالٍ | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
            "| 5 | هـ | متوسط | عالٍ | خطة |\n| 6 | و | متوسط | عالٍ | خطة |\n"
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_missing_justification_calls_ai(self):
        # No justification heading and no inline justification keyword.
        # NB: we use a benign Arabic heading ("ملخص") so the
        # ``just_inline_re`` doesn't accidentally fire.
        conf = (
            "## 7. تقييم\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### ملخص\n\nنص عام.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | عالٍ | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
            "| 5 | هـ | متوسط | عالٍ | خطة |\n| 6 | و | متوسط | عالٍ | خطة |\n"
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')


# ---------------------------------------------------------------------------
# 6. Non-cyber AI failure RE-RAISES RepairError(section='confidence')
#    instead of swallowing.
# ---------------------------------------------------------------------------

class TestNonCyberAIFailureReRaises(unittest.TestCase):

    def test_non_cyber_ai_failure_propagates_repair_error(self):
        sections = {'confidence': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.repair_confidence_risk_section(
                    sections, lang='en',
                    **_kwargs(domain='Artificial Intelligence',
                              frameworks=[]))
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        # Section MUST remain unchanged on failure (no cyber bank leak).
        self.assertEqual(sections.get('confidence', ''), '')


# ---------------------------------------------------------------------------
# 7. Cyber AI failure RE-RAISES RepairError(section='confidence').
# ---------------------------------------------------------------------------

class TestCyberAIFailureReRaises(unittest.TestCase):

    def test_cyber_ai_failure_propagates_repair_error(self):
        sections = {'confidence': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.repair_confidence_risk_section(
                    sections, lang='ar', **_kwargs(domain='Cyber Security'))
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        self.assertEqual(sections.get('confidence', ''), '')


# ---------------------------------------------------------------------------
# 8. AI-repaired section replaces confidence section ONLY after validation.
# ---------------------------------------------------------------------------

class TestAIOutputReplacesAfterValidation(unittest.TestCase):

    def test_valid_ai_output_replaces_section(self):
        sections = {'confidence': '## 7. تقييم الثقة والمخاطر\n\nسطر فاسد.\n'}

        def _spy(**_kw):
            return _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.repair_confidence_risk_section(
                sections, lang='ar', **_kwargs())
        self.assertEqual(sections['confidence'], _REPAIRED_AR)
        self.assertNotIn('سطر فاسد', sections['confidence'])

    def test_english_ai_output_replaces_section(self):
        sections = {'confidence': '## 7. Confidence Assessment & Risks\n\nold.\n'}

        def _spy(**_kw):
            return _REPAIRED_EN

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.repair_confidence_risk_section(
                sections, lang='en', **_kwargs())
        self.assertEqual(sections['confidence'], _REPAIRED_EN)


# ---------------------------------------------------------------------------
# 9-10. Invalid AI output is rejected; original section unchanged.
# ---------------------------------------------------------------------------

class TestInvalidAIOutputRejected(unittest.TestCase):

    def _expect_reject(self, repaired, lang='ar'):
        original = "## 7. تقييم الثقة والمخاطر\n\nأصلي.\n"
        sections = {'confidence': original}

        def _spy(**_kw):
            return repaired

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.repair_confidence_risk_section(
                    sections, lang=lang, **_kwargs())
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        # Original confidence section MUST remain unchanged on rejection.
        self.assertEqual(sections.get('confidence', ''), original)

    def test_too_few_csf_rows_rejected(self):
        # Score + justification + risks but only 1 CSF row.
        repaired = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص مبرر.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | متوسط | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
            "| 5 | هـ | متوسط | عالٍ | خطة |\n| 6 | و | متوسط | عالٍ | خطة |\n"
        )
        self._expect_reject(repaired)

    def test_too_few_risk_rows_rejected(self):
        repaired = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص مبرر.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n"
        )
        self._expect_reject(repaired)


# ---------------------------------------------------------------------------
# 11. Deterministic CSF / risk bank strings are NOT inserted.
# ---------------------------------------------------------------------------

class TestNoDeterministicBankInsertion(unittest.TestCase):

    _BANK_PHRASES = (
        'MSSP',
        'Tabletop Exercise',
        'IAM/PAM/MFA',
        'فريق SOC',
        'رئيس الأمن السيبراني',
        'SIEM Integration',
    )

    def test_ai_failure_does_not_insert_bank_strings(self):
        sections = {'confidence': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError):
                _APP.repair_confidence_risk_section(
                    sections, lang='en',
                    **_kwargs(domain='Cyber Security'))
        text = sections.get('confidence', '')
        for term in self._BANK_PHRASES:
            self.assertNotIn(
                term, text,
                f'Bank phrase {term!r} must NOT leak in on AI failure')

    def test_no_op_path_does_not_insert_bank_strings(self):
        sections = {'confidence': _REPAIRED_AR}

        def _spy(**_kw):  # would be cyber-tainted bank if it were called
            return ('CISO oversees SOC, SIEM Integration, IAM/PAM/MFA, '
                    'MSSP and Tabletop Exercise.')

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.repair_confidence_risk_section(
                sections, lang='ar', **_kwargs())
        # Already-sufficient inputs short-circuit before AI.
        self.assertEqual(sections['confidence'], _REPAIRED_AR)
        for term in self._BANK_PHRASES:
            self.assertNotIn(term, sections['confidence'])


# ---------------------------------------------------------------------------
# 12. Production caller marks ``synth_failed:confidence`` on RepairError.
# ---------------------------------------------------------------------------

class TestProductionCallerFailClosed(unittest.TestCase):
    """Static-source proof: the caller around ``api_generate_strategy``
    final repair pass catches ``RepairError`` before generic ``Exception``
    and routes through ``_mark_synth_failed`` with section 'confidence'.
    """

    def test_caller_catches_repair_error_and_marks_synth_failed(self):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            src = f.read()
        # Locate the call site.
        idx = src.find('_risk_repair = repair_confidence_risk_section(')
        self.assertGreater(idx, 0,
                           'production caller for repair_confidence_risk_section'
                           ' must exist')
        # Examine a generous window around the call site.
        window = src[idx:idx + 2000]
        self.assertIn('except RepairError', window,
                      'production caller must handle RepairError before generic'
                      ' Exception')
        # Routes through _mark_synth_failed with section attribute.
        self.assertIn('_mark_synth_failed(_synth_status,', window)
        self.assertIn("getattr(_crre, 'section', 'confidence')", window)
        # RepairError handler must precede the generic Exception handler.
        self.assertLess(
            window.find('except RepairError'),
            window.find('except Exception'),
            'except RepairError must come BEFORE except Exception')


# ---------------------------------------------------------------------------
# 13. ``_final_strategy_audit`` blocks ``synth_failed:confidence``.
# ---------------------------------------------------------------------------

class TestFinalAuditBlocksSynthFailedConfidence(unittest.TestCase):

    def test_final_audit_emits_synth_failed_defect_for_confidence(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': '', 'kpis': '',
            'confidence': _REPAIRED_AR,
        }
        synth_status = {'confidence': 'failed'}
        defects = _APP._final_strategy_audit(
            sections, 'ar', None, synth_status=synth_status)
        self.assertTrue(
            any(code == 'synth_failed:confidence'
                for (_sec, code, *_rest) in defects),
            f'Expected synth_failed:confidence defect; got {defects}')


# ---------------------------------------------------------------------------
# 14. Duplicate-heading collapse still works as schema-only cleanup.
# ---------------------------------------------------------------------------

class TestDuplicateHeadingCollapseSchemaOnly(unittest.TestCase):

    def test_duplicate_risk_heading_collapsed_no_ai_when_already_sufficient(self):
        # Build a confidence section that has TWO '### المخاطر الرئيسية'
        # headings and is otherwise sufficient under the FIRST heading.
        # After collapse, the section must satisfy the sufficiency check
        # and AI must not be called.
        conf = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | عالٍ | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
            "| 5 | هـ | متوسط | عالٍ | خطة |\n| 6 | و | متوسط | عالٍ | خطة |\n"
            "\n### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | duplicate | متوسط | عالٍ | خطة |\n"
        )
        sections = {'confidence': conf}
        _calls = []

        def _spy(**kw):
            _calls.append(kw)
            return _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            result = _APP.repair_confidence_risk_section(
                sections, lang='ar', **_kwargs())
        self.assertEqual(result['dup_headings_removed'], 1)
        self.assertEqual(_calls, [],
                         'AI must NOT be called when collapse alone yields '
                         'a sufficient section')
        # Exactly one risk heading after collapse.
        self.assertEqual(
            sections['confidence'].count('### المخاطر الرئيسية'), 1)


# ---------------------------------------------------------------------------
# AST / source proof: deterministic CSF / risk bank vocabulary is gone
# from ``repair_confidence_risk_section``.
# ---------------------------------------------------------------------------

class TestNoDeterministicBankInRepairConfidence(unittest.TestCase):
    """Static guarantee that the deterministic CSF / risk bank is no
    longer present inside ``repair_confidence_risk_section``.
    """

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        cls._fn_node = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'repair_confidence_risk_section'):
                cls._fn_node = node
                break
        assert cls._fn_node is not None, (
            'repair_confidence_risk_section function not found in app.py')

    def test_no_deterministic_locals(self):
        forbidden_locals = {'_csf_bank', '_risk_bank',
                            '_csf_block', '_risk_block'}
        for node in ast.walk(self._fn_node):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id in forbidden_locals:
                        self.fail(
                            f'Local {tgt.id!r} must be removed from '
                            f'repair_confidence_risk_section (PR-5B.6C.3)')

    def test_no_deterministic_phrases(self):
        forbidden = [
            'MSSP', 'Tabletop Exercise', 'IAM/PAM/MFA',
            'فريق SOC', 'رئيس الأمن السيبراني',
            'SIEM Integration Failure',
        ]
        body = list(self._fn_node.body)
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
            f'Deterministic CSF/risk bank phrases must be removed from '
            f'repair_confidence_risk_section: {sorted(set(offending))}',
        )

    def test_calls_ai_repair_with_confidence(self):
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
            'repair_confidence_risk_section must delegate to '
            'ai_repair_strategy_section(section_key="confidence", ...)')

    def test_raises_repair_error_with_section_attr(self):
        # AST-level proof: at least one setattr(err, 'section',
        # 'confidence') invocation exists in the function body.
        found = False
        for node in ast.walk(self._fn_node):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'setattr'
                    and len(node.args) >= 3):
                a1, a2 = node.args[1], node.args[2]
                if (isinstance(a1, ast.Constant) and a1.value == 'section'
                        and isinstance(a2, ast.Constant)
                        and a2.value == 'confidence'):
                    found = True
                    break
        self.assertTrue(
            found,
            'repair_confidence_risk_section must annotate RepairError '
            'with section="confidence" via setattr')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
