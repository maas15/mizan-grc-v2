"""PR-5B.6C.2: AI-first ``synthesize_confidence_depth``.

This module pins down the post-migration contract for the confidence
synthesizer:

  * Sufficient confidence (score + justification + ``>= min_csf`` CSF
    rows + ``>= min_risk`` risk rows with mitigation) does NOT trigger
    AI repair.
  * Insufficient / malformed confidence delegates to
    :func:`ai_repair_strategy_section` with ``section_key='confidence'``.
  * Strict domain resolution: no ``domain or 'Cyber Security'`` fallback;
    a :class:`DomainResolutionError` is converted to a
    :class:`RepairError` annotated with ``section='confidence'``.
  * On AI failure or invalid repaired output, a :class:`RepairError` is
    raised with ``section='confidence'`` and ``sections['confidence']``
    is left UNCHANGED — no deterministic CSF / risk bank is ever
    consulted.
  * The two production call sites (``_apply_final_synthesis_pass`` and
    ``converge_strategy_sections``) catch ``RepairError`` and route
    through ``_mark_synth_failed`` so the post-normalization save gate
    refuses the strategy.
  * AST scan: ``synthesize_confidence_depth`` no longer references the
    deleted deterministic-bank vocabulary (templates_ar/en, risks_ar/en,
    "Resource & Skills Constraints", "Change Resistance", etc.).

Run:  python -m pytest tests/test_synthesize_confidence_ai_first_pr5b6c2.py -q
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
    'sqlite:///tmp/test_synthesize_confidence_ai_first_pr5b6c2.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_APP = importlib.import_module('app')
_APP_PY_PATH = os.path.join(_REPO_ROOT, 'app.py')


# ---------------------------------------------------------------------------
# _Patch helper (mirrors PR-5B.6B test pattern).
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
# 5 risk rows with mitigation).
# ---------------------------------------------------------------------------

_REPAIRED_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 65%\n\n"
    "### مبررات التقييم\n\n"
    "تستند هذه الدرجة إلى مستوى النضج الحالي والفجوات المحددة في "
    "الضوابط المعتمدة. كما تأخذ في الاعتبار القدرة التنفيذية المتاحة.\n\n"
    "### عوامل النجاح الحرجة\n\n"
    "| # | العامل | الوصف | الأهمية |\n"
    "|---|-------|-------|--------|\n"
    "| 1 | دعم القيادة | رعاية تنفيذية فعّالة | حرج |\n"
    "| 2 | توفر الكفاءات | كوادر مؤهلة لتشغيل الضوابط | عالٍ |\n"
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
)

_REPAIRED_EN = (
    "## 7. Confidence Assessment & Risks\n\n"
    "**Confidence Score:** 65%\n\n"
    "### Score Justification\n\n"
    "This score reflects the current maturity posture and the gaps "
    "identified in the chosen control framework. It also accounts "
    "for the executive capacity available to execute remediation.\n\n"
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
            result = _APP.synthesize_confidence_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(_calls, [],
                         'AI repair must not be called for sufficient confidence')
        self.assertEqual(sections['confidence'], original,
                         'Sufficient confidence must remain byte-identical')
        self.assertEqual(result['csf_added'], 0)
        self.assertEqual(result['risks_added'], 0)
        self.assertFalse(result['score_added'])
        self.assertFalse(result['justification_added'])


# ---------------------------------------------------------------------------
# 2-5. Insufficient inputs trigger AI repair (section_key='confidence').
# ---------------------------------------------------------------------------

class TestInsufficientTriggersAI(unittest.TestCase):

    def _run(self, conf, lang='ar', repaired=None):
        sections = {'confidence': conf}
        _calls = []

        def _spy(**kwargs):
            _calls.append(kwargs)
            return repaired or _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.synthesize_confidence_depth(
                sections, lang=lang,
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        return sections, _calls

    def test_missing_score_triggers_ai_repair(self):
        # Confidence with justification + tables but NO score line.
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
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_missing_justification_triggers_ai_repair(self):
        conf = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
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
        )
        # Strip any words that might fall under just_inline_re.
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_insufficient_csf_rows_triggers_ai_repair(self):
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
        )
        _, calls = self._run(conf)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get('section_key'), 'confidence')

    def test_insufficient_risk_rows_triggers_ai_repair(self):
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


# ---------------------------------------------------------------------------
# 6-7. AI output fully replaces the confidence section (no merging).
# ---------------------------------------------------------------------------

class TestAIOutputReplacesSection(unittest.TestCase):

    def test_ai_output_replaces_section_not_merged(self):
        sections = {'confidence': '## 7. تقييم الثقة والمخاطر\n\nسطر فاسد.\n'}

        def _spy(**_kw):
            return _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.synthesize_confidence_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(sections['confidence'], _REPAIRED_AR,
                         'AI output must REPLACE, not merge with, the section')
        self.assertNotIn('سطر فاسد', sections['confidence'])

    def test_malformed_old_rows_not_merged(self):
        sections = {'confidence': (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | بنية فاسدة | -- | -- | -- |\n"
        )}

        def _spy(**_kw):
            return _REPAIRED_AR

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            _APP.synthesize_confidence_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
            )
        self.assertEqual(sections['confidence'], _REPAIRED_AR)
        self.assertNotIn('بنية فاسدة', sections['confidence'])


# ---------------------------------------------------------------------------
# 8. Deterministic CSF/risk bank strings are not inserted on AI failure or
#    sufficient-input no-op.
# ---------------------------------------------------------------------------

class TestNoDeterministicBankInsertion(unittest.TestCase):

    _BANK_PHRASES = (
        'Resource & Skills Constraints', 'Change Resistance',
        'Technology Vendor Delays', 'Scope Creep', 'Regulatory Change',
        'Executive Leadership Support', 'Qualified Resources',
        'محدودية الموارد والكفاءات', 'مقاومة التغيير',
        'تأخر موردي التقنية',
    )

    def test_ai_failure_does_not_insert_bank_strings(self):
        sections = {'confidence': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_confidence_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # Section must remain unchanged (empty) — no deterministic
        # bank rows leaked in on failure.
        self.assertEqual(sections.get('confidence', ''), '')


# ---------------------------------------------------------------------------
# 9. Non-cyber AI output rejects cyber contamination — handled inside
#    ``ai_repair_strategy_section`` via forbidden_terms; the synth must
#    propagate the resulting RepairError with section='confidence'.
# ---------------------------------------------------------------------------

class TestCyberContaminationRejected(unittest.TestCase):

    def test_non_cyber_domain_contamination_propagates_repair_error(self):
        sections = {'confidence': ''}

        def _raise_contam(**_kw):
            raise _APP.RepairError(
                "ai_repair[confidence]: forbidden cross-domain terms in AI "
                "output: ['SIEM', 'phishing']"
            )

        with _Patch(_APP, 'ai_repair_strategy_section', _raise_contam):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_confidence_depth(
                    sections, lang='en',
                    domain='Artificial Intelligence',
                    fw_short='NCA AI Ethics',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        self.assertEqual(sections.get('confidence', ''), '')


# ---------------------------------------------------------------------------
# 10. AI failure raises RepairError(section='confidence').
# ---------------------------------------------------------------------------

class TestAIFailureRaisesRepairError(unittest.TestCase):

    def test_ai_repair_error_propagates_with_section_confidence(self):
        sections = {'confidence': ''}

        def _raise(**_kw):
            raise _APP.RepairError('no provider available')

        with _Patch(_APP, 'ai_repair_strategy_section', _raise):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_confidence_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        self.assertEqual(sections.get('confidence', ''), '')

    def test_invalid_domain_raises_repair_error_confidence(self):
        sections = {'confidence': ''}

        def _raise_dre(*_a, **_kw):
            raise _APP.DomainResolutionError('unknown domain')

        with _Patch(_APP, 'get_strategy_domain_context', _raise_dre):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_confidence_depth(
                    sections, lang='ar',
                    domain='NotARealDomain', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        self.assertEqual(sections.get('confidence', ''), '')


# ---------------------------------------------------------------------------
# 11-13. Invalid AI output is rejected (missing CSF / risks / score).
# ---------------------------------------------------------------------------

class TestInvalidAIOutputRejected(unittest.TestCase):

    def _expect_reject(self, repaired):
        sections = {'confidence': ''}

        def _spy(**_kw):
            return repaired

        with _Patch(_APP, 'ai_repair_strategy_section', _spy):
            with self.assertRaises(_APP.RepairError) as _ctx:
                _APP.synthesize_confidence_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(getattr(_ctx.exception, 'section', None),
                         'confidence')
        # Original section MUST remain unchanged on rejection.
        self.assertEqual(sections.get('confidence', ''), '')

    def test_missing_csf_table_rejected(self):
        # Score + justification + risk table, but no CSF table.
        repaired = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص مبرر.\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | متوسط | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
        )
        self._expect_reject(repaired)

    def test_missing_risk_table_rejected(self):
        repaired = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "**درجة الثقة:** 65%\n\n"
            "### مبررات التقييم\n\nنص مبرر.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n"
        )
        self._expect_reject(repaired)

    def test_missing_score_rejected(self):
        # No **درجة الثقة:** / Confidence Score line.
        repaired = (
            "## 7. تقييم الثقة والمخاطر\n\n"
            "### مبررات التقييم\n\nنص مبرر.\n\n"
            "### عوامل النجاح الحرجة\n\n"
            "| # | العامل | الوصف | الأهمية |\n"
            "|---|-------|-------|--------|\n"
            "| 1 | أ | ب | حرج |\n| 2 | ج | د | عالٍ |\n"
            "| 3 | هـ | و | عالٍ |\n| 4 | ز | ح | عالٍ |\n\n"
            "### المخاطر الرئيسية\n\n"
            "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
            "|---|--------|-----------|--------|-------------|\n"
            "| 1 | أ | متوسط | عالٍ | خطة |\n| 2 | ب | متوسط | عالٍ | خطة |\n"
            "| 3 | ج | متوسط | عالٍ | خطة |\n| 4 | د | متوسط | عالٍ | خطة |\n"
        )
        self._expect_reject(repaired)


# ---------------------------------------------------------------------------
# 14. ``_apply_final_synthesis_pass`` marks synth_failed:confidence on
#     RepairError (catch RepairError before generic Exception).
# ---------------------------------------------------------------------------

class TestApplyFinalSynthesisPassFailClosed(unittest.TestCase):

    def test_apply_final_synth_marks_confidence_on_repair_error(self):
        # Mock synthesize_confidence_depth to raise an annotated RepairError;
        # the call site must catch it and route through _mark_synth_failed.
        def _raise(*_a, **_kw):
            err = _APP.RepairError('boom')
            setattr(err, 'section', 'confidence')
            raise err

        # Stub out the other synthesizers so the pass terminates quickly.
        def _noop(*_a, **_kw):
            return {}

        def _noop_int(*_a, **_kw):
            return 0

        sections = {
            'vision': '', 'pillars': '', 'environment': '', 'gaps': '',
            'roadmap': '', 'kpis': '', 'confidence': 'malformed',
        }

        with _Patch(_APP, 'synthesize_objectives_depth', _noop), \
             _Patch(_APP, 'synthesize_gaps_depth', _noop_int), \
             _Patch(_APP, 'synthesize_pillars_depth', _noop), \
             _Patch(_APP, 'synthesize_roadmap_depth', _noop_int), \
             _Patch(_APP, 'synthesize_kpi_depth', _noop_int), \
             _Patch(_APP, 'synthesize_confidence_depth', _raise):
            summary = _APP._apply_final_synthesis_pass(
                sections, 'ar', 'Cyber Security', 'NCA ECC',
                ctx={'org_name': 'Test', 'maturity': 'initial',
                     'generation_mode': 'drafting'})
        self.assertEqual(summary.get('synth_status', {}).get('confidence'),
                         'failed')


# ---------------------------------------------------------------------------
# 15. ``converge_strategy_sections`` marks synth_failed:confidence on
#     RepairError (static-source proof to avoid running the convergence
#     loop, which depends on heavy upstream context).
# ---------------------------------------------------------------------------

class TestConvergeStrategySectionsFailClosed(unittest.TestCase):

    def test_converge_call_site_handles_repair_error(self):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            src = f.read()
        # Find the converge_strategy_sections function source.
        tree = ast.parse(src)
        fn_node = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'converge_strategy_sections'):
                fn_node = node
                break
        self.assertIsNotNone(fn_node, 'converge_strategy_sections not found')
        body_src = ast.unparse(fn_node)
        # The confidence branch must catch RepairError before Exception
        # and call _mark_synth_failed(log, 'confidence', ...).
        self.assertIn('synthesize_confidence_depth(', body_src)
        self.assertIn("_mark_synth_failed(log, 'confidence'", body_src)


# ---------------------------------------------------------------------------
# 16. ``_final_strategy_audit`` blocks synth_failed:confidence.
# ---------------------------------------------------------------------------

class TestFinalAuditBlocksSynthFailedConfidence(unittest.TestCase):

    def test_final_audit_emits_synth_failed_defect_for_confidence(self):
        sections = {
            'vision': _REPAIRED_AR, 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': '', 'kpis': '',
            'confidence': _REPAIRED_AR,
        }
        synth_status = {'confidence': 'failed'}
        defects = _APP._final_strategy_audit(
            sections, 'ar', None, synth_status=synth_status)
        # synth_failed:<section> defect must appear for confidence.
        self.assertTrue(
            any(code == 'synth_failed:confidence'
                for (_sec, code, *_rest) in defects),
            f'Expected synth_failed:confidence defect; got {defects}')


# ---------------------------------------------------------------------------
# AST / source proof: deterministic-bank vocabulary is gone from
# ``synthesize_confidence_depth``.
# ---------------------------------------------------------------------------

class TestNoDeterministicBankInConfidenceSynth(unittest.TestCase):
    """Static guarantee that the deterministic CSF / risk bank is no
    longer present inside ``synthesize_confidence_depth``.
    """

    @classmethod
    def setUpClass(cls):
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        cls._fn_node = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == 'synthesize_confidence_depth'):
                cls._fn_node = node
                break
        assert cls._fn_node is not None, (
            'synthesize_confidence_depth function not found in app.py')

    def test_no_deterministic_locals(self):
        forbidden_locals = {'templates_ar', 'templates_en',
                            'risks_ar', 'risks_en'}
        for node in ast.walk(self._fn_node):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id in forbidden_locals:
                        self.fail(
                            f'Local {tgt.id!r} must be removed from '
                            f'synthesize_confidence_depth (PR-5B.6C.2 AI-first)')

    def test_no_deterministic_phrases(self):
        forbidden = [
            'Resource & Skills Constraints', 'Change Resistance',
            'Technology Vendor Delays', 'Scope Creep', 'Regulatory Change',
            'Executive Leadership Support', 'Qualified Resources & Talent',
        ]
        # Skip the function docstring (first stmt if Expr(Constant(str))).
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
            f'synthesize_confidence_depth: {sorted(set(offending))}',
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
            'synthesize_confidence_depth must delegate to '
            'ai_repair_strategy_section(section_key="confidence", ...)')


# ---------------------------------------------------------------------------
# Schema entry registered for "confidence" with new placeholders.
# ---------------------------------------------------------------------------

class TestConfidenceSchemaRegistered(unittest.TestCase):

    def test_schema_has_confidence_entry_with_new_placeholders(self):
        schema = getattr(_APP, '_AI_REPAIR_SECTION_SCHEMA', None)
        self.assertIsInstance(schema, dict)
        self.assertIn('confidence', schema)
        self.assertIn('ar', schema['confidence'])
        self.assertIn('en', schema['confidence'])

        ar = schema['confidence']['ar']
        en = schema['confidence']['en']
        # Canonical headings.
        self.assertIn('## 7. تقييم الثقة والمخاطر', ar)
        self.assertIn('## 7. Confidence Assessment & Risks', en)
        # Score / justification / CSF / risks structure.
        self.assertIn('درجة الثقة', ar)
        self.assertIn('Confidence Score', en)
        self.assertIn('مبررات التقييم', ar)
        self.assertIn('Score Justification', en)
        self.assertIn('عوامل النجاح الحرجة', ar)
        self.assertIn('Critical Success Factors', en)
        self.assertIn('المخاطر الرئيسية', ar)
        self.assertIn('Key Risks', en)
        # New placeholders (AI repair must format with both minimums).
        self.assertIn('{min_csf_rows}', ar)
        self.assertIn('{min_risk_rows}', ar)
        self.assertIn('{min_csf_rows}', en)
        self.assertIn('{min_risk_rows}', en)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
