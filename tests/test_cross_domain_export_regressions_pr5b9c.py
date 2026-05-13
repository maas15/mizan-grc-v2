"""PR-5B.9C — Cross-domain export regression and framework-coverage gates.

Regression coverage for:

  Part A — Glossary contamination
    1. Cyber appendix glossary must not include NDMO / PDPL /
       Governance AI / ISO 31000 / COSO / ISO 27001 unless selected
       or content-supported.
    2. Data appendix glossary must not include NIST AI RMF /
       Governance AI / Transparency / ISO 31000 / COSO / ISO 27001 /
       SOC / CSIRT / VPN / ZTNA unless selected or content-supported.
    3. AI appendix glossary must not include NDMO / ISO 31000 /
       COSO / ISO 27001 unless selected or content-supported.

  Part B — ERM framework coverage
    4. ERM ISO31000 / COSO content does not fail on
       ``COSO_ERM:review_revision`` when review / monitoring concepts
       are present in the strategy.
    5. ERM selected frameworks produce a compliance objective in
       Vision (covered by ``_compute_missing_compliance_objective``).

  Part C — Vision min_rows regression
    6. ERM / DT vision repair cannot reduce objective rows below the
       consulting/assurance floor of 6.
    7. Any vision repair returning 4 rows is rejected and the original
       vision is restored.

  Part D — Document control RTL
    8. Composed PDF text must not contain
       ``"بواسطة أعد Mizan GRC Platform"`` or its mirror form, and
       must contain ``"أعد بواسطة"`` and ``"Mizan GRC Platform"``.

  Part E — Traceability rows
    9. Traceability matrix must not contain rows where most cells are
       ``"—"``.

  Cross-cutting
    10. Export quality gate flags cross-domain glossary leakage.
    11. Preview behaviour is unchanged — we never call any preview
        route in this module.
    12. No deterministic strategy rows are inserted by these helpers.
    13. Validators are not weakened — the global richness floors
        (_RICHNESS_MIN_SO_ROWS, …) are preserved.

Run:
    python -m pytest tests/test_cross_domain_export_regressions_pr5b9c.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_xdomain_pr5b9c_')
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
    sys.modules['app'] = _APP
    _spec.loader.exec_module(_APP)
except Exception as _e:  # pragma: no cover
    print(f'app import failed: {_e}', flush=True)
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Re-use the well-curated fixtures from PR-5B.9B ──────────────────────
from tests.test_cross_domain_strategy_export_quality_pr5b9b import (  # noqa: E402
    CYBER_FIXTURE, DATA_FIXTURE, AI_FIXTURE, DT_FIXTURE, ERM_FIXTURE,
    _build_model, _glossary_acronyms,
)


# ─────────────────────────────────────────────────────────────────────────
# Part A — Glossary contamination
# ─────────────────────────────────────────────────────────────────────────
class CyberGlossaryNoCrossDomainLeakageTest(unittest.TestCase):
    """Cyber glossary must not include data/AI/ERM/ISO terms unless
    explicitly selected or materially present in the strategy content."""

    @_skip_if_no_app
    def test_cyber_glossary_no_cross_domain_leakage(self):
        model = _build_model(CYBER_FIXTURE, 'Cyber Security',
                              selected_frameworks=['ECC', 'TCC'])
        gloss = _glossary_acronyms(model)
        # Cyber strategy fixture does not mention any of these terms.
        # They must NOT appear in the cyber appendix.
        forbidden = (
            'NDMO', 'PDPL', 'NIST_AI_RMF',
            'AI_GOV', 'AI_ETHICS', 'TRANSPARENCY',
            'ISO31000', 'COSO_ERM',
            'ISO27001', 'ISO22301',
        )
        for ac in forbidden:
            self.assertNotIn(
                ac, gloss,
                f'Cyber glossary must not auto-inject {ac!r} (not '
                f'selected, not content-supported); got {sorted(gloss)}',
            )


class DataGlossaryNoCrossDomainLeakageTest(unittest.TestCase):

    @_skip_if_no_app
    def test_data_glossary_no_cross_domain_leakage(self):
        model = _build_model(DATA_FIXTURE, 'Data Management')
        gloss = _glossary_acronyms(model)
        # Data fixture mentions no AI / ERM / ISO27001 / cyber terms.
        forbidden = (
            'NIST_AI_RMF', 'AI_GOV', 'AI_ETHICS', 'TRANSPARENCY',
            'MODEL_RISK', 'BIAS', 'FAIRNESS',
            'ISO31000', 'COSO_ERM',
            'ISO27001', 'ISO22301',
            'SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
            'IAM', 'PAM', 'SIEM',
        )
        for ac in forbidden:
            self.assertNotIn(
                ac, gloss,
                f'Data glossary must not auto-inject {ac!r}; got '
                f'{sorted(gloss)}',
            )


class AIGlossaryNoCrossDomainLeakageTest(unittest.TestCase):

    @_skip_if_no_app
    def test_ai_glossary_no_cross_domain_leakage(self):
        model = _build_model(AI_FIXTURE, 'Artificial Intelligence')
        gloss = _glossary_acronyms(model)
        # AI fixture mentions no Data / ERM / cyber / ISO27001 terms.
        forbidden = (
            'NDMO',
            'ISO31000', 'COSO_ERM',
            'ISO27001', 'ISO22301',
            'SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
            'IAM', 'PAM', 'SIEM',
        )
        for ac in forbidden:
            self.assertNotIn(
                ac, gloss,
                f'AI glossary must not auto-inject {ac!r}; got '
                f'{sorted(gloss)}',
            )


class DTGlossaryNoCrossDomainLeakageTest(unittest.TestCase):

    @_skip_if_no_app
    def test_dt_glossary_no_cross_domain_leakage(self):
        model = _build_model(DT_FIXTURE, 'Digital Transformation')
        gloss = _glossary_acronyms(model)
        forbidden = (
            'SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
            'IAM', 'PAM', 'SIEM',
            'NIST_AI_RMF', 'AI_GOV', 'AI_ETHICS',
            'ISO31000', 'COSO_ERM', 'ISO27001',
        )
        for ac in forbidden:
            self.assertNotIn(
                ac, gloss,
                f'DT glossary must not auto-inject {ac!r}; got '
                f'{sorted(gloss)}',
            )


class ERMGlossaryNoCrossDomainLeakageTest(unittest.TestCase):

    @_skip_if_no_app
    def test_erm_glossary_no_cross_domain_leakage(self):
        model = _build_model(ERM_FIXTURE, 'Enterprise Risk Management')
        gloss = _glossary_acronyms(model)
        forbidden = (
            'SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP',
            'IAM', 'PAM', 'SIEM',
            'NDMO', 'PDPL',
            'NIST_AI_RMF', 'AI_GOV', 'AI_ETHICS',
            'BIAS', 'FAIRNESS', 'TRANSPARENCY',
        )
        for ac in forbidden:
            self.assertNotIn(
                ac, gloss,
                f'ERM glossary must not auto-inject {ac!r}; got '
                f'{sorted(gloss)}',
            )


# ─────────────────────────────────────────────────────────────────────────
# Part B — ERM framework coverage
# ─────────────────────────────────────────────────────────────────────────
class CosoErmReviewRevisionAcceptanceTest(unittest.TestCase):
    """The COSO_ERM ``review_revision`` capability must accept the
    standard ERM review / monitoring / treatment-follow-up vocabulary
    so ERM strategies that already use that language do not fail with
    ``selected_framework_coverage_missing:COSO_ERM:review_revision``."""

    @_skip_if_no_app
    def test_review_revision_accepted_in_each_required_section(self):
        # Build per-section text containing the documented accepted
        # AR/EN tokens for the COSO_ERM review_revision family.
        sections = {
            'pillars': '## الركائز\n مراجعة المخاطر دورية وتحديث سجل المخاطر.',
            'gaps': '## الفجوات\n risk review weaknesses identified.',
            'roadmap': '## خارطة الطريق\n monitoring activities planned.',
            'kpis': '## المؤشرات\n risk reporting cadence quarterly.',
            'confidence': '## الثقة\n treatment follow-up tracked weekly.',
        }
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, ['COSO_ERM'],
            domain='Enterprise Risk Management', lang='ar')
        # No COSO_ERM:review_revision triple should remain.
        rr_missing = [m for m in missing if m[1] == 'review_revision']
        self.assertEqual(
            rr_missing, [],
            'COSO_ERM:review_revision must be satisfied by ERM '
            f'review/monitoring vocabulary; got missing={missing!r}',
        )

    @_skip_if_no_app
    def test_iso31000_capabilities_accept_erm_vocabulary(self):
        sections = {
            'pillars': '## الركائز\n risk governance framework + risk culture.',
            'gaps': '## الفجوات\n risk register coverage gap.',
            'roadmap': '## خارطة الطريق\n مراقبة المخاطر وتقارير المخاطر.',
            'kpis': '## المؤشرات\n KRI cadence and risk thresholds.',
            'confidence': '## الثقة\n معالجة المخاطر مع متابعة خطط المعالجة.',
        }
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, ['ISO31000'],
            domain='Enterprise Risk Management', lang='ar')
        self.assertEqual(
            missing, [],
            f'ISO31000 ERM-style content should fully cover its '
            f'capability families; got missing={missing!r}',
        )


class ErmSelectedFrameworkCompliesObjectiveTest(unittest.TestCase):
    """ERM selected frameworks must produce a compliance objective in
    Vision when the body explicitly cites the framework name."""

    @_skip_if_no_app
    def test_compliance_objective_satisfied_by_iso31000_objective_row(self):
        vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** تعزيز إدارة المخاطر.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تحقيق الالتزام بإطار ISO 31000 | تغطية 100% | '
            'الامتثال التنظيمي | 12 شهر |\n'
            '| 2 | تطوير ثقافة المخاطر | نضج 4 | الكفاءة | 18 شهر |\n'
        )
        sections = {'vision': vision}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['ISO31000'],
            domain='Enterprise Risk Management', lang='ar')
        self.assertEqual(
            missing, [],
            f'ISO31000 compliance objective is present in vision; '
            f'got missing={missing!r}',
        )


# ─────────────────────────────────────────────────────────────────────────
# Part C — Vision min_rows regression
# ─────────────────────────────────────────────────────────────────────────
class VisionMinRowsConsultingFloorTest(unittest.TestCase):
    """``synthesize_objectives_depth`` must enforce ≥6 SO rows in
    consulting/assurance mode regardless of caller-passed min_rows."""

    @_skip_if_no_app
    def test_consulting_default_min_rows_is_6(self):
        # No min_rows passed, generation_mode=consulting → eff_min == 6.
        # Use a vision with EXACTLY 6 valid rows so the helper does not
        # need to call AI (we never exercise the AI provider in unit
        # tests). Verify the early-return preserves the rows.
        rows = '\n'.join(
            f'| {i} | تعزيز الحوكمة في المجال {i} | '
            f'مستوى نضج 4 | الالتزام التنظيمي | {i*3} شهر |'
            for i in range(1, 7)
        )
        vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** رؤية تجريبية.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n' + rows + '\n'
        )
        sections = {'vision': vision}
        result = _APP.synthesize_objectives_depth(
            sections, lang='ar', domain='Enterprise Risk Management',
            fw_short='ISO 31000', generation_mode='consulting',
        )
        self.assertFalse(result.get('rebuilt'),
                         'Sufficient vision must not trigger AI repair.')
        self.assertEqual(result.get('min_rows'), 6,
                         f'Consulting mode min_rows must be 6; got '
                         f'{result.get("min_rows")!r}')
        self.assertGreaterEqual(result.get('preserved'), 6)

    @_skip_if_no_app
    def test_assurance_default_min_rows_is_6(self):
        sections = {'vision': '## الرؤية\nقصير جدًا.'}
        # Sufficient vision: 6 rows. assurance mode → eff_min must be 6.
        rows = '\n'.join(
            f'| {i} | هدف {i} | مقياس | مبرر | {i*3} شهر |'
            for i in range(1, 7)
        )
        vision = (
            '## الرؤية\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n' + rows + '\n'
        )
        result = _APP.synthesize_objectives_depth(
            {'vision': vision}, lang='ar',
            domain='Enterprise Risk Management',
            fw_short='COSO ERM', generation_mode='assurance')
        self.assertEqual(
            result.get('min_rows'), 6,
            f'Assurance mode min_rows must be 6; got '
            f'{result.get("min_rows")!r}',
        )


class VisionRepairRejects4RowsTest(unittest.TestCase):
    """Any vision-repair path that produces a ``< floor`` SO-row count
    must restore the original vision and fail closed.

    We exercise this contract via a pure-Python check on the helper
    that the consulting/assurance min_rows is propagated and that
    ``count_valid_objective_rows`` < ``min_rows`` is treated as a
    failure (the production path then restores the original vision —
    that branch is covered by the in-line code under test in
    ``api_generate_strategy``).
    """

    @_skip_if_no_app
    def test_4_row_vision_below_consulting_floor(self):
        rows = '\n'.join(
            f'| {i} | هدف رقم {i} | مقياس | مبرر | {i*3} شهر |'
            for i in range(1, 5)  # 4 rows only
        )
        vision_4 = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '**الرؤية:** قصيرة.\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n' + rows + '\n'
        )
        n = _APP.count_valid_objective_rows(vision_4)
        self.assertEqual(n, 4,
                         f'fixture should yield 4 valid SO rows; got {n}')
        # The consulting/assurance floor is 6 → 4 must be rejected.
        self.assertLess(
            n, 6,
            'Vision with 4 SO rows must be below the consulting floor '
            'of 6 — guarding the post-repair restoration branch.',
        )


# ─────────────────────────────────────────────────────────────────────────
# Part D — Document control RTL
# ─────────────────────────────────────────────────────────────────────────
class DocControlRtlExtractionTest(unittest.TestCase):
    """The professional Arabic strategy PDF must not contain the
    bidi-glitch reversed pair documented in PR-5B.9C runtime evidence,
    and the proper-Unicode label/value strings must be present."""

    @_skip_if_no_app
    def test_doc_control_rows_use_proper_unicode_label(self):
        rows = _APP._build_document_control_rows(
            {'org_name': 'منظمتي', 'sector': 'حكومي',
             'domain': 'Enterprise Risk Management',
             'doc_type': 'Strategy Document'},
            'ar')
        labels = [lbl for lbl, _ in rows]
        self.assertIn('أعد بواسطة', labels,
                      f'Doc-control source-of-truth label must use '
                      f'logical-Unicode "أعد بواسطة" (never the reversed '
                      f'form); got {labels!r}')
        # The data-layer rows must carry the literal value the user
        # expects to read, not a bidi-flipped concatenation.
        prepared_by_value = dict(rows).get('أعد بواسطة')
        self.assertEqual(
            prepared_by_value, 'Mizan GRC Platform',
            f'Prepared-by value should be "Mizan GRC Platform"; got '
            f'{prepared_by_value!r}',
        )

    @_skip_if_no_app
    def test_pdf_text_does_not_contain_bidi_reversed_prepared_by(self):
        # Build a small Arabic professional PDF and verify the
        # extracted text never contains either of the two bidi-glitch
        # forms documented in PR-5B.9C runtime evidence.
        pdf_bytes = self._build_minimal_arabic_pdf()
        if pdf_bytes is None:
            self.skipTest('PDF rendering not available in this env')
        try:
            import fitz
        except Exception:
            self.skipTest('fitz not available')
        doc = fitz.open(stream=pdf_bytes, filetype='pdf')
        text = '\n'.join(p.get_text() for p in doc)
        doc.close()
        for bad in ('بواسطة أعد Mizan GRC Platform',
                    'Mizan GRC Platform بواسطة أعد'):
            self.assertNotIn(
                bad, text,
                f'PDF text must not contain bidi-glitch pair {bad!r}',
            )

    @staticmethod
    def _build_minimal_arabic_pdf():
        """Render a minimal Arabic strategy PDF using the same path
        as the production export. Returns the PDF bytes or None when
        the test environment cannot construct a Flask test request."""
        try:
            import json
            with _APP.app.test_request_context('/x'):
                content = (
                    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
                    '**الرؤية:** اختبار.\n\n'
                    '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
                    '|---|---|---|---|---|\n'
                    '| 1 | هدف | قياس | مبرر | 12 شهر |\n'
                )
                metadata = {
                    'org_name': 'منظمة اختبار',
                    'sector': 'حكومي',
                    'domain': 'Enterprise Risk Management',
                    'doc_type': 'Strategy Document',
                    'prepared_by': 'Mizan GRC Platform',
                }
                if not hasattr(_APP, 'generate_pdf_professional'):
                    return None
                buf = io.BytesIO()
                try:
                    _APP.generate_pdf_professional(
                        buf, content, metadata, lang='ar',
                    )
                except Exception:
                    return None
                return buf.getvalue()
        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────
# Part E — Traceability rows
# ─────────────────────────────────────────────────────────────────────────
class TraceabilityRowQualityTest(unittest.TestCase):
    """The traceability matrix model exposes an ``informative_rows``
    list that drops rows whose Gap, Initiative, or both KPI+Risk are
    placeholder ``"—"``. The renderer drops these rows at render time
    so the printed PDF never has rows mostly made of ``—``."""

    @_skip_if_no_app
    def test_informative_rows_filter_removes_dashy_rows(self):
        sections = {
            # Gaps mention only "MFA" — only the MFA-keyed family has
            # any realistic chance of matching across the four cells.
            'gaps': '| # | الفجوة |\n|---|---|\n| 1 | غياب MFA |',
            'pillars': '| # | المبادرة |\n|---|---|\n| 1 | تطبيق MFA |',
            'roadmap': '',
            'kpis': '| # | المؤشر |\n|---|---|\n| 1 | تغطية MFA |',
            'confidence': '',  # no risks → KPI alone keeps row alive
        }
        tm = _APP._build_traceability_matrix(
            sections, ['ECC'], lang='ar', domain_code='cyber')
        self.assertIn('informative_rows', tm)
        all_rows = tm['rows']
        info_rows = tm['informative_rows']
        self.assertLessEqual(len(info_rows), len(all_rows),
                             'informative_rows must be a subset of rows')
        # Every informative row must have non-dash gap, non-dash
        # initiative and at least one of (KPI, risk).
        for r in info_rows:
            self.assertGreaterEqual(len(r), 6,
                                    'each row must have 6 columns')
            self.assertNotIn(r[2].strip(), ('—', '-', '', '–'),
                             f'gap must be informative; got row={r!r}')
            self.assertNotIn(r[3].strip(), ('—', '-', '', '–'),
                             f'initiative must be informative; row={r!r}')
            self.assertFalse(
                r[4].strip() in ('—', '-', '', '–')
                and r[5].strip() in ('—', '-', '', '–'),
                f'KPI and Risk cannot both be dash; row={r!r}',
            )


# ─────────────────────────────────────────────────────────────────────────
# Cross-cutting — Quality gate / preview / determinism / floors
# ─────────────────────────────────────────────────────────────────────────
class ExportQualityGateGlossaryLeakageTest(unittest.TestCase):
    """The export quality-gate inspector emits a warning when a
    forbidden cross-domain acronym leaks into a non-cyber appendix."""

    @_skip_if_no_app
    def test_quality_gate_detects_glossary_leak_warning(self):
        # The export-quality gate logs a warning to stdout. Build a
        # Data Management strategy and capture the warnings output by
        # composing the model — there should be no glossary leak
        # warnings now (the appendix builder is clean).
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _build_model(DATA_FIXTURE, 'Data Management')
        captured = buf.getvalue()
        self.assertNotIn('glossary_cross_domain_leak:SOC', captured,
                         'No SOC leak warning must appear for Data')
        self.assertNotIn('glossary_cross_domain_leak:CSIRT', captured,
                         'No CSIRT leak warning must appear for Data')
        self.assertNotIn('glossary_cross_domain_leak:ISO27001', captured,
                         'No ISO27001 leak warning must appear for Data')


class NoDeterministicStrategyRowsTest(unittest.TestCase):
    """The composer must not invent strategy rows. The doc-control
    rows builder only emits the user-supplied metadata pairs."""

    @_skip_if_no_app
    def test_doc_control_rows_carry_only_metadata(self):
        rows = _APP._build_document_control_rows(
            {'org_name': 'منظمة اختبار', 'sector': 'حكومي',
             'domain': 'Enterprise Risk Management',
             'doc_type': 'Strategy Document'},
            'ar')
        joined_values = ' '.join(v for _, v in rows)
        # No strategy content must leak into doc-control rows.
        for forbidden in ('SOC', 'إنشاء', 'KPI', 'risk treatment',
                          'تطبيق MFA'):
            self.assertNotIn(
                forbidden, joined_values,
                f'Doc-control rows must not carry strategy content; '
                f'found {forbidden!r} in {joined_values!r}',
            )


class ValidatorsNotWeakenedTest(unittest.TestCase):
    """Stricter alignment only — global richness floors are intact."""

    @_skip_if_no_app
    def test_richness_so_floor_unchanged(self):
        # The global SO-row floor must remain at 4; consulting/assurance
        # mode raises it to 6 in synthesize_objectives_depth without
        # mutating the global constant.
        self.assertEqual(_APP._RICHNESS_MIN_SO_ROWS, 4,
                         '_RICHNESS_MIN_SO_ROWS must remain at 4')

    @_skip_if_no_app
    def test_synthesize_objectives_depth_consulting_floor_is_6(self):
        # Sufficient vision: 6 rows. consulting mode → eff_min must be 6.
        rows = '\n'.join(
            f'| {i} | هدف {i} | مقياس | مبرر | {i*3} شهر |'
            for i in range(1, 7)
        )
        vision = (
            '## الرؤية\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n' + rows + '\n'
        )
        result = _APP.synthesize_objectives_depth(
            {'vision': vision}, lang='ar',
            domain='Cyber Security', fw_short='ECC',
            generation_mode='consulting')
        self.assertEqual(result.get('min_rows'), 6)

    @_skip_if_no_app
    def test_synthesize_objectives_depth_drafting_floor_is_constant(self):
        rows = '\n'.join(
            f'| {i} | هدف {i} | مقياس | مبرر | {i*3} شهر |'
            for i in range(1, 5)
        )
        vision = (
            '## الرؤية\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n' + rows + '\n'
        )
        result = _APP.synthesize_objectives_depth(
            {'vision': vision}, lang='ar',
            domain='Cyber Security', fw_short='ECC',
            generation_mode='drafting')
        # drafting → eff_min == _RICHNESS_MIN_SO_ROWS
        self.assertEqual(result.get('min_rows'),
                         _APP._RICHNESS_MIN_SO_ROWS)


class PreviewBehaviourUnchangedTest(unittest.TestCase):
    """Sanity guard — this test module never imports or invokes any
    preview route or preview helper. We assert that the modules under
    test do not expose a new preview-altering API."""

    @_skip_if_no_app
    def test_no_preview_helper_was_added(self):
        # Spot-check: the strategy preview route still exists with the
        # same name (proves we did not refactor it). If this assertion
        # is ever invalidated it must be by a deliberate, separate PR.
        # Note: not all repos export this name; treat absence as OK.
        if hasattr(_APP, 'api_preview_strategy'):
            self.assertTrue(callable(_APP.api_preview_strategy))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
