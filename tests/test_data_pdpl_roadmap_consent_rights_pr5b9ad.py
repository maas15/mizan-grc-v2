"""PR-5B.9AD — Data PDPL roadmap consent_management + data_subject_rights
coverage.

Runtime trace after PR-5B.9AA narrowed to ::

    selected_framework_coverage_missing:PDPL:consent_management,\
data_subject_rights (roadmap) 0/1

Root cause: PR-5B.9AA wired ``data_subject_rights`` and
``breach_notification`` into the convergence-stage roadmap balance
repair acceptance gate and the PR-5B.9Y FINAL PDPL DATA SAVE GUARD,
but ``consent_management`` was still missing from
``_PR5B9Y_PDPL_EXACT_TERMS``, ``_PDPL_TARGETS``, ``_PR5B9X_PDPL_TARGETS``,
the convergence balance repair pre/post filters + candidate gate +
prompt contract block, and the Part C overwrite guard. The runtime
residual ``selected_framework_coverage_missing:PDPL:consent_management``
therefore drained straight into the generic 422 with no final repair
attempt.

This module validates the PR-5B.9AD contract WITHOUT requiring an AI
provider. The AI repair helpers raise ``RepairError`` when no API key
is configured; the test asserts the wiring + detection + acceptance
gate behave correctly and the existing PR-5B.9AA fail-closed plumbing
still fires (now extended to consent_management).

Run::

    python -m pytest \\
        tests/test_data_pdpl_roadmap_consent_rights_pr5b9ad.py -q
"""
import importlib.util
import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ad_')
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


_FRAMEWORKS = ['NDMO', 'PDPL']


def _full_data_sections(roadmap_text):
    """Build a sections dict that satisfies every NDMO family AND the
    PDPL families NOT under test (privacy_governance,
    personal_data_classification / data_classification_pdpl,
    breach_notification) EXCEPT ``consent_management`` and
    ``data_subject_rights`` — those must be sourced from the roadmap
    text only. Isolates roadmap as the single variable for the
    detection / acceptance tests.
    """
    common_pdpl = (
        ' حوكمة الخصوصية. حماية البيانات الشخصية. '
        'تصنيف البيانات الشخصية. الإبلاغ عن الانتهاكات. '
        'إخطار الخروقات. '
        'privacy governance; personal data protection; '
        'personal data classification; breach notification; '
    )
    common_ndmo = (
        ' حوكمة البيانات. أمناء البيانات. جودة البيانات. '
        'كتالوج البيانات والبيانات الوصفية. دورة حياة البيانات. '
        'data stewards; data quality; data catalog; metadata; '
        'data lifecycle; '
    )
    body = common_pdpl + common_ndmo
    return {
        'vision': '## 1. الرؤية\n' + body,
        'pillars': '## 2. الركائز الاستراتيجية\n' + body,
        'environment': '## 3. السياق التنظيمي\nNDMO and PDPL. '
                       + body,
        'gaps': '## 4. تحليل الفجوات\n' + body,
        'roadmap': roadmap_text,
        'kpis': '## 6. مؤشرات الأداء\n' + body,
        'confidence': '## 7. تقييم الجاهزية\n' + body,
    }


# Generic roadmap that mentions ONLY "حماية البيانات الشخصية" (generic
# PDPL privacy phrase) plus office setup — NEITHER consent_management
# nor data_subject_rights tokens appear.
_ROADMAP_GENERIC_PRIVACY_ONLY = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق مكتب البيانات |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | CDO | Q1 | ميثاق اللجنة |\n'
    '| 3 | اعتماد نموذج التشغيل وخطوط الرفع | CDO | Q1 | نموذج تشغيل |\n'
    '| 4 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 5 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 | كتالوج |\n'
    '| 6 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 | سياسة |\n'
    '| 7 | حماية البيانات الشخصية (إطار عام) | CDO | Q3 | سياسة |\n'
    '| 8 | تصنيف البيانات الشخصية | CDO | Q3 | مصفوفة التصنيف |\n'
    '| 9 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q4 | إجراء |\n'
)

_ROADMAP_WITH_IDARAH_MUWAFAQAT = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | إدارة الموافقات | CDO | Q4 | إجراء |\n'
)

_ROADMAP_WITH_SIJIL_MUWAFAQAT = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | بناء سجل الموافقات | CDO | Q4 | سجل |\n'
)

_ROADMAP_WITH_DSR_EXPLICIT = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | تفعيل حقوق صاحب البيانات | CDO | Q4 | آلية |\n'
)

_ROADMAP_WITH_ACCESS_RECT_ERASURE = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | حق الوصول، حق التصحيح، حق الحذف | CDO | Q4 | آلية |\n'
)


class TestPart1To7DetectionAndAcceptance(unittest.TestCase):
    """Tests 1-7 — detection + acceptance via
    ``_compute_missing_selected_framework_coverage``."""

    @_skip_if_no_app
    def _roadmap_pdpl_missing(self, roadmap_text):
        sections = _full_data_sections(roadmap_text)
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, _FRAMEWORKS,
            domain='Data Management', lang='ar') or []
        return sorted({
            fam for fw, fam, sk in missing
            if fw == 'PDPL'
            and fam in ('consent_management', 'data_subject_rights')
            and sk == 'roadmap'
        })

    @_skip_if_no_app
    def test_01_missing_consent_management_in_roadmap_emits_defect(self):
        # Roadmap mentions DSR + breach but NOT consent.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | تفعيل حقوق صاحب البيانات | CDO | Q1 | آلية |\n'
            '| 3 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q2 | |\n'
            '| 4 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        m = self._roadmap_pdpl_missing(roadmap)
        self.assertIn('consent_management', m)
        self.assertNotIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_02_missing_data_subject_rights_in_roadmap_emits_defect(self):
        # Roadmap mentions consent + breach but NOT DSR.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | إدارة الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q2 | |\n'
            '| 4 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        m = self._roadmap_pdpl_missing(roadmap)
        self.assertIn('data_subject_rights', m)
        self.assertNotIn('consent_management', m)

    @_skip_if_no_app
    def test_03_generic_privacy_phrase_only_fails_consent_and_dsr(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_GENERIC_PRIVACY_ONLY)
        self.assertIn('consent_management', m)
        self.assertIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_04_idarah_muwafaqat_passes_consent_management(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_IDARAH_MUWAFAQAT)
        self.assertNotIn('consent_management', m)

    @_skip_if_no_app
    def test_05_sijil_muwafaqat_passes_consent_management(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_SIJIL_MUWAFAQAT)
        self.assertNotIn('consent_management', m)

    @_skip_if_no_app
    def test_06_huquq_sahib_albayanat_passes_data_subject_rights(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_DSR_EXPLICIT)
        self.assertNotIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_07_haq_alwusool_tashih_hadhf_passes_data_subject_rights(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_ACCESS_RECT_ERASURE)
        self.assertNotIn('data_subject_rights', m)


class TestPart8ConvergenceRoadmapRepairPrompt(unittest.TestCase):
    """Test 8 — convergence roadmap repair prompt source contains the
    consent / DSR / breach exact terms required by the problem
    statement (PR-5B.9AD)."""

    @_skip_if_no_app
    def test_08_prompt_contains_consent_and_rights_exact_terms(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # PR-5B.9AD contract block headings + family labels.
        self.assertIn('PR-5B.9AA', src)
        self.assertIn('PR-5B.9AD', src)
        self.assertIn('consent_management', src)
        self.assertIn('data_subject_rights', src)
        # Required Arabic consent terms surfaced in the prompt.
        for t in ('إدارة الموافقات', 'سجل الموافقات',
                  'الموافقة الصريحة'):
            self.assertIn(t, src)
        # Required Arabic rights terms surfaced in the prompt.
        for t in ('حقوق صاحب البيانات', 'حق الوصول', 'حق التصحيح',
                  'حق الحذف', 'طلبات أصحاب البيانات'):
            self.assertIn(t, src)
        # Registry exposes the consent / DSR English equivalents.
        cns_ar, cns_en = _APP._pdpl_save_guard_required_terms(
            'consent_management')
        dsr_ar, dsr_en = _APP._pdpl_save_guard_required_terms(
            'data_subject_rights')
        for t in ('consent management', 'consent register',
                  'explicit consent'):
            self.assertIn(t, cns_en)
        for t in ('إدارة الموافقات', 'سجل الموافقات',
                  'الموافقة الصريحة', 'موافقات أصحاب البيانات'):
            self.assertIn(t, cns_ar)
        for t in ('data subject rights', 'access request',
                  'rectification', 'erasure'):
            self.assertIn(t, dsr_en)
        for t in ('حقوق صاحب البيانات', 'حقوق أصحاب البيانات',
                  'حق الوصول', 'حق التصحيح', 'حق الحذف',
                  'طلبات أصحاب البيانات'):
            self.assertIn(t, dsr_ar)


class TestPart9To12AcceptanceGate(unittest.TestCase):
    """Tests 9-12 — candidate acceptance / second-attempt /
    final-audit fail-closed plumbing for consent_management +
    data_subject_rights."""

    def _run_repair(self, roadmap):
        sections = _full_data_sections(roadmap)
        before = sections['roadmap']
        log = {'synth_status': {}}
        ctx = {'frameworks': _FRAMEWORKS,
               'org_structure_is_none': False,
               'org_name': 'Test', 'sector': 'General',
               'maturity': 'initial',
               'generation_mode': 'drafting'}
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._convergence_data_roadmap_balance_repair(
                sections, 'ar', 'Data Management', ctx, log, 1)
        return sections, before, log, buf.getvalue()

    @_skip_if_no_app
    def test_09_candidate_missing_consent_is_rejected_and_restored(self):
        # No API keys => ai_repair_strategy_section raises RepairError;
        # the balance repair must restore the original roadmap and
        # mark synth_failed:roadmap. The pre-state for this roadmap
        # surfaces consent_management as missing.
        sections, before, log, out = self._run_repair(
            _ROADMAP_GENERIC_PRIVACY_ONLY)
        self.assertEqual(sections['roadmap'], before)

        def _walk_status(node):
            if isinstance(node, dict):
                if node.get('roadmap') == 'failed':
                    return True
                for v in node.values():
                    if _walk_status(v):
                        return True
            return False

        self.assertTrue(
            _walk_status(log),
            f'expected roadmap synth_failed marker in log; log={log}')
        # Both legacy + dedicated consent/rights diagnostic emitted.
        self.assertIn('[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR]', out)
        self.assertIn('[DATA-ROADMAP-PDPL-CONSENT-RIGHTS]', out)

    @_skip_if_no_app
    def test_10_candidate_missing_dsr_is_rejected_and_restored(self):
        # Same shape as test_09 but uses a roadmap that has consent
        # text but no DSR text — verifies DSR residual still triggers
        # the consent/rights diagnostic and fail-closes.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | إدارة الموافقات وسجل الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q2 | |\n'
            '| 4 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        sections, before, log, out = self._run_repair(roadmap)
        self.assertEqual(sections['roadmap'], before)
        self.assertIn('[DATA-ROADMAP-PDPL-CONSENT-RIGHTS]', out)

    @_skip_if_no_app
    def test_11_second_attempt_triggered_on_first_failure(self):
        """Test 11 — the convergence balance repair issues up to TWO
        ``ai_repair_strategy_section`` attempts before fail-closing.
        Verified via the source (``while attempt < 2 and not
        accepted``)."""
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        self.assertIn('while attempt < 2 and not accepted', src)
        # The stricter second-pass requirement block must reference
        # the unmet families and ask for at least one literal term per
        # family.
        self.assertIn('SECOND-PASS STRICT REQUIREMENT', src)

    @_skip_if_no_app
    def test_12_final_audit_blocks_save_when_roadmap_lacks_consent_rights(
            self):
        """Test 12 —
        ``_compute_missing_selected_framework_coverage`` on a sections
        dict with a generic-only roadmap surfaces BOTH
        ``(PDPL, consent_management, roadmap)`` and
        ``(PDPL, data_subject_rights, roadmap)`` so the final audit
        emits a 422 (validators not weakened)."""
        sections = _full_data_sections(_ROADMAP_GENERIC_PRIVACY_ONLY)
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, _FRAMEWORKS,
            domain='Data Management', lang='ar') or []
        pairs = {(fw, fam, sk) for fw, fam, sk in missing}
        self.assertIn(
            ('PDPL', 'consent_management', 'roadmap'), pairs)
        self.assertIn(
            ('PDPL', 'data_subject_rights', 'roadmap'), pairs)


class TestPart13To18Isolation(unittest.TestCase):
    """Tests 13-18 — breach/classification still pass, NDMO unchanged,
    Cyber/AI/DT/ERM unchanged, no deterministic rows, validators not
    weakened, auth/DB/export untouched."""

    @_skip_if_no_app
    def test_13_breach_and_classification_still_pass(self):
        # Roadmap that explicitly satisfies breach + classification +
        # consent + DSR — all four PDPL families that previously
        # surfaced as residuals should be clean.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | إدارة الموافقات وسجل الموافقات | CDO | Q1 | سجل |\n'
            '| 2 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
            'حق الحذف | CDO | Q1 | آلية |\n'
            '| 3 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 4 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q2 '
            '| إجراء |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات والبيانات الوصفية | CDO | Q3 | '
            'كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
            '| 10 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
        )
        sections = _full_data_sections(roadmap)
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, _FRAMEWORKS,
            domain='Data Management', lang='ar') or []
        pdpl_roadmap_missing = sorted({
            fam for fw, fam, sk in missing
            if fw == 'PDPL' and sk == 'roadmap'
        })
        self.assertNotIn(
            'breach_notification', pdpl_roadmap_missing)
        self.assertNotIn(
            'personal_data_classification', pdpl_roadmap_missing)
        self.assertNotIn(
            'consent_management', pdpl_roadmap_missing)
        self.assertNotIn(
            'data_subject_rights', pdpl_roadmap_missing)

    @_skip_if_no_app
    def test_14_ndmo_capability_vocab_unchanged(self):
        req = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO', {})
        caps = {fam for fam, _ar, _en in req.get('capabilities', [])}
        for fam in ('data_governance', 'data_quality', 'data_catalog',
                    'data_stewardship', 'data_lifecycle'):
            self.assertIn(fam, caps)
        for fam in ('consent_management', 'data_subject_rights',
                    'breach_notification',
                    'personal_data_classification'):
            self.assertNotIn(fam, caps)

    @_skip_if_no_app
    def test_15_cyber_ai_dt_erm_framework_registries_untouched(self):
        for fw_key in ('NCA_ECC', 'NCA_DCC', 'SDAIA', 'COSO_ERM'):
            spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get(fw_key)
            if spec is None:
                continue
            caps = {fam for fam, _ar, _en in spec.get('capabilities',
                                                       [])}
            for fam in ('consent_management', 'data_subject_rights',
                        'breach_notification',
                        'personal_data_classification'):
                self.assertNotIn(
                    fam, caps,
                    f'{fw_key} must not list PDPL family {fam}')

    @_skip_if_no_app
    def test_16_no_deterministic_rows_inserted(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        self.assertIn('ai_repair_strategy_section', src)
        self.assertIn('_mark_synth_failed', src)
        forbidden = (
            "sections['roadmap'] = (before_text + '|'",
            "sections['roadmap'] += '|",
            "sections['roadmap'] = before_text + \"| ",
        )
        for f in forbidden:
            self.assertNotIn(
                f, src,
                'deterministic fallback row insertion forbidden')

    @_skip_if_no_app
    def test_17_validators_not_weakened(self):
        # Registry vocabulary for consent_management + DSR is preserved
        # (only ADDITIONS to the save-guard exact-terms registry — no
        # tokens were removed).
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL', {})
        caps = {fam: (ar, en)
                for fam, ar, en in spec.get('capabilities', [])}
        self.assertIn('consent_management', caps)
        self.assertIn('data_subject_rights', caps)
        self.assertIn('breach_notification', caps)
        # Save guard exact-term registry now includes consent_management
        # (the PR-5B.9AD addition) AND retains DSR / breach / personal-
        # data classification.
        for fam in ('consent_management', 'data_subject_rights',
                    'breach_notification', 'personal_data_classification',
                    'data_classification_pdpl'):
            ar, en = _APP._pdpl_save_guard_required_terms(fam)
            self.assertTrue(ar, f'{fam} missing AR exact terms')
            self.assertTrue(en, f'{fam} missing EN exact terms')

    @_skip_if_no_app
    def test_18_auth_db_export_untouched(self):
        # The PR-5B.9AD change-set only touches the PDPL save-guard
        # registries, _convergence_data_roadmap_balance_repair, the
        # converge_strategy_sections overwrite guard, and the DATA-
        # PDPL-SAVE-GUARD target set. Verify there is no incidental
        # mention of auth / db / export work in those functions.
        repair_src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        for forbidden in ('@app.route', 'login_required', 'pdf',
                          'docx', 'export', 'db.session', 'DATABASE_URL'):
            self.assertNotIn(
                forbidden, repair_src,
                f'unexpected {forbidden} in PDPL balance repair')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
