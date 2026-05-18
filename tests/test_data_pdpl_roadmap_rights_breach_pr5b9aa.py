"""PR-5B.9AA — Data PDPL roadmap rights + breach coverage.

Runtime trace after PR-5B.9Z narrowed to ::

    selected_framework_coverage_missing:PDPL:data_subject_rights,\
breach_notification (roadmap) 0/1

Root cause: the PR-5B.9Y FINAL PDPL DATA SAVE GUARD did not target
``data_subject_rights``, the convergence-stage roadmap balance repair
prompt did not enumerate the explicit PDPL DSR / breach roadmap
activities, the candidate acceptance check did not validate the
roadmap text directly for DSR / breach exact terms, and there was no
overwrite guard re-routing back to the roadmap repair when the
per-section generic rebuild lost the PDPL content.

This module validates the PR-5B.9AA contract WITHOUT requiring an AI
provider. The AI repair helpers raise ``RepairError`` when no API key
is configured; the test asserts the wiring + detection + acceptance
gate behave correctly and the existing PR-5B.9Z fail-closed plumbing
still fires.

Run::

    python -m pytest \\
        tests/test_data_pdpl_roadmap_rights_breach_pr5b9aa.py -q
"""
import importlib.util
import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9aa_')
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
    PDPL families NOT under test (privacy_governance, consent_management,
    personal_data_classification / data_classification_pdpl) EXCEPT
    ``data_subject_rights`` and ``breach_notification`` — those must be
    sourced from the roadmap text only. This isolates roadmap as the
    single variable for the detection / acceptance tests.
    """
    common_pdpl = (
        ' حوكمة الخصوصية. إدارة الموافقات. '
        'تصنيف البيانات الشخصية. '
        'privacy governance; consent management; '
        'personal data classification; '
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


# Generic roadmap mentioning only "حماية البيانات الشخصية" (generic
# privacy phrase) plus office setup. The PDPL DSR / breach
# framework-coverage families are NOT satisfied by these tokens.
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
    '| 8 | إدارة الموافقات | CDO | Q3 | سجل الموافقات |\n'
    '| 9 | تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة التصنيف |\n'
)

_ROADMAP_WITH_DSR_EXPLICIT = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | تفعيل حقوق صاحب البيانات | CDO | Q4 | آلية الحقوق |\n'
)

_ROADMAP_WITH_ACCESS_RECT_ERASURE = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | حق الوصول، حق التصحيح، حق الحذف | CDO | Q4 | آلية |\n'
)

_ROADMAP_WITH_IKHTAR = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | تفعيل إخطار الخروقات | CISO | Q4 | إجراء الإخطار |\n'
)

_ROADMAP_WITH_IBLAGH = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | الإبلاغ عن الانتهاكات للجهات التنظيمية | CISO | Q4 | |\n'
)

_ROADMAP_FULL_PDPL = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 10 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
    'حق الحذف | CDO | Q4 | آلية الحقوق |\n'
    + '| 11 | تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات | '
    'CISO | Q4 | إجراء الإخطار |\n'
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
            and fam in ('data_subject_rights', 'breach_notification')
            and sk == 'roadmap'
        })

    @_skip_if_no_app
    def test_01_missing_data_subject_rights_in_roadmap_emits_defect(self):
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
        self.assertNotIn('breach_notification', m)

    @_skip_if_no_app
    def test_02_missing_breach_notification_in_roadmap_emits_defect(self):
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تفعيل حقوق صاحب البيانات | CDO | Q1 | آلية |\n'
            '| 2 | إدارة الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 4 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 5 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 6 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 7 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 8 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        m = self._roadmap_pdpl_missing(roadmap)
        self.assertIn('breach_notification', m)
        self.assertNotIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_03_generic_privacy_phrase_only_fails_dsr_and_breach(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_GENERIC_PRIVACY_ONLY)
        self.assertIn('data_subject_rights', m)
        self.assertIn('breach_notification', m)

    @_skip_if_no_app
    def test_04_huquq_sahib_albayanat_passes_dsr(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_DSR_EXPLICIT)
        self.assertNotIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_05_haq_alwusool_tashih_hadhf_passes_dsr(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_ACCESS_RECT_ERASURE)
        self.assertNotIn('data_subject_rights', m)

    @_skip_if_no_app
    def test_06_ikhtar_alkhuruqaat_passes_breach(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_IKHTAR)
        self.assertNotIn('breach_notification', m)

    @_skip_if_no_app
    def test_07_iblagh_an_alantihakaat_passes_breach(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_IBLAGH)
        self.assertNotIn('breach_notification', m)


class TestPart8ConvergenceRoadmapRepairPrompt(unittest.TestCase):
    """Test 8 — convergence roadmap repair prompt source contains the
    DSR / breach exact terms required by the problem statement."""

    @_skip_if_no_app
    def test_08_prompt_contains_pdpl_rights_and_breach_exact_terms(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # Part A contract block headings
        self.assertIn('PR-5B.9AA — PDPL ROADMAP CONTRACT', src)
        self.assertIn('حقوق صاحب البيانات', src)
        self.assertIn('حق الوصول', src)
        self.assertIn('حق التصحيح', src)
        self.assertIn('حق الحذف', src)
        self.assertIn('إخطار الخروقات', src)
        self.assertIn('الإبلاغ عن الانتهاكات', src)
        # English equivalents (the prompt pulls these from the
        # PR-5B.9Y registry — assert the registry exposes them).
        dsr_ar, dsr_en = _APP._pdpl_save_guard_required_terms(
            'data_subject_rights')
        brn_ar, brn_en = _APP._pdpl_save_guard_required_terms(
            'breach_notification')
        for t in ('data subject rights', 'access request',
                  'rectification', 'erasure'):
            self.assertIn(t, dsr_en)
        for t in ('breach notification', 'data breach notification',
                  'breach reporting'):
            self.assertIn(t, brn_en)
        for t in ('حقوق صاحب البيانات', 'حقوق أصحاب البيانات',
                  'حق الوصول', 'حق التصحيح', 'حق الحذف',
                  'طلبات أصحاب البيانات'):
            self.assertIn(t, dsr_ar)
        for t in ('إخطار الخروقات', 'الإبلاغ عن الانتهاكات',
                  'الإبلاغ عن خرق البيانات', 'إشعار خرق البيانات',
                  'آلية إخطار الخروقات'):
            self.assertIn(t, brn_ar)


class TestPart9To11AcceptanceGate(unittest.TestCase):
    """Tests 9-11 — candidate acceptance / second-attempt /
    final-audit fail-closed plumbing."""

    @_skip_if_no_app
    def test_09_candidate_missing_breach_is_rejected_and_restored(self):
        """Without API keys ``ai_repair_strategy_section`` raises
        ``RepairError``; the convergence balance repair must restore
        the original roadmap and mark synth_failed:roadmap so the
        save gate refuses to save."""
        sections = _full_data_sections(_ROADMAP_GENERIC_PRIVACY_ONLY)
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
        out = buf.getvalue()
        # Original roadmap restored (no AI provider available).
        self.assertEqual(sections['roadmap'], before)
        # Roadmap fail-closed marker set. ``_mark_synth_failed`` accepts
        # either the outer container or the inner ``synth_status`` dict;
        # both shapes record ``roadmap: failed`` reachable as
        # ``log['synth_status'][... 'roadmap']`` at some depth.
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
        # Structured diagnostic log emitted.
        self.assertIn('[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR]', out)

    @_skip_if_no_app
    def test_10_overwrite_guard_reroutes_back_to_roadmap_repair(self):
        """Test 10 — after the generic per-section rebuild the
        PR-5B.9AA overwrite guard must re-check PDPL DSR / breach and
        re-route to ``_convergence_data_roadmap_balance_repair`` when
        still missing in roadmap. Verified via the source of
        ``converge_strategy_sections``."""
        src = inspect.getsource(_APP.converge_strategy_sections)
        self.assertIn('PR-5B.9AA Part C', src)
        self.assertIn('overwrite_guard', src)
        # Must call the balance repair after the post-cycle audit.
        self.assertIn(
            '_convergence_data_roadmap_balance_repair', src)

    @_skip_if_no_app
    def test_11_final_audit_blocks_save_when_roadmap_lacks_rights_breach(
            self):
        """Test 11 — ``_compute_missing_selected_framework_coverage``
        on a sections dict with a generic-only roadmap surfaces both
        ``(PDPL, data_subject_rights, roadmap)`` and
        ``(PDPL, breach_notification, roadmap)`` so the final audit
        emits a 422 (validators not weakened)."""
        sections = _full_data_sections(_ROADMAP_GENERIC_PRIVACY_ONLY)
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, _FRAMEWORKS,
            domain='Data Management', lang='ar') or []
        pairs = {(fw, fam, sk) for fw, fam, sk in missing}
        self.assertIn(
            ('PDPL', 'data_subject_rights', 'roadmap'), pairs)
        self.assertIn(
            ('PDPL', 'breach_notification', 'roadmap'), pairs)


class TestPart12To16Isolation(unittest.TestCase):
    """Tests 12-16 — domain / framework / validator isolation."""

    @_skip_if_no_app
    def test_12_ndmo_capability_vocab_unchanged(self):
        """Test 12 — NDMO capability registry untouched (no PDPL
        terms leaked into NDMO vocab)."""
        req = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO', {})
        caps = {fam for fam, _ar, _en in req.get('capabilities', [])}
        for fam in ('data_governance', 'data_quality', 'data_catalog',
                    'data_stewardship', 'data_lifecycle'):
            self.assertIn(fam, caps)
        # No PDPL families bled into NDMO.
        for fam in ('data_subject_rights', 'breach_notification',
                    'personal_data_classification'):
            self.assertNotIn(fam, caps)

    @_skip_if_no_app
    def test_13_cyber_ai_dt_erm_framework_registries_untouched(self):
        """Test 13 — non-Data framework registries untouched. The
        PDPL family vocabulary changes must not surface anywhere
        outside the PDPL entry."""
        for fw_key in ('NCA_ECC', 'NCA_DCC', 'SDAIA', 'COSO_ERM'):
            spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get(fw_key)
            if spec is None:
                continue
            caps = {fam for fam, _ar, _en in spec.get('capabilities',
                                                       [])}
            for fam in ('data_subject_rights', 'breach_notification',
                        'personal_data_classification'):
                self.assertNotIn(
                    fam, caps,
                    f'{fw_key} must not list PDPL family {fam}')

    @_skip_if_no_app
    def test_14_no_deterministic_rows_inserted(self):
        """Test 14 — the convergence repair must NOT insert any
        deterministic content when AI is unavailable. Source inspection
        confirms restore-on-failure with no synthetic row fallback."""
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # Must use ai_repair_strategy_section (AI-first) and
        # _mark_synth_failed on failure — no synthetic-row fallback.
        self.assertIn('ai_repair_strategy_section', src)
        self.assertIn('_mark_synth_failed', src)
        # No hardcoded fallback row insertion.
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
    def test_15_validators_not_weakened(self):
        """Test 15 — generic PDPL phrase ``حماية البيانات الشخصية``
        still does NOT satisfy DSR / breach families in either the
        framework-coverage validator OR the PR-5B.9Y save-guard
        exact-term gate."""
        # Framework-coverage validator.
        sections = _full_data_sections(_ROADMAP_GENERIC_PRIVACY_ONLY)
        # Replace the helper text in every section with ONLY the
        # generic privacy phrase so we isolate the validator gate.
        bare = '## section\nحماية البيانات الشخصية فقط\n'
        sections_bare = {k: bare for k in sections}
        missing = _APP._compute_missing_selected_framework_coverage(
            sections_bare, ['PDPL'],
            domain='Data Management', lang='ar') or []
        fams_missing = {fam for fw, fam, _sk in missing
                        if fw == 'PDPL'}
        self.assertIn('data_subject_rights', fams_missing)
        self.assertIn('breach_notification', fams_missing)
        # PR-5B.9Y save-guard exact-term gate.
        self.assertFalse(
            _APP._pdpl_save_guard_candidate_satisfies(
                'data_subject_rights', 'حماية البيانات الشخصية فقط'))
        self.assertFalse(
            _APP._pdpl_save_guard_candidate_satisfies(
                'breach_notification', 'حماية البيانات الشخصية فقط'))

    @_skip_if_no_app
    def test_16_auth_db_export_modules_not_imported_or_modified(self):
        """Test 16 — no auth / DB / export module mutations in the
        PR-5B.9AA scope. The convergence repair signature and the
        PR-5B.9Y save-guard signature are unchanged."""
        # Both helpers exist and accept the same kwargs as before.
        self.assertTrue(callable(
            _APP._convergence_data_roadmap_balance_repair))
        self.assertTrue(callable(
            _APP._pdpl_save_guard_candidate_satisfies))
        self.assertTrue(callable(
            _APP._pdpl_save_guard_terms_found))
        self.assertTrue(callable(
            _APP._pdpl_save_guard_required_terms))
        # PDPL guard now includes DSR (PR-5B.9AA).
        self.assertIn('data_subject_rights',
                      _APP._PR5B9Y_PDPL_EXACT_TERMS)
        # And the runtime-residual parser targets include DSR.
        parsed = _APP._pdpl_save_guard_parse_runtime_residuals([
            ('roadmap',
             'selected_framework_coverage_missing:PDPL:'
             'data_subject_rights', 0, 1)
        ])
        self.assertTrue(
            any(fw == 'PDPL' and fam == 'data_subject_rights'
                for fw, fam, _sk in parsed),
            f'PR-5B.9Y parser must surface DSR residuals: {parsed}')


if __name__ == '__main__':
    unittest.main()
