"""PR-5B.9AE — Data PDPL roadmap personal_data_classification +
breach_notification coverage.

Runtime trace after PR-5B.9AA + PR-5B.9AD narrowed to ::

    selected_framework_coverage_missing:PDPL:\
personal_data_classification,breach_notification (roadmap) 0/1

Root cause: PR-5B.9AA wired ``data_subject_rights`` and
``breach_notification`` into the convergence-stage roadmap balance
repair acceptance gate; PR-5B.9AD added ``consent_management``. But
``personal_data_classification`` was still missing from the
convergence balance repair pre/post filters, candidate acceptance
gate, prompt contract block exact-term section, and the Part C
overwrite guard filter — so when only classification (or
classification + breach) regressed at runtime the convergence repair
never enforced the exact classification vocabulary and the residual
drained to the generic 422.

This module validates the PR-5B.9AE contract WITHOUT requiring an AI
provider. The AI repair helpers raise ``RepairError`` when no API key
is configured; the test asserts the wiring + detection + acceptance
gate behave correctly and the existing PR-5B.9AA/AD fail-closed
plumbing still fires (now extended to personal_data_classification).

Run::

    python -m pytest \\
        tests/test_data_pdpl_roadmap_classification_breach_pr5b9ae.py -q
"""
import importlib.util
import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ae_')
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
    data_subject_rights) EXCEPT ``personal_data_classification`` and
    ``breach_notification`` — those must be sourced from the roadmap
    text only. Isolates roadmap as the single variable for the
    detection / acceptance tests.
    """
    common_pdpl = (
        ' حوكمة الخصوصية. حماية البيانات الشخصية. '
        'إدارة الموافقات وسجل الموافقات والموافقة الصريحة. '
        'تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، حق الحذف. '
        'privacy governance; consent management; consent register; '
        'data subject rights; access request; rectification; erasure; '
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


# Generic roadmap that mentions ONLY "حماية البيانات الشخصية" and
# "PDPL compliance" — generic privacy phrases that must NOT satisfy
# either personal_data_classification or breach_notification.
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
    '| 8 | الامتثال لـ PDPL | CDO | Q3 | تقرير |\n'
    '| 9 | إدارة الموافقات وسجل الموافقات | CDO | Q4 | سجل |\n'
    '| 10 | تفعيل حقوق صاحب البيانات | CDO | Q4 | آلية |\n'
)

_ROADMAP_WITH_CLASSIFICATION_PERSONAL = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 11 | تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة |\n'
)

_ROADMAP_WITH_CLASSIFICATION_HANDLING = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 11 | تصنيف ومعالجة البيانات الشخصية | CDO | Q4 | إطار |\n'
)

_ROADMAP_WITH_BREACH_EKHTAR = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 11 | إخطار الخروقات | CISO | Q4 | آلية |\n'
)

_ROADMAP_WITH_BREACH_REPORTING = (
    _ROADMAP_GENERIC_PRIVACY_ONLY
    + '| 11 | الإبلاغ عن الانتهاكات | CISO | Q4 | سجل |\n'
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
            and fam in ('personal_data_classification',
                        'data_classification_pdpl',
                        'breach_notification')
            and sk == 'roadmap'
        })

    @_skip_if_no_app
    def test_01_missing_classification_in_roadmap_emits_defect(self):
        # Roadmap mentions breach but NOT classification.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | إدارة الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | تفعيل حقوق صاحب البيانات | CDO | Q1 | آلية |\n'
            '| 4 | إخطار الخروقات والإبلاغ عن الانتهاكات | CISO | Q2 | |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        m = self._roadmap_pdpl_missing(roadmap)
        # personal_data_classification or its alias must be flagged.
        self.assertTrue(
            {'personal_data_classification',
             'data_classification_pdpl'} & set(m),
            f'expected classification in missing; got {m}')
        self.assertNotIn('breach_notification', m)

    @_skip_if_no_app
    def test_02_missing_breach_in_roadmap_emits_defect(self):
        # Roadmap mentions classification but NOT breach.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | إدارة الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | تفعيل حقوق صاحب البيانات | CDO | Q1 | آلية |\n'
            '| 4 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        m = self._roadmap_pdpl_missing(roadmap)
        self.assertIn('breach_notification', m)

    @_skip_if_no_app
    def test_03_generic_privacy_phrase_only_fails_classification_and_breach(
            self):
        m = self._roadmap_pdpl_missing(_ROADMAP_GENERIC_PRIVACY_ONLY)
        self.assertTrue(
            {'personal_data_classification',
             'data_classification_pdpl'} & set(m),
            f'expected classification flagged for generic-only roadmap;'
            f' got {m}')
        self.assertIn('breach_notification', m)

    @_skip_if_no_app
    def test_04_tasnif_albayanat_alshakhsiyya_passes_classification(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_CLASSIFICATION_PERSONAL)
        self.assertNotIn('personal_data_classification', m)
        self.assertNotIn('data_classification_pdpl', m)

    @_skip_if_no_app
    def test_05_tasnif_wa_muajalat_passes_classification(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_CLASSIFICATION_HANDLING)
        self.assertNotIn('personal_data_classification', m)
        self.assertNotIn('data_classification_pdpl', m)

    @_skip_if_no_app
    def test_06_ekhtar_alkhuruqat_passes_breach_notification(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_BREACH_EKHTAR)
        self.assertNotIn('breach_notification', m)

    @_skip_if_no_app
    def test_07_ablagh_an_alintihakat_passes_breach_notification(self):
        m = self._roadmap_pdpl_missing(_ROADMAP_WITH_BREACH_REPORTING)
        self.assertNotIn('breach_notification', m)


class TestPart8ConvergenceRoadmapRepairPrompt(unittest.TestCase):
    """Test 8 — convergence roadmap repair prompt source contains the
    classification + breach exact terms and explicit row requirements
    per the problem statement (PR-5B.9AE)."""

    @_skip_if_no_app
    def test_08_prompt_contains_classification_and_breach_exact_terms(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # PR-5B.9AE contract block headings + family labels.
        self.assertIn('PR-5B.9AE', src)
        self.assertIn('personal_data_classification', src)
        self.assertIn('breach_notification', src)
        # Required explicit row activities from problem statement Part B.
        for t in ('تطبيق تصنيف البيانات الشخصية',
                  'تفعيل إخطار الخروقات',
                  'إطار تصنيف البيانات الشخصية',
                  'آلية إخطار الخروقات',
                  'سجل الإبلاغ عن الانتهاكات'):
            self.assertIn(t, src, f'missing required prompt term: {t}')
        # Required Arabic classification + breach terms surfaced in
        # the prompt (via _pdpl_save_guard_required_terms expansion).
        pdc_ar, pdc_en = _APP._pdpl_save_guard_required_terms(
            'personal_data_classification')
        brn_ar, brn_en = _APP._pdpl_save_guard_required_terms(
            'breach_notification')
        for t in ('تصنيف البيانات الشخصية',
                  'تصنيف البيانات الحساسة',
                  'تصنيف ومعالجة البيانات الشخصية'):
            self.assertIn(t, pdc_ar, f'missing AR classification term: {t}')
        for t in ('personal data classification',
                  'sensitive personal data classification',
                  'personal data handling'):
            self.assertIn(t, pdc_en, f'missing EN classification term: {t}')
        for t in ('إخطار الخروقات',
                  'الإبلاغ عن الانتهاكات',
                  'الإبلاغ عن خرق البيانات',
                  'إشعار خرق البيانات'):
            self.assertIn(t, brn_ar, f'missing AR breach term: {t}')
        for t in ('breach notification',
                  'data breach notification',
                  'breach reporting'):
            self.assertIn(t, brn_en, f'missing EN breach term: {t}')


class TestPart9To12AcceptanceGate(unittest.TestCase):
    """Tests 9-12 — candidate acceptance / second-attempt /
    final-audit fail-closed plumbing for personal_data_classification
    + breach_notification."""

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
    def test_09_candidate_missing_classification_is_rejected_and_restored(
            self):
        # No API keys => ai_repair_strategy_section raises RepairError;
        # the balance repair must restore the original roadmap and
        # mark synth_failed:roadmap. Pre-state for this roadmap surfaces
        # personal_data_classification AND breach_notification as
        # missing.
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
        # Both legacy + dedicated classification/breach diagnostic
        # emitted.
        self.assertIn('[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR]', out)
        self.assertIn('[DATA-ROADMAP-PDPL-COVERAGE]', out)
        # Per-family diagnostic naming surfaces both target families.
        self.assertIn('family=personal_data_classification', out)
        self.assertIn('family=breach_notification', out)
        # Trigger pre-state log includes the classification signal.
        self.assertIn('roadmap_pdpl_classification=True', out)

    @_skip_if_no_app
    def test_10_candidate_missing_breach_is_rejected_and_restored(self):
        # Roadmap that has classification but no breach text — verifies
        # breach residual still triggers fail-closed plumbing.
        roadmap = (
            '## 5. خارطة الطريق\n'
            '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
            '|---|------|------|------|------|\n'
            '| 1 | تأسيس مكتب البيانات | CDO | Q1 | ميثاق |\n'
            '| 2 | إدارة الموافقات | CDO | Q1 | سجل |\n'
            '| 3 | تفعيل حقوق صاحب البيانات | CDO | Q1 | آلية |\n'
            '| 4 | تصنيف البيانات الشخصية | CDO | Q2 | مصفوفة |\n'
            '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
            '| 6 | جودة البيانات | CDO | Q3 | مقاييس |\n'
            '| 7 | كتالوج البيانات | CDO | Q3 | كتالوج |\n'
            '| 8 | دورة حياة البيانات | CDO | Q4 | سياسة |\n'
            '| 9 | أمناء البيانات | CDO | Q4 | أدوار |\n'
        )
        sections, before, log, out = self._run_repair(roadmap)
        self.assertEqual(sections['roadmap'], before)
        self.assertIn('[DATA-ROADMAP-PDPL-COVERAGE]', out)
        self.assertIn('family=breach_notification', out)

    @_skip_if_no_app
    def test_11_second_attempt_triggered_on_first_failure(self):
        """Test 11 — the convergence balance repair issues up to TWO
        ``ai_repair_strategy_section`` attempts before fail-closing.
        Verified via the source (``while attempt < 2 and not
        accepted``); stricter second-pass requirement block must
        reference the unmet families (including classification /
        breach) and ask for at least one literal term per family."""
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        self.assertIn('while attempt < 2 and not accepted', src)
        self.assertIn('SECOND-PASS STRICT REQUIREMENT', src)
        # The strict-lines builder iterates _unmet_combined which is
        # the union of candidate_unmet (now including classification)
        # and _roadmap_pdpl_missing_post (also including
        # classification).
        self.assertIn('_pdpl_save_guard_required_terms(_ufam)', src)

    @_skip_if_no_app
    def test_12_final_audit_blocks_save_when_roadmap_lacks_classification_breach(
            self):
        """Test 12 —
        ``_compute_missing_selected_framework_coverage`` on a sections
        dict with a generic-only roadmap surfaces BOTH
        ``(PDPL, personal_data_classification|data_classification_pdpl,
        roadmap)`` and ``(PDPL, breach_notification, roadmap)`` so the
        final audit emits a 422 (validators not weakened)."""
        sections = _full_data_sections(_ROADMAP_GENERIC_PRIVACY_ONLY)
        missing = _APP._compute_missing_selected_framework_coverage(
            sections, _FRAMEWORKS,
            domain='Data Management', lang='ar') or []
        pairs = {(fw, fam, sk) for fw, fam, sk in missing}
        self.assertTrue(
            ('PDPL', 'personal_data_classification', 'roadmap') in pairs
            or ('PDPL', 'data_classification_pdpl', 'roadmap') in pairs,
            f'expected classification residual in {pairs}')
        self.assertIn(
            ('PDPL', 'breach_notification', 'roadmap'), pairs)


class TestPart13To18Isolation(unittest.TestCase):
    """Tests 13-18 — consent/rights still pass, NDMO unchanged,
    Cyber/AI/DT/ERM unchanged, no deterministic rows, validators not
    weakened, auth/DB/export untouched."""

    @_skip_if_no_app
    def test_13_consent_and_rights_still_pass(self):
        # Roadmap that explicitly satisfies all four PDPL families that
        # have surfaced as runtime residuals should be clean.
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
            'consent_management', pdpl_roadmap_missing)
        self.assertNotIn(
            'data_subject_rights', pdpl_roadmap_missing)
        self.assertNotIn(
            'personal_data_classification', pdpl_roadmap_missing)
        self.assertNotIn(
            'data_classification_pdpl', pdpl_roadmap_missing)
        self.assertNotIn(
            'breach_notification', pdpl_roadmap_missing)

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
        # Registry vocabulary for all four target PDPL families is
        # preserved (only additions to the save-guard exact-terms
        # registry — no tokens were removed).
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL', {})
        caps = {fam: (ar, en)
                for fam, ar, en in spec.get('capabilities', [])}
        self.assertIn('consent_management', caps)
        self.assertIn('data_subject_rights', caps)
        self.assertIn('breach_notification', caps)
        # Save guard exact-term registry includes classification +
        # breach AND retains consent / DSR.
        for fam in ('consent_management', 'data_subject_rights',
                    'breach_notification', 'personal_data_classification',
                    'data_classification_pdpl'):
            ar, en = _APP._pdpl_save_guard_required_terms(fam)
            self.assertTrue(ar, f'{fam} missing AR exact terms')
            self.assertTrue(en, f'{fam} missing EN exact terms')
        # Generic phrases must NOT satisfy classification or breach.
        generic_text = (
            'حماية البيانات الشخصية. الامتثال لـ PDPL. '
            'personal data protection; PDPL compliance.')
        self.assertFalse(
            _APP._pdpl_save_guard_candidate_satisfies(
                'personal_data_classification', generic_text),
            'generic privacy phrasing must not satisfy classification')
        self.assertFalse(
            _APP._pdpl_save_guard_candidate_satisfies(
                'breach_notification', generic_text),
            'generic privacy phrasing must not satisfy breach')

    @_skip_if_no_app
    def test_18_auth_db_export_untouched(self):
        # The PR-5B.9AE change-set only touches
        # _convergence_data_roadmap_balance_repair and the
        # converge_strategy_sections overwrite guard. Verify there is
        # no incidental mention of auth / db / export work in the
        # repair function.
        repair_src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        for forbidden in ('@app.route', 'login_required', 'pdf',
                          'docx', 'export', 'db.session', 'DATABASE_URL'):
            self.assertNotIn(
                forbidden, repair_src,
                f'unexpected {forbidden} in PDPL balance repair')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
