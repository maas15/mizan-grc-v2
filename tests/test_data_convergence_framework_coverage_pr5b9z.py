"""PR-5B.9Z — Convergence-stage Data framework coverage repair.

Runtime diagnosis showed convergence failing BEFORE the late
``[DATA-FRAMEWORK-COVERAGE-REPAIR]`` and PDPL final save guard could
run (cycle 1 before=11 after=11; cycle 2 before=11 after=16 ⇒
``save_decision=BLOCKED reason=convergence_failed``). The fix wires
the Data Management NDMO/PDPL coverage repair and roadmap-balance
repair INTO ``converge_strategy_sections``, adds rollback when a
cycle increases defects, and tightens progress accounting.

This module validates the wiring + accounting changes without needing
an actual AI provider. The AI repair helpers raise ``RepairError``
when no API key is configured; the test asserts that the helpers run
inside convergence and the fail-closed plumbing surfaces correctly.

Run:
    python -m pytest \\
        tests/test_data_convergence_framework_coverage_pr5b9z.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_conv_pr5b9z_')
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


# Office-only Data Management roadmap — has no NDMO/PDPL balance topics
# and triggers data_roadmap_balance_missing.
_OFFICE_ONLY_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) | DMO |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | data governance committee |\n'
    '| 3 | اعتماد نموذج التشغيل وخطوط الرفع | operating model |\n'
)


def _empty_data_sections():
    return {
        'vision': '', 'pillars': '', 'environment': '',
        'gaps': '', 'roadmap': _OFFICE_ONLY_ROADMAP_AR,
        'kpis': '', 'confidence': '',
    }


class TestConvergenceVocabularyAndConstants(unittest.TestCase):
    """Part B / Part C — vocabulary registry assertions."""

    @_skip_if_no_app
    def test_ndmo_data_stewardship_vocab_expanded(self):
        """Part B — NDMO data_stewardship validator vocabulary must
        accept the full AR/EN phrase set from the problem statement."""
        req = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO', {})
        caps = req.get('capabilities', [])
        stew = next(((fam, ar, en) for fam, ar, en in caps
                     if fam == 'data_stewardship'), None)
        self.assertIsNotNone(stew, 'data_stewardship missing from NDMO')
        _fam, ar, en = stew
        # AR phrases mandated by problem statement Part B
        for phrase in ('أمناء البيانات', 'مشرفو البيانات',
                       'ملاك البيانات', 'مالكو البيانات',
                       'ملكية البيانات',
                       'مسؤوليات أمناء البيانات',
                       'أدوار أمناء البيانات'):
            self.assertIn(phrase, ar,
                          f'AR stewardship phrase missing: {phrase}')
        # EN phrases mandated by problem statement Part B
        for phrase in ('data stewards', 'data stewardship',
                       'data owners', 'data ownership',
                       'data owner roles',
                       'data steward responsibilities'):
            self.assertIn(phrase, en,
                          f'EN stewardship phrase missing: {phrase}')

    @_skip_if_no_app
    def test_conv_dfc_family_tokens_module_level(self):
        """The convergence-stage DFC token registry must be exposed
        at module level so it is reachable from inside
        converge_strategy_sections."""
        self.assertTrue(hasattr(_APP, '_CONV_DATAFW_FAMILY_TOKENS'))
        toks = _APP._CONV_DATAFW_FAMILY_TOKENS
        # NDMO stewardship vocab in the convergence prompt
        stew = toks.get(('NDMO', 'data_stewardship'), {})
        self.assertIn('أمناء البيانات', stew.get('ar', []))
        self.assertIn('data stewards', stew.get('en', []))
        # PDPL classification exact terms (Part C)
        cls_pdpl = toks.get(('PDPL', 'data_classification_pdpl'), {})
        self.assertIn('تصنيف البيانات الشخصية', cls_pdpl.get('ar', []))
        self.assertIn('personal data classification',
                      cls_pdpl.get('en', []))
        # Generic PDPL phrases MUST NOT be in the classification
        # vocab (problem statement Part C explicitly forbids them).
        self.assertNotIn('حماية البيانات الشخصية',
                         cls_pdpl.get('ar', []))
        self.assertNotIn('الامتثال لـ PDPL',
                         cls_pdpl.get('ar', []))
        # Breach notification exact terms (Part C)
        breach = toks.get(('PDPL', 'breach_notification'), {})
        for p in ('إخطار الخروقات', 'الإبلاغ عن الانتهاكات',
                  'الإبلاغ عن خرق البيانات'):
            self.assertIn(p, breach.get('ar', []))
        for p in ('data breach notification', 'breach notification',
                  'breach reporting'):
            self.assertIn(p, breach.get('en', []))

    @_skip_if_no_app
    def test_conv_dfc_section_guidance_present(self):
        """All six affected sections must have convergence-stage
        guidance (Part B section contracts)."""
        g = _APP._CONV_DATAFW_SECTION_GUIDANCE
        for sec in ('environment', 'pillars', 'gaps', 'roadmap',
                    'kpis', 'confidence'):
            self.assertIn(sec, g, f'missing guidance: {sec}')
        # Steward / ownership content must appear in each contract
        # (Part B).
        for sec in ('environment', 'pillars', 'gaps', 'roadmap',
                    'kpis', 'confidence'):
            text = g[sec].lower()
            self.assertTrue(
                'steward' in text or 'ownership' in text,
                f'section {sec} guidance missing steward/ownership '
                f'wording: {g[sec]!r}')


class TestConvergenceTriggersDataFrameworkCoverageRepair(
        unittest.TestCase):
    """Tests 1-4 — convergence-stage DFC repair fires for NDMO /
    PDPL defects."""

    @_skip_if_no_app
    def _run_capturing_logs(self):
        sections = _empty_data_sections()
        buf = io.StringIO()
        with redirect_stdout(buf):
            log = _APP.converge_strategy_sections(
                sections, 'ar', 'Data Management', 'NDMO',
                ctx={'frameworks': ['NDMO', 'PDPL'],
                     'org_structure_is_none': False},
                doc_subtype=None, max_iter=1,
            )
        return log, buf.getvalue()

    @_skip_if_no_app
    def test_selected_framework_missing_triggers_convergence_repair(
            self):
        """Test 1 — selected_framework_coverage_missing during
        convergence triggers CONVERGENCE-DATA-FRAMEWORK-COVERAGE-
        REPAIR."""
        _log, out = self._run_capturing_logs()
        self.assertIn(
            '[CONVERGENCE-DATA-FRAMEWORK-COVERAGE-REPAIR]', out,
            'expected convergence-stage DFC repair log not emitted')

    @_skip_if_no_app
    def test_ndmo_data_stewardship_defect_handled_in_convergence(self):
        """Test 2 — NDMO:data_stewardship is one of the families the
        convergence-stage DFC repair must address. Without AI keys the
        repair attempt fails closed, but it MUST be attempted (i.e.
        the per-family CHECK / REPAIR diagnostic mentions
        data_stewardship)."""
        _log, out = self._run_capturing_logs()
        # Either the convergence repair attempt mentioned
        # data_stewardship in its diagnostic line, OR the convergence
        # loop's final defects include it as a remaining selected-
        # framework coverage defect (still detected, never silently
        # dropped).
        mentions = ('data_stewardship' in out)
        defects_str = repr(_log.get('final_defects') or [])
        defects_mention = 'data_stewardship' in defects_str
        self.assertTrue(
            mentions or defects_mention,
            f'data_stewardship neither repaired nor surfaced; '
            f'log_excerpt={out[-2000:]}')

    @_skip_if_no_app
    def test_pdpl_data_classification_pdpl_defect_handled(self):
        """Test 3 — PDPL:data_classification_pdpl handled inside
        convergence."""
        _log, out = self._run_capturing_logs()
        # PDPL classification canonicalises to
        # personal_data_classification in some paths; accept either.
        defects_str = repr(_log.get('final_defects') or [])
        mentioned = (
            'data_classification_pdpl' in out
            or 'personal_data_classification' in out
            or 'data_classification_pdpl' in defects_str
            or 'personal_data_classification' in defects_str)
        self.assertTrue(
            mentioned,
            f'PDPL classification family neither repaired nor '
            f'surfaced; log_excerpt={out[-2000:]}')

    @_skip_if_no_app
    def test_pdpl_personal_data_classification_defect_handled(self):
        """Test 4 — PDPL:personal_data_classification handled."""
        _log, out = self._run_capturing_logs()
        defects_str = repr(_log.get('final_defects') or [])
        self.assertTrue(
            'personal_data_classification' in out
            or 'personal_data_classification' in defects_str
            or 'data_classification' in out,
            f'personal_data_classification not addressed: '
            f'{out[-2000:]}')


class TestConvergenceRoadmapBalanceRepair(unittest.TestCase):
    """Test 5 — data_roadmap_balance_missing triggers convergence-
    stage roadmap balance repair."""

    @_skip_if_no_app
    def test_data_roadmap_balance_triggers_convergence_repair(self):
        sections = _empty_data_sections()
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP.converge_strategy_sections(
                sections, 'ar', 'Data Management', 'NDMO',
                ctx={'frameworks': ['NDMO', 'PDPL'],
                     'org_structure_is_none': False},
                doc_subtype=None, max_iter=1,
            )
        self.assertIn(
            '[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR]',
            buf.getvalue(),
            'expected convergence-stage roadmap-balance repair log '
            'not emitted')


class TestProgressAccounting(unittest.TestCase):
    """Tests 6-8 — progress accounting + rollback."""

    @_skip_if_no_app
    def test_repair_increasing_defects_is_rejected_and_rolled_back(
            self):
        """Test 6 / 8 — a cycle that increases defects must be
        rejected and originals restored. We force the situation by
        monkey-patching _final_strategy_audit to return a
        post-defect set larger than the pre-defect set."""
        original_audit = _APP._final_strategy_audit
        call_counter = {'n': 0}

        def fake_audit(*a, **kw):
            call_counter['n'] += 1
            # Calls: 1 = initial audit, 2 = start of cycle audit,
            # 3 = post-cycle audit. We want before=11 / after=16.
            n = call_counter['n']
            if n <= 2:
                return [('pillars', f'demo:{i}', 0, 1)
                        for i in range(11)]
            # After repairs: increased to 16
            return [('pillars', f'demo:{i}', 0, 1)
                    for i in range(16)]

        sections = {
            'vision': 'x', 'pillars': 'p',
            'environment': 'e', 'gaps': 'g',
            'roadmap': 'r', 'kpis': 'k', 'confidence': 'c',
        }
        snapshot = dict(sections)
        _APP._final_strategy_audit = fake_audit
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                log = _APP.converge_strategy_sections(
                    sections, 'en', 'Cyber Security', 'ECC',
                    ctx={'frameworks': ['ECC'],
                         'org_structure_is_none': False},
                    doc_subtype=None, max_iter=2,
                )
            out = buf.getvalue()
        finally:
            _APP._final_strategy_audit = original_audit

        # Progress must be False (defects increased), originals
        # restored, and a [CONVERGENCE-REPAIR-RESULT] log emitted.
        self.assertFalse(log.get('progress'),
                         f'progress wrongly True: {log}')
        self.assertIn('[CONVERGENCE-REPAIR-RESULT]', out)
        self.assertIn('accepted=False', out)
        self.assertIn('defects_increased', out)
        # Sections rolled back to their pre-cycle values
        self.assertEqual(sections['pillars'], snapshot['pillars'])
        self.assertEqual(sections['vision'], snapshot['vision'])

    @_skip_if_no_app
    def test_repair_equal_defects_not_counted_as_progress(self):
        """Test 7 — before=11 after=11 must not count as progress."""
        original_audit = _APP._final_strategy_audit
        call_counter = {'n': 0}

        def fake_audit(*a, **kw):
            call_counter['n'] += 1
            return [('pillars', f'demo:{i}', 0, 1)
                    for i in range(11)]

        sections = {
            'vision': 'x', 'pillars': 'p',
            'environment': 'e', 'gaps': 'g',
            'roadmap': 'r', 'kpis': 'k', 'confidence': 'c',
        }
        _APP._final_strategy_audit = fake_audit
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                log = _APP.converge_strategy_sections(
                    sections, 'en', 'Cyber Security', 'ECC',
                    ctx={'frameworks': ['ECC'],
                         'org_structure_is_none': False},
                    doc_subtype=None, max_iter=3,
                )
            out = buf.getvalue()
        finally:
            _APP._final_strategy_audit = original_audit

        self.assertFalse(log.get('progress'),
                         f'before==after wrongly counted as progress: '
                         f'{log}')
        self.assertIn('[CONVERGENCE-REPAIR-RESULT]', out)
        self.assertIn('no_progress', out)


class TestConvergenceFailClosed(unittest.TestCase):
    """Tests 9-11 — fail-closed behaviour + save guard relationship."""

    @_skip_if_no_app
    def test_convergence_fails_closed_when_dfc_defects_remain(self):
        """Test 10 — after two attempts, if coverage defects remain
        the convergence loop must NOT report converged=True."""
        sections = _empty_data_sections()
        buf = io.StringIO()
        with redirect_stdout(buf):
            log = _APP.converge_strategy_sections(
                sections, 'ar', 'Data Management', 'NDMO',
                ctx={'frameworks': ['NDMO', 'PDPL'],
                     'org_structure_is_none': False},
                doc_subtype=None, max_iter=2,
            )
        self.assertFalse(
            log.get('converged'),
            f'convergence wrongly converged with NDMO/PDPL '
            f'coverage gaps unfixed: {log}')

    @_skip_if_no_app
    def test_pdpl_final_save_guard_still_present(self):
        """Test 11 — PR-5B.9Y PDPL final save guard remains as a
        defense-in-depth fallback (we only added a primary repair
        inside convergence; the late guard MUST still be wired)."""
        # Sanity: helper names from prior PR-5B.9Y must still exist.
        self.assertTrue(
            hasattr(_APP, '_pdpl_save_guard_required_terms'),
            'PR-5B.9Y PDPL save guard helpers removed — fallback '
            'broken')


class TestScopeIsolation(unittest.TestCase):
    """Tests 12-15 — strict scope: Data only; no deterministic rows;
    validators not weakened; cross-domain unaffected."""

    @_skip_if_no_app
    def test_convergence_dfc_noop_for_cyber_domain(self):
        """Test 12 — Cyber convergence must not trigger
        CONVERGENCE-DATA-FRAMEWORK-COVERAGE-REPAIR."""
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP.converge_strategy_sections(
                sections, 'en', 'Cyber Security', 'ECC',
                ctx={'frameworks': ['ECC'],
                     'org_structure_is_none': False},
                doc_subtype=None, max_iter=1,
            )
        out = buf.getvalue()
        # The convergence-stage Data repair logs must NOT appear for
        # non-Data domains.
        self.assertNotIn(
            '[CONVERGENCE-DATA-FRAMEWORK-COVERAGE-REPAIR] '
            'cycle=1 missing_sections=', out)
        self.assertNotIn(
            '[CONVERGENCE-DATA-ROADMAP-BALANCE-REPAIR] '
            'cycle=1 missing_before=', out)

    @_skip_if_no_app
    def test_convergence_dfc_noop_for_ai_and_dt_and_erm(self):
        """Test 12 (cont) — AI / DT / ERM convergence not affected."""
        for dom, fws in (('Artificial Intelligence', ['SDAIA']),
                         ('Digital Transformation', ['DGA']),
                         ('Enterprise Risk Management', ['ISO22301'])):
            sections = {
                'vision': '', 'pillars': '', 'environment': '',
                'gaps': '', 'roadmap': 'short',
                'kpis': '', 'confidence': '',
            }
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP.converge_strategy_sections(
                    sections, 'en', dom, fws[0],
                    ctx={'frameworks': fws,
                         'org_structure_is_none': False},
                    doc_subtype=None, max_iter=1,
                )
            out = buf.getvalue()
            self.assertNotIn(
                '[CONVERGENCE-DATA-FRAMEWORK-COVERAGE-REPAIR] '
                'cycle=1 missing_sections=', out,
                f'{dom} convergence wrongly fired Data DFC repair')

    @_skip_if_no_app
    def test_no_deterministic_rows_inserted_on_repair_failure(self):
        """Test 13 — when AI keys are absent, the convergence DFC
        helper MUST fail closed (restore originals + mark
        synth_failed) and NOT insert any deterministic content."""
        sections = _empty_data_sections()
        before_pillars = sections['pillars']
        before_gaps = sections['gaps']
        _APP.converge_strategy_sections(
            sections, 'ar', 'Data Management', 'NDMO',
            ctx={'frameworks': ['NDMO', 'PDPL'],
                 'org_structure_is_none': False},
            doc_subtype=None, max_iter=1,
        )
        # Pillars / gaps started empty; without AI they must REMAIN
        # empty (we accept any side-effect from the generic synth
        # rebuilds which themselves may fail-close to empty). The
        # critical invariant: no canned NDMO/PDPL paragraph appears
        # without an AI provider.
        for canned in ('PR-5B', 'PLACEHOLDER',
                       'TODO', 'INSERT_NDMO_HERE'):
            self.assertNotIn(canned, sections.get('pillars', ''))
            self.assertNotIn(canned, sections.get('gaps', ''))
        # Ensure no obvious deterministic insertion happened for an
        # empty input.
        self.assertEqual(sections['pillars'], before_pillars)
        self.assertEqual(sections['gaps'], before_gaps)

    @_skip_if_no_app
    def test_validators_not_weakened(self):
        """Test 14 — the existing framework-coverage validator must
        still reject the office-only roadmap and detect every
        previously-required NDMO/PDPL family."""
        missing = _APP._compute_missing_selected_framework_coverage(
            _empty_data_sections(),
            ['NDMO', 'PDPL'],
            domain='Data Management',
            lang='ar',
        )
        fams_by_fw = {}
        for fw, fam, _sk in missing:
            fams_by_fw.setdefault(fw, set()).add(fam)
        # NB: 'data_governance' is intentionally NOT in the must-be-
        # missing list — the office-only roadmap fixture itself
        # mentions "data governance committee", which satisfies the
        # data_governance family vocabulary. The remaining four NDMO
        # families have no such incidental mention.
        for fam in ('data_quality', 'data_catalog',
                    'data_stewardship', 'data_lifecycle'):
            self.assertIn(fam, fams_by_fw.get('NDMO', set()),
                          f'NDMO {fam} no longer detected — validator '
                          f'weakened')
        for fam in ('privacy_governance', 'consent_management',
                    'data_subject_rights',
                    'personal_data_classification',
                    'breach_notification'):
            self.assertIn(fam, fams_by_fw.get('PDPL', set()),
                          f'PDPL {fam} no longer detected — validator '
                          f'weakened')


if __name__ == '__main__':
    unittest.main()
