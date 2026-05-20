"""PR-CY9 — Persistent Cyber + ECC + DCC ``data_classification``
roadmap-balance failure after PR-CY8.

Runtime evidence (cyber + ECC + DCC, AR):

    [CYBER-ROADMAP-TOPUP-FAMILY]
    family=data_classification
    canonical_family=data_classification
    terms_found=[]
    accepted=False
    ...
    cyber_roadmap_balance_missing:data_classification (roadmap) 0/1

After PR-CY8 the family canonicalisation, exact-term list, and
per-family diagnostic plumbing were already in place. The remaining
failure was caused by the BUNDLED top-up prompt: when several DCC
families were missing at once the AI emitted rows satisfying
``data_protection`` / ``sensitive_data_handling`` / ``dlp`` /
``encryption`` but produced NO row literally containing
``تصنيف البيانات`` / ``تصنيف المعلومات`` / ``تصنيف الأصول البيانية``.

PR-CY9 adds:

  Part A — a LITERAL single-family contract block appended to the
           shared ``ve_base`` whenever ``data_classification`` is in
           the missing-families set. The block forbids substituting
           protection / sensitive-handling / DLP / encryption wording
           and lists the eight exact AR/EN classification terms.

  Part B — an ULTRA-STRICT second-pass addendum that requires the
           literal Arabic phrase ``تصنيف البيانات`` in the activity
           cell when ``data_classification`` is still missing after
           attempt 1.

  Part C — a runtime ``[CYBER-ROADMAP-TOPUP-FAMILY]`` diagnostic that
           emits ``candidate_preview`` (≤300 chars, whitespace-
           collapsed, no secrets) for rejected ``data_classification``
           attempts so operators can see what the AI actually wrote.

This module validates the PR-CY9 fix. Strictly Cyber-scoped — Data
Management / AI / DT / ERM behaviour is not exercised. No
deterministic rows are inserted. Validators are not weakened.

Run::

    python -m pytest \\
        tests/test_cyber_data_classification_topup_prcy9.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dc_prcy9_')
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


def _roadmap_with_row(activity):
    return (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        f'| 1 | {activity} | Q3 | DCC |\n'
    )


def _baseline_dcc_roadmap_missing_classification():
    """Existing DCC roadmap that covers encryption, DLP, sensitive
    handling and protection — but NOT classification."""
    return (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        '| 1 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
        '| 2 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
        '| 3 | معالجة البيانات الحساسة | Q4 | DCC |\n'
        '| 4 | ضوابط حماية البيانات أثناء النقل والتخزين | Q4 | DCC |\n'
    )


class TestAttemptOneClassificationAcceptance(unittest.TestCase):
    """Tests 1–7: per-row acceptance under the existing extractor +
    family detector. Attempt 1 (no classification term) is rejected;
    rows with any of the canonical classification phrases are
    accepted; rows with ONLY protection / sensitive-handling wording
    do NOT satisfy ``data_classification``."""

    @_skip_if_no_app
    def test_1_attempt_one_without_classification_terms_rejected(self):
        """Test 1 — Attempt 1 with no classification terms is
        rejected: the family extractor MUST NOT match a row that
        only contains protection / sensitive-handling wording."""
        ai_attempt1 = (
            '| 5 | تعزيز حماية البيانات ومعالجة البيانات الحساسة '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_attempt1, terms)
        self.assertNotIn(
            'data_classification', extracted,
            'Attempt 1 with NO classification term must NOT be '
            'extracted under data_classification')

    @_skip_if_no_app
    def test_2_attempt_two_with_tasnif_albayanat_accepted(self):
        """Test 2 — Attempt 2 with ``تصنيف البيانات`` is accepted."""
        ai_attempt2 = (
            '| 5 | تنفيذ تصنيف البيانات وفق ضوابط DCC '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_attempt2, terms)
        self.assertIn('data_classification', extracted)
        self.assertIn('تصنيف البيانات',
                      extracted['data_classification'])

    @_skip_if_no_app
    def test_3_sensitive_classification_accepted(self):
        """Test 3 — ``تصنيف البيانات الحساسة`` is accepted."""
        ai_row = (
            '| 5 | تطبيق تصنيف البيانات الحساسة عبر القطاعات '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_row, terms)
        self.assertIn('data_classification', extracted)
        self.assertIn('تصنيف البيانات الحساسة',
                      extracted['data_classification'])

    @_skip_if_no_app
    def test_4_information_classification_accepted(self):
        """Test 4 — ``تصنيف المعلومات`` is accepted."""
        ai_row = (
            '| 5 | تطوير إطار تصنيف المعلومات '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_row, terms)
        self.assertIn('data_classification', extracted)

    @_skip_if_no_app
    def test_5_data_asset_classification_accepted(self):
        """Test 5 — ``تصنيف الأصول البيانية`` is accepted."""
        ai_row = (
            '| 5 | تطبيق تصنيف الأصول البيانية '
            '| Q4 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_row, terms)
        self.assertIn('data_classification', extracted)

    @_skip_if_no_app
    def test_6_data_protection_alone_does_not_satisfy(self):
        """Test 6 — ``حماية البيانات`` alone does NOT satisfy
        ``data_classification`` (separate DCC family)."""
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row('تعزيز حماية البيانات بشكل عام'),
            ['DCC'], lang='ar')
        self.assertIn(
            'data_classification', miss,
            'حماية البيانات alone must NOT clear data_classification')

    @_skip_if_no_app
    def test_7_sensitive_handling_alone_does_not_satisfy(self):
        """Test 7 — ``معالجة البيانات الحساسة`` alone does NOT
        satisfy ``data_classification``."""
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _roadmap_with_row(
                'ضوابط التعامل مع البيانات الحساسة ومعالجة البيانات '
                'الحساسة'),
            ['DCC'], lang='ar')
        self.assertIn(
            'data_classification', miss,
            'sensitive-handling wording alone must NOT clear '
            'data_classification')


class TestSpliceAndFinalAudit(unittest.TestCase):
    """Tests 8–9: spliced ``data_classification`` row is retained
    verbatim and the final balance audit clears the defect."""

    @_skip_if_no_app
    def test_8_accepted_classification_row_spliced_and_retained(self):
        """Test 8 — Accepted ``data_classification`` row is spliced
        into the original roadmap and every original line is
        preserved verbatim."""
        before = _baseline_dcc_roadmap_missing_classification()
        # data_classification is missing pre-splice.
        miss_before = _APP._compute_missing_cyber_roadmap_balance_topics(
            before, ['DCC'], lang='ar')
        self.assertIn('data_classification', miss_before)

        ai_row = (
            '| 5 | تنفيذ تصنيف البيانات وتصنيف البيانات الحساسة '
            '| Q3 | DCC |\n'
        )
        terms = {
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(ai_row, terms)
        self.assertIn('data_classification', extracted)

        merged = _APP._splice_data_roadmap_topup_rows(
            before, [extracted['data_classification']])
        # Every original line preserved verbatim.
        for ln in before.split('\n'):
            self.assertIn(ln, merged,
                          f'splice dropped original line: {ln!r}')
        # Top-up row landed.
        self.assertIn(extracted['data_classification'], merged)
        # And the family is no longer missing after the splice.
        miss_after = _APP._compute_missing_cyber_roadmap_balance_topics(
            merged, ['DCC'], lang='ar')
        self.assertNotIn('data_classification', miss_after)

    @_skip_if_no_app
    def test_9_final_audit_clears_data_classification(self):
        """Test 9 — Final balance audit no longer emits
        ``cyber_roadmap_balance_missing:data_classification`` when a
        classification row is present."""
        full = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 1 | تنفيذ تصنيف البيانات وتصنيف البيانات الحساسة '
            '| Q3 | DCC |\n'
            '| 2 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
            '| 3 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
            '| 4 | معالجة البيانات الحساسة | Q4 | DCC |\n'
            '| 5 | ضوابط حماية البيانات أثناء النقل والتخزين '
            '| Q4 | DCC |\n'
        )
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            full, ['DCC'], lang='ar')
        self.assertNotIn('data_classification', miss)


class TestCandidatePreviewDiagnostic(unittest.TestCase):
    """Tests 10–11 (Part C): the convergence repair emits a
    ``[CYBER-ROADMAP-TOPUP-FAMILY] family=data_classification ...
    candidate_preview=...`` line for rejected attempts. We exercise
    this by injecting a stub ``ai_repair_strategy_section`` that
    returns AI output WITHOUT any classification term and capturing
    the printed diagnostic."""

    @_skip_if_no_app
    def test_10_candidate_preview_emitted_on_reject(self):
        """The diagnostic line MUST contain ``candidate_preview=``
        and the preview MUST be capped at 300 chars."""
        sections = {
            'roadmap': _baseline_dcc_roadmap_missing_classification(),
        }
        ctx = {
            'frameworks': ['DCC'],
            'org_name': 'TestOrg',
            'sector': 'General',
            'maturity': 'initial',
            'generation_mode': 'drafting',
            'org_structure_is_none': False,
        }
        # Stub the AI call so the repair runs offline. The stub
        # returns an AI candidate WITHOUT any classification term,
        # which must trigger the candidate_preview diagnostic.
        long_filler = 'ا' * 500
        stub_response = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 5 | تعزيز حماية البيانات ومعالجة البيانات الحساسة '
            f'وضوابط التشفير {long_filler} | Q3 | DCC |\n'
        )
        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = (
            lambda **kw: stub_response)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=ctx,
                    log={'synth_status': {}},
                    cycle_no=1,
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        # The targeted diagnostic appears.
        self.assertIn(
            '[CYBER-ROADMAP-TOPUP-FAMILY] family=data_classification',
            out)
        self.assertIn('candidate_preview=', out)
        # Each candidate_preview field is capped at 300 chars
        # (excluding the surrounding repr quotes).
        for line in out.split('\n'):
            if 'candidate_preview=' not in line:
                continue
            after = line.split('candidate_preview=', 1)[1]
            # repr() output starts/ends with quote; strip them.
            after = after.split(' terms_found=', 1)[0].strip()
            if after.startswith(("'", '"')) and after.endswith(
                    ("'", '"')):
                after = after[1:-1]
            self.assertLessEqual(
                len(after), 300,
                f'candidate_preview must be ≤300 chars: '
                f'len={len(after)}')

    @_skip_if_no_app
    def test_11_second_pass_includes_ultrastrict_addendum(self):
        """Part B — the second-pass validation_error addendum
        contains the verbatim ultra-strict prompt fragment when
        ``data_classification`` is still missing. We inspect the
        last validation_error string passed to the AI stub."""
        sections = {
            'roadmap': _baseline_dcc_roadmap_missing_classification(),
        }
        ctx = {
            'frameworks': ['DCC'],
            'org_name': 'TestOrg',
            'sector': 'General',
            'maturity': 'initial',
            'generation_mode': 'drafting',
            'org_structure_is_none': False,
        }
        ves = []

        def _stub(**kw):
            ves.append(kw.get('validation_error', ''))
            # Return a non-classification candidate so attempt 1 is
            # rejected and the strict second-pass prompt is built.
            return (
                '## 5. خارطة الطريق\n\n'
                '| # | النشاط | المرحلة | الإطار |\n'
                '|---|---|---|---|\n'
                '| 5 | تعزيز حماية البيانات | Q3 | DCC |\n')

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = _stub
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=ctx,
                    log={'synth_status': {}},
                    cycle_no=1,
                )
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        # Two attempts were made.
        self.assertGreaterEqual(len(ves), 2)
        # The second attempt validation_error must contain the
        # ultra-strict literal phrase requirement.
        self.assertIn(
            'يجب أن يحتوي نص النشاط حرفياً على عبارة: تصنيف البيانات',
            ves[1])
        self.assertIn('ULTRA-STRICT SECOND-PASS', ves[1])

    @_skip_if_no_app
    def test_12_attempt_one_prompt_contains_literal_strict_block(self):
        """Part A — the first-attempt ``ve_base`` already contains
        the literal STRICT FAMILY=data_classification CONTRACT block
        with all eight exact terms, and explicit rejection of
        protection / sensitive-handling / DLP / encryption rows."""
        sections = {
            'roadmap': _baseline_dcc_roadmap_missing_classification(),
        }
        ctx = {
            'frameworks': ['DCC'],
            'org_name': 'TestOrg',
            'sector': 'General',
            'maturity': 'initial',
            'generation_mode': 'drafting',
            'org_structure_is_none': False,
        }
        ves = []

        def _stub(**kw):
            ves.append(kw.get('validation_error', ''))
            # Stop after first attempt: return a valid all-families
            # row so accumulation completes — but classification is
            # still missing → repair will retry, that's fine for the
            # assertion below which only inspects ves[0].
            return (
                '## 5. خارطة الطريق\n\n'
                '| # | النشاط | المرحلة | الإطار |\n'
                '|---|---|---|---|\n'
                '| 5 | حماية البيانات | Q3 | DCC |\n')

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = _stub
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=ctx,
                    log={'synth_status': {}},
                    cycle_no=1,
                )
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        self.assertTrue(ves, 'AI stub must have been called')
        first = ves[0]
        self.assertIn('STRICT FAMILY=data_classification CONTRACT',
                      first)
        for exact in (
                'تصنيف البيانات',
                'تصنيف البيانات الحساسة',
                'تصنيف المعلومات',
                'تصنيف الأصول البيانية',
                'data classification',
                'sensitive data classification',
                'information classification',
                'data asset classification'):
            self.assertIn(exact, first,
                          f'Part A prompt must include exact term: '
                          f'{exact!r}')
        # Forbidden-substitution warning present.
        self.assertIn('REJECT rows that ONLY contain', first)


class TestRegressionScope(unittest.TestCase):
    """Tests 13–16 (regression): PR-CY9 must not modify Data
    Management / AI / DT / ERM behaviour, must not weaken validators,
    and must not insert deterministic rows."""

    @_skip_if_no_app
    def test_13_data_audit_unchanged(self):
        defects = _APP._final_strategy_audit(
            sections={'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': 'r',
                      'kpis': '', 'confidence': ''},
            lang='en',
            selected_frameworks=['NDMO'],
            domain='Data Management')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'))

    @_skip_if_no_app
    def test_14_ai_audit_unchanged(self):
        defects = _APP._final_strategy_audit(
            sections={'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': 'r',
                      'kpis': '', 'confidence': ''},
            lang='en',
            selected_frameworks=['SDAIA'],
            domain='Artificial Intelligence')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'))

    @_skip_if_no_app
    def test_15_repair_noop_for_non_cyber_domain(self):
        sections = {
            'roadmap': _baseline_dcc_roadmap_missing_classification(),
        }
        ctx = {'frameworks': ['NDMO'], 'org_name': 'X',
               'sector': 'General', 'maturity': 'initial',
               'generation_mode': 'drafting',
               'org_structure_is_none': False}
        orig_ai = _APP.ai_repair_strategy_section

        def _should_not_be_called(**kw):
            raise AssertionError(
                'AI must not be called for non-cyber domain')

        _APP.ai_repair_strategy_section = _should_not_be_called
        try:
            res = _APP._convergence_cyber_roadmap_balance_repair(
                sections, lang='ar', domain='Data Management',
                ctx=ctx, log={'synth_status': {}}, cycle_no=1)
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        self.assertEqual(res, 0)

    @_skip_if_no_app
    def test_16_no_deterministic_classification_row_inserted(self):
        """Per problem statement Part B: the repair must NOT
        synthesise a deterministic classification row. If the AI
        returns empty output, the original roadmap is preserved as-is
        AND the family remains missing (fail-closed semantics)."""
        before = _baseline_dcc_roadmap_missing_classification()
        sections = {'roadmap': before}
        ctx = {'frameworks': ['DCC'], 'org_name': 'X',
               'sector': 'General', 'maturity': 'initial',
               'generation_mode': 'drafting',
               'org_structure_is_none': False}
        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: ''
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=ctx,
                    log={'synth_status': {}},
                    cycle_no=1,
                )
        finally:
            _APP.ai_repair_strategy_section = orig_ai
        # Roadmap unchanged — no deterministic row was inserted.
        self.assertEqual(sections['roadmap'], before)
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['DCC'], lang='ar')
        self.assertIn('data_classification', miss)


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
