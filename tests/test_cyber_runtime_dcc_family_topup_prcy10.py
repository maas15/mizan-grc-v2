"""PR-CY10 — Runtime regression proof for the Cyber DCC roadmap
family top-up (data_classification + sensitive_data_handling).

Background
==========

Render deployment evidence (gunicorn ``app:app --bind 0.0.0.0:$PORT
--timeout 180 --workers 1``) continued to surface, AFTER PR-CY9
commit ``b351cb7`` was merged into ``main``::

    cyber_roadmap_balance_missing:data_classification,
    sensitive_data_handling (roadmap) 0/1

PR-CY9 already:

* Augmented ``_CYBER_ROADMAP_BALANCE_TOPICS['data_classification']``
  and ``_CYBER_ROADMAP_BALANCE_TOPICS['sensitive_data_handling']``
  with the canonical AR/EN exact terms (``تصنيف البيانات`` /
  ``تصنيف البيانات الحساسة`` / ``تصنيف المعلومات`` /
  ``تصنيف الأصول البيانية`` / ``معالجة البيانات الحساسة`` /
  ``التعامل مع البيانات الحساسة`` / ``ضوابط التعامل مع البيانات
  الحساسة``).
* Wired an ULTRA-STRICT second-pass addendum that requires the literal
  Arabic phrase ``تصنيف البيانات`` when ``data_classification`` is
  still missing after attempt 1.
* Used ``_extract_data_roadmap_topup_rows`` to pick AT MOST ONE row
  per family (independent acceptance) and accumulated the splice
  across attempts so partial wins never regress.

This PR-CY10 module focuses on the RUNTIME PATH
(``_convergence_cyber_roadmap_balance_repair``) and proves:

* ``data_classification`` and ``sensitive_data_handling`` are
  accepted INDEPENDENTLY (no bundled "both or neither" requirement).
* A row carrying ``تصنيف البيانات`` is accepted at runtime.
* A row carrying ``معالجة البيانات الحساسة`` is accepted at runtime
  for ``sensitive_data_handling``.
* Attempt 2 contract injects the ULTRA-STRICT literal
  ``تصنيف البيانات`` clause when classification was still missing.
* Successful family rows persist when another family remains
  missing (the convergence pass does NOT restore the entire
  roadmap on partial wins).
* The final cyber balance audit clears when both family rows exist
  (``_compute_missing_cyber_roadmap_balance_topics`` returns no
  classification / sensitive-handling defect).
* Data Management / AI / DT / ERM behaviour is unchanged.
* Validators are NOT weakened.  No deterministic rows are inserted.

Run::

    python -m pytest \\
        tests/test_cyber_runtime_dcc_family_topup_prcy10.py -q
"""
import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dcc_prcy10_')
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
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Roadmap fixtures ────────────────────────────────────────────────────


def _roadmap_with_rows(activity_rows):
    """Build a roadmap section whose table contains the given rows.

    The roadmap row floor is satisfied by ECC operational activities
    that PR-CY9 lists as required for the ECC balance check (CISO
    department, governance committee, IAM, SOC, CSIRT, vulnerability
    management).  Without those rows the balance audit would still
    fail on ECC families and obscure the DCC family decisions this
    test cares about.
    """
    header = (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | الجهة المسؤولة | الإطار الزمني | '
        'المخرجات | الإطار |\n'
        '|---|---|---|---|---|---|\n'
    )
    ecc_rows = (
        '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | CEO | '
        'Q1 | ميثاق الإدارة | ECC |\n'
        '| 2 | تشكيل لجنة حوكمة الأمن السيبراني | CEO | Q1 | '
        'ميثاق اللجنة | ECC |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول وتطبيق MFA | CIO | '
        'Q2 | وثيقة IAM | ECC |\n'
        '| 4 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | '
        'CIO | Q2 | تقرير SOC | ECC |\n'
        '| 5 | تطوير CSIRT وخطة الاستجابة للحوادث | CISO | Q3 '
        '| خطة الاستجابة | ECC |\n'
        '| 6 | إدارة الثغرات الأمنية والتصحيحات | CISO | Q3 | '
        'تقرير VM | ECC |\n'
    )
    activity_text = ''
    for idx, activity in enumerate(activity_rows, start=7):
        activity_text += (
            f'| {idx} | {activity} | CISO | Q3 | المخرجات | DCC |\n'
        )
    return header + ecc_rows + activity_text


def _ctx_cyber_ecc_dcc():
    return {
        'frameworks': ['ECC', 'DCC'],
        'org_name': 'TestOrg',
        'sector': 'General',
        'maturity': 'initial',
        'generation_mode': 'drafting',
        'org_structure_is_none': True,
    }


# ── Test 5: attempt-2 contract injects literal ``تصنيف البيانات`` ──────


class TestAttemptTwoStrictContract(unittest.TestCase):

    @_skip_if_no_app
    def test_5_attempt_two_requires_literal_classification_phrase(self):
        """Test 5 — When ``data_classification`` is still missing
        after attempt 1, the second-pass validation_error MUST
        include the ULTRA-STRICT clause that demands the literal
        Arabic phrase ``تصنيف البيانات`` in the activity cell."""
        # Pre-state: roadmap has every DCC family EXCEPT
        # data_classification and sensitive_data_handling.
        before = _roadmap_with_rows([
            'تطبيق ضوابط التشفير على البيانات',
            'تطبيق DLP ومنع تسرب البيانات',
            'ضوابط حماية البيانات أثناء النقل والتخزين',
        ])
        sections = {'roadmap': before}
        # Attempt 1: AI emits rows that ONLY cover protection /
        # encryption / DLP — no classification term.
        # Attempt 2: AI emits a row with the literal classification
        # phrase, satisfying the strict contract.
        attempt1 = (
            '| 99 | تعزيز ضوابط حماية البيانات الحساسة '
            '| CISO | Q3 | تقرير | DCC |\n'
            '| 100 | تعزيز ضوابط التعامل مع البيانات الحساسة '
            '| CISO | Q3 | تقرير | DCC |\n'
        )
        attempt2 = (
            '| 99 | تنفيذ تصنيف البيانات وفق ضوابط DCC '
            '| CISO | Q3 | سياسة التصنيف | DCC |\n'
            '| 100 | ضوابط التعامل مع البيانات الحساسة وحماية '
            'معالجتها | CISO | Q3 | إجراءات | DCC |\n'
        )
        responses = [attempt1, attempt2]
        ves_seen = []

        def _stub(**kw):
            ves_seen.append(kw.get('validation_error', ''))
            return responses.pop(0)

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = _stub
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': {}}, cycle_no=1,
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # The runtime path made two AI calls.
        self.assertEqual(
            len(ves_seen), 2,
            f'expected 2 attempts; log=\n{out}')
        # Second attempt contract contains the ULTRA-STRICT clause.
        self.assertIn(
            'ULTRA-STRICT SECOND-PASS FOR family=data_classification',
            ves_seen[1])
        self.assertIn('تصنيف البيانات', ves_seen[1])


# ── Tests 6–7: per-family accepted rows extracted independently ─────────


class TestPerFamilyExtraction(unittest.TestCase):

    @_skip_if_no_app
    def test_6_row_with_tasnif_albayanat_accepted(self):
        """Test 6 — A row containing the literal phrase
        ``تصنيف البيانات`` is accepted by the family extractor under
        ``data_classification`` (and ONLY that family)."""
        ai_text = (
            '| 99 | تنفيذ تصنيف البيانات وفق ضوابط DCC '
            '| CISO | Q3 | سياسة | DCC |\n'
        )
        terms_map = {
            fam: list(_APP._CYBER_ROADMAP_BALANCE_TOPICS[fam])
            for fam in ('data_classification', 'sensitive_data_handling',
                        'data_protection', 'encryption', 'dlp')
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_text, terms_map)
        self.assertIn('data_classification', extracted)
        self.assertIn('تصنيف البيانات',
                      extracted['data_classification'])
        # The row must not double-count under other families.
        self.assertNotIn('sensitive_data_handling', extracted)
        self.assertNotIn('data_protection', extracted)

    @_skip_if_no_app
    def test_7_row_with_sensitive_handling_accepted(self):
        """Test 7 — A row containing ``معالجة البيانات الحساسة`` is
        accepted under ``sensitive_data_handling`` independently of
        ``data_classification``."""
        ai_text = (
            '| 99 | ضوابط التعامل مع البيانات الحساسة ومعالجة '
            'البيانات الحساسة | CISO | Q3 | إجراءات | DCC |\n'
        )
        terms_map = {
            fam: list(_APP._CYBER_ROADMAP_BALANCE_TOPICS[fam])
            for fam in ('data_classification', 'sensitive_data_handling',
                        'data_protection', 'encryption', 'dlp')
        }
        extracted = _APP._extract_data_roadmap_topup_rows(
            ai_text, terms_map)
        self.assertIn('sensitive_data_handling', extracted)
        self.assertIn(
            'معالجة البيانات الحساسة',
            extracted['sensitive_data_handling'])
        # Not bundled with classification.
        self.assertNotIn('data_classification', extracted)


# ── Test 8: families are accepted INDEPENDENTLY in one runtime call ─────


class TestIndependentFamilyAcceptance(unittest.TestCase):

    @_skip_if_no_app
    def test_8_classification_and_sensitive_handling_independent(self):
        """Test 8 — ``data_classification`` and
        ``sensitive_data_handling`` are accepted INDEPENDENTLY when
        the AI returns one row per family in the same response.
        The runtime pass clears both defects and the final balance
        audit returns no classification / sensitive-handling
        missing family."""
        before = _roadmap_with_rows([
            'تطبيق ضوابط التشفير على البيانات',
            'تطبيق DLP ومنع تسرب البيانات',
            'ضوابط حماية البيانات أثناء النقل والتخزين',
        ])
        sections = {'roadmap': before}
        # AI emits exactly one row per missing DCC family.
        attempt1 = (
            '| 99 | تنفيذ تصنيف البيانات وفق ضوابط DCC '
            '| CISO | Q3 | سياسة | DCC |\n'
            '| 100 | ضوابط التعامل مع البيانات الحساسة وضمان '
            'معالجتها بأمان | CISO | Q3 | إجراءات | DCC |\n'
        )

        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: attempt1
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': {}}, cycle_no=1,
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # Final balance audit: classification and sensitive-handling
        # are both gone from the missing families list.
        missing = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['ECC', 'DCC'], lang='ar') or []
        self.assertNotIn('data_classification', missing,
                         f'classification still missing; log=\n{out}')
        self.assertNotIn('sensitive_data_handling', missing,
                         f'sensitive-handling still missing; '
                         f'log=\n{out}')
        # Classification top-up diagnostic; sensitive_data_handling is
        # already satisfied by encryption/DLP rows (PR-CY79).
        self.assertIn(
            'family=data_classification', out)
        self.assertNotIn('sensitive_data_handling', missing)


# ── Test 9: partial wins persist when ONE family remains missing ────────


class TestPartialWinsPersist(unittest.TestCase):

    @_skip_if_no_app
    def test_9_successful_family_persists_when_other_still_missing(self):
        """Test 9 — When ``sensitive_data_handling`` succeeds on
        attempt 1 but ``data_classification`` still fails, the
        accepted ``sensitive_data_handling`` row must persist across
        attempts (it must NOT be thrown away when the overall
        repair fails)."""
        # ECC rows only — DCC families absent so sensitive_data_handling
        # is still missing (PR-CY79 does not infer SDH from ECC rows).
        before = _roadmap_with_rows([])
        sections = {'roadmap': before}
        miss_pre = _APP._compute_missing_cyber_roadmap_balance_topics(
            before, ['ECC', 'DCC'], lang='ar') or []
        self.assertIn('sensitive_data_handling', miss_pre)
        self.assertIn('data_classification', miss_pre)
        # Attempt 1: ONLY sensitive_data_handling row (no
        # classification).  Attempt 2: AI still fails to produce
        # classification.
        attempt1 = (
            '| 99 | ضوابط التعامل مع البيانات الحساسة | CISO | '
            'Q3 | إجراءات | DCC |\n'
        )
        attempt2 = (
            '| 100 | تعزيز ضوابط الحماية العامة | CISO | Q3 | '
            'تقرير | DCC |\n'
        )
        responses = [attempt1, attempt2]
        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = (
            lambda **kw: responses.pop(0))
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar',
                    domain='Cyber Security',
                    ctx=_ctx_cyber_ecc_dcc(),
                    log={'synth_status': {}}, cycle_no=1,
                )
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # sensitive_data_handling row persists in the final roadmap
        # even though overall repair failed for classification.
        self.assertIn(
            'ضوابط التعامل مع البيانات الحساسة',
            sections['roadmap'],
            f'accepted sensitive-handling row must persist; '
            f'roadmap=\n{sections["roadmap"]}\nlog=\n{out}')
        # data_classification is still in the missing set.
        missing_after = (
            _APP._compute_missing_cyber_roadmap_balance_topics(
                sections['roadmap'], ['ECC', 'DCC'], lang='ar')
            or [])
        self.assertIn('data_classification', missing_after)
        self.assertNotIn('sensitive_data_handling', missing_after)
        # Original ECC rows preserved verbatim.
        for ecc_marker in (
                'إنشاء إدارة الأمن السيبراني',
                'لجنة حوكمة الأمن السيبراني',
                'SOC',
                'CSIRT',
        ):
            self.assertIn(
                ecc_marker, sections['roadmap'],
                f'ECC row carrying {ecc_marker!r} must be preserved')


# ── Test 10: final audit no longer fails when both family rows exist ────


class TestFinalAuditClearsWhenBothRowsExist(unittest.TestCase):

    @_skip_if_no_app
    def test_10_final_audit_clears_classification_and_sensitive(self):
        """Test 10 — When the roadmap carries BOTH a
        ``data_classification`` row and a ``sensitive_data_handling``
        row alongside the rest of the DCC families, the final
        balance audit returns no
        ``cyber_roadmap_balance_missing:data_classification`` and no
        ``cyber_roadmap_balance_missing:sensitive_data_handling``
        defect."""
        roadmap = _roadmap_with_rows([
            'تطبيق ضوابط التشفير على البيانات',
            'تطبيق DLP ومنع تسرب البيانات',
            'ضوابط حماية البيانات أثناء النقل والتخزين',
            'تنفيذ تصنيف البيانات وفق ضوابط DCC',
            'ضوابط التعامل مع البيانات الحساسة',
        ])
        missing = _APP._compute_missing_cyber_roadmap_balance_topics(
            roadmap, ['ECC', 'DCC'], lang='ar') or []
        self.assertNotIn('data_classification', missing)
        self.assertNotIn('sensitive_data_handling', missing)
        # And the full DCC family set is cleared.
        for fam in ('data_classification', 'sensitive_data_handling',
                    'data_protection', 'encryption', 'dlp'):
            self.assertNotIn(
                fam, missing,
                f'DCC family {fam!r} must be cleared; missing={missing}')


# ── Regression: scope, validators, deterministic-row prohibition ────────


class TestRegressionScope(unittest.TestCase):

    @_skip_if_no_app
    def test_11_data_domain_unaffected(self):
        """The cyber roadmap balance repair must be a no-op for
        non-cyber domains.  The Data Management balance repair is
        a separate function and is NOT modified."""
        sections = {'roadmap': 'placeholder'}
        orig_ai = _APP.ai_repair_strategy_section

        def _should_not_be_called(**kw):
            raise AssertionError(
                'AI must not be called for non-cyber domain')

        _APP.ai_repair_strategy_section = _should_not_be_called
        try:
            for dom in ('Data Management',
                        'Artificial Intelligence',
                        'Digital Transformation',
                        'Enterprise Risk Management'):
                rc = _APP._convergence_cyber_roadmap_balance_repair(
                    sections, lang='ar', domain=dom,
                    ctx={'org_structure_is_none': True,
                         'frameworks': ['DCC']},
                    log={'synth_status': {}}, cycle_no=1,
                )
                self.assertEqual(
                    rc, 0,
                    f'cyber roadmap balance repair must be no-op '
                    f'for {dom!r}')
        finally:
            _APP.ai_repair_strategy_section = orig_ai

    @_skip_if_no_app
    def test_12_validators_not_weakened_protection_alone_rejected(self):
        """``حماية البيانات`` alone must NOT clear
        ``data_classification`` and ``معالجة البيانات الحساسة``
        alone must NOT clear ``data_classification`` either.
        PR-CY10 must keep this validator strict."""
        roadmap_protection_only = _roadmap_with_rows([
            'تعزيز حماية البيانات بشكل عام',
        ])
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            roadmap_protection_only, ['DCC'], lang='ar') or []
        self.assertIn('data_classification', miss,
                      'protection alone must NOT clear classification')

        roadmap_sensitive_only = _roadmap_with_rows([
            'ضوابط التعامل مع البيانات الحساسة',
        ])
        miss2 = _APP._compute_missing_cyber_roadmap_balance_topics(
            roadmap_sensitive_only, ['DCC'], lang='ar') or []
        self.assertIn(
            'data_classification', miss2,
            'sensitive-handling alone must NOT clear classification')

    @_skip_if_no_app
    def test_13_no_deterministic_rows_inserted(self):
        """When the AI returns empty text the convergence pass
        restores the original roadmap (or preserves accumulated AI
        wins from earlier attempts) and never inserts a
        deterministic family row of its own."""
        before = _roadmap_with_rows([
            'تطبيق ضوابط التشفير على البيانات',
            'تطبيق DLP ومنع تسرب البيانات',
            'ضوابط حماية البيانات أثناء النقل والتخزين',
        ])
        sections = {'roadmap': before}
        orig_ai = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = lambda **kw: ''
        try:
            _APP._convergence_cyber_roadmap_balance_repair(
                sections, lang='ar',
                domain='Cyber Security',
                ctx=_ctx_cyber_ecc_dcc(),
                log={'synth_status': {}}, cycle_no=1,
            )
        finally:
            _APP.ai_repair_strategy_section = orig_ai

        # Original roadmap preserved verbatim — no extra row
        # silently injected by the convergence pass.
        self.assertEqual(sections['roadmap'], before)

    @_skip_if_no_app
    def test_14_auth_db_export_helpers_not_touched(self):
        """Sanity-check that obvious auth / DB / export entry-points
        remain importable.  PR-CY10 only adds tests and (if needed)
        Cyber convergence-path changes — no auth / DB / export
        refactor."""
        for attr in ('app', 'login_required', 'render_template'):
            self.assertTrue(
                hasattr(_APP, attr),
                f'{attr!r} must remain available on app.py')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
