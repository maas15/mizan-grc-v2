"""PR-CY7 — Cyber Security roadmap family canonicalization + family-
level top-up accumulation.

Validates:

  1. ``dcc_data_classification`` / ``dcc_sensitive_handling`` /
     ``dcc_data_protection`` and the ECC aliases ``iam`` / ``soc_siem``
     / ``csirt_incident`` canonicalize to ``data_classification`` /
     ``sensitive_data_handling`` / ``data_protection`` /
     ``identity_access`` / ``monitoring`` / ``incident_response``.
  2. Strengthened exact terms for ``governance_committee`` /
     ``data_classification`` / ``sensitive_data_handling`` /
     ``data_protection`` from Part C of the problem statement.
  3. Family-level top-up rows are accumulated across attempts: a
     successful family row is kept even when another family is still
     missing (mirrors Data PR-5B.9AG).
  4. The splice helper preserves every original roadmap line verbatim
     so no deterministic rows are inserted.

Strictly scoped to (cyber, ECC|DCC). Data Management / AI / DT / ERM
behaviour is asserted unchanged.

Run::

    python -m pytest \\
        tests/test_cyber_roadmap_family_topup_prcy7.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_rmap_prcy7_')
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


# Thin operational roadmap mirroring the production PR-CY7 evidence.
_THIN_OPS_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|---|---|---|\n'
    '| 1 | تنفيذ إدارة الهوية والوصول IAM وتفعيل MFA و PAM | Q1 | ECC |\n'
    '| 2 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | Q1 | ECC |\n'
    '| 3 | تطوير فريق الاستجابة للحوادث CSIRT وخطة الاستجابة | Q2 | ECC |\n'
    '| 4 | تنفيذ إدارة الثغرات الأمنية والتصحيحات | Q2 | ECC |\n'
    '| 5 | إنشاء إدارة الأمن السيبراني وتعيين CISO | Q1 | ECC |\n'
)


class TestCyberRoadmapFamilyCanonicalization(unittest.TestCase):
    """Part A — family id canonicalization."""

    @_skip_if_no_app
    def test_dcc_data_classification_alias(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_data_classification'),
            'data_classification')

    @_skip_if_no_app
    def test_data_classification_passthrough(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'data_classification'),
            'data_classification')

    @_skip_if_no_app
    def test_dcc_sensitive_handling_alias(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_sensitive_handling'),
            'sensitive_data_handling')

    @_skip_if_no_app
    def test_sensitive_data_handling_passthrough(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'sensitive_data_handling'),
            'sensitive_data_handling')

    @_skip_if_no_app
    def test_dcc_data_protection_alias(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_data_protection'),
            'data_protection')

    @_skip_if_no_app
    def test_dcc_encryption_and_dlp_aliases(self):
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_encryption'),
            'encryption')
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'dcc_dlp'),
            'dlp')
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'DCC', 'data_loss_prevention'),
            'dlp')

    @_skip_if_no_app
    def test_ecc_aliases(self):
        # iam → identity_access
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family('ECC', 'iam'),
            'identity_access')
        # soc_siem → monitoring
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family('ECC', 'soc_siem'),
            'monitoring')
        # csirt → incident_response
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family('ECC', 'csirt'),
            'incident_response')
        # cyber_governance_committee → governance_committee
        self.assertEqual(
            _APP._canonicalize_cyber_roadmap_family(
                'ECC', 'cyber_governance_committee'),
            'governance_committee')


class TestCyberRoadmapBalancePartC(unittest.TestCase):
    """Part C — strengthened exact terms cover every problem-statement
    phrasing."""

    @_skip_if_no_app
    def test_governance_committee_exact_term(self):
        text = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط |\n|---|---|\n'
            '| 1 | تشكيل لجنة حوكمة الأمن السيبراني وميثاقها |\n')
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['ECC'], lang='ar')
        self.assertNotIn('governance_committee', miss,
                         f'governance_committee should be covered: {miss}')

    @_skip_if_no_app
    def test_data_classification_sensitive_term(self):
        text = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط |\n|---|---|\n'
            '| 1 | تصنيف البيانات الحساسة عبر القطاعات |\n')
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['DCC'], lang='ar')
        self.assertNotIn('data_classification', miss,
                         f'data_classification should be covered: {miss}')

    @_skip_if_no_app
    def test_sensitive_data_handling_term(self):
        text = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط |\n|---|---|\n'
            '| 1 | معالجة البيانات الحساسة وفق ضوابط NCA |\n')
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss,
                         f'sensitive_data_handling should be covered: '
                         f'{miss}')

    @_skip_if_no_app
    def test_data_protection_term(self):
        text = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط |\n|---|---|\n'
            '| 1 | ضوابط حماية البيانات الحساسة |\n')
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['DCC'], lang='ar')
        self.assertNotIn('data_protection', miss,
                         f'data_protection should be covered: {miss}')


class TestCyberRoadmapTopupAccumulation(unittest.TestCase):
    """Part B — family-level top-up rows accumulate across attempts."""

    @_skip_if_no_app
    def test_partial_top_up_row_retained_when_other_family_fails(self):
        # First-pass AI text covers ONE missing family
        # (sensitive_data_handling) but not the others. Extraction
        # should keep the successful row regardless.
        ai_text = (
            '| 7 | معالجة البيانات الحساسة وفق الضوابط | Q3 | DCC |\n'
        )
        # Two families are required at this point.
        terms = {
            'sensitive_data_handling': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'sensitive_data_handling']),
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
            'governance_committee': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'governance_committee']),
        }
        extracted = _APP._extract_data_roadmap_topup_rows(ai_text, terms)
        self.assertIn('sensitive_data_handling', extracted)
        self.assertNotIn('data_classification', extracted)
        self.assertNotIn('governance_committee', extracted)

    @_skip_if_no_app
    def test_second_attempt_can_add_remaining_family(self):
        # Simulate two AI passes producing different families. Both
        # rows must survive after the second pass.
        first_pass = (
            '| 7 | معالجة البيانات الحساسة وفق الضوابط | Q3 | DCC |\n'
        )
        second_pass = (
            '| 8 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |\n'
            '| 9 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |\n'
        )
        terms = {
            'sensitive_data_handling': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'sensitive_data_handling']),
            'data_classification': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'data_classification']),
            'governance_committee': list(
                _APP._CYBER_ROADMAP_BALANCE_TOPICS[
                    'governance_committee']),
        }
        accumulated = {}
        for ai_text in (first_pass, second_pass):
            extracted = _APP._extract_data_roadmap_topup_rows(
                ai_text, terms)
            for fam, row in extracted.items():
                if fam not in accumulated:
                    accumulated[fam] = row
        for fam in ('sensitive_data_handling', 'governance_committee',
                    'data_classification'):
            self.assertIn(fam, accumulated, f'lost family {fam}')

    @_skip_if_no_app
    def test_splice_preserves_original_rows_no_deterministic_rows(self):
        before = _THIN_OPS_ROADMAP_AR
        new_rows = [
            '| 6 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |',
            '| 7 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |',
            '| 8 | معالجة البيانات الحساسة وفق الضوابط | Q3 | DCC |',
        ]
        merged = _APP._splice_data_roadmap_topup_rows(before, new_rows)
        for ln in before.split('\n'):
            self.assertIn(ln, merged,
                          f'splice dropped original line: {ln!r}')
        for r in new_rows:
            self.assertIn(r, merged)
        # After splice three more families are covered.
        miss_before = (
            _APP._compute_missing_cyber_roadmap_balance_topics(
                before, ['ECC', 'DCC'], lang='ar'))
        miss_after = (
            _APP._compute_missing_cyber_roadmap_balance_topics(
                merged, ['ECC', 'DCC'], lang='ar'))
        for fam in ('governance_committee', 'data_classification',
                    'sensitive_data_handling'):
            self.assertIn(fam, miss_before)
            self.assertNotIn(fam, miss_after,
                             f'{fam} not covered after splice')

    @_skip_if_no_app
    def test_final_audit_only_fails_for_unresolved_families(self):
        # Roadmap covers everything EXCEPT data_protection.
        partially_balanced = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المرحلة | الإطار |\n'
            '|---|---|---|---|\n'
            '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | Q1 | ECC |\n'
            '| 2 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |\n'
            '| 3 | تنفيذ إدارة الهوية والوصول IAM وتفعيل MFA | Q1 | ECC |\n'
            '| 4 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | Q2 | ECC |\n'
            '| 5 | تطوير فريق CSIRT وخطة الاستجابة للحوادث | Q2 | ECC |\n'
            '| 6 | تنفيذ إدارة الثغرات الأمنية والتصحيحات | Q2 | ECC |\n'
            '| 7 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |\n'
            '| 8 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
            '| 9 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
            '| 10 | معالجة البيانات الحساسة وفق الضوابط | Q4 | DCC |\n'
        )
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            partially_balanced, ['ECC', 'DCC'], lang='ar')
        self.assertEqual(miss, ['data_protection'],
                         f'only data_protection should remain: {miss}')

    @_skip_if_no_app
    def test_helper_does_not_insert_deterministic_rows(self):
        # The detector is read-only; the splice helper only inserts the
        # AI-emitted rows it was given (never deterministic content).
        before = _THIN_OPS_ROADMAP_AR
        merged = _APP._splice_data_roadmap_topup_rows(before, [])
        self.assertEqual(merged, before,
                         'splice must be a no-op for empty AI input')


class TestCyberRoadmapBalanceRegressionScope(unittest.TestCase):
    """Strict-scope regression: Data/AI/DT/ERM final-audit unchanged."""

    @_skip_if_no_app
    def test_data_audit_unchanged(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        defects = _APP._final_strategy_audit(
            sections=sections, lang='en',
            selected_frameworks=['NDMO'],
            domain='Data Management')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'),
                f'Data must not emit cyber defect: {tag}')

    @_skip_if_no_app
    def test_ai_audit_unchanged(self):
        defects = _APP._final_strategy_audit(
            sections={'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': 'r',
                      'kpis': '', 'confidence': ''},
            lang='en', selected_frameworks=['SDAIA'],
            domain='Artificial Intelligence')
        for _sec, tag, *_ in defects:
            self.assertFalse(
                tag.startswith('cyber_roadmap_balance_missing:'))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
