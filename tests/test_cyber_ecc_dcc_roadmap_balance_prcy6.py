"""PR-CY6 — Cyber Security ECC + DCC roadmap balance enforcement.

Validates that when ``domain='Cyber Security'`` and ECC and/or DCC is
selected, the roadmap MUST cover the six ECC operational families
(CISO department setup, governance committee, IAM/MFA/PAM, SOC/SIEM,
CSIRT/incident response, vulnerability management) and the five DCC
families (data classification, encryption, DLP, sensitive data
handling, data protection). Detection-only — no deterministic content
is inserted by the helper. AI-first repair is wired into
``converge_strategy_sections`` via
``_convergence_cyber_roadmap_balance_repair`` and emits
``[CYBER-ROADMAP-BALANCE-REPAIR]`` diagnostics.

Strictly scoped to (cyber, ECC|DCC):
  * Data Management / AI / Digital Transformation / ERM final audit
    must NOT emit a ``cyber_roadmap_balance_missing`` defect.
  * No deterministic roadmap rows are inserted anywhere by this PR.
  * Validators, scope, glossary, repair passes, auth / DB / export
    routes are untouched.

Run:
    python -m pytest \
        tests/test_cyber_ecc_dcc_roadmap_balance_prcy6.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_rmap_prcy6_')
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


# Thin operational-only roadmap mirroring the production PR-CY6
# evidence: IAM / SOC / CSIRT / vulnerability management activities
# only — no CISO-setup, no governance committee, no DCC families.
_THIN_OPS_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|---|---|---|\n'
    '| 1 | تنفيذ إدارة الهوية والوصول IAM وتفعيل MFA و PAM | Q1 | ECC |\n'
    '| 2 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | Q1 | ECC |\n'
    '| 3 | تطوير فريق الاستجابة للحوادث CSIRT وخطة الاستجابة للحوادث | Q2 | ECC |\n'
    '| 4 | تنفيذ إدارة الثغرات الأمنية والتصحيحات | Q2 | ECC |\n'
)

# Balanced roadmap — covers all 6 ECC + 5 DCC families.
_BALANCED_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | Q1 | ECC |\n'
    '| 2 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |\n'
    '| 3 | تنفيذ إدارة الهوية والوصول IAM وتفعيل MFA و PAM | Q1 | ECC |\n'
    '| 4 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | Q2 | ECC |\n'
    '| 5 | تطوير فريق الاستجابة للحوادث CSIRT وخطة الاستجابة للحوادث | Q2 | ECC |\n'
    '| 6 | تنفيذ إدارة الثغرات الأمنية والتصحيحات | Q2 | ECC |\n'
    '| 7 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |\n'
    '| 8 | تطبيق ضوابط التشفير على البيانات | Q3 | DCC |\n'
    '| 9 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
    '| 10 | معالجة البيانات الحساسة وفق الضوابط | Q4 | DCC |\n'
    '| 11 | حماية البيانات أثناء النقل والتخزين | Q4 | DCC |\n'
)


class TestCyberRoadmapBalanceHelper(unittest.TestCase):
    """Detection helper returns the missing family set, no
    deterministic rows ever inserted."""

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_ciso_setup(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        self.assertIn('ciso_department', miss,
                      f'missing CISO-department defect; got {miss}')

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_governance_committee(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        self.assertIn('governance_committee', miss)

    @_skip_if_no_app
    def test_empty_roadmap_missing_iam(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            '', ['ECC'], lang='ar')
        # PR-CY7 — canonical id is ``identity_access``.
        self.assertIn('identity_access', miss)

    @_skip_if_no_app
    def test_empty_roadmap_missing_soc_siem(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            '', ['ECC'], lang='ar')
        # PR-CY7 — canonical id is ``monitoring``.
        self.assertIn('monitoring', miss)

    @_skip_if_no_app
    def test_empty_roadmap_missing_csirt_incident(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            '', ['ECC'], lang='ar')
        # PR-CY7 — canonical id is ``incident_response``.
        self.assertIn('incident_response', miss)

    @_skip_if_no_app
    def test_empty_roadmap_missing_vulnerability_management(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            '', ['ECC'], lang='ar')
        self.assertIn('vulnerability_management', miss)

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_dcc_data_classification(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        # PR-CY7 — canonical id is ``data_classification``.
        self.assertIn('data_classification', miss)

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_dcc_encryption(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        # PR-CY7 — canonical id is ``encryption``.
        self.assertIn('encryption', miss)

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_dcc_dlp(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        # PR-CY7 — canonical id is ``dlp``.
        self.assertIn('dlp', miss)

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_dcc_sensitive_handling(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        # PR-CY7 — canonical id is ``sensitive_data_handling``.
        self.assertIn('sensitive_data_handling', miss)

    @_skip_if_no_app
    def test_thin_ops_roadmap_missing_dcc_data_protection(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        # PR-CY7 — canonical id is ``data_protection``.
        self.assertIn('data_protection', miss)

    @_skip_if_no_app
    def test_balanced_roadmap_emits_no_defect(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _BALANCED_ROADMAP_AR, ['ECC', 'DCC'], lang='ar')
        self.assertEqual(miss, [],
                         f'expected no missing, got {miss}')

    @_skip_if_no_app
    def test_ecc_only_selection_does_not_require_dcc_families(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['ECC'], lang='ar')
        # PR-CY7 — canonical DCC family ids.
        for dcc_fam in ('data_classification', 'encryption',
                        'dlp', 'sensitive_data_handling',
                        'data_protection'):
            self.assertNotIn(dcc_fam, miss,
                             f'ECC-only must not require {dcc_fam}')

    @_skip_if_no_app
    def test_dcc_only_selection_does_not_require_ecc_families(self):
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            _THIN_OPS_ROADMAP_AR, ['DCC'], lang='ar')
        # PR-CY7 — canonical ECC family ids.
        for ecc_fam in ('ciso_department', 'governance_committee',
                        'identity_access', 'monitoring',
                        'incident_response',
                        'vulnerability_management'):
            self.assertNotIn(ecc_fam, miss,
                             f'DCC-only must not require {ecc_fam}')


class TestCyberRoadmapBalanceAuditWiring(unittest.TestCase):
    """``_final_strategy_audit`` must emit
    ``cyber_roadmap_balance_missing:...`` for Cyber + ECC/DCC and
    must NOT emit it for other domains."""

    @_skip_if_no_app
    def _audit_tags(self, **kw):
        defects = _APP._final_strategy_audit(**kw)
        return [d[1] for d in defects]

    @_skip_if_no_app
    def test_audit_emits_balance_defect_for_thin_ops_roadmap(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _THIN_OPS_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='ar',
            selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security',
        )
        bal = [t for t in tags
               if t.startswith('cyber_roadmap_balance_missing:')]
        self.assertEqual(len(bal), 1,
                         f'expected one balance defect, got {tags}')
        self.assertIn('ciso_department', bal[0])
        # PR-CY7 — canonical id (was ``dcc_data_classification``).
        self.assertIn('data_classification', bal[0])

    @_skip_if_no_app
    def test_audit_no_balance_defect_for_balanced_roadmap(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': _BALANCED_ROADMAP_AR,
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='ar',
            selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security',
        )
        bal = [t for t in tags
               if t.startswith('cyber_roadmap_balance_missing:')]
        self.assertEqual(bal, [], f'unexpected defect: {tags}')

    @_skip_if_no_app
    def test_data_audit_unchanged_no_cyber_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['NDMO'],
            domain='Data Management',
        )
        self.assertFalse(
            any(t.startswith('cyber_roadmap_balance_missing:')
                for t in tags),
            f'Data domain must not emit cyber balance defect: {tags}')

    @_skip_if_no_app
    def test_ai_audit_unchanged_no_cyber_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=['SDAIA'], domain='Artificial Intelligence',
        )
        self.assertFalse(
            any(t.startswith('cyber_roadmap_balance_missing:')
                for t in tags),
            f'AI domain must not emit cyber balance defect: {tags}')

    @_skip_if_no_app
    def test_dt_audit_unchanged_no_cyber_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=[], domain='Digital Transformation',
        )
        self.assertFalse(
            any(t.startswith('cyber_roadmap_balance_missing:')
                for t in tags),
            f'DT domain must not emit cyber balance defect: {tags}')

    @_skip_if_no_app
    def test_erm_audit_unchanged_no_cyber_defect(self):
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': 'short roadmap',
            'kpis': '', 'confidence': '',
        }
        tags = self._audit_tags(
            sections=sections, lang='en',
            selected_frameworks=[], domain='Enterprise Risk Management',
        )
        self.assertFalse(
            any(t.startswith('cyber_roadmap_balance_missing:')
                for t in tags),
            f'ERM domain must not emit cyber balance defect: {tags}')


class TestCyberRoadmapTopupSplicePreservation(unittest.TestCase):
    """Top-up splice helper preserves existing roadmap rows verbatim
    and appends only the new family rows (mirrors PR-5B.9AF behaviour
    reused by the cyber convergence repair)."""

    @_skip_if_no_app
    def test_splice_preserves_existing_rows(self):
        before = _THIN_OPS_ROADMAP_AR
        new_rows = [
            '| 5 | إنشاء إدارة الأمن السيبراني وتعيين CISO | Q1 | ECC |',
            '| 6 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |',
            '| 7 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |',
        ]
        merged = _APP._splice_data_roadmap_topup_rows(before, new_rows)
        # Every original line must survive verbatim.
        for ln in before.split('\n'):
            self.assertIn(ln, merged,
                          f'splice dropped existing line: {ln!r}')

    @_skip_if_no_app
    def test_splice_appends_only_missing_family_rows(self):
        before = _THIN_OPS_ROADMAP_AR
        new_rows = [
            '| 5 | إنشاء إدارة الأمن السيبراني وتعيين CISO | Q1 | ECC |',
            '| 6 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |',
        ]
        merged = _APP._splice_data_roadmap_topup_rows(before, new_rows)
        # The new rows are present in the merged output.
        for r in new_rows:
            self.assertIn(r, merged)
        # Re-running the balance helper on the merged text shows the
        # corresponding families are now covered.
        miss_before = (
            _APP._compute_missing_cyber_roadmap_balance_topics(
                before, ['ECC', 'DCC'], lang='ar'))
        miss_after = (
            _APP._compute_missing_cyber_roadmap_balance_topics(
                merged, ['ECC', 'DCC'], lang='ar'))
        self.assertIn('ciso_department', miss_before)
        self.assertNotIn('ciso_department', miss_after)
        # PR-CY7 — canonical id (was ``dcc_data_classification``).
        self.assertIn('data_classification', miss_before)
        self.assertNotIn('data_classification', miss_after)


class TestNoDeterministicRowsInserted(unittest.TestCase):
    """The detection helper itself never modifies the sections dict."""

    @_skip_if_no_app
    def test_helper_does_not_mutate_input(self):
        before = _THIN_OPS_ROADMAP_AR
        snapshot = before
        _ = _APP._compute_missing_cyber_roadmap_balance_topics(
            before, ['ECC', 'DCC'], lang='ar')
        self.assertEqual(before, snapshot,
                         'helper must not mutate roadmap text')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
