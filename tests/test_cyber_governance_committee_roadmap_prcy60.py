"""PR-CY60 — Cyber roadmap governance committee balance repair.

Run:
    python -m pytest tests/test_cyber_governance_committee_roadmap_prcy60.py -v
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_gc_roadmap_prcy60_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app.py: {_e!r}')

_THIN_OPS = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|---|---|---|\n'
    '| 1 | تنفيذ إدارة الهوية والوصول IAM وتفعيل MFA و PAM | Q1 | ECC |\n'
    '| 2 | تأسيس مركز العمليات الأمنية SOC وتفعيل SIEM | Q1 | ECC |\n'
    '| 3 | تطوير فريق الاستجابة للحوادث CSIRT | Q2 | ECC |\n'
    '| 4 | تنفيذ إدارة الثغرات الأمنية والتصحيحات | Q2 | ECC |\n'
    '| 5 | تنفيذ تصنيف البيانات الحساسة | Q3 | DCC |\n'
    '| 6 | تطبيق DLP ومنع تسرب البيانات | Q3 | DCC |\n'
)

_VALID_GC_ROW = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المرحلة | الإطار |\n'
    '|---|---|---|---|\n'
    '| 1 | تشكيل لجنة حوكمة الأمن السيبراني | Q1 | ECC |\n'
)


def _skip(fn):
    import functools
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


class GovernanceCommitteeRoadmapPrcy60Tests(unittest.TestCase):

    @_skip
    def test_missing_governance_committee_repaired_before_gate(self):
        sections = {'roadmap': _THIN_OPS}
        miss_before = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['ECC', 'DCC'], lang='ar')
        self.assertIn('governance_committee', miss_before)
        out = _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security',
            phase='test')
        self.assertTrue(out.get('gate_passed'))
        self.assertTrue(out.get('inserted_governance_committee_row'))
        miss_after = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['ECC', 'DCC'], lang='ar')
        self.assertNotIn('governance_committee', miss_after)

    @_skip
    def test_existing_row_not_duplicated(self):
        sections = {'roadmap': _VALID_GC_ROW}
        before = sections['roadmap']
        out = _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC'], 'Cyber Security', phase='test')
        self.assertEqual(out.get('action_taken'), 'already_present')
        self.assertFalse(out.get('inserted_governance_committee_row'))
        self.assertEqual(sections['roadmap'].count('لجنة حوكمة الأمن السيبراني'), 1)
        self.assertEqual(before, sections['roadmap'])

    @_skip
    def test_arabic_lajna_hokoma_recognized(self):
        text = '| 1 | لجنة حوكمة الأمن السيبراني | Q1 | ECC |'
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['ECC'], lang='ar')
        self.assertNotIn('governance_committee', miss)

    @_skip
    def test_arabic_steering_committee_recognized(self):
        text = '| 1 | اللجنة التوجيهية للأمن السيبراني | Q1 | ECC |'
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['ECC'], lang='ar')
        self.assertNotIn('governance_committee', miss)

    @_skip
    def test_english_steering_committee_recognized(self):
        text = '| 1 | Cybersecurity Steering Committee charter | Q1 | ECC |'
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            text, ['ECC'], lang='en')
        self.assertNotIn('governance_committee', miss)

    @_skip
    def test_repair_survives_resplice_not_duplicated(self):
        sections = {'roadmap': _THIN_OPS}
        _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='t1')
        first = sections['roadmap']
        _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='t2')
        self.assertEqual(first, sections['roadmap'])
        self.assertEqual(
            sections['roadmap'].count('تأسيس لجنة حوكمة الأمن السيبراني'), 1)

    @_skip
    def test_dcc_rows_preserved_after_repair(self):
        sections = {'roadmap': _THIN_OPS}
        _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='test')
        self.assertIn('تصنيف البيانات', sections['roadmap'])
        self.assertIn('DLP', sections['roadmap'])

    @_skip
    def test_roadmap_horizon_coverage_remains_valid(self):
        sections = {'roadmap': _THIN_OPS}
        out = _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='test')
        self.assertGreater(out.get('final_roadmap_rows', 0), 0)
        cov = _APP._prcy25_compute_roadmap_coverage_months(sections)
        self.assertGreaterEqual(cov, out.get('final_coverage_months', 0))

    @_skip
    def test_audit_no_governance_committee_defect_after_repair(self):
        sections = {'roadmap': _THIN_OPS}
        _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='test')
        defects = _APP._final_strategy_audit(
            sections, 'ar', selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security')
        tags = [d[1] for d in defects]
        gc = [t for t in tags if 'governance_committee' in t
              and 'roadmap_balance' in t]
        self.assertEqual(gc, [], f'unexpected defects: {tags}')

    @_skip
    def test_non_cyber_domain_untouched(self):
        sections = {'roadmap': 'short roadmap without committee'}
        before = sections['roadmap']
        out = _APP._cyber_roadmap_governance_committee_balance_repair(
            sections, 'en', ['NDMO'], 'Data Management', phase='test')
        self.assertEqual(out.get('action_taken'), 'skipped_non_cyber')
        self.assertEqual(sections['roadmap'], before)


if __name__ == '__main__':
    unittest.main()
