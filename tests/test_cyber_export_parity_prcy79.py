"""PR-CY79 — sensitive_data_handling roadmap balance before save gate."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy79_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


def _dcc_row(initiative, output='مخرج', fw='NCA DCC'):
    return (
        '| المرحلة 2: تمكين | 7-18 شهر | '
        f'{initiative} | مدير حماية البيانات | {output} | {fw} |'
    )


def _roadmap_header():
    return (
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
        '|---|---|---|---|---|---|\n'
    )


class Prcy79SensitiveDataHandlingTests(unittest.TestCase):

    @_skip
    def test_helpers_and_flag(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy79'))
        self.assertTrue(hasattr(_APP, '_cyber_sensitive_data_handling_detected_in_roadmap'))
        self.assertTrue(hasattr(_APP, '_cyber_roadmap_sensitive_data_handling_balance_repair'))

    @_skip
    def test_dlp_row_satisfies_sensitive_data_handling(self):
        rm = _roadmap_header() + _dcc_row('تفعيل DLP ومراقبة تسرب البيانات')
        self.assertTrue(
            _APP._cyber_sensitive_data_handling_detected_in_roadmap(rm))
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            rm, ['DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss)

    @_skip
    def test_encryption_row_satisfies_sensitive_data_handling(self):
        rm = _roadmap_header() + _dcc_row(
            'تطبيق ضوابط التشفير وإدارة المفاتيح')
        self.assertTrue(
            _APP._cyber_sensitive_data_handling_detected_in_roadmap(rm))
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            rm, ['DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss)

    @_skip
    def test_classification_row_satisfies_sensitive_data_handling(self):
        rm = _roadmap_header() + _dcc_row('تصنيف وجرد البيانات الحساسة')
        self.assertTrue(
            _APP._cyber_sensitive_data_handling_detected_in_roadmap(rm))
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            rm, ['DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss)

    @_skip
    def test_generic_data_alone_does_not_satisfy(self):
        rm = _roadmap_header() + _dcc_row('data')
        self.assertFalse(
            _APP._cyber_sensitive_data_handling_detected_in_roadmap(rm))
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            rm, ['DCC'], lang='ar')
        self.assertIn('sensitive_data_handling', miss)

    @_skip
    def test_owner_only_does_not_satisfy(self):
        rm = (
            _roadmap_header()
            + '| المرحلة 2: تمكين | 7-18 شهر | — | مدير حماية البيانات | — | NCA DCC |\n'
        )
        self.assertFalse(
            _APP._cyber_sensitive_data_handling_detected_in_roadmap(rm))
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            rm, ['DCC'], lang='ar')
        self.assertIn('sensitive_data_handling', miss)

    @_skip
    def test_canonical_row_inserted_when_missing(self):
        rm = _roadmap_header() + _dcc_row('تأسيس حوكمة DCC عامة', 'مخرج عام')
        sections = {'roadmap': rm}
        miss_before = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['ECC', 'DCC'], lang='ar')
        self.assertIn('sensitive_data_handling', miss_before)
        out = _APP._cyber_roadmap_sensitive_data_handling_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='test')
        self.assertTrue(out.get('inserted_row'))
        self.assertTrue(out.get('gate_passed'))
        miss_after = _APP._compute_missing_cyber_roadmap_balance_topics(
            sections['roadmap'], ['ECC', 'DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss_after)

    @_skip
    def test_canonical_row_not_duplicated(self):
        rm = _roadmap_header() + _dcc_row('تفعيل DLP ومراقبة تسرب البيانات')
        sections = {'roadmap': rm}
        _APP._cyber_roadmap_sensitive_data_handling_balance_repair(
            sections, 'ar', ['DCC'], 'Cyber Security', phase='t1')
        before = sections['roadmap']
        _APP._cyber_roadmap_sensitive_data_handling_balance_repair(
            sections, 'ar', ['DCC'], 'Cyber Security', phase='t2')
        self.assertEqual(before, sections['roadmap'])
        init = _APP._CYBER_SENSITIVE_DATA_HANDLING_CANONICAL_INIT_AR
        self.assertLessEqual(sections['roadmap'].count(init), 1)

    @_skip
    def test_audit_no_sensitive_data_handling_defect_after_repair(self):
        rm = _roadmap_header() + _dcc_row('تأسيس حوكمة DCC', 'مخرج')
        sections = {'roadmap': rm}
        _APP._cyber_roadmap_sensitive_data_handling_balance_repair(
            sections, 'ar', ['ECC', 'DCC'], 'Cyber Security', phase='test')
        defects = _APP._final_strategy_audit(
            sections, 'ar', selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security')
        tags = [d[1] for d in defects]
        sdh = [t for t in tags if 'sensitive_data_handling' in t
               and 'roadmap_balance' in t]
        self.assertEqual(sdh, [], f'unexpected defects: {tags}')


if __name__ == '__main__':
    unittest.main()
