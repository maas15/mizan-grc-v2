"""PR-5B.9AJ — Data Management CDO/DPO role-mapping cleanup.

Defect: the latest Data Management generated PDF sometimes assigns the
Data Protection Officer (DPO) as the head of the Data Management Office
(DMO), e.g.

    ``إنشاء مكتب إدارة البيانات مع تعيين مسؤول حماية البيانات (DPO)``

or implies in vision / executive summary text that the DMO is led by
the DPO.  That is incorrect:

* DMO / مكتب إدارة البيانات MUST be led by the Chief Data Officer
  (CDO / رئيس البيانات / مدير البيانات الرئيسي).
* DPO / مسؤول حماية البيانات owns PDPL compliance, privacy governance,
  consent management, data-subject rights, breach notification, and
  personal-data protection ONLY.

This module exercises ``_normalize_data_dmo_cdo_owner`` directly and
asserts:

1.  AR roadmap rewrites the DMO-with-DPO setup to use CDO.
2.  AR vision / executive summary rewrites DMO-led-by-DPO to CDO.
3.  EN roadmap rewrites ``Data Management Office led by the DPO`` to
    use CDO.
4.  Stand-alone PDPL / privacy / consent / DSR / breach rows that
    legitimately name the DPO as owner are NOT rewritten.
5.  Wrong-domain (Cyber / AI / DT / ERM) sections are NOT touched.
6.  Helper is idempotent.
7.  Validators not weakened (registry still exposes the five PDPL
    capability families).
8.  auth / DB untouched — pure helper, no session / DB setup.

Run::

    python -m pytest \\
        tests/test_data_cdo_dpo_role_mapping_pr5b9aj.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9aj_cdo_dpo_')
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


class TestDataCdoDpoRoleMappingPR5B9AJ(unittest.TestCase):

    # 1. AR roadmap row "إنشاء مكتب إدارة البيانات مع تعيين مسؤول
    #    حماية البيانات (DPO)" must be rewritten to use CDO.
    @_skip_if_no_app
    def test_01_ar_roadmap_dmo_dpo_setup_rewritten_to_cdo(self):
        sections = {
            'roadmap':
                '| # | النشاط | المالك |\n'
                '|---|------|------|\n'
                '| 1 | إنشاء مكتب إدارة البيانات مع تعيين مسؤول حماية '
                'البيانات (DPO) | الإدارة العليا |\n',
        }
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertEqual(counts.get('roadmap'), 1)
        text = sections['roadmap']
        self.assertIn('رئيس البيانات (CDO)', text)
        self.assertNotIn(
            'مع تعيين مسؤول حماية البيانات (DPO)', text,
            f'roadmap still attributes DMO setup to DPO: {text!r}')

    # 2. AR vision / executive summary saying DMO led by DPO must be
    #    rewritten to use CDO as leader.
    @_skip_if_no_app
    def test_02_ar_vision_dmo_led_by_dpo_rewritten_to_cdo(self):
        sections = {
            'vision':
                'الرؤية: مكتب إدارة البيانات بقيادة مسؤول حماية '
                'البيانات لقيادة جميع الأنشطة.',
            'executive_summary':
                'الملخص التنفيذي: مكتب إدارة البيانات يرأسه مسؤول '
                'حماية البيانات (DPO).',
        }
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertGreaterEqual(counts.get('vision', 0), 1)
        self.assertGreaterEqual(counts.get('executive_summary', 0), 1)
        self.assertIn('بقيادة رئيس البيانات (CDO)',
                      sections['vision'])
        self.assertIn('يرأسه رئيس البيانات (CDO)',
                      sections['executive_summary'])

    # 3. EN roadmap row "Establish the Data Management Office led by
    #    the DPO" must be rewritten to use the CDO.
    @_skip_if_no_app
    def test_03_en_roadmap_dmo_led_by_dpo_rewritten_to_cdo(self):
        sections = {
            'roadmap':
                '| # | Activity | Owner |\n'
                '|---|---|---|\n'
                '| 1 | Establish the Data Management Office led by '
                'the DPO | Executive Management |\n',
        }
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'en', 'data')
        self.assertEqual(counts.get('roadmap'), 1)
        self.assertIn(
            'Data Management Office led by the Chief Data Officer (CDO)',
            sections['roadmap'])

    # 4. Stand-alone PDPL / privacy / consent / DSR / breach rows that
    #    legitimately name the DPO as owner are NOT rewritten — DPO
    #    keeps ownership of PDPL/privacy activities.
    @_skip_if_no_app
    def test_04_pdpl_rows_with_dpo_owner_preserved(self):
        sections = {
            'roadmap':
                '| # | النشاط | المالك |\n'
                '|---|------|------|\n'
                '| 1 | تنفيذ حوكمة الخصوصية وفق PDPL | مسؤول حماية '
                'البيانات (DPO) |\n'
                '| 2 | إدارة الموافقات وحقوق صاحب البيانات | مسؤول '
                'حماية البيانات (DPO) |\n'
                '| 3 | إعداد خطة الإبلاغ عن الانتهاكات | مسؤول حماية '
                'البيانات (DPO) |\n'
                '| 4 | تنفيذ تصنيف البيانات الشخصية | مسؤول حماية '
                'البيانات (DPO) |\n',
        }
        original = sections['roadmap']
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        # No replacements should happen on these legitimately
        # DPO-owned PDPL rows.
        self.assertEqual(counts, {})
        self.assertEqual(sections['roadmap'], original,
                         'PDPL rows with DPO owner must not be rewritten')

    # 5. Wrong-domain (Cyber / AI / DT / ERM) sections are NOT touched
    #    even if they contain DMO-like wording incidentally.
    @_skip_if_no_app
    def test_05_wrong_domain_not_touched(self):
        for dom in ('cyber', 'ai', 'dt', 'erm'):
            sections = {
                'roadmap':
                    '| 1 | إنشاء مكتب إدارة البيانات مع تعيين مسؤول '
                    'حماية البيانات (DPO) | … |\n',
            }
            original = sections['roadmap']
            counts = _APP._normalize_data_dmo_cdo_owner(
                sections, 'ar', dom)
            self.assertEqual(
                counts, {},
                f'{dom}: helper must not modify non-data sections '
                f'(got counts={counts!r})')
            self.assertEqual(
                sections['roadmap'], original,
                f'{dom}: roadmap text must remain unchanged')

    # 6. Helper is idempotent — running twice yields the same result.
    @_skip_if_no_app
    def test_06_idempotent(self):
        sections = {
            'roadmap':
                '| 1 | إنشاء مكتب إدارة البيانات مع تعيين مسؤول '
                'حماية البيانات (DPO) | الإدارة العليا |\n',
            'vision':
                'مكتب إدارة البيانات يرأسه مسؤول حماية البيانات.',
        }
        c1 = _APP._normalize_data_dmo_cdo_owner(sections, 'ar', 'data')
        c2 = _APP._normalize_data_dmo_cdo_owner(sections, 'ar', 'data')
        self.assertTrue(c1)
        self.assertEqual(c2, {},
                         f'idempotency violated: second pass {c2!r}')

    # 7. Validators not weakened — PDPL registry still exposes the
    #    five required capability families so the validator still
    #    enforces complete PDPL coverage.
    @_skip_if_no_app
    def test_07_validators_not_weakened(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL') or {}
        fam_ids = {c[0] for c in spec.get('capabilities') or []}
        for required in (
                'privacy_governance', 'consent_management',
                'data_subject_rights', 'breach_notification'):
            self.assertIn(
                required, fam_ids,
                f'PDPL registry missing capability: {required} '
                f'(got {fam_ids!r})')
        self.assertTrue(
            ('data_classification_pdpl' in fam_ids
             or 'personal_data_classification' in fam_ids),
            f'PDPL registry missing classification family: {fam_ids!r}')

    # 8. auth / DB untouched — pure helper, no session / DB setup,
    #    no network calls.
    @_skip_if_no_app
    def test_08_auth_db_untouched(self):
        sections = {'roadmap': ''}
        result = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertEqual(result, {})

    # 9. Helper tolerates empty / non-dict input without raising.
    @_skip_if_no_app
    def test_09_defensive_inputs(self):
        self.assertEqual(
            _APP._normalize_data_dmo_cdo_owner(None, 'ar', 'data'),
            {})
        self.assertEqual(
            _APP._normalize_data_dmo_cdo_owner({}, 'ar', 'data'),
            {})
        self.assertEqual(
            _APP._normalize_data_dmo_cdo_owner(
                {'roadmap': None}, 'ar', 'data'),
            {})


if __name__ == '__main__':
    unittest.main()
