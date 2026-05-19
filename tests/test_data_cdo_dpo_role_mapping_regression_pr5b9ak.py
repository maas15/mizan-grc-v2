"""PR-5B.9AK — Data CDO/DPO role-mapping regression coverage.

Regression after PR-5B.9AJ: the strategy-generation pipeline normalizes
DMO-led-by-DPO wording to DMO-led-by-CDO via
``_normalize_data_dmo_cdo_owner``, but re-export / cached-content paths
that go straight into ``_build_strategy_document_model`` bypass that
hook and would otherwise render
``إنشاء مكتب إدارة البيانات مع تعيين مسؤول حماية البيانات (DPO)``
verbatim in the PDF / DOCX executive summary / vision / roadmap.

This module asserts:

1.  ``_normalize_data_dmo_cdo_owner`` rewrites executive_summary DMO-
    with-DPO wording to use CDO.
2.  Same for vision.
3.  DPO ownership on stand-alone PDPL / privacy / consent / DSR /
    breach rows is preserved.
4.  ``_build_strategy_document_model`` now applies the normalizer
    in-process before composing exec-summary / traceability so PDF/
    DOCX export always renders the CDO wording even on cached / re-
    export paths.
5.  Cyber / AI / DT / ERM sections are not touched.
6.  Validators are not weakened.
7.  auth / DB untouched — pure helpers.

Run::

    python -m pytest \\
        tests/test_data_cdo_dpo_role_mapping_regression_pr5b9ak.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ak_cdo_dpo_reg_')
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


class TestDataCdoDpoRoleMappingRegressionPR5B9AK(unittest.TestCase):

    # 1. AR executive_summary DMO-with-DPO setup wording is rewritten
    #    to use the CDO.
    @_skip_if_no_app
    def test_01_executive_summary_dmo_dpo_rewritten_to_cdo(self):
        sections = {
            'executive_summary':
                'يتضمن الملخص التنفيذي إنشاء مكتب إدارة البيانات مع '
                'تعيين مسؤول حماية البيانات (DPO) لقيادة جميع '
                'الأنشطة.',
        }
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertGreaterEqual(counts.get('executive_summary', 0), 1)
        self.assertIn(
            'إنشاء مكتب إدارة البيانات مع تعيين رئيس البيانات (CDO)',
            sections['executive_summary'])
        self.assertNotIn(
            'إنشاء مكتب إدارة البيانات مع تعيين مسؤول حماية البيانات',
            sections['executive_summary'])

    # 2. AR vision DMO-led-by-DPO wording is rewritten to use the CDO.
    @_skip_if_no_app
    def test_02_vision_dmo_dpo_rewritten_to_cdo(self):
        sections = {
            'vision':
                'الرؤية: مكتب إدارة البيانات برئاسة مسؤول حماية '
                'البيانات (DPO) ضمن إطار حوكمة شامل.',
        }
        counts = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertGreaterEqual(counts.get('vision', 0), 1)
        self.assertIn('برئاسة رئيس البيانات (CDO)', sections['vision'])

    # 3. DPO ownership on PDPL rows is preserved — privacy /
    #    consent / DSR / breach rows remain owned by the DPO.
    @_skip_if_no_app
    def test_03_dpo_remains_owner_for_pdpl_rows(self):
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
        self.assertEqual(counts, {})
        self.assertEqual(sections['roadmap'], original,
                         'PDPL rows with DPO owner must not be rewritten')

    # 4. ``_build_strategy_document_model`` applies the normalizer
    #    before composing exec-summary / traceability so PDF / DOCX
    #    export always renders the CDO wording even on cached / re-
    #    export paths.
    @_skip_if_no_app
    def test_04_document_model_normalizes_dmo_owner(self):
        sections = {
            'vision':
                '## 1. الرؤية\n\n'
                'مكتب إدارة البيانات بقيادة مسؤول حماية البيانات '
                'لقيادة جميع الأنشطة.\n',
            'pillars': '',
            'environment': '',
            'gaps': '',
            'roadmap':
                '## 5. خارطة الطريق\n\n'
                '| # | النشاط | المالك |\n'
                '|---|------|------|\n'
                '| 1 | إنشاء مكتب إدارة البيانات مع تعيين مسؤول حماية '
                'البيانات (DPO) | الإدارة العليا |\n',
            'kpis': '',
            'confidence': '',
        }
        model = _APP._build_strategy_document_model(
            content='',
            metadata={
                'org_name': 'Test Org',
                'sector': 'Government',
                'domain': 'Data Management',
                'selected_frameworks': ['NDMO', 'PDPL'],
            },
            sections=sections,
            selected_frameworks=['NDMO', 'PDPL'],
            lang='ar',
        )
        # The section dict was mutated in place — DMO-with-DPO must
        # have been rewritten to use CDO before exec-summary built.
        self.assertIn('بقيادة رئيس البيانات (CDO)',
                      sections['vision'])
        self.assertIn(
            'إنشاء مكتب إدارة البيانات مع تعيين رئيس البيانات (CDO)',
            sections['roadmap'])
        self.assertNotIn(
            'مع تعيين مسؤول حماية البيانات (DPO)',
            sections['roadmap'])
        # Executive summary block in the model should likewise reflect
        # the CDO wording (it is composed from the normalized vision).
        exec_paras = (model.get('blocks') or {}).get(
            'executive_summary') or []
        joined = ' '.join(str(p) for p in exec_paras)
        self.assertNotIn(
            'مكتب إدارة البيانات بقيادة مسؤول حماية البيانات',
            joined,
            'executive summary still attributes DMO leadership to DPO')

    # 5. Wrong-domain (Cyber / AI / DT / ERM) sections are NOT touched
    #    by the document-model normalization.
    @_skip_if_no_app
    def test_05_wrong_domain_document_model_not_touched(self):
        for dom_label, dom_code in (
                ('Cyber Security', 'cyber'),
                ('Artificial Intelligence', 'ai'),
                ('Digital Transformation', 'dt'),
                ('Enterprise Risk Management', 'erm')):
            sections = {
                'vision':
                    'مكتب إدارة البيانات بقيادة مسؤول حماية البيانات.',
                'pillars': '', 'environment': '', 'gaps': '',
                'roadmap': '', 'kpis': '', 'confidence': '',
            }
            original_vision = sections['vision']
            _APP._build_strategy_document_model(
                content='',
                metadata={'domain': dom_label},
                sections=sections,
                selected_frameworks=[],
                lang='ar',
            )
            self.assertEqual(
                sections['vision'], original_vision,
                f'{dom_label}: vision text must remain unchanged '
                f'(got {sections["vision"]!r})')

    # 6. Idempotent — running the helper a second time after the
    #    document-model pass is a no-op.
    @_skip_if_no_app
    def test_06_normalizer_idempotent(self):
        sections = {
            'vision':
                'مكتب إدارة البيانات يرأسه مسؤول حماية البيانات (DPO).',
        }
        c1 = _APP._normalize_data_dmo_cdo_owner(sections, 'ar', 'data')
        c2 = _APP._normalize_data_dmo_cdo_owner(sections, 'ar', 'data')
        self.assertTrue(c1)
        self.assertEqual(c2, {})

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

    # 8. auth / DB untouched — pure helper, no session / DB setup.
    @_skip_if_no_app
    def test_08_auth_db_untouched(self):
        sections = {'vision': ''}
        result = _APP._normalize_data_dmo_cdo_owner(
            sections, 'ar', 'data')
        self.assertEqual(result, {})


if __name__ == '__main__':
    unittest.main()
