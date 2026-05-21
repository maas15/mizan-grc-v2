"""PR-CY17 — Cyber governance model rendering tests.

Production symptom (cyber + ECC + DCC, Arabic PDF): the
``نموذج الحوكمة والمسؤوليات`` / ``Governance and Ownership Model``
section was populated by the legacy KPI-table owner extractor with
KPI assessment-procedure rows (``جمع بيانات الحسابات المميزة
النشطة``, ``فحص تكوين MFA لكل حساب مميز``, etc.) instead of actual
governance roles.

PR-CY17 introduces the deterministic ``_CYBER_GOVERNANCE_ROLES_AR``
/ ``_CYBER_GOVERNANCE_ROLES_EN`` table consumed by
``_extract_owners_from_content`` when the domain is Cyber Security
and the document has substantive content.

Run:
    python -m pytest tests/test_cyber_governance_model_rendering_prcy17.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_gov_prcy17_')
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


# A non-empty Cyber strategy-content fixture so the extractor returns
# the deterministic Cyber governance roles (the empty-content guard
# stays in place to satisfy PR-5B.8R / PR-5B.8S).
_CYBER_FIXTURE_AR = {
    'vision':    'تأسيس إدارة الأمن السيبراني وتعيين CISO.',
    'pillars':   'الركائز: الحوكمة، SOC، IAM/PAM/MFA، CSIRT.',
    'roadmap':   'تأسيس SOC، تطبيق MFA.',
    'kpis':      'متوسط زمن كشف الحوادث.',
    'gaps':      'ضعف الحوكمة.',
    'environment': 'بيئة تنظيمية NCA ECC و NCA DCC.',
    'confidence':  'مخاطر الاستجابة للحوادث.',
}


def _govern_rows(lang='ar'):
    return _APP._extract_owners_from_content(
        _CYBER_FIXTURE_AR, lang, domain_code='cyber')


def _flatten(rows):
    parts = []
    for r in rows:
        parts.extend(str(c) for c in r)
    return ' \n '.join(parts)


class CyberGovernanceModelRenderingTests(unittest.TestCase):

    @_skip_if_no_app
    def test_01_governance_model_includes_ciso(self):
        rows = _govern_rows('ar')
        self.assertTrue(rows, 'Cyber governance rows missing')
        blob = _flatten(rows)
        self.assertIn('CISO', blob)

    @_skip_if_no_app
    def test_02_governance_model_includes_steering_committee(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        self.assertIn('اللجنة التوجيهية للأمن السيبراني', blob)

    @_skip_if_no_app
    def test_03_governance_model_includes_soc_manager(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        self.assertIn('SOC', blob)
        # Either AR ``مدير مركز العمليات الأمنية`` or EN ``SOC Manager``.
        self.assertTrue(
            ('مدير مركز العمليات الأمنية' in blob)
            or ('SOC Manager' in blob),
            f'SOC manager role missing; blob={blob!r}')

    @_skip_if_no_app
    def test_04_governance_model_includes_data_protection_manager(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        self.assertTrue(
            ('مدير حماية البيانات' in blob)
            or ('Data Protection Manager' in blob),
            f'Data protection manager role missing; blob={blob!r}')

    @_skip_if_no_app
    def test_05_governance_model_excludes_kpi_assessment_procedure_rows(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        # KPI assessment / measurement procedure phrases must NEVER appear
        # in the governance model output.
        forbidden = (
            'جمع بيانات الحسابات المميزة النشطة',
            'فحص تكوين MFA لكل حساب مميز',
            'احتساب النسبة المئوية للامتثال',
            'تسجيل أوقات بداية ونهاية كشف كل حادثة',
            'مسح وتحديد الثغرات الأمنية الحرجة',
        )
        for f in forbidden:
            self.assertNotIn(
                f, blob,
                f'Governance model contains forbidden KPI step: {f!r}')

    @_skip_if_no_app
    def test_06_governance_model_excludes_account_data_collection(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        self.assertNotIn('جمع بيانات الحسابات المميزة النشطة', blob)

    @_skip_if_no_app
    def test_07_governance_model_excludes_mfa_config_check(self):
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        self.assertNotIn('فحص تكوين MFA لكل حساب مميز', blob)

    @_skip_if_no_app
    def test_08_governance_rows_are_five_columns(self):
        rows = _govern_rows('ar')
        self.assertTrue(rows)
        for r in rows:
            self.assertGreaterEqual(
                len(r), 5,
                f'Cyber governance row should be 5-column: {r!r}')

    @_skip_if_no_app
    def test_09_governance_includes_required_role_set(self):
        """All 11 required governance roles must be present in AR."""
        rows = _govern_rows('ar')
        blob = _flatten(rows)
        for role in (
            'اللجنة التوجيهية للأمن السيبراني',
            'CISO',
            'مدير حوكمة الأمن السيبراني',
            'مدير مركز العمليات الأمنية SOC',
            'مدير حماية البيانات',
            'مدير إدارة الهوية والوصول IAM/PAM',
            'مدير الاستجابة للحوادث CSIRT',
            'مدير إدارة الثغرات',
            'مدير استمرارية الأعمال',
            'مكتب إدارة المشاريع PMO',
            'الإدارة العليا',
        ):
            self.assertIn(role, blob,
                          f'Required governance role missing: {role!r}')

    @_skip_if_no_app
    def test_10_governance_empty_content_returns_no_rows(self):
        """PR-5B.8R contract preserved: empty content → empty rows."""
        rows = _APP._extract_owners_from_content(
            {}, 'ar', domain_code='cyber')
        self.assertEqual(rows, [])

    @_skip_if_no_app
    def test_11_non_cyber_domain_uses_legacy_extractor(self):
        """For a non-Cyber domain the deterministic Cyber roles MUST
        NOT be returned — keep the legacy KPI-table owner extractor."""
        rows = _APP._extract_owners_from_content(
            _CYBER_FIXTURE_AR, 'ar', domain_code='data')
        blob = _flatten(rows)
        self.assertNotIn('اللجنة التوجيهية للأمن السيبراني', blob)


if __name__ == '__main__':
    unittest.main()
