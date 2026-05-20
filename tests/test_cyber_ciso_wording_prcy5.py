"""PR-CY5 — Cyber CISO wording normalization tests.

Production symptom: the Cyber Security executive summary / vision /
roadmap could render unprofessional wording such as ``إنشاء مكتب CISO
متخصص`` (treating CISO as an office name rather than a role).  PR-CY5
adds ``_normalize_cyber_ar_ciso_wording`` which rewrites the bad
``مكتب CISO`` constructions to professional CISO wording per the
problem statement:

  * إنشاء مكتب CISO متخصص → إنشاء إدارة الأمن السيبراني بقيادة CISO
  * مكتب CISO → إدارة الأمن السيبراني بقيادة CISO

Legitimate CISO role references (``تعيين CISO``, ``دور CISO``, ``led
by the CISO``) are preserved.  Scoped to ``domain == 'cyber'`` only.

Run:
    python -m pytest tests/test_cyber_ciso_wording_prcy5.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_ciso_prcy5_')
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


class CyberCisoWordingArabicTests(unittest.TestCase):
    """The normalizer must rewrite bad ``مكتب CISO`` constructions and
    preserve legitimate CISO role references in the Arabic sections.
    """

    @_skip_if_no_app
    def test_replaces_specific_office_phrase(self):
        sections = {
            'executive_summary': (
                'سيتم إنشاء مكتب CISO متخصص لقيادة برنامج الأمن '
                'السيبراني.'
            ),
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        self.assertTrue(n,
                        'normalizer returned no replacements')
        new = sections['executive_summary']
        self.assertNotIn('مكتب CISO', new,
                         f'bad phrase still present: {new!r}')
        self.assertIn('إدارة الأمن السيبراني', new)
        self.assertIn('CISO', new,
                      'legitimate CISO role reference removed')

    @_skip_if_no_app
    def test_replaces_construction_phrase(self):
        sections = {
            'vision': (
                'الهدف: إنشاء مكتب CISO وسلطة الحوكمة لتعزيز الأمن.'
            ),
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        self.assertTrue(n)
        self.assertNotIn('مكتب CISO', sections['vision'])
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO',
                      sections['vision'])

    @_skip_if_no_app
    def test_bare_office_phrase_rewritten(self):
        sections = {
            'roadmap': 'يتولى مكتب CISO الإشراف على البرنامج.',
        }
        _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertNotIn('مكتب CISO', sections['roadmap'])
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO',
                      sections['roadmap'])

    @_skip_if_no_app
    def test_legitimate_ciso_role_preserved(self):
        sections = {
            'vision': (
                'تعيين CISO وتشكيل لجنة حوكمة الأمن السيبراني، '
                'مع تحديد دور CISO ومسؤولياته.'
            ),
            'pillars': (
                'دور CISO أساسي في حوكمة الأمن السيبراني.'
            ),
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        # Nothing to rewrite — no ``مكتب CISO`` constructions present.
        self.assertEqual(n, {},
                         'normalizer rewrote legitimate CISO role text')
        self.assertIn('تعيين CISO', sections['vision'])
        self.assertIn('دور CISO', sections['vision'])
        self.assertIn('دور CISO', sections['pillars'])

    @_skip_if_no_app
    def test_idempotent_on_already_normalized_text(self):
        sections = {
            'executive_summary': (
                'إنشاء إدارة الأمن السيبراني بقيادة CISO وتشكيل '
                'لجنة الحوكمة.'
            ),
        }
        n1 = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertEqual(n1, {})
        n2 = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertEqual(n2, {})
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO',
                      sections['executive_summary'])


class CyberCisoWordingEnglishTests(unittest.TestCase):
    """English-side normalizer behaviour."""

    @_skip_if_no_app
    def test_replaces_english_dedicated_ciso_office(self):
        sections = {
            'executive_summary': (
                'Establish a dedicated CISO office to lead the '
                'cybersecurity program.'
            ),
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'en', 'cyber')
        self.assertTrue(n)
        new = sections['executive_summary']
        self.assertNotIn('CISO office', new)
        self.assertIn('cybersecurity department led by the CISO', new)
        self.assertIn('CISO', new)

    @_skip_if_no_app
    def test_english_legitimate_ciso_role_preserved(self):
        sections = {
            'vision': (
                'Appoint a CISO and form the cybersecurity governance '
                'committee.  The CISO leads the program.'
            ),
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'en', 'cyber')
        self.assertEqual(n, {})
        self.assertIn('Appoint a CISO', sections['vision'])
        self.assertIn('The CISO leads', sections['vision'])


class CyberCisoWordingScopeTests(unittest.TestCase):
    """The normalizer must be strictly scoped to the cyber domain so
    other domains (data / AI / DT / ERM) are byte-for-byte unchanged.
    """

    @_skip_if_no_app
    def test_data_domain_untouched(self):
        # A Data Management strategy mentioning ``مكتب CISO`` (which
        # shouldn't happen, but the normalizer must still respect
        # scope) should NOT be rewritten.
        sections = {
            'executive_summary': 'إنشاء مكتب CISO متخصص في الأمن.',
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Data Management')
        self.assertEqual(n, {})
        self.assertIn('مكتب CISO', sections['executive_summary'])

    @_skip_if_no_app
    def test_ai_domain_untouched(self):
        sections = {'vision': 'إنشاء مكتب CISO متخصص.'}
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Artificial Intelligence')
        self.assertEqual(n, {})

    @_skip_if_no_app
    def test_dt_domain_untouched(self):
        sections = {'vision': 'إنشاء مكتب CISO متخصص.'}
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Digital Transformation')
        self.assertEqual(n, {})

    @_skip_if_no_app
    def test_erm_domain_untouched(self):
        sections = {'vision': 'إنشاء مكتب CISO متخصص.'}
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Enterprise Risk Management')
        self.assertEqual(n, {})

    @_skip_if_no_app
    def test_empty_or_none_inputs_safe(self):
        self.assertEqual(
            _APP._normalize_cyber_ar_ciso_wording({}, 'ar', 'cyber'),
            {},
        )
        self.assertEqual(
            _APP._normalize_cyber_ar_ciso_wording(None, 'ar', 'cyber'),
            {},
        )

    @_skip_if_no_app
    def test_prompt_template_example_uses_correct_wording(self):
        """The prompt template at app.py used to instruct the AI with
        the bad example ``إنشاء مكتب CISO وسلطة الحوكمة``; PR-CY5
        fixed it to ``إنشاء إدارة الأمن السيبراني بقيادة CISO وسلطة
        الحوكمة``.  Guard against regression by inspecting the file.
        """
        app_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(app_path, encoding='utf-8') as f:
            src = f.read()
        self.assertNotIn(
            'إنشاء مكتب CISO وسلطة الحوكمة', src,
            'Bad prompt-template example reintroduced in app.py')
        self.assertIn(
            'إنشاء إدارة الأمن السيبراني بقيادة CISO وسلطة الحوكمة',
            src,
            'Corrected CISO prompt example missing in app.py')


class CyberCisoWordingExportHookTests(unittest.TestCase):
    """The export-time hook must call ``_normalize_cyber_ar_ciso_wording``
    on the content sections before the document model is built.
    """

    @_skip_if_no_app
    def test_export_hook_call_present_in_source(self):
        app_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(app_path, encoding='utf-8') as f:
            src = f.read()
        self.assertIn(
            '_normalize_cyber_ar_ciso_wording(', src,
            'Cyber CISO normalizer not wired in app.py')
        self.assertIn(
            'cyber_ciso_wording_normalization', src,
            'EXPORT-DIAG / STRATEGY-DIAG hook for CISO normalization '
            'not wired in app.py')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
