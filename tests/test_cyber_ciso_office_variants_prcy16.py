"""PR-CY16 — Arabic CISO-office variant normalization + bad-office
detector tests.

Production runtime symptom (cyber + ECC + DCC, org_structure_is_none):
    [CYBER-VISION-SPECIALIZED-OBJECTIVE]
    has_establishment_phrase=False
    has_leadership_phrase=True
    contains_bad_ciso_office=True
    accepted=False
    -> specialized_function_objective_missing:cyber (vision) 0/1

The earlier PR-CY5 ``_normalize_cyber_ar_ciso_wording`` / ``_CYBER_CISO_
WORDING_AR`` only handled simple ``مكتب CISO`` / ``إنشاء مكتب CISO``
phrasings. PR-CY16 extends the normalizer + bad-office detector to
every Arabic variant where ``مكتب`` is attached to a CISO-equivalent
title:

    * مكتب رئيس أمن المعلومات [CISO]
    * مكتب رئيس الأمن السيبراني [CISO]
    * تأسيس / إنشاء مكتب رئيس أمن المعلومات [CISO]
    * تأسيس / إنشاء مكتب رئيس الأمن السيبراني [CISO]
    * مكتب الرئيس التنفيذي لأمن المعلومات
    * مكتب مسؤول أمن المعلومات
    * مكتب مدير أمن المعلومات
    * CISO office / Chief Information Security Officer office (EN)

Legitimate role references (``تعيين CISO``, ``دور CISO``, ``رئيس
الأمن السيبراني`` without ``مكتب``) MUST be preserved.

Run:
    python -m pytest tests/test_cyber_ciso_office_variants_prcy16.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_ciso_prcy16_')
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


# ─────────────────────────────────────────────────────────────────────
# Tests 1-4 — Arabic normalizer rewrites every new bad-office variant
# ─────────────────────────────────────────────────────────────────────


class Test01ToTest04NormalizerRewritesNewVariants(unittest.TestCase):
    """Each new Arabic variant must normalize to the canonical
    ``إدارة الأمن السيبراني بقيادة CISO`` wording while leaving the
    surrounding text intact and never re-introducing ``مكتب`` next to
    a CISO title."""

    @_skip_if_no_app
    def test_01_bare_office_ciso_normalizes(self):
        """``مكتب CISO`` → ``إدارة الأمن السيبراني بقيادة CISO``."""
        sections = {'vision': 'يتولى مكتب CISO الإشراف على البرنامج.'}
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        self.assertNotIn('مكتب CISO', sections['vision'])
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO',
                      sections['vision'])

    @_skip_if_no_app
    def test_02_taasis_maktab_rais_amn_almalumat_ciso_normalizes(self):
        """``تأسيس مكتب رئيس أمن المعلومات CISO`` → professional
        ``تأسيس إدارة الأمن السيبراني بقيادة CISO``."""
        sections = {
            'vision': (
                'تأسيس مكتب رئيس أمن المعلومات CISO خلال 12 شهراً.'
            )
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        self.assertTrue(n)
        new = sections['vision']
        self.assertNotIn('مكتب رئيس أمن المعلومات', new)
        self.assertNotIn('مكتب CISO', new)
        self.assertIn('تأسيس إدارة الأمن السيبراني بقيادة CISO', new)

    @_skip_if_no_app
    def test_03_inshaa_maktab_rais_alamn_alsaybarani_ciso_normalizes(self):
        """``إنشاء مكتب رئيس الأمن السيبراني CISO`` → professional
        ``إنشاء إدارة الأمن السيبراني بقيادة CISO``."""
        sections = {
            'pillars': (
                'إنشاء مكتب رئيس الأمن السيبراني CISO وفقاً لإطار ECC.'
            )
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        new = sections['pillars']
        self.assertNotIn('مكتب رئيس الأمن السيبراني', new)
        self.assertIn('إنشاء إدارة الأمن السيبراني بقيادة CISO', new)

    @_skip_if_no_app
    def test_04_maktab_alraees_altanfeezee_normalizes(self):
        """``مكتب الرئيس التنفيذي لأمن المعلومات`` → ``إدارة الأمن
        السيبراني بقيادة CISO``."""
        sections = {
            'roadmap': (
                'تشكيل مكتب الرئيس التنفيذي لأمن المعلومات لقيادة '
                'الحوكمة.'
            )
        }
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertTrue(n)
        new = sections['roadmap']
        self.assertNotIn(
            'مكتب الرئيس التنفيذي لأمن المعلومات', new)
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO', new)


# ─────────────────────────────────────────────────────────────────────
# Tests 5-6 — legitimate role references are PRESERVED verbatim
# ─────────────────────────────────────────────────────────────────────


class Test05ToTest06LegitimateRolesPreserved(unittest.TestCase):
    """The normalizer only rewrites wording where ``مكتب`` is attached
    to a CISO title. Bare role references (``تعيين CISO``, ``رئيس
    الأمن السيبراني`` without ``مكتب``) MUST survive untouched."""

    @_skip_if_no_app
    def test_05_taeen_ciso_preserved(self):
        sections = {
            'vision': (
                'تعيين CISO وتحديد دور CISO ومسؤولياته في الحوكمة.'
            ),
            'pillars': 'دور CISO أساسي في إدارة المخاطر.',
        }
        original_vision = sections['vision']
        original_pillars = sections['pillars']
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertEqual(n, {})
        self.assertEqual(sections['vision'], original_vision)
        self.assertEqual(sections['pillars'], original_pillars)
        self.assertIn('تعيين CISO', sections['vision'])

    @_skip_if_no_app
    def test_06_rais_alamn_alsaybarani_preserved(self):
        """``رئيس الأمن السيبراني`` (without leading ``مكتب``) must
        be preserved — it is the canonical Arabic term for the CISO
        role itself, not an office wording."""
        sections = {
            'vision': (
                'يتولى رئيس الأمن السيبراني قيادة برنامج الحوكمة '
                'والإشراف على لجنة حوكمة الأمن السيبراني.'
            )
        }
        original = sections['vision']
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'cyber')
        self.assertEqual(n, {})
        self.assertEqual(sections['vision'], original)
        self.assertIn('رئيس الأمن السيبراني', sections['vision'])


# ─────────────────────────────────────────────────────────────────────
# Tests 7-8 — Bad-office detector flags every new variant
# ─────────────────────────────────────────────────────────────────────


class Test07ToTest08BadOfficeDetectorFlagsVariants(unittest.TestCase):
    """``_cyber_vision_objective_row_diagnostic`` (and the shared
    ``_cyber_blob_contains_bad_ciso_office`` helper) must surface
    ``contains_bad_ciso_office=True`` for every new bad variant."""

    @_skip_if_no_app
    def test_07_detector_flags_maktab_rais_amn_almalumat_ciso(self):
        blob = (
            'تأسيس مكتب رئيس أمن المعلومات CISO لقيادة الحوكمة'
        )
        diag = _APP._cyber_vision_objective_row_diagnostic(blob)
        self.assertTrue(diag['contains_bad_ciso_office'],
                        f'detector failed to flag: {blob!r}')
        self.assertTrue(
            _APP._cyber_blob_contains_bad_ciso_office(blob))

    @_skip_if_no_app
    def test_08_detector_flags_maktab_rais_alamn_alsaybarani_ciso(self):
        blob = (
            'إنشاء مكتب رئيس الأمن السيبراني CISO لتولي القيادة'
        )
        diag = _APP._cyber_vision_objective_row_diagnostic(blob)
        self.assertTrue(diag['contains_bad_ciso_office'],
                        f'detector failed to flag: {blob!r}')
        self.assertTrue(
            _APP._cyber_blob_contains_bad_ciso_office(blob))

    @_skip_if_no_app
    def test_08b_detector_flags_remaining_variants(self):
        """Every new Arabic variant + the EN ``Chief Information
        Security Officer office`` wording must be flagged."""
        for blob in (
                'مكتب الرئيس التنفيذي لأمن المعلومات',
                'مكتب مسؤول أمن المعلومات',
                'مكتب مدير أمن المعلومات',
                'Establish a Chief Information Security Officer office',
                'CISO office leadership',
        ):
            self.assertTrue(
                _APP._cyber_blob_contains_bad_ciso_office(blob),
                f'detector failed to flag: {blob!r}')

    @_skip_if_no_app
    def test_08c_detector_does_not_false_positive_on_legitimate(self):
        """Legitimate phrasings (no ``مكتب``+CISO-title pairing) must
        return False."""
        for blob in (
                'تعيين CISO ومسؤولياته',
                'رئيس الأمن السيبراني يقود البرنامج',
                'لجنة حوكمة الأمن السيبراني',
                'cybersecurity department led by the CISO',
                '',
                None,
        ):
            self.assertFalse(
                _APP._cyber_blob_contains_bad_ciso_office(blob),
                f'detector falsely flagged: {blob!r}')


# ─────────────────────────────────────────────────────────────────────
# Test 9 — _compute_missing_specialized_function_objective passes after
#          normalization yields a row with establishment + leadership
# ─────────────────────────────────────────────────────────────────────


def _vision_with_objective(extra_row_objective):
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        f'| 5 | {extra_row_objective} | 100% | NCA حوكمة | 12 شهراً |\n'
    )


class Test09NormalizedRowClearsDetector(unittest.TestCase):

    @_skip_if_no_app
    def test_09_specialized_function_passes_after_normalization(self):
        """A vision whose 5th objective row uses the bad
        ``تأسيس مكتب رئيس أمن المعلومات CISO`` wording fails the
        detector pre-normalization (contains_bad_ciso_office=True),
        but after ``_normalize_cyber_ar_ciso_wording`` the row carries
        BOTH the establishment phrase (``تأسيس إدارة الأمن
        السيبراني``) AND the leadership phrase (``CISO``) so the
        detector returns False."""
        bad_row = 'تأسيس مكتب رئيس أمن المعلومات CISO'
        sections = {'vision': _vision_with_objective(bad_row)}
        # Pre-normalization the detector still rejects (validators
        # are NOT weakened — bad wording fails until normalized).
        miss_before = (
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))
        self.assertTrue(miss_before)
        # After the normalizer rewrites the row, the same row carries
        # establishment + leadership phrases and clears the detector.
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        self.assertTrue(n)
        miss_after = (
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))
        self.assertFalse(
            miss_after,
            f'detector still missing after normalization; vision='
            f'{sections["vision"]!r}')


# ─────────────────────────────────────────────────────────────────────
# Test 12 — No deterministic objective row is inserted by the
#          normalizer (only existing wording is rewritten in-place).
# ─────────────────────────────────────────────────────────────────────


class Test12NoDeterministicRowInserted(unittest.TestCase):

    @_skip_if_no_app
    def test_12_normalizer_does_not_add_rows(self):
        """``_normalize_cyber_ar_ciso_wording`` must NOT add a new
        markdown table row to satisfy the detector — it must only
        rewrite existing wording in-place."""
        bad_row = 'تأسيس مكتب رئيس الأمن السيبراني CISO'
        sections = {'vision': _vision_with_objective(bad_row)}
        before_lines = sections['vision'].count('\n')
        before_rows = _APP.count_valid_objective_rows(
            sections['vision'])
        _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        after_lines = sections['vision'].count('\n')
        after_rows = _APP.count_valid_objective_rows(
            sections['vision'])
        self.assertEqual(before_lines, after_lines,
                         'normalizer changed line count')
        self.assertEqual(before_rows, after_rows,
                         'normalizer changed objective-row count')


# ─────────────────────────────────────────────────────────────────────
# Test 14 — Data Management strategies are unchanged (scope guard)
# ─────────────────────────────────────────────────────────────────────


class Test14DataManagementUnchanged(unittest.TestCase):

    @_skip_if_no_app
    def test_14_data_domain_byte_for_byte_unchanged(self):
        """Even when a (hypothetical) Data Management section
        contains ``مكتب CISO`` wording, the cyber-scoped normalizer
        must leave it untouched."""
        sections = {
            'vision': (
                'إنشاء مكتب رئيس أمن المعلومات CISO ضمن خطة Data '
                'Management.'
            ),
            'roadmap': 'مكتب CISO يدير برنامج الجودة.',
        }
        snapshot = dict(sections)
        n = _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Data Management')
        self.assertEqual(n, {})
        self.assertEqual(sections, snapshot)


# ─────────────────────────────────────────────────────────────────────
# Test 15 — Validators are NOT weakened: when a row has neither
#          establishment nor leadership, the detector still rejects
#          even after the normalizer runs.
# ─────────────────────────────────────────────────────────────────────


class Test15ValidatorsNotWeakened(unittest.TestCase):

    @_skip_if_no_app
    def test_15_weak_row_still_rejected_post_normalization(self):
        """Even after running the normalizer, a vision lacking both
        the establishment phrase and the leadership phrase must still
        trip ``specialized_function_objective_missing:cyber``."""
        weak_vision = _vision_with_objective(
            'تحقيق نتائج عامة في الأمن')
        sections = {'vision': weak_vision}
        _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        miss = _APP._compute_missing_specialized_function_objective(
            sections, 'Cyber Security', lang='ar',
            org_structure_is_none=True)
        self.assertTrue(
            miss,
            'weak row cleared the detector — validator was weakened')

    @_skip_if_no_app
    def test_15b_bare_taeen_ciso_still_rejected(self):
        """Bare ``تعيين CISO`` (leadership without establishment) must
        still be rejected — PR-CY8 dual-requirement invariant."""
        sections = {'vision': _vision_with_objective('تعيين CISO')}
        _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        self.assertTrue(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
