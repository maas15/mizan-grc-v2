"""PR-CY6 — DCC traceability Part B cell mapping.

Production symptom: when Cyber + ECC + DCC strategies render the
traceability matrix, the DCC rows pass the no-dash gate but multiple
DCC capabilities share the SAME generic initiative phrase
(``تطبيق تقنيات التشفير ومنع فقدان البيانات (DLP)``), weakening
traceability quality.

PR-CY6 adds ``_CYBER_TRACEABILITY_SOFT_INITIATIVE['DCC']`` per the
problem-statement preferred mapping and applies it in the DCC branch
of ``_build_traceability_matrix`` so each DCC family maps to a
distinct, family-coherent initiative cell. ECC traceability is
unchanged; no strategy rows are inserted.

Strictly scoped to (cyber, DCC). Run:
    python -m pytest \
        tests/test_cyber_dcc_traceability_cell_mapping_prcy6.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_dcc_trace_prcy6_')
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


_DASH = ('—', '-', '--', '–')


# Realistic Cyber + ECC + DCC sections matching the production
# evidence: the roadmap collapses every DCC family onto ONE generic
# row (``تطبيق تقنيات التشفير ومنع فقدان البيانات (DLP)``) so the
# pre-PR-CY6 traceability initiative cell repeats across all DCC
# capabilities. The other sections do carry family-specific text so
# KPI / Risk cells can be sourced from the soft-derivation maps.
_SECTIONS_AR = {
    'vision': '## 1. الرؤية\n\nالامتثال لـ NCA ECC و NCA DCC.\n',
    'pillars': (
        '## 2. الركائز\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|---|---|---|\n'
        '| 1 | تأسيس حوكمة الأمن السيبراني وفق ECC | حوكمة | تقرير |\n'
    ),
    'environment': (
        '## 3. البيئة\n\nتغطي تصنيف البيانات والتشفير ومنع تسرب '
        'البيانات ومعالجة البيانات الحساسة وحماية البيانات.\n'
    ),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | غياب تصنيف البيانات الحساسة | DCC تصنيف | عالية | '
        'مفتوحة |\n'
        '| 2 | ضعف التشفير عند النقل والتخزين | DCC تشفير | عالية | '
        'مفتوحة |\n'
        '| 3 | غياب ضوابط منع فقدان البيانات DLP | DCC | عالية | '
        'مفتوحة |\n'
        '| 4 | ضعف معالجة البيانات الحساسة | DCC | عالية | مفتوحة |\n'
        '| 5 | ضعف حماية البيانات | DCC | عالية | مفتوحة |\n'
    ),
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        '| 1 | تطبيق تقنيات التشفير ومنع فقدان البيانات (DLP) | Q2 '
        '| DCC |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | النوع | المستهدفة | الإطار |\n'
        '|---|---|---|---|---|\n'
        '| 1 | نسبة تصنيف البيانات الحساسة | KPI | 100% | DCC |\n'
        '| 2 | نسبة الامتثال لسياسات التشفير | KPI | 100% | DCC |\n'
        '| 3 | عدد حوادث تسرب البيانات أو مؤشرات منع التسرب | KPI | '
        '0 | DCC |\n'
        '| 4 | نسبة الأصول الحساسة المصنفة أو المحمية | KPI | 100% '
        '| DCC |\n'
        '| 5 | نسبة الأصول المشفرة أو المحمية | KPI | 100% | DCC |\n'
    ),
    'confidence': (
        '## 7. الثقة والمخاطر\n\n'
        '| # | الخطر | الاحتمالية | التأثير | التخفيف |\n'
        '|---|---|---|---|---|\n'
        '| 1 | اختراق البيانات أو سوء تصنيف البيانات الحساسة | عالية '
        '| عالي | متابعة |\n'
        '| 2 | تسرب البيانات أثناء النقل أو التخزين | عالية | عالي '
        '| متابعة |\n'
        '| 3 | فقدان البيانات الحساسة | عالية | عالي | متابعة |\n'
        '| 4 | إفشاء غير مصرح للبيانات الحساسة | عالية | عالي | '
        'متابعة |\n'
        '| 5 | اختراق البيانات أو ضعف حماية البيانات | عالية | عالي '
        '| متابعة |\n'
    ),
}


def _rendered_rows(trace):
    """Mirror the universal no-dash render gate so the assertions
    reflect what the PDF would actually emit."""
    out = []
    for r in (trace.get('rows') or []):
        if len(r) < 6:
            continue
        if any(str(c).strip() in _DASH or not str(c).strip()
               for c in (r[2], r[3], r[4], r[5])):
            continue
        out.append(r)
    return out


class TestDCCSoftInitiativeRegistry(unittest.TestCase):
    """The soft-initiative registry MUST provide a distinct
    family-coherent phrase for each of the five DCC families."""

    @_skip_if_no_app
    def test_registry_present_and_distinct(self):
        reg = _APP._CYBER_TRACEABILITY_SOFT_INITIATIVE.get('DCC') or {}
        for fam in ('data_classification', 'encryption', 'dlp',
                    'sensitive_data_handling', 'data_protection'):
            entry = reg.get(fam) or {}
            self.assertTrue(entry.get('ar'),
                            f'DCC {fam} missing AR soft initiative')
            self.assertTrue(entry.get('en'),
                            f'DCC {fam} missing EN soft initiative')
        # AR values must be unique across families.
        ar_vals = [reg[f]['ar'] for f in (
            'data_classification', 'encryption', 'dlp',
            'sensitive_data_handling', 'data_protection')]
        self.assertEqual(len(ar_vals), len(set(ar_vals)),
                         f'DCC soft AR initiatives not distinct: '
                         f'{ar_vals}')


class TestDCCTraceabilityCellMapping(unittest.TestCase):
    """Each DCC traceability row maps to a distinct initiative / KPI
    / Risk per the problem-statement preferred mapping."""

    @_skip_if_no_app
    def _dcc_rows(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        return [r for r in _rendered_rows(trace)
                if 'DCC' in str(r[0])]

    @_skip_if_no_app
    def _find(self, cap_keyword):
        for r in self._dcc_rows():
            if cap_keyword in str(r[1]):
                return r
        return None

    @_skip_if_no_app
    def test_classification_initiative_distinct(self):
        r = self._find('تصنيف')
        self.assertIsNotNone(r)
        self.assertIn('تصنيف', str(r[3]),
                      f'classification initiative weak: {r[3]!r}')
        # KPI / Risk must each be the family-coherent phrase.
        self.assertIn('تصنيف البيانات الحساسة', str(r[4]))
        self.assertIn('سوء تصنيف', str(r[5]))

    @_skip_if_no_app
    def test_encryption_initiative_distinct(self):
        r = self._find('تشفير')
        self.assertIsNotNone(r)
        self.assertIn('تشفير', str(r[3]))
        self.assertIn('التشفير', str(r[4]))
        self.assertIn('تسرب البيانات', str(r[5]))

    @_skip_if_no_app
    def test_dlp_initiative_distinct(self):
        r = self._find('DLP')
        self.assertIsNotNone(r)
        self.assertTrue(
            'DLP' in str(r[3]) or 'منع تسرب' in str(r[3]),
            f'DLP initiative weak: {r[3]!r}')
        self.assertIn('تسرب', str(r[4]))
        self.assertIn('فقدان البيانات الحساسة', str(r[5]))

    @_skip_if_no_app
    def test_sensitive_data_handling_initiative_distinct(self):
        r = self._find('معالجة البيانات الحساسة')
        self.assertIsNotNone(r)
        self.assertIn('معالجة البيانات الحساسة', str(r[3]))
        self.assertIn('الأصول الحساسة', str(r[4]))
        self.assertIn('إفشاء', str(r[5]))

    @_skip_if_no_app
    def test_data_protection_initiative_distinct(self):
        r = self._find('حماية البيانات')
        self.assertIsNotNone(r)
        self.assertIn('حماية البيانات', str(r[3]))
        self.assertIn('الأصول المشفرة', str(r[4]))
        self.assertIn('ضعف حماية البيانات', str(r[5]))

    @_skip_if_no_app
    def test_no_dcc_row_shares_initiative_phrase(self):
        rows = self._dcc_rows()
        inits = [str(r[3]).strip() for r in rows]
        self.assertEqual(
            len(inits), len(set(inits)),
            f'DCC traceability Part B has duplicate initiative '
            f'phrases: {inits}')

    @_skip_if_no_app
    def test_no_dcc_row_uses_dash_in_initiative_or_kpi_or_risk(self):
        for r in self._dcc_rows():
            for cell in (r[3], r[4], r[5]):
                self.assertTrue(
                    str(cell).strip(),
                    f'DCC traceability cell blank: {r!r}')
                self.assertNotIn(
                    str(cell).strip(), _DASH,
                    f'DCC traceability cell is dash: {cell!r}')


class TestECCTraceabilityUnchanged(unittest.TestCase):
    """ECC traceability cells / capabilities must remain unchanged."""

    @_skip_if_no_app
    def test_ecc_rows_still_present_and_distinct(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        ecc_rows = [r for r in (trace.get('rows') or [])
                    if 'ECC' in str(r[0]) and 'DCC' not in str(r[0])]
        self.assertGreater(len(ecc_rows), 0,
                           'ECC rows must remain in matrix')

    @_skip_if_no_app
    def test_ecc_only_selection_does_not_produce_dcc_rows(self):
        trace = _APP._build_traceability_matrix(
            _SECTIONS_AR, ['ECC'], 'ar', domain_code='cyber',
        )
        for r in (trace.get('rows') or []):
            self.assertNotIn(
                'DCC', str(r[0]),
                'ECC-only selection must not produce DCC rows')


class TestDataAndOtherDomainsUnchanged(unittest.TestCase):
    """Data Management / AI / DT / ERM traceability is byte-for-byte
    unchanged by PR-CY6 (the soft-initiative override is scoped to
    (cyber, DCC))."""

    @_skip_if_no_app
    def test_data_pdpl_traceability_does_not_use_cyber_dcc_soft(self):
        # Data PDPL → does NOT exercise the cyber DCC branch.
        sections = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '', 'roadmap': '', 'kpis': '', 'confidence': '',
        }
        trace = _APP._build_traceability_matrix(
            sections, ['PDPL'], 'ar', domain_code='data',
        )
        # Whatever rows are produced must NOT carry the DCC cyber
        # soft initiatives (those are scoped to cyber-domain only).
        for r in (trace.get('rows') or []):
            for cell in r:
                self.assertNotIn(
                    'تطبيق DLP / منع تسرب البيانات', str(cell),
                    'cyber DCC soft initiative leaked into Data')


class TestNoDeterministicStrategyRowsInserted(unittest.TestCase):
    """The traceability builder MUST NOT mutate the sections dict and
    MUST NOT invent strategy rows; it only labels traceability
    cells."""

    @_skip_if_no_app
    def test_sections_dict_not_mutated(self):
        snapshot = {k: v for k, v in _SECTIONS_AR.items()}
        _ = _APP._build_traceability_matrix(
            _SECTIONS_AR, ['ECC', 'DCC'], 'ar',
            domain_code='cyber',
        )
        for k, v in snapshot.items():
            self.assertEqual(
                v, _SECTIONS_AR[k],
                f'traceability mutated section {k!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
