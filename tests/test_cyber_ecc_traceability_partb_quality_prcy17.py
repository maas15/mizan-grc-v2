"""PR-CY17 — ECC traceability Part B quality tests.

Production symptom: ECC traceability rendered rows still contained
weak / misplaced cell values in the Initiative / KPI / Risk columns:

    * ``5-8`` / ``7-9`` / ``21-24`` (numeric roadmap range tokens
      leaking into the Initiative cell),
    * ``تصنيف الثغرات المعالجة في الوقت وخارجه`` (KPI measurement
      procedure phrase),
    * ``احتساب نسبة المجتازين من إجمالي المستهدفين`` (KPI
      measurement procedure phrase).

PR-CY17 updates ``_CYBER_TRACEABILITY_SOFT_INITIATIVE['ECC']`` and
``_CYBER_TRACEABILITY_SOFT_KPI_RISK['ECC']`` to the problem-statement
preferred wording and changes the (cyber, ECC) branch of
``_build_traceability_matrix`` to always prefer the soft maps when
the row already has real content (mirror of the (cyber, DCC) branch)
so weak cells from the per-section lookup never reach Part B.

DCC traceability behaviour is unchanged.

Run:
    python -m pytest tests/test_cyber_ecc_traceability_partb_quality_prcy17.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_ecc_partb_prcy17_')
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


_DASH_TOKENS = ('—', '-', '--', '–')


# Production-like fixture deliberately includes weak tokens that the
# previous lookup path would have surfaced into the rendered Initiative
# / KPI / Risk cells (numeric ranges ``5-8`` / ``7-9`` / ``21-24`` and
# KPI measurement-procedure text).  The PR-CY17 always-prefer-soft
# behaviour must replace those with coherent capability-derived
# phrases.
_SECTIONS_AR_PRCY17 = {
    'vision': (
        '## 1. الرؤية والأهداف\n\n'
        'الالتزام بمتطلبات NCA ECC و NCA DCC وتأسيس إدارة الأمن '
        'السيبراني وتعيين CISO وتشكيل فريق CSIRT.\n'
    ),
    'pillars': (
        '## 2. الركائز الاستراتيجية\n\n'
        '### الركيزة 1: حوكمة الأمن السيبراني\n\n'
        '| # | المبادرة | الوصف | المخرج |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة الأمن السيبراني | حوكمة | تقرير |\n'
        '| 2 | إدارة الهوية والوصول | IAM | تقرير |\n'
        '| 3 | مركز العمليات الأمنية SOC | SOC | تقرير |\n'
        '| 4 | الاستجابة للحوادث CSIRT | IR | تقرير |\n'
        '| 5 | إدارة الثغرات | Vuln | تقرير |\n'
        '| 6 | تصنيف البيانات الحساسة | DCC | تقرير |\n'
        '| 7 | التشفير ومنع تسرب البيانات DLP | DCC | تقرير |\n'
        '| 8 | حماية البيانات الحساسة | DCC | تقرير |\n'
    ),
    # Note: the roadmap deliberately uses range-style tokens ``5-8``
    # and ``7-9`` and ``21-24`` so the test verifies these never reach
    # the rendered Initiative column.
    'roadmap': (
        '## 5. خارطة الطريق\n\n'
        '| # | النشاط | المرحلة | الإطار |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة الأمن السيبراني | 5-8 | ECC |\n'
        '| 2 | إدارة الهوية والوصول | 7-9 | ECC |\n'
        '| 3 | مركز العمليات الأمنية SOC | 21-24 | ECC |\n'
        '| 4 | الاستجابة للحوادث CSIRT | 5-8 | ECC |\n'
        '| 5 | إدارة الثغرات | 7-9 | ECC |\n'
        '| 6 | تصنيف البيانات الحساسة | Q1 | DCC |\n'
        '| 7 | التشفير ومنع فقدان البيانات DLP | Q2 | DCC |\n'
        '| 8 | حماية البيانات الحساسة | Q3 | DCC |\n'
    ),
    'gaps': (
        '## 4. الفجوات\n\n'
        '| # | الفجوة | الإطار |\n'
        '|---|---|---|\n'
        '| 1 | غياب حوكمة الأمن السيبراني | ECC |\n'
        '| 2 | ضعف إدارة الهوية والوصول | ECC |\n'
        '| 3 | غياب مركز العمليات الأمنية | ECC |\n'
        '| 4 | غياب خطة الاستجابة للحوادث | ECC |\n'
        '| 5 | ضعف إدارة الثغرات | ECC |\n'
        '| 6 | غياب تصنيف البيانات الحساسة | DCC |\n'
        '| 7 | ضعف التشفير | DCC |\n'
        '| 8 | غياب ضوابط منع فقدان البيانات DLP | DCC |\n'
        '| 9 | ضعف معالجة البيانات الحساسة | DCC |\n'
        '| 10 | ضعف حماية البيانات | DCC |\n'
    ),
    'kpis': (
        '## 6. مؤشرات الأداء\n\n'
        '| # | المؤشر | الإطار |\n'
        '|---|---|---|\n'
        '| 1 | احتساب نسبة المجتازين من إجمالي المستهدفين | ECC |\n'
        '| 2 | نسبة تطبيق MFA | ECC |\n'
        '| 3 | متوسط زمن كشف الحوادث | ECC |\n'
        '| 4 | وقت الاستجابة للحوادث | ECC |\n'
        '| 5 | تصنيف الثغرات المعالجة في الوقت وخارجه | ECC |\n'
        '| 6 | نسبة تصنيف البيانات الحساسة | DCC |\n'
        '| 7 | نسبة الامتثال لسياسات التشفير | DCC |\n'
    ),
    'confidence': (
        '## 7. الثقة والمخاطر\n\n'
        '| # | الخطر |\n'
        '|---|---|\n'
        '| 1 | ضعف حوكمة الأمن السيبراني |\n'
        '| 2 | اختراق أنظمة التحكم في الوصول والهوية |\n'
        '| 3 | فشل آليات الكشف المبكر للتهديدات المتقدمة |\n'
        '| 4 | تأخر احتواء الحوادث |\n'
        '| 5 | استغلال الثغرات الأمنية |\n'
        '| 6 | اختراق البيانات أو سوء تصنيف البيانات الحساسة |\n'
    ),
    'environment': (
        '## 3. تحليل البيئة\n\nبيئة NCA ECC و NCA DCC تتطلب '
        'الحوكمة وإدارة الهوية والوصول والرصد والاستجابة للحوادث '
        'وإدارة الثغرات وتصنيف البيانات والتشفير ومنع تسرب '
        'البيانات.\n'
    ),
}


def _build_trace():
    return _APP._build_traceability_matrix(
        _SECTIONS_AR_PRCY17, ['ECC', 'DCC'], 'ar',
        domain_code='cyber',
    )


def _ecc_rendered(trace):
    out = []
    for r in (trace.get('rows') or []):
        if not r or len(r) < 6:
            continue
        if 'ECC' in str(r[0]) and 'DCC' not in str(r[0]):
            cells = (r[2], r[3], r[4], r[5])
            if all(str(c).strip() and str(c).strip() not in _DASH_TOKENS
                   for c in cells):
                out.append(r)
    return out


def _dcc_rendered(trace):
    out = []
    for r in (trace.get('rows') or []):
        if not r or len(r) < 6:
            continue
        if 'DCC' in str(r[0]):
            cells = (r[2], r[3], r[4], r[5])
            if all(str(c).strip() and str(c).strip() not in _DASH_TOKENS
                   for c in cells):
                out.append(r)
    return out


def _find_ecc(trace, kws):
    for r in _ecc_rendered(trace):
        cap = str(r[1])
        for kw in kws:
            if kw in cap or kw.lower() in cap.lower():
                return r
    return None


class ECCPartBCoherentRowsTests(unittest.TestCase):

    @_skip_if_no_app
    def test_08_governance_row_coherent(self):
        r = _find_ecc(_build_trace(), ('حوكمة', 'governance'))
        self.assertIsNotNone(r, 'ECC governance row missing')
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        self.assertIn('تأسيس إدارة الأمن السيبراني', init)
        self.assertIn('لجنة حوكمة الأمن السيبراني', init)
        self.assertIn('نسبة اكتمال الهيكل التنظيمي والسياسات المعتمدة',
                      kpi)
        self.assertIn('ضعف الحوكمة', risk)

    @_skip_if_no_app
    def test_09_iam_row_coherent(self):
        r = _find_ecc(_build_trace(),
                      ('الهوية', 'الوصول', 'IAM'))
        self.assertIsNotNone(r, 'ECC IAM row missing')
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        self.assertIn('IAM/PAM/MFA', init)
        self.assertIn('المصادقة متعددة العوامل', kpi)
        self.assertIn('اختراق أنظمة التحكم في الوصول والهوية', risk)

    @_skip_if_no_app
    def test_10_soc_row_coherent(self):
        r = _find_ecc(_build_trace(), ('SOC', 'SIEM', 'الرصد', 'مراقبة'))
        self.assertIsNotNone(r, 'ECC SOC row missing')
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        self.assertIn('SOC', init)
        self.assertIn('SIEM', init)
        self.assertIn('متوسط زمن كشف الحوادث الأمنية الحرجة', kpi)
        self.assertIn('فشل آليات الكشف المبكر', risk)

    @_skip_if_no_app
    def test_11_csirt_row_coherent(self):
        r = _find_ecc(_build_trace(),
                      ('الاستجابة للحوادث', 'CSIRT', 'incident'))
        self.assertIsNotNone(r, 'ECC CSIRT row missing')
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        self.assertIn('CSIRT', init)
        self.assertIn('خطة الاستجابة للحوادث', init)
        self.assertIn('متوسط زمن الاستجابة للحوادث الحرجة', kpi)
        self.assertIn('احتواء الحوادث', risk)

    @_skip_if_no_app
    def test_12_vulnerability_row_coherent(self):
        r = _find_ecc(_build_trace(), ('الثغرات', 'vulnerability'))
        self.assertIsNotNone(r, 'ECC vulnerability row missing')
        init, kpi, risk = str(r[3]), str(r[4]), str(r[5])
        self.assertIn('برنامج إدارة الثغرات الأمنية', init)
        self.assertIn('نسبة الثغرات الحرجة المعالجة', kpi)
        self.assertIn('استغلال الثغرات الحرجة', risk)


class ECCPartBNoWeakValuesTests(unittest.TestCase):

    @_skip_if_no_app
    def test_13_no_numeric_range_initiatives_in_ecc(self):
        """The Initiative column for ECC rows must never contain a
        bare numeric range token like ``5-8`` / ``7-9`` / ``21-24``.
        """
        import re
        rng_re = re.compile(r'^\s*\d+\s*-\s*\d+\s*$')
        for r in _ecc_rendered(_build_trace()):
            init = str(r[3])
            self.assertFalse(
                rng_re.match(init),
                f'ECC Initiative is a bare numeric range: {init!r}')
            # And weaker rule: the cell should not equal any of the
            # specific tokens the production PDF was leaking.
            for tok in ('5-8', '7-9', '21-24'):
                self.assertNotEqual(
                    init.strip(), tok,
                    f'ECC Initiative contains roadmap range token '
                    f'{tok!r}: {r!r}')

    @_skip_if_no_app
    def test_13b_no_kpi_procedure_text_in_ecc(self):
        """KPI measurement-procedure text from the KPI section must
        not surface as Initiative / KPI / Risk on ECC rows."""
        forbidden = (
            'تصنيف الثغرات المعالجة في الوقت وخارجه',
            'احتساب نسبة المجتازين من إجمالي المستهدفين',
        )
        for r in _ecc_rendered(_build_trace()):
            for cell in (r[3], r[4], r[5]):
                for f in forbidden:
                    self.assertNotIn(
                        f, str(cell),
                        f'ECC Part B carries KPI procedure text {f!r}: '
                        f'row={r!r}')


class DCCPartBUnchangedTests(unittest.TestCase):

    @_skip_if_no_app
    def test_14_dcc_part_b_remains_unchanged(self):
        """DCC rendered rows must still cover all five DCC families
        with non-dash cells (PR-CY4 / PR-CY6 contract preserved)."""
        rows = _dcc_rendered(_build_trace())
        self.assertTrue(rows, 'DCC rendered Part B is empty')
        cap_blob = ' '.join(str(r[1]) for r in rows)
        # Capability column should mention each DCC family theme.
        for theme in ('تصنيف', 'تشفير', 'البيانات الحساسة',
                      'حماية البيانات'):
            self.assertIn(
                theme, cap_blob,
                f'DCC Part B no longer covers theme {theme!r}; '
                f'cap_blob={cap_blob!r}')
        # And every DCC row must have non-dash Initiative / KPI / Risk.
        for r in rows:
            for idx, name in ((3, 'init'), (4, 'kpi'), (5, 'risk')):
                cell = str(r[idx])
                self.assertTrue(
                    cell.strip()
                    and cell.strip() not in _DASH_TOKENS,
                    f'DCC {name} empty/dash: {r!r}')


if __name__ == '__main__':
    unittest.main()
