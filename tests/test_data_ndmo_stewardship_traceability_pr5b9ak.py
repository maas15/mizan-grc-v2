"""PR-5B.9AK — NDMO stewardship traceability rendering coverage.

Regression: the latest Data Management generated PDF renders NDMO
traceability rows for governance / quality / catalog / lifecycle but
drops ``data_stewardship`` (``أمناء البيانات`` / ``ملكية البيانات``)
whenever the KPI / confidence sections happen to be silent on
stewardship even though the roadmap / gaps / pillars clearly cover it.

This module fixtures ``_build_traceability_matrix`` with the NDMO
stewardship row only present in the roadmap / gaps / pillars and
asserts that the stewardship row still renders complete (no-dash,
no-broken-cell, distinct initiative / KPI / risk) via the soft
KPI/Risk derivation map added in PR-5B.9AK.

Run::

    python -m pytest \\
        tests/test_data_ndmo_stewardship_traceability_pr5b9ak.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ak_ndmo_stew_')
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


# ── Fixture: NDMO stewardship covered in roadmap / gaps / pillars
# but absent from KPI and confidence sections.
_GAPS_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة |\n'
    '|---|------|\n'
    '| 1 | ضعف حوكمة البيانات |\n'
    '| 2 | ضعف جودة البيانات |\n'
    '| 3 | غياب كتالوج البيانات |\n'
    '| 4 | غياب أمناء البيانات وضعف ملكية البيانات |\n'
    '| 5 | غياب دورة حياة البيانات |\n'
)

_PILLARS_AR = (
    '## 2. الركائز\n\n'
    '| # | المبادرة |\n'
    '|---|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات (DMO) بقيادة CDO |\n'
    '| 2 | بناء كتالوج البيانات |\n'
    '| 3 | تعيين أمناء البيانات وتحديد مالكي البيانات |\n'
)

_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط |\n'
    '|---|------|\n'
    '| 1 | تشكيل لجنة حوكمة البيانات |\n'
    '| 2 | إطلاق برنامج إدارة جودة البيانات |\n'
    '| 3 | بناء كتالوج البيانات والبيانات الوصفية |\n'
    '| 4 | تفعيل أمناء البيانات وتعيين ملاك البيانات |\n'
    '| 5 | دورة حياة البيانات والاحتفاظ والإتلاف |\n'
)

# KPI + confidence silent on stewardship — only governance / quality
# / catalog / lifecycle are listed.
_KPIS_AR = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | المؤشر |\n'
    '|---|------|\n'
    '| 1 | نسبة تغطية حوكمة البيانات |\n'
    '| 2 | نسبة جودة البيانات |\n'
    '| 3 | نسبة فهرسة البيانات الوصفية في كتالوج البيانات |\n'
    '| 4 | نسبة الالتزام بدورة حياة البيانات |\n'
)

_CONFIDENCE_AR = (
    '## 7. سجل المخاطر\n\n'
    '| # | الخطر |\n'
    '|---|------|\n'
    '| 1 | مخاطر حوكمة البيانات |\n'
    '| 2 | مخاطر جودة البيانات |\n'
    '| 3 | مخاطر كتالوج البيانات |\n'
    '| 4 | مخاطر دورة حياة البيانات |\n'
)

_SECTIONS = {
    'vision': '',
    'pillars': _PILLARS_AR,
    'environment': '',
    'gaps': _GAPS_AR,
    'roadmap': _ROADMAP_AR,
    'kpis': _KPIS_AR,
    'confidence': _CONFIDENCE_AR,
}


def _ndmo_rows(out):
    return [r for r in out['rows']
            if 'NDMO' in str(r[0]) or 'إدارة البيانات' in str(r[0])]


def _stewardship_row(out):
    for r in _ndmo_rows(out):
        cap = str(r[1])
        if ('أمناء البيانات' in cap or 'ملكية البيانات' in cap
                or 'stewardship' in cap.lower()
                or 'ownership' in cap.lower()):
            return r
    return None


class TestNdmoStewardshipTraceabilityPR5B9AK(unittest.TestCase):

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO'], 'ar', domain_code='data')

    # 1. NDMO stewardship row renders even when KPI / confidence
    #    sections are silent on stewardship.
    @_skip_if_no_app
    def test_01_ndmo_stewardship_row_renders(self):
        out = self._build()
        row = _stewardship_row(out)
        self.assertIsNotNone(
            row,
            'NDMO stewardship/ownership row missing from traceability: '
            f'{[r[1] for r in _ndmo_rows(out)]!r}')

    # 2. The stewardship row capability label uses canonical wording
    #    (أمناء البيانات or stewardship/ownership).
    @_skip_if_no_app
    def test_02_stewardship_row_label_canonical(self):
        out = self._build()
        row = _stewardship_row(out)
        self.assertIsNotNone(row)
        cap = str(row[1])
        self.assertTrue(
            'أمناء البيانات' in cap or 'ملكية البيانات' in cap,
            f'stewardship row label not canonical AR: {cap!r}')

    # 3. NDMO renders all five families (governance, quality, catalog,
    #    stewardship, lifecycle) — five distinct rows.
    @_skip_if_no_app
    def test_03_ndmo_all_five_families_render(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _ndmo_rows(out))
        for kw in ('حوكمة البيانات', 'جودة البيانات',
                   'كتالوج البيانات', 'أمناء البيانات',
                   'دورة حياة البيانات'):
            self.assertIn(
                kw, caps,
                f'NDMO capability missing from traceability: '
                f'{kw} (caps={caps!r})')

    # 4. No NDMO row contains a dash placeholder.
    @_skip_if_no_app
    def test_04_no_dash_in_ndmo_rows(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in _ndmo_rows(out):
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'NDMO row contains dash placeholder: {r!r}')

    # 5. Stewardship row initiative / KPI / risk cells are distinct.
    @_skip_if_no_app
    def test_05_stewardship_row_cells_distinct(self):
        out = self._build()
        row = _stewardship_row(out)
        self.assertIsNotNone(row)
        initiative, kpi, risk = row[3], row[4], row[5]
        self.assertNotEqual(
            initiative, kpi,
            f'stewardship initiative==kpi: {row!r}')
        self.assertNotEqual(
            initiative, risk,
            f'stewardship initiative==risk: {row!r}')
        self.assertNotEqual(
            kpi, risk,
            f'stewardship kpi==risk: {row!r}')

    # 6. NDMO registry still exposes data_stewardship as a capability
    #    family — validators not weakened.
    @_skip_if_no_app
    def test_06_validators_not_weakened(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('NDMO') or {}
        fam_ids = {c[0] for c in spec.get('capabilities') or []}
        for required in ('data_governance', 'data_quality',
                         'data_catalog', 'data_stewardship',
                         'data_lifecycle'):
            self.assertIn(
                required, fam_ids,
                f'NDMO registry missing capability: {required} '
                f'(got {fam_ids!r})')

    # 7. No deterministic stewardship row when sections are empty —
    #    soft derivation only fires when gap+initiative resolve from
    #    real content.
    @_skip_if_no_app
    def test_07_no_stewardship_row_when_sections_empty(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO'], 'ar', domain_code='data')
        self.assertEqual(
            out['rows'], [],
            f'soft derivation must not fabricate stewardship row '
            f'from empty sections, got: {out["rows"]!r}')

    # 8. Cross-domain (Cyber) rendering unchanged — soft derivation
    #    does not fire outside Data scope.
    @_skip_if_no_app
    def test_08_cross_domain_unchanged(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['ECC'], 'en', domain_code='cyber')
        if out['rows']:
            dash_rows = [
                r for r in out['rows']
                if any((c or '').strip() == '—' for c in r)
            ]
            self.assertGreaterEqual(
                len(dash_rows), 1,
                f'cyber ECC: expected at least one dash row, '
                f'got rows={out["rows"]!r}')


if __name__ == '__main__':
    unittest.main()
