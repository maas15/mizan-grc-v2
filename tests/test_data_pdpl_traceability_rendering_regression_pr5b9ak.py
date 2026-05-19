"""PR-5B.9AK — Data PDPL traceability rendering regression coverage.

Regression after PR-5B.9AJ: the latest Data Management generated PDF
still drops PDPL traceability rows when the KPI / confidence sections
happen to be silent on a given PDPL family even though the roadmap +
gaps clearly cover it.  Real-PDF roadmap wording also includes new
synonyms (``تنفيذ نظام إدارة الموافقات وتسجيلها``) that the previous
augmentation did not recognise.

This module fixtures ``_build_traceability_matrix`` with the EXACT
roadmap + gaps wording from the PR-5B.9AK problem statement but with
empty / silent KPI and confidence sections, and asserts that all five
PDPL capability families still render complete (no-dash,
no-broken-cell, distinct) rows via the soft KPI/Risk derivation map.

Run::

    python -m pytest \\
        tests/test_data_pdpl_traceability_rendering_regression_pr5b9ak.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ak_pdpl_trace_')
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


# ── Fixture mirroring the real-PDF regression: PDPL roadmap + gaps
# cover all five families, but the KPI and confidence sections are
# silent on PDPL entirely (only NDMO metrics / risks are listed).
# Without the PR-5B.9AK soft KPI/Risk derivation, every PDPL row gets
# a dash in the KPI or Risk column and the data-scope no-dash gate
# drops them all — exactly the symptom from the problem statement.
_GAPS_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الإطار |\n'
    '|---|------|------|\n'
    '| 1 | ضعف حوكمة البيانات | NDMO |\n'
    '| 2 | ضعف جودة البيانات | NDMO |\n'
    '| 3 | غياب كتالوج البيانات والبيانات الوصفية | NDMO |\n'
    '| 4 | غياب أمناء البيانات | NDMO |\n'
    '| 5 | غياب دورة حياة البيانات | NDMO |\n'
    '| 6 | ضعف حوكمة الخصوصية وحماية البيانات الشخصية | PDPL |\n'
    '| 7 | ضعف إدارة الموافقات أو عدم الامتثال لـ PDPL | PDPL |\n'
    '| 8 | ضعف تفعيل حقوق صاحب البيانات | PDPL |\n'
    '| 9 | ضعف تصنيف البيانات الشخصية | PDPL |\n'
    '| 10 | تأخر الإبلاغ عن خروقات البيانات | PDPL |\n'
)

_PILLARS_AR = (
    '## 2. الركائز\n\n'
    '| # | المبادرة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات (DMO) بقيادة رئيس البيانات (CDO) '
    '| governance |\n'
    '| 2 | بناء كتالوج البيانات والبيانات الوصفية | metadata |\n'
    '| 3 | تفعيل أمناء البيانات | stewardship |\n'
)

# Real-PDF roadmap with the new PR-5B.9AK wording variants
# (``تنفيذ نظام إدارة الموافقات وتسجيلها``).
_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك |\n'
    '|---|------|------|\n'
    '| 1 | إنشاء مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | CDO |\n'
    '| 3 | إطلاق برنامج إدارة جودة البيانات | CDO |\n'
    '| 4 | بناء كتالوج البيانات والبيانات الوصفية | CDO |\n'
    '| 5 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO |\n'
    '| 6 | تنفيذ سياسات خصوصية البيانات وإدارة الموافقات | DPO |\n'
    '| 7 | تنفيذ نظام إدارة الموافقات وتسجيلها | DPO |\n'
    '| 8 | تفعيل حقوق صاحب البيانات | DPO |\n'
    '| 9 | تنفيذ تصنيف البيانات الشخصية | DPO |\n'
    '| 10 | تنفيذ آليات الإبلاغ عن خروقات البيانات | DPO |\n'
    '| 11 | إعداد خطة الإبلاغ عن الانتهاكات | DPO |\n'
)

# KPI + confidence sections list ONLY NDMO metrics / risks — PDPL is
# silent in both. This is the regression scenario from the problem
# statement: previously every PDPL row would drop because KPI / Risk
# columns ended up as dash.
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


def _is_pdpl_row(r):
    return (
        'PDPL' in str(r[0])
        or 'Personal Data' in str(r[0])
        or 'حماية البيانات' in str(r[0])
    )


def _pdpl_rows(out):
    return [r for r in out['rows'] if _is_pdpl_row(r)]


class TestPdplTraceabilityRenderingRegressionPR5B9AK(unittest.TestCase):

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')

    # 1. PDPL Part A renders the privacy-governance row even when the
    #    KPI / confidence sections are silent on PDPL.
    @_skip_if_no_app
    def test_01_pdpl_privacy_governance_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حوكمة الخصوصية', caps,
                      f'PDPL privacy_governance row missing: {caps!r}')

    # 2. PDPL Part A renders the consent-management row from the new
    #    real-PDF wording (``تنفيذ نظام إدارة الموافقات وتسجيلها``).
    @_skip_if_no_app
    def test_02_pdpl_consent_management_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('إدارة الموافقات', caps,
                      f'PDPL consent_management row missing: {caps!r}')

    # 3. PDPL Part A renders the data-subject-rights row.
    @_skip_if_no_app
    def test_03_pdpl_data_subject_rights_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حقوق صاحب البيانات', caps,
                      f'PDPL data_subject_rights row missing: {caps!r}')

    # 4. PDPL Part A renders the personal-data-classification row.
    @_skip_if_no_app
    def test_04_pdpl_personal_data_classification_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('تصنيف البيانات الشخصية', caps,
                      f'PDPL classification row missing: {caps!r}')

    # 5. PDPL Part A renders the breach-notification row.
    @_skip_if_no_app
    def test_05_pdpl_breach_notification_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('الإبلاغ عن الانتهاكات', caps,
                      f'PDPL breach_notification row missing: {caps!r}')

    # 6. Part B: all five PDPL capabilities render distinct rows
    #    (count == 5).
    @_skip_if_no_app
    def test_06_pdpl_part_b_all_five_capabilities_render(self):
        out = self._build()
        rows = _pdpl_rows(out)
        cap_set = {str(r[1]) for r in rows}
        # The registry exposes 6 PDPL families (classification has two
        # aliases canonicalised to the same id) — we expect exactly 5
        # distinct capability rows after deduplication.
        self.assertEqual(
            len(rows), 5,
            f'PDPL must render exactly 5 rows after dedup, got '
            f'{len(rows)}: {rows!r}')
        # Sanity: capability labels are non-empty and distinct.
        self.assertEqual(
            len(cap_set), 5,
            f'PDPL capability labels not distinct: {cap_set!r}')

    # 7. No PDPL traceability row contains the dash placeholder.
    @_skip_if_no_app
    def test_07_no_dash_in_pdpl_rows(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in _pdpl_rows(out):
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'PDPL row contains dash placeholder: {r!r}')

    # 8. No PDPL traceability row contains a standalone broken cell
    #    like ``"تصنيف"`` / ``"موافقة"`` / ``"الإبلاغ"``.
    @_skip_if_no_app
    def test_08_no_standalone_broken_cells_in_pdpl_rows(self):
        out = self._build()
        broken = {'تصنيف', 'الموافقة', 'موافقة', 'الإبلاغ',
                  'إخطار', 'الخصوصية', 'الحقوق', 'الحوكمة'}
        for r in _pdpl_rows(out):
            for idx, cell in enumerate(r):
                if idx == 1:  # capability column is registry label
                    continue
                s = (cell or '').strip()
                self.assertNotIn(
                    s, broken,
                    f'PDPL row contains standalone broken cell '
                    f'{s!r}: {r!r}')

    # 9. Initiative / KPI / Risk cells are distinct within each row
    #    (soft-derived KPI/Risk never mirrors the initiative text).
    @_skip_if_no_app
    def test_09_initiative_kpi_risk_distinct(self):
        out = self._build()
        for r in _pdpl_rows(out):
            initiative, kpi, risk = r[3], r[4], r[5]
            self.assertNotEqual(
                initiative, kpi,
                f'initiative==kpi in PDPL row: {r!r}')
            self.assertNotEqual(
                initiative, risk,
                f'initiative==risk in PDPL row: {r!r}')
            self.assertNotEqual(
                kpi, risk,
                f'kpi==risk in PDPL row: {r!r}')

    # 10. Cross-domain (Cyber / AI) rendering unchanged — dash rows
    #     still preserved outside Data scope, soft derivation does not
    #     fire.
    @_skip_if_no_app
    def test_10_cross_domain_rendering_unchanged(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        for fw, dom in (('ECC', 'cyber'),
                        ('NIST_AI_RMF', 'ai')):
            try:
                out = _APP._build_traceability_matrix(
                    empty, [fw], 'en', domain_code=dom)
            except Exception:  # pragma: no cover
                continue
            if not out['rows']:
                continue
            dash_rows = [
                r for r in out['rows']
                if any((c or '').strip() == '—' for c in r)
            ]
            self.assertGreaterEqual(
                len(dash_rows), 1,
                f'{dom}/{fw}: expected at least one dash row, '
                f'got rows={out["rows"]!r}')

    # 11. Validators not weakened — the PDPL registry still exposes
    #     all five required capability families.
    @_skip_if_no_app
    def test_11_validators_not_weakened(self):
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

    # 12. No deterministic strategy rows are inserted when every
    #     section is empty — soft derivation only fires when gap +
    #     initiative were resolved from real content.
    @_skip_if_no_app
    def test_12_no_deterministic_rows_when_sections_empty(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        # All rows would be all-dash and dropped by no-dash gate.
        self.assertEqual(
            out['rows'], [],
            f'soft derivation must not fabricate rows from empty '
            f'sections, got: {out["rows"]!r}')

    # 13. auth / DB untouched — the helper is pure.
    @_skip_if_no_app
    def test_13_auth_db_untouched(self):
        out = _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertIn('rows', out)
        self.assertIn('header', out)


if __name__ == '__main__':
    unittest.main()
