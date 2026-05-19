"""PR-5B.9AJ — PDPL traceability rendering from real generated PDF wording.

Defect: the latest Data Management generated PDF lists PDPL capabilities
in scope and includes the related PDPL roadmap activities (privacy
governance, consent + DSR, classification, breach notification) but the
traceability matrix renders only the privacy-governance PDPL row and
drops the other four families.  PR-5B.9AI added regression coverage
with the AI's "ideal" wording, but production PDFs use slightly
different phrasings such as ``إدارة الموافقات وحقوق صاحب البيانات``
(one row covering both consent and DSR), ``تنفيذ تصنيف البيانات
الشخصية`` and ``إعداد خطة الإبلاغ عن الانتهاكات``.

This module fixtures ``_build_traceability_matrix`` with the EXACT
roadmap wording from the problem statement and asserts that all five
PDPL families render with complete (no-dash, no-broken-cell, distinct)
initiative / KPI / risk cells derived from the existing roadmap /
KPI / risk content.  It also pins NDMO traceability depth, validators
strength, and cross-domain rendering.

Run::

    python -m pytest \\
        tests/test_data_pdpl_traceability_real_output_pr5b9aj.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9aj_trace_real_')
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


# ── Fixture mirroring real generated Data PDF wording ─────────────────
# Roadmap rows use the EXACT phrasings listed in the PR-5B.9AJ problem
# statement.  Note that consent_management and data_subject_rights are
# combined into a SINGLE roadmap row ("إدارة الموافقات وحقوق صاحب
# البيانات") — the matrix must still derive a complete row for BOTH
# families from that source.
_GAPS_AR = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف |\n'
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
    '| 10 | تأخر الإبلاغ عن خروقات البيانات أو عدم الامتثال '
    'التنظيمي | PDPL |\n'
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

# Real-PDF roadmap phrasings from the PR-5B.9AJ problem statement.
_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | إنشاء مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | CDO | Q1 | ميثاق |\n'
    '| 3 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 4 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 '
    '| كتالوج |\n'
    '| 5 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 '
    '| سياسة |\n'
    '| 6 | تنفيذ حوكمة الخصوصية وفق PDPL | DPO | Q3 | سياسة |\n'
    '| 7 | إدارة الموافقات وحقوق صاحب البيانات | DPO | Q3 | آلية |\n'
    '| 8 | تنفيذ تصنيف البيانات الشخصية | DPO | Q4 | مصفوفة |\n'
    '| 9 | إعداد خطة الإبلاغ عن الانتهاكات | DPO | Q4 | إجراء |\n'
)

_KPIS_AR = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | المؤشر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | نسبة تغطية حوكمة البيانات | governance |\n'
    '| 2 | نسبة جودة البيانات | quality |\n'
    '| 3 | نسبة فهرسة البيانات الوصفية في كتالوج البيانات | metadata |\n'
    '| 4 | نسبة تغطية أمناء البيانات | stewardship |\n'
    '| 5 | نسبة الالتزام بدورة حياة البيانات | lifecycle |\n'
    '| 6 | نسبة الالتزام بحوكمة الخصوصية | privacy |\n'
    '| 7 | نسبة الموافقات المدارة | consent |\n'
    '| 8 | نسبة معالجة طلبات حقوق أصحاب البيانات | DSR |\n'
    '| 9 | دقة تصنيف البيانات الشخصية | classification |\n'
    '| 10 | نسبة الإبلاغ عن اختراقات البيانات | breach |\n'
)

_CONFIDENCE_AR = (
    '## 7. سجل المخاطر\n\n'
    '| # | الخطر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | مخاطر حوكمة البيانات | governance |\n'
    '| 2 | مخاطر جودة البيانات | quality |\n'
    '| 3 | مخاطر كتالوج البيانات | metadata |\n'
    '| 4 | مخاطر أمناء البيانات | stewardship |\n'
    '| 5 | مخاطر دورة حياة البيانات | lifecycle |\n'
    '| 6 | مخاطر حوكمة الخصوصية | privacy |\n'
    '| 7 | ضعف إدارة الموافقات أو عدم الامتثال لـ PDPL '
    '| consent risk |\n'
    '| 8 | عدم الاستجابة لحقوق أصحاب البيانات أو عدم الامتثال '
    'لـ PDPL | DSR risk |\n'
    '| 9 | ضعف تصنيف البيانات الشخصية أو مخاطر عدم الامتثال '
    '| classification risk |\n'
    '| 10 | تأخر الإبلاغ عن خروقات البيانات أو عدم الامتثال '
    'التنظيمي | breach risk |\n'
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


def _ndmo_rows(out):
    return [r for r in out['rows']
            if 'NDMO' in str(r[0]) or 'حوكمة وإدارة' in str(r[0])
            or 'إدارة البيانات الوطني' in str(r[0])]


class TestPdplTraceabilityRealOutputPR5B9AJ(unittest.TestCase):

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')

    # 1. PDPL Part A renders the privacy-governance row from the real
    #    roadmap wording ``تنفيذ حوكمة الخصوصية وفق PDPL``.
    @_skip_if_no_app
    def test_01_pdpl_privacy_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حوكمة الخصوصية', caps,
                      f'PDPL privacy_governance row missing: {caps!r}')

    # 2. PDPL Part A renders the consent-management row from the
    #    combined roadmap wording ``إدارة الموافقات وحقوق صاحب
    #    البيانات``.
    @_skip_if_no_app
    def test_02_pdpl_consent_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('إدارة الموافقات', caps,
                      f'PDPL consent_management row missing: {caps!r}')

    # 3. PDPL Part A renders the data-subject-rights row from the same
    #    combined roadmap wording ``إدارة الموافقات وحقوق صاحب
    #    البيانات``.
    @_skip_if_no_app
    def test_03_pdpl_data_subject_rights_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حقوق صاحب البيانات', caps,
                      f'PDPL data_subject_rights row missing: {caps!r}')

    # 4. PDPL Part A renders the personal-data-classification row from
    #    the real roadmap wording ``تنفيذ تصنيف البيانات الشخصية``.
    @_skip_if_no_app
    def test_04_pdpl_personal_data_classification_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('تصنيف البيانات الشخصية', caps,
                      f'PDPL classification row missing: {caps!r}')

    # 5. PDPL Part A renders the breach-notification row from the real
    #    roadmap wording ``إعداد خطة الإبلاغ عن الانتهاكات``.
    @_skip_if_no_app
    def test_05_pdpl_breach_notification_row_renders(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('الإبلاغ عن الانتهاكات', caps,
                      f'PDPL breach_notification row missing: {caps!r}')

    # 6. No PDPL row contains a dash placeholder.
    @_skip_if_no_app
    def test_06_no_dash_in_pdpl_rows(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in _pdpl_rows(out):
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'PDPL row contains dash placeholder: {r!r}')

    # 7. No PDPL row contains a standalone broken cell like "تصنيف".
    @_skip_if_no_app
    def test_07_no_standalone_broken_cell(self):
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

    # 8. NDMO traceability remains unchanged — five families render
    #    (governance, quality, catalog, stewardship, lifecycle).
    @_skip_if_no_app
    def test_08_ndmo_unchanged(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _ndmo_rows(out))
        for kw in ('حوكمة البيانات', 'جودة البيانات',
                   'كتالوج البيانات', 'أمناء البيانات',
                   'دورة حياة البيانات'):
            self.assertIn(
                kw, caps,
                f'NDMO capability missing from traceability: '
                f'{kw} (caps={caps!r})')

    # 9. Initiative / KPI / Risk cells are not identical duplicates
    #    when distinct source content exists.
    @_skip_if_no_app
    def test_09_initiative_kpi_risk_not_identical(self):
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

    # 10. Cross-domain (Cyber / AI / DT / ERM) rendering unchanged —
    #     dash rows still preserved outside Data scope.
    @_skip_if_no_app
    def test_10_cross_domain_unchanged(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        checked = 0
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
            checked += 1
        self.assertGreater(
            checked, 0,
            'no cross-domain framework produced any traceability rows')

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

    # 12. auth / DB untouched — the helper is pure and runs without
    #     any database or session bootstrap.
    @_skip_if_no_app
    def test_12_auth_db_untouched(self):
        out = _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertIn('rows', out)
        self.assertIn('header', out)


if __name__ == '__main__':
    unittest.main()
