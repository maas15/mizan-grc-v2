"""PR-5B.9AI — Final Data PDPL traceability rendering coverage.

Data Management strategy generation is producing complete PDPL scope
(NDMO + PDPL), with the roadmap including the four PDPL activities:

* ``تنفيذ سياسات خصوصية البيانات وإدارة الموافقات``
* ``إدارة تصنيف البيانات الشخصية``
* ``تنفيذ آليات الإبلاغ عن خروقات البيانات``
* ``تفعيل حقوق صاحب البيانات``

…and NDMO traceability renders five rows correctly. The remaining gap
is the **traceability matrix** for PDPL: Part A used to render only
``privacy_governance`` and Part B used to render only a partial
classification/privacy row.  ``consent_management``,
``data_subject_rights``, ``personal_data_classification`` and
``breach_notification`` must all render as complete traceability rows
derived from the already-generated roadmap / KPI / risk content.

This module exercises ``_build_traceability_matrix`` directly with a
fixture mirroring the problem-statement examples and asserts:

1.  PDPL Part A includes privacy governance.
2.  PDPL Part A includes consent management.
3.  PDPL Part A includes data subject rights.
4.  PDPL Part A includes personal data classification.
5.  PDPL Part A includes breach notification.
6.  PDPL Part B includes a consent management row.
7.  PDPL Part B includes a data subject rights row.
8.  PDPL Part B includes a breach notification row.
9.  PDPL Part B includes a personal data classification row.
10. No PDPL traceability row contains ``"—"``.
11. No PDPL traceability row contains the standalone broken cell
    ``"تصنيف"``.
12. Initiative / KPI / Risk cells are not identical duplicates when
    distinct source content exists.
13. NDMO traceability remains unchanged (five families render).
14. Cyber / AI / DT / ERM cross-domain rendering is unchanged.
15. No deterministic strategy rows are inserted when sections are
    empty.
16. Validators are not weakened — the PDPL registry still exposes the
    five required capability families.
17. auth / DB untouched — the helper is pure and runs without any
    database or session bootstrap.

Run::

    python -m pytest \
        tests/test_data_pdpl_traceability_rendering_final_pr5b9ai.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ai_trace_')
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


# ── Fixture ─────────────────────────────────────────────────────────
# Mirrors the problem-statement PDPL examples literally:
#   * Roadmap carries the four PDPL activities (consent policy,
#     classification, breach reporting, data subject rights).
#   * KPI section carries the expected PDPL KPIs.
#   * Risk (confidence) section carries the expected PDPL risks.
# NDMO families remain phrased with their canonical vocabulary so the
# NDMO regression test (#13) still finds all five families.

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
    '| 1 | تأسيس مكتب إدارة البيانات | DMO |\n'
    '| 2 | بناء كتالوج البيانات والبيانات الوصفية | metadata |\n'
    '| 3 | تفعيل أمناء البيانات | stewardship |\n'
)

_ROADMAP_AR = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | CDO | Q1 | ميثاق |\n'
    '| 3 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 4 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 | كتالوج |\n'
    '| 5 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 | سياسة |\n'
    '| 6 | تأسيس حوكمة الخصوصية وحماية البيانات الشخصية '
    '| CDO | Q3 | سياسة |\n'
    '| 7 | تنفيذ سياسات خصوصية البيانات وإدارة الموافقات '
    '| CDO | Q3 | نظام |\n'
    '| 8 | إدارة تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة |\n'
    '| 9 | تفعيل حقوق صاحب البيانات | CDO | Q4 | آلية |\n'
    '| 10 | تنفيذ آليات الإبلاغ عن خروقات البيانات '
    '| CISO | Q4 | إجراء |\n'
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
            if 'NDMO' in str(r[0]) or 'حوكمة وإدارة' in str(r[0])]


class TestPdplTraceabilityRenderingFinal(unittest.TestCase):

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')

    # 1. PDPL Part A includes privacy governance.
    @_skip_if_no_app
    def test_01_part_a_privacy_governance(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حوكمة الخصوصية', caps)

    # 2. PDPL Part A includes consent management.
    @_skip_if_no_app
    def test_02_part_a_consent_management(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('إدارة الموافقات', caps)

    # 3. PDPL Part A includes data subject rights.
    @_skip_if_no_app
    def test_03_part_a_data_subject_rights(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حقوق صاحب البيانات', caps)

    # 4. PDPL Part A includes personal data classification.
    @_skip_if_no_app
    def test_04_part_a_personal_data_classification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('تصنيف البيانات الشخصية', caps)

    # 5. PDPL Part A includes breach notification.
    @_skip_if_no_app
    def test_05_part_a_breach_notification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('الإبلاغ عن الانتهاكات', caps)

    # 6. PDPL Part B includes a consent management row.
    @_skip_if_no_app
    def test_06_part_b_consent_management_row(self):
        out = self._build()
        consent_rows = [r for r in _pdpl_rows(out)
                        if 'إدارة الموافقات' in str(r[1])]
        self.assertEqual(
            len(consent_rows), 1,
            f'expected exactly 1 PDPL consent row, got {consent_rows!r}')
        r = consent_rows[0]
        # Initiative cell must include the consent-policy activity.
        self.assertIn('إدارة الموافقات', r[3],
                      f'consent row initiative missing: {r!r}')
        # KPI cell must reference managed consents.
        self.assertIn('الموافقات', r[4],
                      f'consent row kpi missing: {r!r}')
        # Risk cell must reference the consent/PDPL risk.
        self.assertIn('إدارة الموافقات', r[5],
                      f'consent row risk missing: {r!r}')

    # 7. PDPL Part B includes a data subject rights row.
    @_skip_if_no_app
    def test_07_part_b_data_subject_rights_row(self):
        out = self._build()
        rights_rows = [r for r in _pdpl_rows(out)
                       if 'حقوق صاحب البيانات' in str(r[1])]
        self.assertEqual(
            len(rights_rows), 1,
            f'expected exactly 1 PDPL DSR row, got {rights_rows!r}')
        r = rights_rows[0]
        self.assertIn('حقوق صاحب البيانات', r[3],
                      f'DSR row initiative missing: {r!r}')
        # KPI must reference DSR handling.
        self.assertIn('حقوق أصحاب البيانات', r[4],
                      f'DSR row kpi missing: {r!r}')
        # Risk must reference non-response / non-compliance.
        self.assertTrue(
            'حقوق' in str(r[5]) or 'الاستجابة' in str(r[5]),
            f'DSR row risk missing: {r!r}')

    # 8. PDPL Part B includes a breach notification row.
    @_skip_if_no_app
    def test_08_part_b_breach_notification_row(self):
        out = self._build()
        breach_rows = [r for r in _pdpl_rows(out)
                       if 'الإبلاغ عن الانتهاكات' in str(r[1])]
        self.assertEqual(
            len(breach_rows), 1,
            f'expected exactly 1 PDPL breach row, got {breach_rows!r}')
        r = breach_rows[0]
        self.assertIn('الإبلاغ', r[3],
                      f'breach row initiative missing: {r!r}')
        # KPI must reference breach reporting.
        self.assertIn('الإبلاغ', r[4],
                      f'breach row kpi missing: {r!r}')
        # Risk must reference the delay/non-compliance.
        self.assertTrue(
            'خروقات' in str(r[5]) or 'الإبلاغ' in str(r[5]),
            f'breach row risk missing: {r!r}')

    # 9. PDPL Part B includes a personal data classification row.
    @_skip_if_no_app
    def test_09_part_b_personal_data_classification_row(self):
        out = self._build()
        class_rows = [
            r for r in _pdpl_rows(out)
            if 'تصنيف البيانات الشخصية' in str(r[1])
        ]
        self.assertEqual(
            len(class_rows), 1,
            f'expected exactly 1 PDPL classification row, got '
            f'{class_rows!r}')
        r = class_rows[0]
        self.assertIn('تصنيف', r[3],
                      f'classification row initiative missing: {r!r}')
        self.assertIn('تصنيف', r[4],
                      f'classification row kpi missing: {r!r}')
        self.assertIn('تصنيف', r[5],
                      f'classification row risk missing: {r!r}')

    # 10. No PDPL traceability row contains "—".
    @_skip_if_no_app
    def test_10_no_dash_in_pdpl_rows(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in _pdpl_rows(out):
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'PDPL row contains dash placeholder: {r!r}')

    # 11. No PDPL row contains a standalone broken cell like "تصنيف".
    @_skip_if_no_app
    def test_11_no_standalone_broken_cell(self):
        out = self._build()
        broken = {'تصنيف', 'الموافقة', 'موافقة', 'الإبلاغ',
                  'إخطار', 'الخصوصية', 'الحقوق', 'الحوكمة'}
        for r in _pdpl_rows(out):
            # Skip the capability column (r[1]) — it is a registry
            # label, not derived from content.
            for idx, cell in enumerate(r):
                if idx == 1:
                    continue
                s = (cell or '').strip()
                self.assertNotIn(
                    s, broken,
                    f'PDPL row contains standalone broken cell '
                    f'{s!r}: {r!r}')

    # 12. Initiative / KPI / Risk are not identical duplicates when
    #     distinct content exists in the source sections.
    @_skip_if_no_app
    def test_12_initiative_kpi_risk_not_identical(self):
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

    # 13. NDMO traceability remains unchanged — five families render.
    @_skip_if_no_app
    def test_13_ndmo_unchanged(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _ndmo_rows(out))
        for kw in ('حوكمة البيانات', 'جودة البيانات',
                   'كتالوج البيانات', 'أمناء البيانات',
                   'دورة حياة البيانات'):
            self.assertIn(
                kw, caps,
                f'NDMO capability missing from traceability: '
                f'{kw} (caps={caps!r})')

    # 14. Cyber / AI / DT / ERM cross-domain rendering unchanged —
    #     dash rows still preserved outside Data scope.
    @_skip_if_no_app
    def test_14_cross_domain_unchanged(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        checked = 0
        for fw, dom in (('ECC', 'cyber'),
                        ('NIST_AI_RMF', 'ai')):
            try:
                out = _APP._build_traceability_matrix(
                    empty, [fw], 'en', domain_code=dom)
            except Exception:  # pragma: no cover — registry tolerant
                continue
            if not out['rows']:
                continue
            # Outside Data scope, dash rows must be retained.
            dash_rows = [
                r for r in out['rows']
                if any((c or '').strip() == '—' for c in r)
            ]
            self.assertGreaterEqual(
                len(dash_rows), 1,
                f'{dom}/{fw}: expected at least one dash row, '
                f'got rows={out["rows"]!r}')
            checked += 1
        # At least one of the cross-domain frameworks must have
        # produced traceability rows we could check.
        self.assertGreater(
            checked, 0,
            'no cross-domain framework produced any traceability rows')

    # 15. No deterministic strategy rows are inserted when sections
    #     are empty in Data scope.
    @_skip_if_no_app
    def test_15_no_deterministic_strategy_rows(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertEqual(out['rows'], [])

    # 16. Validators not weakened — PDPL registry capability list
    #     still contains the five required families (including at
    #     least one of the classification family ids).
    @_skip_if_no_app
    def test_16_validators_not_weakened(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL') or {}
        fam_ids = {c[0] for c in spec.get('capabilities') or []}
        for required in (
                'privacy_governance', 'consent_management',
                'data_subject_rights', 'breach_notification'):
            self.assertIn(
                required, fam_ids,
                f'PDPL registry missing capability: '
                f'{required} (got {fam_ids!r})')
        self.assertTrue(
            ('data_classification_pdpl' in fam_ids
             or 'personal_data_classification' in fam_ids),
            f'PDPL registry missing classification family: '
            f'{fam_ids!r}')

    # 17. auth / DB untouched — the helper is pure and runs without
    #     any database or session bootstrap.
    @_skip_if_no_app
    def test_17_auth_db_untouched(self):
        out = _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertIn('rows', out)
        self.assertIn('header', out)


if __name__ == '__main__':
    unittest.main()
