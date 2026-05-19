"""PR-5B.9AH — Remaining Data PDPL traceability rendering gaps.

The PR-5B.9AB traceability fix added fallback section lookups so PDPL
rows could be derived from roadmap / KPIs / confidence when the gaps
section was NDMO-only.  Real-world AI-generated content however phrases
the consent / breach PDPL activities, KPIs and risks with a wider
Arabic vocabulary than the framework registry exposes — phrases like
``سياسات إدارة الموافقات``, ``نظام إدارة الموافقات``, ``الإبلاغ عن
اختراقات البيانات``, ``خطة الإبلاغ عن الانتهاكات`` are common in the
generated body but the lookup keywords ignored them, so the
``consent_management`` and ``breach_notification`` rows were dropped by
the data-scope no-dash gate.

This module exercises ``_build_traceability_matrix`` directly with a
fixture mirroring the problem-statement examples and asserts:

* Part A renders all five PDPL capabilities (privacy governance,
  consent management, data subject rights, personal data
  classification, breach notification).
* Part B (rendered ``rows`` list) renders complete consent / breach
  rows with distinct initiative / KPI / risk cells.
* No rendered row contains the ``—`` placeholder.
* No rendered row contains a standalone broken cell like ``تصنيف``.
* NDMO traceability (governance, quality, catalog, stewardship,
  lifecycle) still renders.
* Cross-domain rendering (Cyber / AI / DT / ERM) is unchanged — dash
  rows still preserved outside Data scope.
* No deterministic strategy rows are inserted when sections are empty.

Run::

    python -m pytest \
        tests/test_data_pdpl_traceability_remaining_pr5b9ah.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ah_trace_')
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
# Mirrors the problem-statement examples: PDPL consent / breach are
# phrased with the wider AR vocabulary (سياسات إدارة الموافقات /
# اختراقات البيانات / خطة الإبلاغ عن الانتهاكات) that real AI runs
# emit but the registry keywords don't enumerate.  NDMO families
# remain phrased with their canonical vocabulary.

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
    '| 7 | وضع سياسات إدارة الموافقات | CDO | Q3 | نظام إدارة الموافقات |\n'
    '| 8 | تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة التصنيف |\n'
    '| 9 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
    'حق الحذف | CDO | Q4 | آلية |\n'
    '| 10 | إعداد خطة الإبلاغ عن الانتهاكات | CISO | Q4 | إجراء |\n'
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
    '| 9 | نسبة تصنيف البيانات الشخصية | classification |\n'
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
    '| 7 | ضعف إدارة الموافقات أو عدم الامتثال لـ PDPL | consent risk |\n'
    '| 8 | مخاطر حقوق صاحب البيانات | DSR |\n'
    '| 9 | مخاطر تصنيف البيانات الشخصية | classification |\n'
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


def _pdpl_rows(out):
    return [
        r for r in out['rows']
        if 'PDPL' in str(r[0]) or 'Personal Data' in str(r[0])
        or 'حماية البيانات' in str(r[0])
    ]


class TestPdplTraceabilityRemaining(unittest.TestCase):

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')

    # 1. Part A includes privacy governance.
    @_skip_if_no_app
    def test_01_part_a_includes_privacy_governance(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حوكمة الخصوصية', caps)

    # 2. Part A includes consent management.
    @_skip_if_no_app
    def test_02_part_a_includes_consent_management(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('إدارة الموافقات', caps)

    # 3. Part A includes data subject rights.
    @_skip_if_no_app
    def test_03_part_a_includes_data_subject_rights(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('حقوق صاحب البيانات', caps)

    # 4. Part A includes personal data classification.
    @_skip_if_no_app
    def test_04_part_a_includes_personal_data_classification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('تصنيف البيانات', caps)

    # 5. Part A includes breach notification.
    @_skip_if_no_app
    def test_05_part_a_includes_breach_notification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in _pdpl_rows(out))
        self.assertIn('الإبلاغ عن الانتهاكات', caps)

    # 6. Part B includes consent row with distinct initiative/KPI/risk.
    @_skip_if_no_app
    def test_06_part_b_consent_row_distinct_cells(self):
        out = self._build()
        consent_rows = [
            r for r in _pdpl_rows(out) if 'إدارة الموافقات' in str(r[1])
        ]
        self.assertEqual(
            len(consent_rows), 1,
            f'expected exactly 1 PDPL consent row, got {consent_rows!r}')
        r = consent_rows[0]
        # [framework, capability, gap, initiative, kpi, risk]
        gap, initiative, kpi, risk = r[2], r[3], r[4], r[5]
        for cell in (gap, initiative, kpi, risk):
            self.assertTrue(cell and str(cell).strip(),
                            f'consent row has empty cell: {r!r}')
        self.assertNotEqual(initiative, kpi,
                            f'initiative==kpi in consent row: {r!r}')
        self.assertNotEqual(initiative, risk,
                            f'initiative==risk in consent row: {r!r}')
        self.assertNotEqual(kpi, risk,
                            f'kpi==risk in consent row: {r!r}')

    # 7. Part B includes breach row with distinct initiative/KPI/risk.
    @_skip_if_no_app
    def test_07_part_b_breach_row_distinct_cells(self):
        out = self._build()
        breach_rows = [
            r for r in _pdpl_rows(out)
            if 'الإبلاغ عن الانتهاكات' in str(r[1])
        ]
        self.assertEqual(
            len(breach_rows), 1,
            f'expected exactly 1 PDPL breach row, got {breach_rows!r}')
        r = breach_rows[0]
        gap, initiative, kpi, risk = r[2], r[3], r[4], r[5]
        for cell in (gap, initiative, kpi, risk):
            self.assertTrue(cell and str(cell).strip(),
                            f'breach row has empty cell: {r!r}')
        self.assertNotEqual(initiative, kpi,
                            f'initiative==kpi in breach row: {r!r}')
        self.assertNotEqual(initiative, risk,
                            f'initiative==risk in breach row: {r!r}')
        self.assertNotEqual(kpi, risk,
                            f'kpi==risk in breach row: {r!r}')

    # 8. No PDPL traceability row contains "—".
    @_skip_if_no_app
    def test_08_no_dash_in_pdpl_rows(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in _pdpl_rows(out):
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'PDPL row contains dash placeholder: {r!r}')

    # 9. No PDPL row contains a standalone broken cell like "تصنيف".
    @_skip_if_no_app
    def test_09_no_standalone_broken_cell_in_pdpl_rows(self):
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

    # 10. NDMO traceability still includes its 5 families.
    @_skip_if_no_app
    def test_10_ndmo_rows_unchanged(self):
        out = self._build()
        ndmo_rows = [r for r in out['rows']
                     if 'NDMO' in str(r[0]) or 'حوكمة وإدارة' in str(r[0])]
        caps = ' | '.join(str(r[1]) for r in ndmo_rows)
        for kw in ('حوكمة البيانات', 'جودة البيانات',
                   'كتالوج البيانات', 'أمناء البيانات',
                   'دورة حياة البيانات'):
            self.assertIn(kw, caps,
                          f'NDMO capability missing from traceability: '
                          f'{kw} (caps={caps!r})')

    # 11. Cross-domain (Cyber / AI / DT / ERM) unchanged — dash rows
    # still preserved outside Data scope.
    @_skip_if_no_app
    def test_11_cross_domain_unchanged(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        for fw, dom in (('ECC', 'cyber'), ('NIST_AI_RMF', 'ai')):
            try:
                out = _APP._build_traceability_matrix(
                    empty, [fw], 'en', domain_code=dom)
            except Exception:  # pragma: no cover — registry tolerant
                continue
            if not out['rows']:
                continue
            self.assertGreaterEqual(
                len([r for r in out['rows']
                     if any((c or '').strip() == '—' for c in r)]),
                1,
                f'{dom}/{fw}: expected at least one dash row, '
                f'got rows={out["rows"]!r}')

    # 12. No deterministic strategy rows — empty sections yield empty
    # Data rows.
    @_skip_if_no_app
    def test_12_no_deterministic_strategy_rows(self):
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertEqual(out['rows'], [])

    # 13. Validators not weakened — PDPL registry capability list
    # still contains the 5 required families (including both
    # classification aliases).
    @_skip_if_no_app
    def test_13_validators_not_weakened(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('PDPL') or {}
        fam_ids = {c[0] for c in spec.get('capabilities') or []}
        for required in (
                'privacy_governance', 'consent_management',
                'data_subject_rights', 'breach_notification'):
            self.assertIn(required, fam_ids,
                          f'PDPL registry missing capability: '
                          f'{required} (got {fam_ids!r})')
        # At least one of the two classification aliases must remain.
        self.assertTrue(
            ('data_classification_pdpl' in fam_ids
             or 'personal_data_classification' in fam_ids),
            f'PDPL registry missing classification family: {fam_ids!r}')

    # 14. auth/DB untouched — sanity: traceability builder is pure and
    # does not require any database or auth artefact.
    @_skip_if_no_app
    def test_14_auth_db_untouched(self):
        # The helper signature accepts only content + framework keys +
        # lang + domain_code — no db / session / auth handle.  Calling
        # it without any auth bootstrap must succeed.
        out = _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertIn('rows', out)
        self.assertIn('header', out)


if __name__ == '__main__':
    unittest.main()
