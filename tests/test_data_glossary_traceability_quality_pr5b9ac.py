"""PR-5B.9AC — Data Management glossary + traceability cell quality.

Two narrowly-scoped quality fixes for the Data Management document:

1. The glossary must NOT render *Mobile Device Management* for the
   acronym MDM. The Data domain registers MDM as Master Data
   Management (إدارة البيانات الرئيسية) and the bare "MDM" token in
   the body must not also surface the Cyber-sense MDM (Mobile Device
   Management) registered under the disambiguated key ``MDM_MOBILE``.

2. The framework traceability matrix must not render the same phrase
   in the Initiative, KPI, and Risk columns of the same row when the
   AI body provides distinct initiative / KPI / risk content. The
   previous fallback would reuse the initiative row text whenever the
   KPI or Risk section was silent on a capability — producing a
   visually empty row even though the columns rendered text.

Both fixes are scoped to the Data domain (or PDPL/NDMO selection) so
Cyber / AI / DT / ERM rendering is unchanged.

Run::

    python -m pytest \\
        tests/test_data_glossary_traceability_quality_pr5b9ac.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ac_quality_')
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


# ── Glossary fixtures ──────────────────────────────────────────────
# Data Management body that literally uses the acronym "MDM" — the
# Data domain reads this as Master Data Management. The cyber-sense
# MDM (Mobile Device Management) must not surface in the appendix.
_DATA_BODY_WITH_MDM = (
    '## الرؤية\nتأسيس حوكمة البيانات وإدارة البيانات الرئيسية (MDM).\n'
    '## الركائز\nبرنامج MDM لتوحيد البيانات المرجعية.\n'
)

# Data Management body that explicitly uses the full Arabic and
# English Master Data Management expansion — appendix must list MDM
# = Master Data Management.
_DATA_BODY_WITH_MASTER_EXPANSION = (
    '## الرؤية\nإدارة البيانات الرئيسية أساسية لجودة البيانات.\n'
    '## الركائز\nMaster Data Management is a strategic capability.\n'
)


class TestDataGlossaryMdmCleanup(unittest.TestCase):
    """Tests 1-4 — Data glossary rendering for MDM."""

    @_skip_if_no_app
    def _build(self, body):
        return _APP._build_appendices_block(
            ['NDMO', 'PDPL'], 'ar',
            content_sections={'vision': body, 'pillars': '',
                              'environment': '', 'gaps': '',
                              'roadmap': '', 'kpis': '',
                              'confidence': ''},
            domain_code='data')

    def _collect_glossary_bodies(self, appendices):
        bodies = []
        # Skip until we reach the Appendix B heading; everything after
        # is glossary content.
        in_glossary = False
        for label, body in appendices:
            if 'الملحق ب' in label or 'Appendix B' in label:
                in_glossary = True
                continue
            if in_glossary and label.startswith('•'):
                bodies.append((label.lstrip('• ').strip(), body))
        return bodies

    @_skip_if_no_app
    def test_01_glossary_does_not_render_mobile_device_management(self):
        appendices = self._build(_DATA_BODY_WITH_MDM)
        for acronym, body in self._collect_glossary_bodies(appendices):
            self.assertNotIn(
                'إدارة الأجهزة المحمولة', body or '',
                f'Mobile Device Management leaked into '
                f'Data appendix entry {acronym!r}: {body!r}')
            self.assertNotIn(
                'Mobile Device Management', body or '',
                f'Mobile Device Management leaked into '
                f'Data appendix entry {acronym!r}: {body!r}')

    @_skip_if_no_app
    def test_02_glossary_renders_master_data_management(self):
        appendices = self._build(_DATA_BODY_WITH_MASTER_EXPANSION)
        joined = ' || '.join(
            f'{lbl}|{body}' for lbl, body
            in self._collect_glossary_bodies(appendices))
        self.assertIn('إدارة البيانات الرئيسية', joined)

    @_skip_if_no_app
    def test_03_mdm_acronym_alone_maps_only_to_master(self):
        appendices = self._build(_DATA_BODY_WITH_MDM)
        entries = self._collect_glossary_bodies(appendices)
        # When MDM appears as a bare acronym the Data appendix should
        # surface the Master Data Management entry (registered under
        # MDM_MASTER with display "MDM" / AR "إدارة البيانات الرئيسية").
        mdm_entries = [(lbl, body) for lbl, body in entries
                       if lbl.strip() == 'MDM']
        self.assertTrue(
            len(mdm_entries) >= 1,
            f'expected at least one MDM glossary entry, got '
            f'{mdm_entries!r} from {entries!r}')
        for _lbl, body in mdm_entries:
            self.assertIn('إدارة البيانات الرئيسية', body or '')
            self.assertNotIn('إدارة الأجهزة المحمولة', body or '')

    @_skip_if_no_app
    def test_04_cyber_domain_mdm_unchanged(self):
        """Cyber domain rendering must keep Mobile Device Management
        for MDM_MOBILE — the fix is scoped to disambiguated forbidden
        acronyms in non-cyber domains; cyber output is byte-stable.
        """
        cyber_body = (
            '## Vision\nDeploy MDM across all endpoints.\n'
            '## Pillars\nMobile Device Management is mandatory.\n'
        )
        appendices = _APP._build_appendices_block(
            ['ECC'], 'en',
            content_sections={'vision': cyber_body, 'pillars': '',
                              'environment': '', 'gaps': '',
                              'roadmap': '', 'kpis': '',
                              'confidence': ''},
            domain_code='cyber')
        joined = ' || '.join(
            f'{lbl}|{body}' for lbl, body in appendices)
        self.assertIn('Mobile Device Management', joined)


# ── Traceability fixtures ──────────────────────────────────────────
# AI body where each PDPL capability has distinct initiative / KPI /
# risk text in roadmap / KPIs / confidence respectively. This is the
# realistic shape the fix protects: every column has its own phrase.
_NDMO_GAPS = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | ضعف حوكمة البيانات | NDMO |\n'
    '| 2 | ضعف جودة البيانات | NDMO |\n'
    '| 3 | غياب كتالوج البيانات والبيانات الوصفية | NDMO |\n'
    '| 4 | غياب أمناء البيانات | NDMO |\n'
    '| 5 | غياب دورة حياة البيانات | NDMO |\n'
    '| 6 | تأخر الإبلاغ عن الانتهاكات وعدم الامتثال '
    'لـ PDPL | PDPL |\n'
)

_PILLARS_FULL = (
    '## 2. الركائز\n\n'
    '| # | المبادرة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات | DMO |\n'
    '| 2 | إعداد خطة الإبلاغ عن الانتهاكات (إخطار الخروقات) '
    '| breach |\n'
)

_ROADMAP_PDPL_DISTINCT = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات | CDO | Q1 | ميثاق |\n'
    '| 2 | إعداد خطة الإبلاغ عن الانتهاكات | CISO | Q2 '
    '| إجراء الإخطار |\n'
    '| 3 | تأسيس حوكمة الخصوصية وحماية البيانات الشخصية | CDO '
    '| Q3 | سياسة |\n'
    '| 4 | تفعيل إدارة الموافقات | CDO | Q3 | سجل الموافقات |\n'
    '| 5 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
    'حق الحذف | CDO | Q4 | آلية الحقوق |\n'
    '| 6 | تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة التصنيف |\n'
)

_KPIS_DISTINCT = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | المؤشر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | نسبة تغطية حوكمة البيانات | governance |\n'
    '| 2 | زمن إخطار الخروقات / نسبة الإبلاغ في الوقت المحدد '
    '| breach |\n'
    '| 3 | نسبة الالتزام بحوكمة الخصوصية | privacy |\n'
    '| 4 | نسبة إدارة الموافقات المنفذة | consent |\n'
    '| 5 | نسبة الاستجابة لحقوق صاحب البيانات | DSR |\n'
    '| 6 | نسبة تصنيف البيانات الشخصية | classification |\n'
)

_CONFIDENCE_DISTINCT = (
    '## 7. سجل المخاطر\n\n'
    '| # | الخطر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | مخاطر حوكمة البيانات | governance |\n'
    '| 2 | تأخر الإبلاغ عن الانتهاكات وعدم الامتثال لـ PDPL '
    '| breach |\n'
    '| 3 | مخاطر حوكمة الخصوصية | privacy |\n'
    '| 4 | مخاطر إدارة الموافقات | consent |\n'
    '| 5 | مخاطر حقوق صاحب البيانات | DSR |\n'
    '| 6 | مخاطر تصنيف البيانات الشخصية | classification |\n'
)

_SECTIONS_DISTINCT = {
    'vision': '',
    'pillars': _PILLARS_FULL,
    'environment': '',
    'gaps': _NDMO_GAPS,
    'roadmap': _ROADMAP_PDPL_DISTINCT,
    'kpis': _KPIS_DISTINCT,
    'confidence': _CONFIDENCE_DISTINCT,
}


class TestPdplTraceabilityNoDuplicateCells(unittest.TestCase):
    """Tests 5-9 — initiative / KPI / risk cell distinctness."""

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS_DISTINCT, ['NDMO', 'PDPL'], 'ar',
            domain_code='data')

    @_skip_if_no_app
    def test_05_initiative_kpi_risk_are_pairwise_distinct(self):
        out = self._build()
        for r in out['rows']:
            if len(r) < 6:
                continue
            _fw, _cap, _gap, init, kpi, risk = r
            init_s = (init or '').strip()
            kpi_s = (kpi or '').strip()
            risk_s = (risk or '').strip()
            dash_tokens = {'—', '-', '--', '–', ''}
            if init_s not in dash_tokens and kpi_s not in dash_tokens:
                self.assertNotEqual(
                    init_s, kpi_s,
                    f'initiative and KPI duplicated in row {r!r}')
            if init_s not in dash_tokens and risk_s not in dash_tokens:
                self.assertNotEqual(
                    init_s, risk_s,
                    f'initiative and Risk duplicated in row {r!r}')
            if kpi_s not in dash_tokens and risk_s not in dash_tokens:
                self.assertNotEqual(
                    kpi_s, risk_s,
                    f'KPI and Risk duplicated in row {r!r}')

    @_skip_if_no_app
    def test_06_breach_notification_row_uses_distinct_phrases(self):
        """Mirrors the exact example from the problem statement."""
        out = self._build()
        breach_rows = [
            r for r in out['rows']
            if 'الإبلاغ' in str(r[1]) or 'الانتهاكات' in str(r[1])
            or 'breach' in str(r[1]).lower()
        ]
        self.assertGreaterEqual(
            len(breach_rows), 1,
            f'expected at least one breach notification row, '
            f'got rows={out["rows"]!r}')
        for r in breach_rows:
            init, kpi, risk = r[3], r[4], r[5]
            # Each must reflect its own source section.
            self.assertIn('إعداد خطة الإبلاغ', init,
                          f'initiative cell wrong: {init!r}')
            self.assertIn('إخطار الخروقات', kpi,
                          f'KPI cell wrong: {kpi!r}')
            self.assertIn('تأخر الإبلاغ', risk,
                          f'risk cell wrong: {risk!r}')
            self.assertNotEqual(init.strip(), kpi.strip())
            self.assertNotEqual(init.strip(), risk.strip())
            self.assertNotEqual(kpi.strip(), risk.strip())

    @_skip_if_no_app
    def test_07_ndmo_pdpl_coverage_remains_intact(self):
        """Both NDMO and PDPL still render rows — the dedupe fix
        must not erase legitimate coverage.
        """
        out = self._build()
        frameworks = {str(r[0]) for r in out['rows']}
        joined_fw = ' || '.join(frameworks)
        self.assertTrue(
            any('NDMO' in f or 'Data Management Framework' in f
                for f in frameworks),
            f'NDMO coverage missing: {joined_fw!r}')
        self.assertTrue(
            any('PDPL' in f or 'Personal Data Protection' in f
                for f in frameworks),
            f'PDPL coverage missing: {joined_fw!r}')

    @_skip_if_no_app
    def test_08_pdpl_capabilities_all_rendered(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('حوكمة الخصوصية', caps)
        self.assertIn('إدارة الموافقات', caps)
        self.assertIn('حقوق صاحب البيانات', caps)
        self.assertIn('تصنيف البيانات', caps)
        self.assertIn('الإبلاغ', caps)

    @_skip_if_no_app
    def test_09_no_dash_cells_for_data_scope(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in out['rows']:
            for cell in r:
                self.assertNotIn(
                    (cell or '').strip(), dash_tokens,
                    f'row contains dash placeholder: {r!r}')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
