"""PR-5B.9AB — Data PDPL traceability rendering.

When the Data Management strategy selects NDMO + PDPL and the AI-
generated body already contains PDPL content (typically in roadmap /
KPIs / confidence) the traceability matrix must render meaningful
PDPL rows for the five PDPL capabilities:

    * privacy governance
    * consent management
    * data subject rights
    * personal data classification
    * breach notification

No rendered row may contain the "—" placeholder. Rows that cannot be
completed even after fallback section lookups are dropped and
``[TRACEABILITY-DIAG] skipped_incomplete_row`` is logged.

This module exercises ``_build_traceability_matrix`` directly so it
does not require an AI provider.

Run::

    python -m pytest \\
        tests/test_data_pdpl_traceability_rendering_pr5b9ab.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ab_trace_')
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


# ── Fixtures ────────────────────────────────────────────────────────
# Sections shaped like the real symptom from the problem statement:
# PDPL content lives in roadmap / KPIs / confidence; the gaps section
# only mentions NDMO families by name. The fallback lookup must still
# render PDPL rows from the other sections.

_NDMO_GAPS = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | ضعف حوكمة البيانات | NDMO |\n'
    '| 2 | ضعف جودة البيانات | NDMO |\n'
    '| 3 | غياب كتالوج البيانات والبيانات الوصفية | NDMO |\n'
    '| 4 | غياب أمناء البيانات | NDMO |\n'
    '| 5 | غياب دورة حياة البيانات | NDMO |\n'
)

_PILLARS_NDMO_ONLY = (
    '## 2. الركائز\n\n'
    '| # | المبادرة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات | DMO |\n'
    '| 2 | بناء كتالوج البيانات والبيانات الوصفية | metadata |\n'
    '| 3 | تفعيل أمناء البيانات | stewardship |\n'
)

# Roadmap is the canonical source of PDPL initiatives + DSR + breach
# (mirrors the PR-5B.9AA fixture style).
_ROADMAP_FULL_PDPL = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق مكتب البيانات |\n'
    '| 2 | تشكيل لجنة حوكمة البيانات | CDO | Q1 | ميثاق اللجنة |\n'
    '| 3 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 4 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 | كتالوج |\n'
    '| 5 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 | سياسة |\n'
    '| 6 | تأسيس حوكمة الخصوصية وحماية البيانات الشخصية '
    '| CDO | Q3 | سياسة |\n'
    '| 7 | تفعيل إدارة الموافقات | CDO | Q3 | سجل الموافقات |\n'
    '| 8 | تصنيف البيانات الشخصية | CDO | Q4 | مصفوفة التصنيف |\n'
    '| 9 | تفعيل حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
    'حق الحذف | CDO | Q4 | آلية الحقوق |\n'
    '| 10 | تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات | '
    'CISO | Q4 | إجراء الإخطار |\n'
)

_KPIS_FULL = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | المؤشر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | نسبة تغطية حوكمة البيانات | governance |\n'
    '| 2 | نسبة جودة البيانات | quality |\n'
    '| 3 | نسبة فهرسة البيانات الوصفية في كتالوج البيانات | metadata |\n'
    '| 4 | نسبة تغطية أمناء البيانات | stewardship |\n'
    '| 5 | نسبة الالتزام بدورة حياة البيانات | lifecycle |\n'
    '| 6 | نسبة الالتزام بحوكمة الخصوصية | privacy |\n'
    '| 7 | نسبة إدارة الموافقات المنفذة | consent |\n'
    '| 8 | نسبة الاستجابة لحقوق صاحب البيانات | DSR |\n'
    '| 9 | نسبة تصنيف البيانات الشخصية | classification |\n'
    '| 10 | متوسط زمن الإبلاغ عن الانتهاكات | breach |\n'
)

_CONFIDENCE_FULL = (
    '## 7. سجل المخاطر\n\n'
    '| # | الخطر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | مخاطر حوكمة البيانات | governance |\n'
    '| 2 | مخاطر جودة البيانات | quality |\n'
    '| 3 | مخاطر كتالوج البيانات | metadata |\n'
    '| 4 | مخاطر أمناء البيانات | stewardship |\n'
    '| 5 | مخاطر دورة حياة البيانات | lifecycle |\n'
    '| 6 | مخاطر حوكمة الخصوصية | privacy |\n'
    '| 7 | مخاطر إدارة الموافقات | consent |\n'
    '| 8 | مخاطر حقوق صاحب البيانات | DSR |\n'
    '| 9 | مخاطر تصنيف البيانات الشخصية | classification |\n'
    '| 10 | مخاطر الإبلاغ عن الانتهاكات | breach |\n'
)

_SECTIONS = {
    'vision': '',
    'pillars': _PILLARS_NDMO_ONLY,
    'environment': '',
    'gaps': _NDMO_GAPS,
    'roadmap': _ROADMAP_FULL_PDPL,
    'kpis': _KPIS_FULL,
    'confidence': _CONFIDENCE_FULL,
}


class TestPdplTraceabilityRendering(unittest.TestCase):
    """Tests 1-7 — PDPL traceability renders all 5 capabilities with
    no dash placeholders when PDPL content exists in any section."""

    @_skip_if_no_app
    def _build(self):
        return _APP._build_traceability_matrix(
            _SECTIONS, ['NDMO', 'PDPL'], 'ar', domain_code='data')

    @_skip_if_no_app
    def test_01_pdpl_rows_at_least_one(self):
        out = self._build()
        pdpl_rows = [r for r in out['rows']
                     if 'PDPL' in str(r[0]) or 'Personal Data' in str(r[0])
                     or 'حماية البيانات' in str(r[0])]
        self.assertGreaterEqual(
            len(pdpl_rows), 1,
            f'expected ≥1 PDPL row, got 0: rows={out["rows"]}')

    @_skip_if_no_app
    def test_02_includes_privacy_governance(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('حوكمة الخصوصية', caps)

    @_skip_if_no_app
    def test_03_includes_consent_management(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('إدارة الموافقات', caps)

    @_skip_if_no_app
    def test_04_includes_data_subject_rights(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('حقوق صاحب البيانات', caps)

    @_skip_if_no_app
    def test_05_includes_personal_data_classification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('تصنيف البيانات', caps)

    @_skip_if_no_app
    def test_06_includes_breach_notification(self):
        out = self._build()
        caps = ' | '.join(str(r[1]) for r in out['rows'])
        self.assertIn('الإبلاغ عن الانتهاكات', caps)

    @_skip_if_no_app
    def test_07_no_dash_rows_for_data_scope(self):
        out = self._build()
        dash_tokens = ('—', '-', '--', '–')
        for r in out['rows']:
            for cell in r:
                s = (cell or '').strip()
                self.assertNotIn(
                    s, dash_tokens,
                    f'row contains dash placeholder: {r}')

    @_skip_if_no_app
    def test_08_pdpl_classification_alias_dedup(self):
        """PDPL registers two alias families with identical labels
        (``data_classification_pdpl`` and
        ``personal_data_classification``). For data scope the matrix
        must render the classification capability only ONCE so the
        traceability doesn't duplicate rows."""
        out = self._build()
        pdpl_classification_rows = [
            r for r in out['rows']
            if 'تصنيف البيانات' in str(r[1])
        ]
        self.assertEqual(
            len(pdpl_classification_rows), 1,
            f'expected exactly 1 PDPL classification row, got '
            f'{len(pdpl_classification_rows)}: '
            f'{pdpl_classification_rows}')

    @_skip_if_no_app
    def test_09_skipped_row_logs_diag(self):
        """When PDPL is selected but a capability cannot be derived
        from any section, the row is dropped AND the
        ``[TRACEABILITY-DIAG] skipped_incomplete_row`` line is
        emitted."""
        partial = {
            'vision': '', 'pillars': '', 'environment': '',
            'gaps': '## 4\n| # | الفجوة |\n|---|------|\n'
                    '| 1 | ضعف حوكمة البيانات |\n',
            'roadmap': '', 'kpis': '', 'confidence': '',
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            _APP._build_traceability_matrix(
                partial, ['PDPL'], 'ar', domain_code='data')
        log = buf.getvalue()
        self.assertIn('[TRACEABILITY-DIAG] skipped_incomplete_row', log)
        self.assertIn('framework=', log)
        self.assertIn('capability=', log)

    @_skip_if_no_app
    def test_10_cross_domain_unchanged_cyber_keeps_dash_rows(self):
        """Regression: non-Data domains (cyber/ai/dt/erm) still keep
        dash rows in ``rows`` — this PR only changes Data behaviour."""
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['ECC'], 'en', domain_code='cyber')
        self.assertGreaterEqual(len(out['rows']), 1)
        # Cyber must still emit dash placeholders so cross-domain
        # rendering is unchanged.
        self.assertGreaterEqual(
            len([r for r in out['rows']
                 if any((c or '').strip() == '—' for c in r)]),
            1)

    @_skip_if_no_app
    def test_11_no_deterministic_strategy_rows_inserted(self):
        """Empty sections produce ZERO Data rows — content is never
        invented."""
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertEqual(out['rows'], [])


if __name__ == '__main__':
    unittest.main()
