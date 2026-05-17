"""PR-5B.9S — Data Management traceability depth.

Scope is **Data Management only** — Cyber / AI / DT / ERM behaviour
must be preserved byte-for-byte. Validates:

  * Part A — NDMO traceability rows render across ≥3 capability
    families (governance / data quality / data catalog & metadata /
    stewardship / data lifecycle) when those families are named in
    the AI-generated content.
  * Part B — PDPL traceability rows render across privacy governance /
    consent management / data subject rights / personal-data
    classification / breach notification when present.
  * Part C — No traceability row contains the dash placeholder
    ("—") for the Data domain (or whenever NDMO/PDPL is selected).
    Dashy rows are dropped and a ``[TRACEABILITY-DIAG]`` line is
    logged. No deterministic content is injected.
  * Part D — Cyber / AI / DT / ERM traceability rendering is
    unchanged: dashy rows for those domains are still preserved in
    ``rows`` so cross-domain renderers don't change their output.

Run:
    python -m pytest \
        tests/test_data_traceability_depth_pr5b9s.py -q
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_trace_pr5b9s_')
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


# ── Fixtures: rich Data Management sections that name 5 NDMO families
# and 5 PDPL families. The traceability builder reads from these
# sections only — nothing is invented by the helper.

_DATA_GAPS = (
    '## 4. تحليل الفجوات\n\n'
    '| # | الفجوة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | ضعف حوكمة البيانات | غياب مكتب إدارة البيانات |\n'
    '| 2 | ضعف جودة البيانات | لا توجد مقاييس |\n'
    '| 3 | غياب كتالوج البيانات والبيانات الوصفية | لا توجد ميتاداتا |\n'
    '| 4 | غياب أمناء البيانات وملكية البيانات | لا ownership |\n'
    '| 5 | غياب دورة حياة البيانات وتصنيف البيانات | لا retention |\n'
    '| 6 | ضعف حوكمة الخصوصية وحماية البيانات الشخصية | privacy gap |\n'
    '| 7 | غياب إدارة الموافقات | consent missing |\n'
    '| 8 | غياب حقوق صاحب البيانات | DSR missing |\n'
    '| 9 | غياب تصنيف البيانات الشخصية | classification |\n'
    '| 10 | غياب الإبلاغ عن الانتهاكات | breach reporting |\n'
)

_DATA_PILLARS = (
    '## 2. الركائز الاستراتيجية\n\n'
    '### الركيزة 1: حوكمة البيانات ومكتب إدارة البيانات\n\n'
    '| # | المبادرة | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات | إنشاء DMO |\n'
    '| 2 | تفعيل إدارة جودة البيانات | data quality program |\n'
    '| 3 | بناء كتالوج البيانات والبيانات الوصفية | metadata |\n'
    '| 4 | تفعيل أمناء البيانات وملكية البيانات | stewardship |\n'
    '| 5 | إدارة دورة حياة البيانات والاحتفاظ | lifecycle |\n'
    '| 6 | تأسيس حوكمة الخصوصية | privacy governance |\n'
    '| 7 | تفعيل إدارة الموافقات | consent management |\n'
    '| 8 | تفعيل حقوق صاحب البيانات | DSR program |\n'
    '| 9 | تصنيف البيانات الشخصية | personal data classification |\n'
    '| 10 | إجراءات الإبلاغ عن الانتهاكات | breach notification |\n'
)

_DATA_ROADMAP = _DATA_PILLARS.replace('الركائز الاستراتيجية', 'خارطة الطريق')

_DATA_KPIS = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | المؤشر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | نسبة تغطية حوكمة البيانات | governance KPI |\n'
    '| 2 | نسبة جودة البيانات | data quality KPI |\n'
    '| 3 | نسبة فهرسة البيانات الوصفية في كتالوج البيانات | metadata |\n'
    '| 4 | نسبة تغطية أمناء البيانات | stewardship KPI |\n'
    '| 5 | نسبة الالتزام بدورة حياة البيانات | lifecycle KPI |\n'
    '| 6 | نسبة الالتزام بحوكمة الخصوصية | privacy KPI |\n'
    '| 7 | نسبة إدارة الموافقات المنفذة | consent KPI |\n'
    '| 8 | نسبة الاستجابة لحقوق صاحب البيانات | DSR KPI |\n'
    '| 9 | نسبة تصنيف البيانات الشخصية | classification KPI |\n'
    '| 10 | متوسط زمن الإبلاغ عن الانتهاكات | breach KPI |\n'
)

_DATA_CONFIDENCE = (
    '## 7. سجل المخاطر\n\n'
    '| # | الخطر | الوصف |\n'
    '|---|------|------|\n'
    '| 1 | مخاطر حوكمة البيانات | governance risk |\n'
    '| 2 | مخاطر جودة البيانات | data quality risk |\n'
    '| 3 | مخاطر كتالوج البيانات والبيانات الوصفية | metadata risk |\n'
    '| 4 | مخاطر أمناء البيانات | stewardship risk |\n'
    '| 5 | مخاطر دورة حياة البيانات | lifecycle risk |\n'
    '| 6 | مخاطر حوكمة الخصوصية | privacy risk |\n'
    '| 7 | مخاطر إدارة الموافقات | consent risk |\n'
    '| 8 | مخاطر حقوق صاحب البيانات | DSR risk |\n'
    '| 9 | مخاطر تصنيف البيانات الشخصية | classification risk |\n'
    '| 10 | مخاطر الإبلاغ عن الانتهاكات | breach risk |\n'
)

_DATA_SECTIONS = {
    'vision': '',
    'pillars': _DATA_PILLARS,
    'environment': '',
    'gaps': _DATA_GAPS,
    'roadmap': _DATA_ROADMAP,
    'kpis': _DATA_KPIS,
    'confidence': _DATA_CONFIDENCE,
}


class TestDataTraceabilityDepth(unittest.TestCase):
    @_skip_if_no_app
    def test_ndmo_traceability_covers_5_capability_families(self):
        """NDMO traceability matrix must map to ≥5 informative rows
        covering governance, quality, catalog/metadata, stewardship
        and lifecycle when those families are named in the AI body.
        """
        out = _APP._build_traceability_matrix(
            _DATA_SECTIONS, ['NDMO'], 'ar', domain_code='data')
        rows = out['rows']
        # All NDMO rows are informative for this rich fixture.
        self.assertGreaterEqual(
            len(rows), 5,
            f'expected ≥5 NDMO informative rows, got {len(rows)}: {rows}')
        # Capability labels (col idx 1) must include all 5 families.
        cap_labels = ' | '.join(str(r[1]) for r in rows)
        for token in (
            'حوكمة البيانات', 'جودة البيانات', 'كتالوج البيانات',
            'أمناء البيانات', 'دورة حياة البيانات',
        ):
            self.assertIn(token, cap_labels,
                          f'NDMO capability "{token}" missing from rows')

    @_skip_if_no_app
    def test_pdpl_traceability_covers_privacy_consent_dsr_classification_breach(self):
        out = _APP._build_traceability_matrix(
            _DATA_SECTIONS, ['PDPL'], 'ar', domain_code='data')
        rows = out['rows']
        self.assertGreaterEqual(
            len(rows), 5,
            f'expected ≥5 PDPL informative rows, got {len(rows)}: {rows}')
        cap_labels = ' | '.join(str(r[1]) for r in rows)
        for token in (
            'حوكمة الخصوصية', 'إدارة الموافقات', 'حقوق صاحب البيانات',
            'تصنيف البيانات', 'الإبلاغ عن الانتهاكات',
        ):
            self.assertIn(token, cap_labels,
                          f'PDPL capability "{token}" missing from rows')

    @_skip_if_no_app
    def test_no_dash_rows_in_data_traceability_when_data_scope(self):
        """For the Data domain (or NDMO/PDPL selection), no rendered
        row may contain "—" placeholders. Incomplete rows are dropped
        and the omission logged via [TRACEABILITY-DIAG] — never
        injected."""
        # Sections that name NDMO/PDPL only partially — gaps mentions
        # only governance + quality; the rest are intentionally
        # absent. The trace builder must drop the dashy rows.
        partial_sections = {
            'vision': '',
            'pillars': (
                '## 2\n\n### الركيزة 1: حوكمة البيانات\n\n'
                '| # | المبادرة |\n|---|------|\n'
                '| 1 | حوكمة البيانات |\n'
            ),
            'environment': '',
            'gaps': (
                '## 4\n\n| # | الفجوة |\n|---|------|\n'
                '| 1 | ضعف حوكمة البيانات |\n'
                '| 2 | ضعف جودة البيانات |\n'
            ),
            'roadmap': '',
            'kpis': (
                '## 6\n\n| # | المؤشر |\n|---|------|\n'
                '| 1 | نسبة حوكمة البيانات |\n'
                '| 2 | نسبة جودة البيانات |\n'
            ),
            'confidence': '',
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = _APP._build_traceability_matrix(
                partial_sections, ['NDMO', 'PDPL'], 'ar',
                domain_code='data')
        rows = out['rows']
        # No cell may contain a dash placeholder.
        dash_tokens = ('—', '-', '--', '–')
        for r in rows:
            for cell in r:
                s = (cell or '').strip()
                self.assertFalse(
                    s in dash_tokens,
                    f'row contains dash placeholder: {r}')
        # And the diagnostic log line was emitted for at least one
        # dropped row (PDPL families + NDMO catalog/stewardship/
        # lifecycle were not present in the partial sections).
        self.assertIn('[TRACEABILITY-DIAG] dropped_incomplete_row',
                      buf.getvalue(),
                      'expected [TRACEABILITY-DIAG] diagnostic for '
                      'dropped incomplete rows')

    @_skip_if_no_app
    def test_helper_does_not_inject_deterministic_rows(self):
        """When the sections are EMPTY the helper must produce ZERO
        rows for the Data domain — never invent content."""
        empty = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        out = _APP._build_traceability_matrix(
            empty, ['NDMO', 'PDPL'], 'ar', domain_code='data')
        self.assertEqual(
            out['rows'], [],
            f'expected empty rows, got: {out["rows"]}')


class TestCrossDomainTraceabilityUnchanged(unittest.TestCase):
    """Regression: Cyber/AI/DT/ERM traceability still preserves dash
    rows in ``rows`` (only the Data/NDMO/PDPL scope drops them)."""

    @_skip_if_no_app
    def _build(self, fws, domain):
        # Sections that exercise the FW-family-no-match branch so the
        # helper produces rows full of dashes.
        sections = {k: '' for k in (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence')}
        return _APP._build_traceability_matrix(
            sections, fws, 'en', domain_code=domain)

    @_skip_if_no_app
    def test_cyber_ecc_dash_rows_preserved(self):
        out = self._build(['ECC'], 'cyber')
        # All Cyber framework families produce dash rows when sections
        # are empty — the historical behaviour must be preserved.
        self.assertGreaterEqual(len(out['rows']), 1)
        self.assertGreaterEqual(
            len([r for r in out['rows']
                 if any((c or '').strip() == '—' for c in r)]),
            1, 'Cyber dashy rows must remain in rows[]')

    @_skip_if_no_app
    def test_ai_sdaia_dash_rows_preserved(self):
        out = self._build(['SDAIA'], 'ai')
        # SDAIA in the AI domain must keep historical dashy-row
        # rendering.
        self.assertTrue(any(
            any((c or '').strip() == '—' for c in r) for r in out['rows']),
            'AI/SDAIA dashy rows must remain in rows[]')

    @_skip_if_no_app
    def test_dt_dga_dash_rows_preserved(self):
        out = self._build(['DGA'], 'dt')
        self.assertTrue(any(
            any((c or '').strip() == '—' for c in r) for r in out['rows']),
            'DT/DGA dashy rows must remain in rows[]')

    @_skip_if_no_app
    def test_erm_iso31000_dash_rows_preserved(self):
        out = self._build(['ISO31000'], 'erm')
        # ISO31000 may not be in the registry — guard accordingly.
        if not out['rows']:
            self.skipTest('ISO31000 not in registry — fallback path')
        self.assertTrue(any(
            any((c or '').strip() == '—' for c in r) for r in out['rows']),
            'ERM dashy rows must remain in rows[]')


if __name__ == '__main__':
    unittest.main()
