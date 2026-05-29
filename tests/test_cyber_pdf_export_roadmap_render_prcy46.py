"""PR-CY46 — PDF export error sanitization + roadmap rendering fix.

Two production defects (Render main 8d45ebb):

  * Part A — ``/api/export-status`` surfaced a nested JSON body
    ``PDF generation failed (HTTP 500): {"error":...,"reason":...}`` because
    the async PDF worker copied the inner route's full error body verbatim.
  * Part B — the PDF quality gate reported
    ``roadmap_rendered=False`` / ``roadmap_table_not_rendered`` even though a
    valid roadmap section existed. Root cause (category 3): the professional
    renderer's ``normalize_roadmap_table`` header detection did not recognize
    the canonical Arabic roadmap columns (النشاط / المخرج / الإطار الزمني),
    so it silently dropped the roadmap table and produced zero roadmap rows.

This suite covers the export-error sanitizer, the build-failure classifier,
the roadmap header-detection fix, and the renderer/gate end-to-end.

Run:
    python -m pytest tests/test_cyber_pdf_export_roadmap_render_prcy46.py -v
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_pdf_roadmap_prcy46_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP = None
_APP_SOURCE = ''
_P41 = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
    import professional_strategy_render as _P41
except Exception as _e:  # noqa: BLE001
    raise SystemExit(f'Cannot load modules: {_e!r}')


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# Canonical Arabic roadmap section with the production header shape
# (# | النشاط | المسؤول | الإطار الزمني | المخرج) that previously failed.
_ROADMAP_SECTION = (
    '## 5. خارطة الطريق التنفيذية\n\n'
    '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | الإدارة العليا | '
    'الشهر 1-3 | إدارة قائمة |\n'
    '| 2 | تحديد الأدوار والمسؤوليات | CISO | الشهر 2-4 | RACI معتمد |\n'
    '| 3 | بناء SOC + SIEM | SOC Manager | الشهر 3-6 | مراقبة 24/7 |\n'
)

_DIAG_LEAK_KEYS = (
    'quality_gate', 'required_sections', 'required_sections_present',
    'arabic_spacing_issues_count', 'raw_markdown_residue_count',
)


# ── Part A — export error sanitizer ─────────────────────────────────────────
class SafeExportErrorTests(unittest.TestCase):

    @_skip_if_no_app
    def test_json_error_becomes_concise_code(self):
        body = ('{"error":"pdf_render_failed:roadmap_table_not_rendered",'
                '"reason":"pdf_render_failed"}')
        self.assertEqual(
            _APP._prcy46_safe_export_error(body, 500),
            'pdf_render_failed:roadmap_table_not_rendered')

    @_skip_if_no_app
    def test_quality_gate_dict_never_appears(self):
        import json
        body = json.dumps({
            'error': 'pdf_render_failed:roadmap_table_not_rendered',
            'reason': 'pdf_render_failed',
            'quality_gate': {
                'arabic_spacing_issues_count': 0,
                'raw_markdown_residue_count': 0,
                'required_sections_present': {'roadmap': True},
                'blockers': ['pdf_render_failed:roadmap_table_not_rendered'],
            },
        })
        out = _APP._prcy46_safe_export_error(body, 500)
        self.assertEqual(out,
                         'pdf_render_failed:roadmap_table_not_rendered')
        for k in _DIAG_LEAK_KEYS:
            self.assertNotIn(k, out)

    @_skip_if_no_app
    def test_reason_fallback_when_no_error_key(self):
        body = '{"reason":"pdf_render_failed"}'
        self.assertEqual(
            _APP._prcy46_safe_export_error(body, 500), 'pdf_render_failed')

    @_skip_if_no_app
    def test_non_json_500_becomes_generic_code(self):
        self.assertEqual(
            _APP._prcy46_safe_export_error('<html>500 Internal</html>', 500),
            'pdf_generation_failed:500')

    @_skip_if_no_app
    def test_embedded_dict_in_error_string_is_refused(self):
        body = '{"error":"boom {\\"k\\": 1}"}'
        out = _APP._prcy46_safe_export_error(body, 500)
        self.assertEqual(out, 'pdf_generation_failed:500')
        for ch in ('{', '}', '"'):
            self.assertNotIn(ch, out)

    @_skip_if_no_app
    def test_async_worker_uses_sanitizer(self):
        # The async PDF worker must route its stored error through the
        # sanitizer and must NOT embed the raw response body / nested JSON.
        self.assertIn('_prcy46_safe_export_error(', _APP_SOURCE)
        self.assertNotIn(
            'PDF generation failed (HTTP {_status_code}): {err_body',
            _APP_SOURCE)


# ── Part B — build-failure classifier ───────────────────────────────────────
class ClassifyPdfFailureTests(unittest.TestCase):

    @_skip_if_no_app
    def test_zero_bytes_is_build_failed(self):
        out = _APP._prcy46_classify_pdf_failure(
            pdf_byte_len=0,
            gate_payload={'blockers': [
                'pdf_render_failed:roadmap_table_not_rendered']},
            roadmap_rows_in_model=5)
        self.assertEqual(out, 'pdf_render_failed:build_failed:zero_pdf_bytes')

    @_skip_if_no_app
    def test_roadmap_rows_present_but_not_rendered_is_build_failed(self):
        out = _APP._prcy46_classify_pdf_failure(
            pdf_byte_len=50000,
            gate_payload={'blockers': [
                'pdf_render_failed:roadmap_table_not_rendered']},
            roadmap_rows_in_model=5)
        self.assertEqual(
            out, 'pdf_render_failed:build_failed:roadmap_rows_lost_in_render')

    @_skip_if_no_app
    def test_genuine_no_roadmap_keeps_original_code(self):
        out = _APP._prcy46_classify_pdf_failure(
            pdf_byte_len=50000,
            gate_payload={'blockers': [
                'pdf_render_failed:roadmap_table_not_rendered']},
            roadmap_rows_in_model=0)
        self.assertEqual(out,
                         'pdf_render_failed:roadmap_table_not_rendered')


# ── Part B — roadmap header detection (the root-cause fix) ───────────────────
class RoadmapNormalizationTests(unittest.TestCase):

    @_skip_if_no_app
    def test_activity_header_roadmap_is_recognized(self):
        tbl = _P41.normalize_roadmap_table(_ROADMAP_SECTION, 'ar')
        self.assertIsNotNone(
            tbl, 'roadmap table with النشاط/المخرج header must be recognized')
        self.assertGreaterEqual(len(tbl['rows']), 3)
        self.assertEqual(tbl['schema'], 'roadmap')

    @_skip_if_no_app
    def test_initiative_header_still_recognized(self):
        legacy = (
            '| # | المبادرة | الوصف | المخرج المتوقع | المسؤول |\n'
            '|---|---|---|---|---|\n'
            '| 1 | بناء SOC | تشغيل المراقبة | SOC عامل | SOC Manager |\n')
        tbl = _P41.normalize_roadmap_table(legacy, 'ar')
        self.assertIsNotNone(tbl)
        self.assertGreaterEqual(len(tbl['rows']), 1)


# ── Part D — renderer + gate end-to-end ──────────────────────────────────────
class RendererAndGateTests(unittest.TestCase):

    def _model(self):
        base = {
            'lang': 'ar',
            'selected_frameworks': ['NCA ECC'],
            'order': ['vision_objectives', 'roadmap', 'kpi_kri_framework'],
            'blocks': {
                'roadmap': {'title': 'خارطة الطريق التنفيذية'},
                'kpi_kri_framework': {'title': 'مؤشرات الأداء'},
            },
        }
        content_sections = {
            'roadmap': _ROADMAP_SECTION,
            'kpis': (
                '| # | المؤشر | القيمة المستهدفة | التكرار | المالك '
                '| الإطار الزمني |\n|---|---|---|---|---|---|\n'
                '| 1 | تغطية الترقيع | 95% | شهري | CISO | 12ش |\n'),
        }
        return _P41.enrich_professional_blocks(
            base, content_sections, {'horizon_months': '12'}, 'ar')

    @_skip_if_no_app
    def test_model_roadmap_block_has_rows(self):
        model = self._model()
        tables = (model['blocks'].get('roadmap') or {}).get('tables') or []
        self.assertTrue(tables, 'roadmap block must carry a table')
        self.assertGreaterEqual(len(tables[0].get('rows') or []), 3)

    @_skip_if_no_app
    def test_rendered_markdown_has_roadmap_heading_and_table(self):
        model = self._model()
        md = _P41.render_professional_model_as_markdown(model)
        self.assertIn('خارطة الطريق', md)
        # A roadmap table is serialized (timeline/detail uses roadmap schema).
        self.assertTrue(
            any(h in md for h in _P41.SCHEMA_ROADMAP_AR),
            'rendered markdown must contain a roadmap table header')

    @_skip_if_no_app
    def test_quality_gate_passes_when_roadmap_rows_rendered(self):
        tracker = _P41.PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 5
        tracker.kpi_tables_rendered = 2
        passed, payload = _P41.run_pdf_quality_gate(
            tracker, _ROADMAP_SECTION, lang='ar')
        self.assertTrue(passed, payload)
        self.assertTrue(payload['roadmap_rendered'])
        self.assertEqual(payload['blockers'], [])

    @_skip_if_no_app
    def test_quality_gate_blocks_when_roadmap_section_but_no_rows(self):
        tracker = _P41.PDFRenderTracker()
        tracker.sections_present['roadmap'] = True
        tracker.roadmap_rows_rendered = 0
        tracker.kpi_tables_rendered = 2
        passed, payload = _P41.run_pdf_quality_gate(
            tracker, _ROADMAP_SECTION, lang='ar')
        self.assertFalse(passed)
        self.assertIn('pdf_render_failed:roadmap_table_not_rendered',
                      payload['blockers'])


# ── Part D — production path / diagnostics (source-level) ────────────────────
class ProductionPathSourceTests(unittest.TestCase):

    @_skip_if_no_app
    def test_pdf_route_uses_professional_renderer(self):
        idx = _APP_SOURCE.find('def api_generate_pdf(')
        self.assertGreater(idx, 0)
        end = _APP_SOURCE.find('\n@app.route', idx + 1)
        body = _APP_SOURCE[idx:end if end > 0 else idx + 120000]
        self.assertIn('_build_professional_strategy_document_model(', body)
        self.assertIn('_prcy41_render_professional_body_sections(', body)
        self.assertIn('run_pdf_quality_gate(', body)

    @_skip_if_no_app
    def test_roadmap_render_diag_emitted(self):
        self.assertIn('[PDF-ROADMAP-RENDER-DIAG]', _APP_SOURCE)
        for field in ('roadmap_rows_detected_in_model',
                      'rendered_markdown_has_roadmap_table',
                      'story_roadmap_table_detected',
                      'quality_gate_roadmap_rendered'):
            self.assertIn(field, _APP_SOURCE)

    @_skip_if_no_app
    def test_debug_artifact_is_dev_only(self):
        self.assertIn('[PDF-QUALITY-GATE-DEBUG-ARTIFACT]', _APP_SOURCE)
        # Gated on debug / TESTING / explicit env flag — never plain prod.
        self.assertIn("os.environ.get('MIZAN_DEBUG_ARTIFACTS')", _APP_SOURCE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
