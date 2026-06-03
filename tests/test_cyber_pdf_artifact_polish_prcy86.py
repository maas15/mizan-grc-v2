"""PR-CY86 — user-visible artifact polish + Arabic PDF dense-table hardening."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_pdf_artifact_polish_prcy86_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


def _base_model():
    from tests.test_cyber_export_parity_prcy50 import _model as _m50
    m = _m50()
    m['_prcy86'] = True
    return m


_ROADMAP_TRACE_ROW = (
    '| 1 | الأجهزة | معدات أمنية | حسب الحاجة | '
    '1.2 مليون ريال <!-- trace:section=roadmap;src=bank_fallback;key=row_1 --> |'
)

_KPI_MAIN = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساس |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
    '| 1 | MTTD | ≤ 60 د | f | SIEM | شهري |\n'
    '| — | امتثال DCC / DLP | ≥ 90% | f | DCC | ربع |\n'
)

_KPI_FORMULA = (
    '| # | صيغة | مصدر |\n'
    '|---|---|---|\n'
    '| — | f | DCC |\n'
)

_VISION_EDR = (
    '## 1. الرؤية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | 100% من الأجهزة محمية بحلول EDR | | حوكمة | 6 أشهر |\n'
)


class Prcy86UserVisiblePolishTests(unittest.TestCase):

    @_skip
    def test_prcy86_flag_live(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy86'))

    @_skip
    def test_trace_roadmap_residue_removed_from_text(self):
        cleaned = _APP._prcy86_strip_user_visible_trace(_ROADMAP_TRACE_ROW)
        self.assertNotIn('trace:section=roadmap', cleaned)
        self.assertNotIn('bank_fallback', cleaned)
        self.assertIn('الأجهزة', cleaned)

    @_skip
    def test_html_trace_comment_removed(self):
        s = '| out | cell <!-- trace:section=roadmap;src=x --> |'
        cleaned = _APP._prcy86_strip_user_visible_trace(s)
        self.assertNotIn('<!--', cleaned)
        self.assertNotIn('trace:', cleaned)

    @_skip
    def test_trace_strip_preserves_table_newlines(self):
        table = (
            '### الأهداف الاستراتيجية\n\n'
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
            ' المبرر | الإطار الزمني |\n'
            '|---|---|---|---|---|\n'
            '| 1 | هدف استراتيجي | 100% | سبب | 6 أشهر |\n'
        )
        cleaned = _APP._prcy86_strip_user_visible_trace(table)
        self.assertIn('\n| 1 |', cleaned)
        valid, _ = _APP._prcy67_count_valid_so_rows(cleaned)
        self.assertGreaterEqual(valid, 1)

    @_skip
    def test_kpi_dash_resequenced_in_section(self):
        text, n = _APP._prcy86_repair_kpi_pipe_rows(_KPI_MAIN)
        self.assertGreaterEqual(n, 1)
        self.assertIn('| 2 |', text)
        self.assertIn('DLP', text)
        self.assertNotIn('| — | امتثال DCC', text)

    @_skip
    def test_kpi_formula_resequenced_with_main(self):
        combined = _KPI_MAIN + '\n' + _KPI_FORMULA.replace(
            '| # | صيغة |', '| # | وصف المؤشر |')
        fixed, n = _APP._prcy86_repair_kpi_pipe_rows(combined)
        self.assertIn('| 2 |', fixed)
        self.assertGreaterEqual(n, 2)

    @_skip
    def test_edr_objective_display_normalized(self):
        text, repairs = _APP._prcy86_repair_vision_so_display(_VISION_EDR)
        self.assertGreaterEqual(repairs, 1)
        self.assertIn('تعزيز حماية نقاط النهاية', text)
        self.assertIn('100% من الأجهزة محمية', text)

    @_skip
    def test_arabic_spacing_residues_cleaned(self):
        raw = 'المسؤولأمن والتنظيميمع يحدمن المواءمةمع'
        out = _APP._prcy86_apply_ar_spacing_and_truncation(raw)
        self.assertNotIn('المسؤولأمن', out)
        self.assertIn('المسؤول أمن', out)

    @_skip
    def test_user_visible_polish_diag_emitted(self):
        secs = {'roadmap': '## 5.\n\n' + _ROADMAP_TRACE_ROW + '\n'}
        buf = io.StringIO()
        with redirect_stdout(buf):
            _, md, diag = _APP._prcy86_apply_user_visible_artifact_polish(
                secs, '\n'.join(secs.values()), 'ar',
                route_name='generation', output_type='generation')
        self.assertIn('[USER-VISIBLE-ARTIFACT-POLISH]', buf.getvalue())
        self.assertGreater(diag.get('trace_residue_count_before', 0), 0)
        self.assertEqual(diag.get('trace_residue_count_after', 0), 0)
        self.assertNotIn('trace:section', md)


class Prcy86PdfDenseTableTests(unittest.TestCase):

    @_skip
    def test_dense_kpi_uses_cards_with_prcy86(self):
        model = _base_model()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'x' * 120, 'KPI', '≥ 95%', 'شهري', 'CISO', '12 شهر']],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('kpi_main'), 'kpi_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_dense_roadmap_uses_roadmap_cards_with_prcy86(self):
        model = _base_model()
        tbl = {
            'schema': 'roadmap',
            'header': list(_PSR.SCHEMA_ROADMAP_AR),
            'rows': [[
                'المرحلة 1', '1-6 أشهر', 'x' * 120, 'CISO', 'out', 'NCA ECC',
            ]],
        }
        model['blocks']['roadmap']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('roadmap'), 'roadmap_cards')
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_vertical_stack_count_list_consistent(self):
        model = _base_model()
        tbl = {
            'schema': 'governance',
            'header': list(_PSR.SCHEMA_GOVERNANCE_AR),
            'rows': [['CISO', 'x' * 80, 'y' * 80, 'z' * 80, 'ECC']],
        }
        model['blocks']['governance_ownership']['rows'] = tbl['rows']
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertTrue(ev.get('count_list_consistent'))
        self.assertEqual(
            ev.get('table_vertical_stack_warning_count'),
            len(ev.get('table_vertical_stack_warnings') or []))

    @_skip
    def test_docmodel_stack_gate_passes_after_fallbacks(self):
        model = _base_model()
        model['blocks']['kpi_kri_framework']['tables'] = [{
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'KPI long ' + 'x' * 100, 'KPI', '≥ 90%', 'm', 'o', '12']],
        }]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        checks = _PSR.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks['pdf_table_vertical_stack_warnings'])
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)
        self.assertEqual(ev.get('table_vertical_stack_warning_count'), 0)

    @_skip
    def test_no_generic_stack_blocker_when_resolved(self):
        model = _base_model()
        tbl = {
            'schema': 'strategic_objectives',
            'header': list(_PSR.SCHEMA_STRATEGIC_OBJECTIVES_AR),
            'rows': [['1', 'x' * 200, 't', 'r', '24 شهر']],
        }
        model['blocks']['vision_objectives']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)
        checks = _PSR.prcy47_docmodel_professional_checks(model, 'ar')
        self.assertTrue(checks.get('pdf_table_vertical_stack_warnings'))


class Prcy86ArtifactIntegrationTests(unittest.TestCase):

    @_skip
    def test_sealed_artifact_polish_removes_roadmap_trace(self):
        from tests.test_cyber_release_acceptance_prcy85 import (
            _sections as _s85,
            _content as _c85,
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            art = _APP._build_cyber_final_strategy_artifact(
                _c85(_s85()),
                sections=_s85(),
                metadata={'domain': 'cyber'},
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar',
                domain='cyber',
                output_type='generation',
            )
        self.assertTrue(art.get('sealed'), art.get('blocking_errors'))
        rm = art.get('sections', {}).get('roadmap', '')
        self.assertNotIn('trace:section=roadmap', rm)
        log = buf.getvalue()
        self.assertIn('[USER-VISIBLE-ARTIFACT-POLISH]', log)


if __name__ == '__main__':
    unittest.main()
