"""PR-CY70 — PDF vertical stack KPI cards + final semantic parity hardening."""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP = tempfile.mkdtemp(prefix='test_cyber_export_parity_prcy70_')
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
    return _m50()


_VISION_GOV_ONLY_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاسترategية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | إنشاء إدارة الأمن السيبراني | 100% | قيادة | 6 أشهر |\n'
)

_ROADMAP_ECC_ONLY_AR = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | المدة | النشاط | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تأسيس SOC | CISO | SOC | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | IAM/MFA | CISO | MFA | NCA ECC |\n'
    '| المرحلة 2 | 6-12 شهر | CSIRT | CISO | CSIRT | NCA ECC |\n'
    '| المرحلة 3 | 9-12 شهر | VM | CISO | VM | NCA ECC |\n'
)

_KPI_STUB = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة | صيغة | مصدر | تواتر |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | x | y | z | a | b |\n'
)

_CONF_STUB = (
    '## 7. تقييم الثقة\n\n**درجة الثقة:** 82%\n**مبررات:** نص.\n'
)


def _minimal_sections(**overrides):
    base = {
        'vision': _VISION_GOV_ONLY_AR,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nتصنيف وتشفير DLP.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP_ECC_ONLY_AR,
        'kpis': _KPI_STUB,
        'confidence': _CONF_STUB,
    }
    base.update(overrides)
    return base


class Prcy70FinalParityAndPdfStackTests(unittest.TestCase):

    @_skip
    def test_helper_present(self):
        self.assertTrue(hasattr(_APP, '_prcy70_gap_is_invalid_mapping'))
        self.assertTrue(hasattr(_APP, '_prcy70_standalone_dcc_objective_in_vision'))

    @_skip
    def test_kpi_dense_table_uses_kpi_cards_fallback(self):
        model = _base_model()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [[
                '1',
                'x' * 120,
                '≥ 95%',
                'formula text ' * 8,
                'source',
                'monthly',
                'notes ' * 6,
            ]],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        self.assertNotEqual(fb.get('kpi_main'), 'kpi_cards')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_dense_objectives_fallback_clears_stack(self):
        model = _base_model()
        tbl = {
            'schema': 'strategic_objectives',
            'header': list(_PSR.SCHEMA_STRATEGIC_OBJECTIVES_AR),
            'rows': [['1', 'x' * 280, 't', 'r', '24']],
        }
        model['blocks']['vision_objectives']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('strategic_objectives'), 'objective_cards')
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_dense_traceability_fallback_clears_stack(self):
        model = _base_model()
        st = {
            'schema': 'trace_fw_init',
            'title': 'DCC',
            'header': ['Capability', 'Gap', 'Initiative', 'KPI'],
            'rows': [[
                'DLP',
                'y' * 200,
                'init',
                'kpi',
            ]],
        }
        model['blocks']['traceability_matrix']['split_tables'] = [st]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('trace_fw_init'), 'trace_cards')
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_dense_governance_fallback_clears_stack(self):
        model = _base_model()
        model['blocks']['governance_ownership']['rows'] = [[
            'Role', 'x' * 180, 'a', 'b', 'c']]
        model['blocks']['governance_ownership']['header'] = [
            'Role', 'Responsibility', 'A', 'B', 'C']
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(fb.get('governance'), 'governance_cards')
        self.assertTrue(ev.get('pdf_table_vertical_stack_warnings'))

    @_skip
    def test_dcc_objective_inserted_in_final_artifact(self):
        sections = _minimal_sections()
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='generation')
        md = result.get('final_markdown') or ''
        self.assertTrue(result.get('diag', {}).get(
            'dcc_objective_present_in_final_artifact'))
        self.assertIn('NCA DCC', md)
        self.assertIn('DLP', md)

    @_skip
    def test_dcc_roadmap_at_least_three_rows(self):
        sections = _minimal_sections()
        content = _APP._prcy66_rebuild_canonical_content(sections, '')
        result = _APP._prcy69_enforce_final_artifact_parity(
            content, sections, 'ar', ['nca_ecc', 'nca_dcc'],
            'cyber', output_type='docx')
        self.assertGreaterEqual(
            result.get('diag', {}).get(
                'dcc_roadmap_rows_count_in_final_artifact', 0), 3)

    @_skip
    def test_exec_summary_residue_removed(self):
        self.assertTrue(_PSR._prcy70_is_exec_priority_residue('المبادرة؛'))
        self.assertTrue(_PSR._prcy70_is_exec_priority_residue('---------'))
        sections = _minimal_sections(
            roadmap=_ROADMAP_ECC_ONLY_AR + (
                '\n| --- | --- | المبادرة؛ --------- | --- | --- | --- |\n'))
        priorities = _PSR._derive_executive_priorities(sections, {}, 'ar')
        joined = ' '.join(priorities)
        self.assertNotIn('---------', joined)
        self.assertNotIn('المبادرة؛', joined)

    @_skip
    def test_dcc_traceability_rejects_month_phase_gap(self):
        self.assertTrue(_APP._prcy70_gap_is_invalid_mapping('الأشهر 1–4'))
        sections = _minimal_sections()
        trace = _APP._build_traceability_matrix(
            sections, ['ECC', 'DCC'], 'ar', domain_code='cyber')
        for r in (trace.get('rows') or []):
            if len(r) >= 3:
                self.assertNotIn('الأشهر 1–4', str(r[2]))

    @_skip
    def test_parity_fails_without_standalone_dcc_objective(self):
        compliance_only = (
            '## 1. الرؤية\n\n### الأهداف\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء إدارة الأمن | 100% | q | 6m |\n'
            '| 2 | تحقيق الالتزام بضوابط NCA ECC و NCA DCC | 90% | q | 12m |\n'
            + _ROADMAP_ECC_ONLY_AR + _KPI_STUB + _CONF_STUB)
        sections = _minimal_sections(vision=compliance_only)
        val = _APP._prcy69_validate_final_artifact(
            compliance_only, sections, ['nca_ecc', 'nca_dcc'], 'ar', 'cyber',
            strict=True)
        self.assertFalse(val.get('parity_valid'))
        self.assertTrue(any(
            'prcy69_final_artifact_missing_dcc_objective' in b
            for b in (val.get('blockers') or [])))


if __name__ == '__main__':
    unittest.main()
