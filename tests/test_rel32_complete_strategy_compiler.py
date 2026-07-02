"""REL3.2 — Final Strategy Completeness Compiler tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel32_complete_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine.traceability_substance_model import TRACE_CANONICAL_REGISTRY
from release_engine_v3.rel32_complete_strategy_compiler import (
    compile_complete_cyber_ar_technical_strategy,
    evaluate_rel32_final_strategy_completeness,
    filter_rel32_stale_blocking_errors,
    legacy_sections_to_markdown,
    refine_stale_legacy_issues_after_final_compile,
    restore_compiler_sections_before_hard_gate,
)
from release_engine_v3.rel32_kpi_assessment_guides import kpi_assessment_guides_present


def _ctx(mode: str = 'drafting'):
    return {
        'lang': 'ar',
        'domain': 'cyber',
        'generation_mode': mode,
        'backend': {
            'flags': {'rel3': True, 'rel31': True, 'rel32': True},
            'lang': 'ar',
            'generation_mode': mode,
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        },
        'flags': {'rel3': True, 'rel31': True, 'rel32': True},
    }


def _compile(sections=None, mode: str = 'drafting'):
    return compile_complete_cyber_ar_technical_strategy(
        dict(sections or {}), request_context=_ctx(mode))


class Rel32CompleteStrategyCompilerTests(unittest.TestCase):

    def test_01_kpi_assessment_guides_inserted_before_save(self):
        r = _compile({'kpis': '## KPIs\n\n| # | وصف | نوع | هدف | صيغة | مصدر | تكرار |\n'})
        kpis = r.legacy_sections.get('kpis', '')
        self.assertTrue(kpi_assessment_guides_present(kpis), kpis[-600:])
        self.assertIn('أدلة تقييم مؤشرات الأداء', kpis)

    def test_02_gap_implementation_guides_inserted(self):
        r = _compile({'gaps': ''})
        gaps = r.legacy_sections.get('gaps', '')
        self.assertRegex(gaps, r'دليل\s+تطبيق|Implementation Guide', gaps[-800:])

    def test_03_governance_model_inserted(self):
        r = _compile({'governance': ''})
        gov = r.legacy_sections.get('governance', '')
        self.assertIn('CISO', gov)
        self.assertIn('نموذج الحوكمة', gov)

    def test_04_traceability_matrix_inserted_from_registry(self):
        r = _compile({'traceability': '| fw | cap | gap |\n|---|---|---|\n| AI | bad | bad |\n'})
        trace = r.legacy_sections.get('traceability', '')
        self.assertIn('NCA DCC', trace)
        self.assertIn(
            TRACE_CANONICAL_REGISTRY['data_classification']['expected_gap'],
            trace)

    def test_05_risk_register_inserted(self):
        r = _compile({'confidence': ''})
        conf = r.legacy_sections.get('confidence', '')
        self.assertIn('المخاطر', conf)
        self.assertIn('خطة المعالجة', conf)

    def test_06_confidence_maturity_trajectory_inserted(self):
        r = _compile({'confidence': '## مخاطر\n\n| r | p |\n|---|---|\n'})
        conf = r.legacy_sections.get('confidence', '')
        self.assertRegex(conf, r'\d+\s*%')
        self.assertIn('مبرر', conf)

    def test_07_stale_so_incomplete_cleared_when_canonical_valid(self):
        r = _compile({})
        self.assertTrue(r.passed, r.blocking_errors)
        stale = [
            'strategic_objectives_incomplete_row',
            'strategic_objectives_incomplete_row:1',
        ]
        refined, cleared = refine_stale_legacy_issues_after_final_compile(
            r.legacy_sections, stale, lang='ar')
        self.assertNotIn('strategic_objectives_incomplete_row', refined)
        self.assertTrue(cleared)

    def test_08_stale_kpi_guides_missing_cleared_when_present(self):
        r = _compile({})
        stale = ['kpi_assessment_guides_missing']
        refined, cleared = refine_stale_legacy_issues_after_final_compile(
            r.legacy_sections, stale, lang='ar')
        self.assertNotIn('kpi_assessment_guides_missing', refined)
        self.assertIn('kpi_assessment_guides_missing', cleared)

    def test_09_complete_strategy_has_all_mandatory_sections(self):
        r = _compile({})
        comp = evaluate_rel32_final_strategy_completeness(
            r.legacy_sections, lang='ar')
        self.assertEqual(comp['missing_sections_after'], [], comp)
        self.assertTrue(comp['saved_content_complete'])

    def test_10_preview_docx_pdf_use_same_frozen_markdown(self):
        r = _compile({})
        md = legacy_sections_to_markdown(r.legacy_sections)
        self.assertIn('الرؤية والأهداف الاستراتيجية', md)
        self.assertIn('مصفوفة تتبع الأطر المرجعية', md)
        self.assertIn('أدلة تقييم مؤشرات الأداء', md)
        for key in ('vision', 'pillars', 'gaps', 'roadmap', 'kpis',
                    'confidence', 'governance', 'traceability'):
            heading = (r.legacy_sections.get(key) or '').splitlines()[0]
            self.assertIn(heading.strip('# ').strip(), md, msg=key)

    def test_11_no_export_only_sections(self):
        r = _compile({})
        md = legacy_sections_to_markdown(r.legacy_sections)
        for key, body in r.legacy_sections.items():
            if key.startswith('_') or not (body or '').strip():
                continue
            snippet = (body or '').strip()[:60]
            if snippet:
                self.assertIn(snippet[:30], md, msg=f'{key} only in sections dict')

    def test_12_drafting_mode_passes(self):
        r = _compile({}, mode='drafting')
        self.assertTrue(r.passed, r.blocking_errors)
        comp = (r.diagnostics or {}).get('final_strategy_completeness') or {}
        self.assertTrue(comp.get('saved_content_complete'))

    def test_13_consulting_mode_passes(self):
        r = _compile({}, mode='consulting')
        self.assertTrue(r.passed, r.blocking_errors)

    def test_14_save_gate_blocks_when_section_unrepairable(self):
        r = _compile({'vision': '', 'pillars': '', 'environment': '',
                      'gaps': '', 'roadmap': '', 'kpis': '',
                      'confidence': '', 'governance': '', 'traceability': ''})
        # Compiler should repair empty input; verify completeness diag exists
        comp = evaluate_rel32_final_strategy_completeness(
            r.legacy_sections, lang='ar')
        if comp.get('saved_content_complete'):
            self.assertEqual(comp['blocking_errors'], [])
        else:
            self.assertTrue(comp['blocking_errors'])

    def test_15_hard_gate_stale_blocking_filter(self):
        r = _compile({})
        errors = [
            'final_quality_gate_failed:strategic_objectives_incomplete_row:1',
            'final_quality_gate_failed:kpi_assessment_guides_missing',
        ]
        kept, cleared = filter_rel32_stale_blocking_errors(
            errors, r.legacy_sections, lang='ar')
        self.assertFalse(
            any('strategic_objectives_incomplete_row' in e for e in kept))
        self.assertFalse(any('kpi_assessment_guides_missing' in e for e in kept))
        self.assertEqual(len(cleared), 2)

    def test_16_restore_compiler_sections_before_hard_gate(self):
        r = _compile({})
        mutated = dict(r.legacy_sections)
        mutated['vision'] = '## corrupted\n\nempty table'
        restored = restore_compiler_sections_before_hard_gate(
            mutated, request_context=_ctx())
        self.assertIn('الرؤية والأهداف الاستراتيجية', restored.get('vision', ''))
        self.assertGreater(
            evaluate_rel32_final_strategy_completeness(restored, lang='ar')
            .get('table_row_counts', {}).get('vision:so_table', 0),
            5)

    def test_17_completeness_diag_fields(self):
        r = _compile({})
        comp = evaluate_rel32_final_strategy_completeness(
            r.legacy_sections,
            lang='ar',
            stale_issues_before=['strategic_objectives_incomplete_row'],
        )
        for field in (
            'mandatory_sections', 'missing_sections_after',
            'stale_issues_before', 'stale_issues_after',
            'saved_content_complete', 'preview_complete',
            'docx_complete', 'pdf_complete', 'blocking_errors',
        ):
            self.assertIn(field, comp)
        if comp.get('saved_content_complete'):
            self.assertEqual(comp['missing_sections_after'], [])
            self.assertEqual(comp['blocking_errors'], [])


if __name__ == '__main__':
    unittest.main()
