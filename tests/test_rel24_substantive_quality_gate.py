"""PR-REL2.4 — substantive board-ready content quality gates."""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel24_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from release_engine.arabic_language_gate import apply_arabic_substance_gate
from release_engine.final_quality_contract import evaluate_final_quality
from release_engine.kpi_substance_model import finalize_kpi_substance
from release_engine.orchestrator import process_release_artifact
from release_engine.pillar_substance_model import finalize_pillar_substance
from release_engine.rel23_finalize import apply_rel23_cyber_finalize
from release_engine.rel24_finalize import apply_rel24_cyber_substance_finalize
from release_engine.roadmap_substance_model import finalize_roadmap_substance
from release_engine.risk_treatment_model import finalize_risk_treatment
from release_engine.so_substance_model import finalize_so_substance
from release_engine.substantive_quality_gate import evaluate_substantive_quality
from release_engine.traceability_substance_model import finalize_traceability_substance


def _backend():
    return _APP._rel2_backend_callables() if hasattr(
        _APP, '_rel2_backend_callables') else {}


def _content(sections):
    return _APP._prcy65_rebuild_content_from_sections(sections, None)


def _live_rel24_defect_sections():
    """Live Cyber Arabic Technical defects — substance layer."""
    from domains.cyber.fixtures_ar import technical_sections
    s = dict(technical_sections())
    s['vision'] = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
        ' المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | إنشاء مركز عمليات الأمن السيبراني المتقدم | ≥ 90% | حوكمة | 6 أشهر |\n'
        '| 2 | تطوير برنامج إدارة الثغرات الأمنية الشامل | ≥ 90% | تشغيل | 12 شهر |\n'
        '| 3 | ال معلومات والبيانات للتعاملمع التهديدات | 100% | بيانات | 18 شهر |\n'
    )
    s['pillars'] = (
        '## 2. الركائز الاستراتيجية\n\n'
        'نص وصفي للركائز للتعاملمع التهديدات الاجتماعيةضد المنظمة.\n'
    )
    s['roadmap'] = (
        '## 5. خارطة الطريق\n\n'
        '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
        '|---|---|---|---|---|---|\n'
        '| المرحلة 1 | 1-6 | حوكمة | Threat Intelligence | هيكل | ECC |\n'
        '| المرحلة 2 | 7-12 | SOC | Data Protection | مركز | ECC |\n'
        '| المرحلة 2 | 7-12 | IAM | Owner | ضوابط | ECC |\n'
    )
    s['kpis'] = (
        '## 6. مؤشرات\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | نسبة الترقيع الأمني خارج SLA | 100% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | أداة | شهري |\n'
        '| 2 | عدد حوادث تسرب البيانات (DLP) | ≥95% | '
        '(عدد العناصر المطابقة / إجمالي العناصر) × 100 | DLP | شهري |\n'
        '| 3 | نسبة محاولات الدخول الفاشلة الشاذة | 100% | عام | SIEM | شهري |\n'
    )
    s['confidence'] = (
        '## 7. تقييم الثقة\n\n'
        '| # | عامل المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
        '|---|---|---|---|---|\n'
        '| 1 | مخاطر الامتثال | متوسط | عالٍ | — |\n'
        '| 2 | نقص القدرات | عالٍ | عالٍ | — |\n'
    )
    s['traceability'] = (
        '## مصفوفة التتبع\n\n'
        '| الإطار | مجال القدرة | الفجوة المرتبطة | المبادرة | المؤشر | الخطر |\n'
        '|---|---|---|---|---|---|\n'
        '| NCA DCC | DLP | — | تفعيل DLP | KPI | خطر |\n'
        '| NCA ECC | الاستجابة للحوادث | نقص مركز SOC | CSIRT | MTTR | خطر |\n'
    )
    return s


class Rel24SOSubstanceTests(unittest.TestCase):

    def test_weak_90_percent_target_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_so_substance(sections, lang='ar')
        self.assertTrue(diag['weak_targets_before'])
        self.assertTrue(diag['objectives_quality_passed'], diag)
        self.assertEqual(diag['weak_targets_after'], [])
        self.assertNotIn('≥ 90%', out['vision'])

    def test_objective_arabic_residue_repaired(self):
        sections = {'vision': 'هدف ال معلومات ول منع التسرب للتعاملمع'}
        out, diag = apply_arabic_substance_gate(sections, lang='ar')
        self.assertNotIn('ال معلومات', out['vision'])
        self.assertNotIn('ل منع', out['vision'])
        self.assertTrue(diag['arabic_quality_passed'])


class Rel24PillarSubstanceTests(unittest.TestCase):

    def test_shallow_pillar_outputs_enriched(self):
        sections = {'pillars': '## 2. الركائز\n\nنص فقط.\n'}
        out, diag = finalize_pillar_substance(sections, lang='ar', domain='cyber')
        self.assertTrue(diag['generic_outputs_before'] or diag['shallow_pillars_before'])
        self.assertEqual(diag['generic_outputs_after'], [])
        self.assertTrue(diag['pillar_depth_passed'])

    def test_pillar_titles_only_fails_before_passes_after(self):
        sections = {'pillars': (
            '### حوكمة\n\n| مبادرة | وصف | مخرج |\n|---|---|---|\n'
            '| أ | ب | منصة حوكمة معتمدة |\n')}
        _, diag = finalize_pillar_substance(sections, lang='ar', domain='cyber')
        self.assertTrue(diag['pillar_depth_passed'])
        self.assertEqual(diag['generic_outputs_after'], [])


class Rel24RoadmapSubstanceTests(unittest.TestCase):

    def test_fewer_than_10_rows_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_roadmap_substance(
            sections, lang='ar', domain='cyber',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            backend=_backend())
        self.assertGreaterEqual(diag['row_count_after'], 10)
        self.assertTrue(diag['roadmap_depth_passed'])

    def test_missing_families_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_roadmap_substance(
            sections, lang='ar', domain='cyber',
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            backend=_backend())
        self.assertEqual(diag['missing_families_after'], [])


class Rel24KPISubstanceTests(unittest.TestCase):

    def test_patch_sla_100_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_kpi_substance(sections, lang='ar', backend=_backend())
        self.assertNotIn('نسبة الترقيع الأمني خارج SLA', out['kpis'])
        self.assertEqual(diag['generic_formula_count'], 0)
        self.assertEqual(diag['invalid_metric_rows_after'], [])

    def test_dlp_percentage_on_count_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_kpi_substance(sections, lang='ar', backend=_backend())
        kpi = out['kpis']
        self.assertIn('حوادث تسرب', kpi)
        self.assertNotIn('≥95%', kpi.split('حوادث')[0] if 'حوادث' in kpi else kpi)

    def test_generic_formula_replaced(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_kpi_substance(sections, lang='ar', backend=_backend())
        self.assertEqual(diag['generic_formula_count'], 0)


class Rel24RiskTraceabilityTests(unittest.TestCase):

    def test_empty_treatment_dash_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_risk_treatment(sections, lang='ar')
        self.assertTrue(diag['empty_treatment_plans_before'])
        self.assertEqual(diag['empty_treatment_plans_after'], [])
        self.assertTrue(diag['risk_treatment_passed'])
        self.assertEqual(diag['empty_treatment_plans_after'], [])

    def test_blank_dlp_gap_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_traceability_substance(sections, lang='ar')
        self.assertTrue(diag['blank_gap_rows_before'] or diag['bad_mappings_before'])
        self.assertEqual(diag['blank_gap_rows_after'], [])
        self.assertIn('ضعف ضوابط منع تسرب البيانات', out['traceability'])

    def test_ecc_incident_wrong_soc_mapping_repaired(self):
        sections = _live_rel24_defect_sections()
        out, diag = finalize_traceability_substance(sections, lang='ar')
        self.assertEqual(diag['bad_mappings_after'], [])
        self.assertIn('غياب فريق الاستجابة للحوادث CSIRT', out['traceability'])


class Rel24ArabicSubstanceTests(unittest.TestCase):

    def test_residues_removed(self):
        sections = {
            'pillars': 'ال معلومات للتعاملمع و ل منع التسرب الاجتماعيةضد',
        }
        out, diag = apply_arabic_substance_gate(sections, lang='ar')
        text = out['pillars']
        self.assertNotIn('للتعاملمع', text)
        self.assertNotIn('ل منع', text)
        self.assertNotIn('ال معلومات', text)
        self.assertTrue(diag['arabic_quality_passed'])

    def test_live_hulul_min_glued_residue_repaired(self):
        """Live staging defect: حلولمن (حلول+من) before whitespace."""
        sections = {
            'vision': 'تطبيق حلولمن متقدمة لمواجهة التهديدات السيبرانية',
            'pillars': 'حلولمنالتهديدات عبر SOC',
        }
        out, diag = apply_arabic_substance_gate(sections, lang='ar')
        self.assertNotIn('حلولمن', out['vision'])
        self.assertIn('حلول من', out['vision'])
        self.assertNotIn('حلولمن', out['pillars'])
        self.assertEqual(diag['residues_after'], [])
        self.assertTrue(diag['arabic_quality_passed'])

    def test_lam_mana_split_residue_repaired(self):
        """Live staging defect: ل منع must not reappear after لمنع glue-split."""
        sections = {
            'vision': 'ضوابط ل منع تسرب البيانات',
            'pillars': 'تفعيل لمنع التسرب عبر DLP',
            'environment': 'ل  منع الحوادث والمراقبة',
        }
        out, diag = apply_arabic_substance_gate(sections, lang='ar')
        self.assertNotIn('ل منع', out['vision'])
        self.assertNotIn('ل منع', out['pillars'])
        self.assertIn('لمنع', out['vision'])
        self.assertIn('لمنع', out['pillars'])
        self.assertEqual(diag['residues_after'], [])
        self.assertTrue(diag['arabic_quality_passed'])

    def test_lam_mana_repair_cycle_stable(self):
        """Repair loop must not oscillate لمنع ↔ ل منع (live staging blocker)."""
        from release_engine.arabic_language_gate import (
            _apply_glue_split, _repair_text, _find_residues)

        for src in ('ل منع', 'ضوابط لمنع التسرب', 'ل\u00a0منع الحوادث'):
            repaired = _repair_text(src)
            self.assertEqual(_find_residues(repaired), [], msg=src)
            self.assertNotIn('ل منع', repaired, msg=src)
        # Explicit regression: glue-split alone must not break لمنع
        self.assertEqual(_apply_glue_split('لمنع التسرب'), 'لمنع التسرب')

    def test_hulul_mana_glued_not_split_into_lam_mana_residue(self):
        """Live defect: حلولمنع must not become حلول منع (false ل منع)."""
        sections = {
            'vision': 'تطبيق حلولمنع تسرب البيانات عبر DLP',
            'pillars': 'حلولمنع التهديدات المتقدمة',
            'environment': 'حلولمن التهديدات و حلولمنع الحوادث',
        }
        out, diag = apply_arabic_substance_gate(sections, lang='ar')
        self.assertNotIn('ل منع', out['vision'])
        self.assertNotIn('ل منع', out['pillars'])
        self.assertIn('حلولمنع', out['vision'])
        self.assertIn('حلول من', out['environment'])
        self.assertEqual(diag['residues_after'], [])
        self.assertTrue(diag['arabic_quality_passed'])


class Rel24IntegrationTests(unittest.TestCase):

    def test_live_fixture_fails_before_rel24_passes_after(self):
        sections = _live_rel24_defect_sections()
        raw = {
            'sections': dict(sections),
            'final_markdown': _content(sections),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        art23, _, _ = apply_rel23_cyber_finalize(
            dict(raw), domain='cyber', lang='ar', backend=_backend())
        self.assertIn('منصة حوكمة معتمدة', art23['sections'].get('pillars', ''))

        out = process_release_artifact(
            raw, domain='cyber', lang='ar',
            backend=_backend(), skip_rel1=True)
        rel24 = (out.get('diagnostics') or {}).get('rel2', {}).get('rel24') or {}
        gate = rel24.get('substantive_gate') or {}
        self.assertTrue(gate.get('board_ready_substance_passed'), gate)
        self.assertEqual(gate.get('blocking_errors'), [])
        self.assertTrue(rel24.get('so', {}).get('objectives_quality_passed'))
        self.assertTrue(rel24.get('arabic', {}).get('arabic_quality_passed'))
        self.assertNotIn(
            'منصة حوكمة معتمدة',
            out['sections'].get('pillars', ''))

    def test_rel24_roadmap_refresh_clears_stale_rel23_blocker(self):
        """REL2.3 roadmap diag must not block after REL2.4 repairs roadmap."""
        sections = _live_rel24_defect_sections()
        raw = {
            'sections': dict(sections),
            'final_markdown': _content(sections),
            'blocking_errors': [],
            'sealed': False,
            'domain': 'cyber',
            'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
        }
        out = process_release_artifact(
            raw, domain='cyber', lang='ar',
            backend=_backend(), skip_rel1=True)
        contract = out.get('final_quality_contract') or {}
        rel23 = (out.get('diagnostics') or {}).get('rel2', {}).get('rel23') or {}
        rel24 = (out.get('diagnostics') or {}).get('rel2', {}).get('rel24') or {}
        self.assertTrue(rel24.get('roadmap', {}).get('roadmap_depth_passed'))
        self.assertTrue(contract.get('roadmap_valid'), contract)
        self.assertNotIn(
            'rel2_roadmap_failed:awareness_training',
            contract.get('blocking_errors') or [])
        self.assertFalse(
            (rel23.get('roadmap') or {}).get('blocking_error_if_any'))

    def test_final_quality_contract_includes_substance_flags(self):
        sections = _live_rel24_defect_sections()
        out = process_release_artifact(
            {
                'sections': sections,
                'final_markdown': _content(sections),
                'blocking_errors': [],
                'sealed': False,
                'domain': 'cyber',
                'contract_meta': {'selected_frameworks': ['nca_ecc', 'nca_dcc']},
            },
            domain='cyber', lang='ar',
            backend=_backend(), skip_rel1=True)
        out['diagnostics'] = out.get('diagnostics') or {}
        out['diagnostics']['rel2'] = (out.get('diagnostics') or {}).get(
            'rel2') or {}
        contract = out.get('final_quality_contract') or evaluate_final_quality(
            out, document_type='strategy', lang='ar')
        rel24 = (out.get('diagnostics') or {}).get('rel2', {}).get('rel24') or {}
        gate = rel24.get('substantive_gate') or {}
        self.assertTrue(gate.get('board_ready_substance_passed'), gate)
        for flag in (
            'pillar_substance_passed', 'roadmap_substance_passed',
            'kpi_substance_passed', 'risk_treatment_passed',
            'traceability_substance_passed', 'objectives_quality_passed',
        ):
            self.assertTrue(contract.get(flag), f'missing or false: {flag}')


if __name__ == '__main__':
    unittest.main()
