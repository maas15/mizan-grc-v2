"""PR-REL3.1 — executable Document Quality Specification positive model."""

from __future__ import annotations

import unittest

from release_engine_v3.document_quality_spec import (
    REQUIRED_KPI_FAMILIES,
    REQUIRED_SO_FAMILIES,
    REQUIRED_TRACE_MAPPINGS,
    check_strategic_objectives_positive_model,
    document_quality_blockers,
    evaluate_document_quality,
)


class DocumentQualitySpecConstantsTests(unittest.TestCase):

    def test_required_so_families_count(self):
        self.assertEqual(len(REQUIRED_SO_FAMILIES), 8)

    def test_required_kpi_families_count(self):
        self.assertEqual(len(REQUIRED_KPI_FAMILIES), 12)

    def test_required_trace_mappings_count(self):
        self.assertEqual(len(REQUIRED_TRACE_MAPPINGS), 7)


class DocumentQualitySpecSoModelTests(unittest.TestCase):

    def test_so_fails_placeholder_and_percent_only_target(self):
        vision = (
            '## 1\n| # | الهدف | المستهدف | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | TBD placeholder | 100% | — | 6 شهور |\n'
        )
        defects = check_strategic_objectives_positive_model(vision)
        self.assertIn('so_placeholder', defects)
        self.assertIn('so_target_percent_only', defects)

    def test_so_passes_scoped_measurable_target(self):
        vision = (
            '## 1\n| # | الهدف | المستهدف | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | إنشاء إدارة CISO وحوكمة | ≥ 95% تغطية حسابات CISO خلال 6 أشهر | '
            'حوكمة ECC | 6 شهور |\n'
        )
        defects = check_strategic_objectives_positive_model(vision)
        self.assertEqual(defects, [])


class DocumentQualitySpecCompilerTests(unittest.TestCase):

    def test_compiler_returns_authority_fields(self):
        dq = evaluate_document_quality(
            legacy_sections={'vision': '', 'pillars': ''},
            extracted_docx_text='',
        )
        self.assertIn('passed', dq)
        self.assertIn('section_results', dq)
        self.assertIn('blocking_errors', dq)
        self.assertIn('visible_text_hashes', dq)
        self.assertIn('national_launch_ready', dq)
        self.assertIn('export_return_allowed', dq)
        self.assertIn('release_ready_final_passed', dq)
        self.assertFalse(dq['passed'])

    def test_document_quality_blockers_prefixed(self):
        dq = {'blocking_errors': ['roadmap_canonical_invalid']}
        blockers = document_quality_blockers(dq)
        self.assertEqual(blockers, ['rel3_document_quality_failed:roadmap_canonical_invalid'])


class StagingDqsRepairTests(unittest.TestCase):
    """Regression for live staging failures (arabic role + KPI percent)."""

    def test_normalize_arabic_strips_cso_role_e_suffix(self):
        from professional_strategy_render import normalize_arabic_for_render
        out = normalize_arabic_for_render('المسؤول أمن السيبرانيe')
        self.assertNotIn('المسؤول أمن السيبرانيe', out)
        self.assertIn('مسؤول أمن السيبراني', out)

    def test_kpi_backup_percent_gets_denominator(self):
        from release_engine.kpi_model import _apply_inline_kpi_repairs
        from release_engine_v3.document_quality_spec import check_kpi_row_schema

        kpis = (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة اكتمال النسخ الاحتياطي والاستعادة | ≥ 99% | '
            'عدد النسخ الناجحة | منصة DR | شهري |\n'
        )
        _, text = _apply_inline_kpi_repairs({'kpis': kpis})
        self.assertIn('÷', text)
        self.assertEqual(
            [d for d in check_kpi_row_schema(text)
             if 'kpi_percent_without_denominator' in d],
            [])

    def test_arabic_role_corruption_triggers_export_repair(self):
        from release_engine.export_evidence_validator import (
            _export_defect_needs_arabic_repair,
        )
        self.assertTrue(_export_defect_needs_arabic_repair({
            'blocking_errors': ['rel3_export_evidence_failed:docx:arabic_role_corruption'],
        }))


if __name__ == '__main__':
    unittest.main()
