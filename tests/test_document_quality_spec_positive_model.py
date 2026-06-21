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

    def test_dqs_so_family_insert_repairs_awareness_training(self):
        from release_engine_v3.document_quality_spec import (
            check_so_families_present,
            repair_document_quality_sections,
        )

        vision = (
            '## 1\n| # | الهدف | المستهدف | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | تأسيس حوكمة CISO | ≥ 95% تغطية CISO خلال 6 أشهر | حوكمة | 6 شهور |\n'
            '| 2 | امتثال ECC | ≥ 90% امتثال | تنظيمي | 12 شهر |\n'
            '| 3 | تشغيل SOC | MTTD ≤ 15 دقيقة | كشف | 12 شهر |\n'
            '| 4 | IAM/PAM/MFA | ≥ 95% تغطية | هوية | 12 شهر |\n'
            '| 5 | CSIRT | SLA ≤ 4 ساعات | استجابة | 12 شهر |\n'
            '| 6 | إدارة الثغرات | ≥ 95% SLA | ثغرات | 12 شهر |\n'
            '| 7 | حماية DCC | ≥ 95% بيانات | dcc | 12 شهر |\n'
            '| 8 | تشفير البيانات | ≥ 95% أصول | تشفير | 12 شهر |\n'
        )
        missing, _ = check_so_families_present(vision)
        self.assertIn('awareness_training', missing)
        class _AppStub:
            @staticmethod
            def _prcy39_locate_so_table(v):
                for i, ln in enumerate(v.splitlines()):
                    if '| # |' in ln or '| 1 |' in ln:
                        return i - 1 if '| # |' not in ln else i, len(v.splitlines())
                return None, None

            @staticmethod
            def _prcy39_parse_table_rows(lines):
                rows = []
                for ln in lines:
                    if ln.strip().startswith('|') and '---' not in ln:
                        cells = [c.strip() for c in ln.strip('|').split('|')]
                        if cells and cells[0].isdigit():
                            rows.append(cells)
                return rows

            @staticmethod
            def _prcy39_row_to_spec(cells, idx, source=''):
                if len(cells) < 5:
                    return None
                return {
                    'row_index': idx,
                    'objective': cells[1],
                    'measurable_target': cells[2],
                    'rationale': cells[3],
                    'timeframe': cells[4],
                    'source': source,
                }

            @staticmethod
            def _prcy39_render_canonical_so_table(specs, lang):
                hdr = '| # | الهدف | المستهدف | المبرر | الإطار |\n|---|---|---|---|---|\n'
                body = ''.join(
                    f'| {s["row_index"]} | {s["objective"]} | '
                    f'{s["measurable_target"]} | {s["rationale"]} | '
                    f'{s["timeframe"]} |\n'
                    for s in specs)
                return hdr + body

        repaired, reps = repair_document_quality_sections(
            {'vision': vision},
            lang='ar',
            backend={'app_module': _AppStub},
        )
        missing_after, _ = check_so_families_present(repaired.get('vision', ''))
        self.assertNotIn('awareness_training', missing_after)
        self.assertTrue(any('so_family_insert' in r for r in reps))

    def test_kpi_vulnerability_percent_gets_denominator(self):
        from release_engine.kpi_model import _apply_inline_kpi_repairs
        from release_engine_v3.document_quality_spec import check_kpi_row_schema

        kpis = (
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نسبة الثغرات الأمنية الحرجة المغلقة | ≥ 95% | '
            'عدد الثغرات المغلقة | منصة | شهري |\n'
        )
        _, text = _apply_inline_kpi_repairs({'kpis': kpis})
        self.assertIn('÷', text)
        self.assertEqual(
            [d for d in check_kpi_row_schema(text)
             if 'kpi_percent_without_denominator' in d],
            [])

    def test_phishing_risk_links_control_family(self):
        from release_engine_v3.document_quality_spec import check_risk_register_schema

        confidence = (
            '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | نجاح حملات التصيد الاحتيالي | متوسط | عالٍ | '
            'محاكاة تصيد وتوعية ربع سنوية — المالك: مدير التوعية | CISO |\n'
        )
        defects, _ = check_risk_register_schema(confidence)
        self.assertEqual(
            [d for d in defects if 'risk_missing_control_family' in d],
            [])

    def test_arabic_glue_repaired_in_dqs_pipeline(self):
        from release_engine_v3.document_quality_spec import (
            check_arabic_tokenization_quality,
            repair_document_quality_sections,
        )

        sections = {
            'vision': 'هدف يعتمد على ال معلومات الحساسة للتعامل مع التهديدات',
            'environment': 'تعتمد ال منظمة على حوكمة أمن المعلومات',
        }
        repaired, reps = repair_document_quality_sections(sections, lang='ar')
        self.assertNotIn('ال معلومات', repaired.get('vision', ''))
        self.assertIn('المعلومات', repaired.get('vision', ''))
        self.assertNotIn('ال منظمة', repaired.get('environment', ''))
        self.assertIn('المنظمة', repaired.get('environment', ''))
        self.assertIn('dqs:arabic_final_gate', reps)
        blob = '\n\n'.join(repaired.values())
        self.assertTrue(check_arabic_tokenization_quality(blob).get('passed'))

    def test_arabic_invisible_lam_glue_repaired(self):
        from release_engine.rendered_evidence_validator import _repair_arabic_blob
        from release_engine.rel27_export_checks import check_arabic_residues_exported

        glued = 'تعتمد ال\u200f منظمة على ال\u200e معلومات حساسة'
        repaired = _repair_arabic_blob(glued)
        self.assertNotIn('ال منظمة', repaired)
        self.assertIn('المنظمة', repaired)
        self.assertIn('المعلومات', repaired)
        residues = check_arabic_residues_exported(repaired)
        self.assertTrue(residues.get('exported_arabic_quality_valid'))


if __name__ == '__main__':
    unittest.main()
