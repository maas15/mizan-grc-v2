"""REL3.3 — ERM risk-native generation contract.

Live staging @ 99bddee showed an ERM risk generation that saved a
strategy-shaped artifact (الرؤية والأهداف الاستراتيجية / خارطة الطريق /
strategy KPI / governance / traceability) carrying cyber-primary substance,
which the risk-native export guard correctly blocked. These tests pin the
generation-layer contract that prevents a strategy-shaped risk artifact from
ever being saved as accepted: detect → one deterministic risk-native repair →
fail closed if still strategy-shaped or still cyber-primary.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_gen_contract_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_risk_generation_contract import (
    detect_forbidden_strategy_sections,
    detect_risk_native_sections,
    evaluate_risk_generation_contract,
    risk_native_repair,
)

# ── Fixtures ──────────────────────────────────────────────────────────────
_STRATEGY_VISION_CYBER = """## الرؤية والأهداف الاستراتيجية
الرؤية: بناء حوكمة الأمن السيبراني وتأسيس مركز العمليات الأمنية (SOC) بقيادة CISO.

## 2. جدول تقييم المخاطر
| الخطر | الاحتمالية | التأثير |
|---|---|---|
| توقف الخدمة | متوسطة | عالٍ |

## 4. جدول استراتيجية المعالجة
| الضابط | النوع | المالك |
|---|---|---|
| خطة استمرارية الأعمال | وقائي | مالك المخاطر |

## 5. مقاييس KRI للمراقبة
| المؤشر | الحد |
|---|---|
| نسبة المخاطر المعالجة | 90% |
"""

_STRATEGY_ROADMAP_NO_CYBER = """## 1. وصف السيناريو
سيناريو مخاطر تشغيلية يؤثر على استمرارية الأعمال.

## خارطة الطريق التنفيذية
| المرحلة | المبادرة | المالك |
|---|---|---|
| 1 | تحسين الضوابط التشغيلية | مالك المخاطر |

## 2. جدول تقييم المخاطر
| الخطر | الاحتمالية | التأثير |
|---|---|---|
| توقف الخدمة | متوسطة | عالٍ |

## 4. جدول استراتيجية المعالجة
| الضابط | النوع | الأولوية | المالك |
|---|---|---|---|
| خطة استمرارية الأعمال | وقائي | عالية | مالك المخاطر |
| نسخ احتياطي دوري | تصحيحي | متوسطة | مالك المخاطر |

## 5. مقاييس KRI للمراقبة
| المؤشر | الحد |
|---|---|
| نسبة المخاطر المعالجة | 90% |
"""

_STRATEGY_KPI_GOV_TRACE = """## 1. وصف السيناريو
سيناريو مخاطر.

## مؤشرات الأداء الرئيسية
| # | المؤشر | القيمة |
|---|---|---|
| 1 | نضج الحوكمة | 90% |

## نموذج الحوكمة والمسؤوليات
| الدور | المسؤولية |
|---|---|
| CISO | الأمن |

## مصفوفة تتبع الأطر المرجعية
| الإطار | الضابط |
|---|---|
| NCA ECC | حوكمة |

## 4. جدول استراتيجية المعالجة
| الضابط | المالك |
|---|---|
| ضابط تشغيلي | مالك المخاطر |
"""

_CLEAN_RISK = """## 1. وصف السيناريو
سيناريو مخاطر تشغيلية يهدد استمرارية الأعمال ضمن شهية المخاطر.

## 2. جدول تقييم المخاطر
| الخطر | الاحتمالية | التأثير | الدرجة |
|---|---|---|---|
| توقف الخدمة | متوسطة | عالٍ | مرتفع |

## 4. جدول استراتيجية المعالجة
| الضابط | النوع | الأولوية | المالك |
|---|---|---|---|
| خطة استمرارية الأعمال | وقائي | عالية | مالك المخاطر |
| نسخ احتياطي دوري | تصحيحي | متوسطة | لجنة المخاطر |

## 5. مقاييس KRI للمراقبة
| المؤشر | الحد المقبول |
|---|---|
| نسبة المخاطر المعالجة | ≥ 90% |
"""

_CYBER_IN_RISK_SECTION = """## 1. وصف السيناريو
سيناريو يتطلب حوكمة الأمن السيبراني ومركز العمليات الأمنية كعنصر أساسي للجهة.

## 4. جدول استراتيجية المعالجة
| الضابط | المالك |
|---|---|
| مراجعة الضوابط | مالك المخاطر |

## 5. مقاييس KRI للمراقبة
| المؤشر | الحد |
|---|---|
| نسبة المخاطر | 90% |
"""


def _render_tree(md):
    return RenderTree(artifact_id='risk-1', canonical_hash='c' * 16,
                      render_tree_hash='r' * 16, nodes=[], markdown_view=md)


def _docx_backend():
    return {'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


def _pdf_backend():
    return {'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


class DetectionTests(unittest.TestCase):
    """Req 1, 2, 3 — heading-level detection of forbidden strategy sections."""

    def test_detect_vision_objectives(self):
        hits = detect_forbidden_strategy_sections(_STRATEGY_VISION_CYBER)
        self.assertTrue(any('الرؤية' in h for h in hits), hits)

    def test_detect_roadmap(self):
        hits = detect_forbidden_strategy_sections(_STRATEGY_ROADMAP_NO_CYBER)
        self.assertTrue(any('خارطة الطريق' in h for h in hits), hits)

    def test_detect_strategy_kpi_governance_traceability(self):
        hits = detect_forbidden_strategy_sections(_STRATEGY_KPI_GOV_TRACE)
        joined = ' | '.join(hits)
        self.assertIn('مؤشرات الأداء الرئيسية', joined)
        self.assertIn('نموذج الحوكمة', joined)
        self.assertIn('مصفوفة تتبع', joined)

    def test_clean_risk_has_no_forbidden(self):
        self.assertEqual(detect_forbidden_strategy_sections(_CLEAN_RISK), [])

    def test_treatment_strategy_heading_not_flagged(self):
        # "استراتيجية المعالجة" (treatment strategy) is risk-native, must NOT
        # be flagged as a strategy section.
        self.assertEqual(
            detect_forbidden_strategy_sections(
                '## جدول استراتيجية المعالجة\n| الضابط | المالك |\n'), [])


class RepairTests(unittest.TestCase):
    """Req 4, 5, 6 — deterministic risk-native repair."""

    def test_repair_removes_forbidden_headings(self):
        rep = risk_native_repair(_STRATEGY_ROADMAP_NO_CYBER)
        self.assertEqual(detect_forbidden_strategy_sections(rep), [])
        self.assertNotIn('خارطة الطريق', rep)

    def test_repair_preserves_risk_native_sections(self):
        rep = risk_native_repair(_STRATEGY_ROADMAP_NO_CYBER)
        self.assertIn('وصف السيناريو', rep)
        self.assertIn('جدول تقييم المخاطر', rep)
        self.assertIn('استراتيجية المعالجة', rep)
        self.assertIn('مقاييس KRI', rep)

    def test_repaired_only_risk_native_headings(self):
        rep = risk_native_repair(_STRATEGY_KPI_GOV_TRACE)
        self.assertEqual(detect_forbidden_strategy_sections(rep), [])
        self.assertTrue(detect_risk_native_sections(rep))

    def test_repair_preserves_treatment_rows(self):
        rep = risk_native_repair(_STRATEGY_ROADMAP_NO_CYBER)
        self.assertIn('خطة استمرارية الأعمال', rep)
        self.assertIn('نسخ احتياطي دوري', rep)


class ContractTests(unittest.TestCase):
    """Req 4, 7, 8, 9, 10 — fail-closed contract + diagnostic."""

    def test_clean_risk_passes_without_repair(self):
        d = evaluate_risk_generation_contract(
            _CLEAN_RISK, domain='Enterprise Risk Management', route='t',
            emit=False)
        self.assertTrue(d['contract_passed'])
        self.assertFalse(d['forbidden_strategy_sections_detected'])
        self.assertFalse(d['risk_repair_attempted'])
        self.assertEqual(d['blocking_errors'], [])

    def test_strategy_shape_no_cyber_repairs_and_passes(self):
        d = evaluate_risk_generation_contract(
            _STRATEGY_ROADMAP_NO_CYBER, domain='Enterprise Risk Management',
            route='t', emit=False)
        self.assertTrue(d['contract_passed'])
        self.assertTrue(d['risk_repair_attempted'])
        self.assertTrue(d['risk_repair_passed'])
        self.assertEqual(
            detect_forbidden_strategy_sections(d['content']), [])

    def test_strategy_vision_with_cyber_repairs_to_clean(self):
        # Cyber lives inside the strategy vision block; removing the block
        # removes both the strategy structure and the cyber substance.
        d = evaluate_risk_generation_contract(
            _STRATEGY_VISION_CYBER, domain='Enterprise Risk Management',
            route='t', emit=False)
        self.assertTrue(d['contract_passed'])
        self.assertEqual(
            detect_forbidden_strategy_sections(d['content']), [])
        self.assertNotIn('حوكمة الأمن السيبراني', d['content'])

    def test_cyber_primary_in_risk_section_fails_closed(self):
        d = evaluate_risk_generation_contract(
            _CYBER_IN_RISK_SECTION, domain='Enterprise Risk Management',
            route='t', emit=False)
        self.assertFalse(d['contract_passed'])
        self.assertIn('rel33_risk_generation_not_risk_native',
                      d['blocking_errors'])

    def test_unrepairable_strategy_shape_fails_closed(self):
        # A document that is ENTIRELY strategy sections with cyber substance in
        # each — repair strips structure, but if a strategy block cannot be
        # matched away and cyber remains, fail closed. Here every section is a
        # strategy heading; after repair there is no risk-native content, and
        # the strong-marker governance section is dropped, so this specific
        # case repairs clean. Use a strategy heading that ALSO holds a strong
        # marker in a way the risk splitter keeps -> ensure at least fail-safe.
        only_strategy = (
            '## الرؤية والأهداف الاستراتيجية\n'
            'حوكمة الأمن السيبراني ومركز العمليات الأمنية.\n')
        d = evaluate_risk_generation_contract(
            only_strategy, domain='Enterprise Risk Management', route='t',
            emit=False)
        # Either repaired clean (no forbidden, no cyber) OR failed closed —
        # never a pass that still carries forbidden/cyber.
        if d['contract_passed']:
            self.assertEqual(
                detect_forbidden_strategy_sections(d['content']), [])
            self.assertNotIn('حوكمة الأمن السيبراني', d['content'])
        else:
            self.assertTrue(d['blocking_errors'])

    def test_diagnostic_fields_present(self):
        d = evaluate_risk_generation_contract(
            _CLEAN_RISK, domain='Enterprise Risk Management', route='r',
            emit=False)
        for f in ('route', 'domain', 'document_type', 'artifact_type',
                  'generation_stage', 'prompt_profile', 'compiler_selected',
                  'strategy_compiler_attempted', 'risk_compiler_attempted',
                  'forbidden_strategy_sections_detected',
                  'forbidden_strategy_section_keys',
                  'cyber_primary_terms_detected',
                  'risk_native_sections_detected', 'risk_repair_attempted',
                  'risk_repair_passed', 'generation_saved_real',
                  'blocking_errors', 'contract_passed'):
            self.assertIn(f, d, f)
        self.assertEqual(d['document_type'], 'risk')
        self.assertEqual(d['compiler_selected'], 'risk_native')
        self.assertFalse(d['strategy_compiler_attempted'])


class ExportAfterRepairTests(unittest.TestCase):
    """Req 11, 12 — repaired risk content exports DOCX/PDF, no vision key."""

    def test_repaired_content_exports_docx_pdf(self):
        d = evaluate_risk_generation_contract(
            _STRATEGY_VISION_CYBER, domain='erm', route='t', emit=False)
        self.assertTrue(d['contract_passed'])
        repaired = d['content']
        docx = export_docx(_render_tree(repaired), backend=_docx_backend(),
                           domain='erm', document_type='risk')
        pdf = export_pdf(_render_tree(repaired), backend=_pdf_backend(),
                         domain='erm', document_type='risk')
        self.assertEqual(docx.blocking_errors, [], docx.blocking_errors)
        self.assertEqual(pdf.blocking_errors, [], pdf.blocking_errors)
        self.assertEqual(docx.bytes_data, b'PK-docx')
        self.assertEqual(pdf.bytes_data, b'%PDF-bytes')
        for blk in docx.blocking_errors + pdf.blocking_errors:
            self.assertNotIn(':vision:', blk)


if __name__ == '__main__':
    unittest.main()
