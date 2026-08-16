"""REL3.3 — ERM risk-native contract at the EXPORT-PREP boundary (defense-in-depth).

Live staging @ f43ca66 saved a strategy-shaped ERM risk artifact
(الرؤية والأهداف الاستراتيجية + cyber-primary substance) that the pre-save
generation contract did not catch in that instance, so the export domain guard
had to fail-close. This suite pins the second hard boundary: a risk-native
structure contract at export-prep (resolve_rel33_risk_export_artifact) plus
widened heading-variant detection, so no strategy-shaped content can ever reach
the exporters for document_type=risk — repaired to risk-native or failed closed
with an export-prep-specific blocker (never a strategy vision/roadmap blocker).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_export_prep_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_risk_artifact import (
    resolve_rel33_risk_export_artifact,
)
from release_engine_v3.rel33_risk_generation_contract import (
    detect_forbidden_strategy_sections,
    evaluate_risk_export_prep_contract,
    evaluate_risk_generation_contract,
    risk_native_repair,
)

# ── Regression fixture mirroring the failing live f43ca66 ERM artifact ──────
# Strategy-shaped ERM risk content with cyber-primary substance INSIDE the
# strategy vision/roadmap blocks (as observed on staging), plus a complete
# risk-native body (register + treatments + KRI). Secrets removed.
_LIVE_FAILING_ERM = """## الرؤية والأهداف الاستراتيجية
الرؤية: بناء حوكمة الأمن السيبراني وتأسيس مركز العمليات الأمنية (SOC) ومنصة SIEM
بقيادة CISO كعنصر أساسي للجهة.

## خارطة الطريق التنفيذية
| المرحلة | الإطار الزمني | المبادرة | المالك |
|---|---|---|---|
| 1 | 1-6 أشهر | تشغيل SOC/SIEM | CISO |
| 2 | 7-18 شهر | تطبيق IAM/PAM/MFA | CISO |

## مؤشرات الأداء الرئيسية
| # | المؤشر | القيمة |
|---|---|---|
| 1 | نضج الحوكمة | 90% |

## نموذج الحوكمة والمسؤوليات
| الدور | المسؤولية |
|---|---|
| CISO | الأمن السيبراني |

## مصفوفة تتبع الأطر المرجعية
| الإطار | الضابط |
|---|---|
| NCA ECC | حوكمة |

## 3. جدول تقييم المخاطر — سجل المخاطر
| الخطر | الاحتمالية | التأثير | الدرجة |
|---|---|---|---|
| توقف الخدمة | متوسطة | عالٍ | مرتفع |
| فقدان بيانات | منخفضة | عالٍ | متوسط |

## 6. جدول استراتيجية المعالجة والضوابط
| الضابط | النوع | الأولوية | المالك |
|---|---|---|---|
| خطة استمرارية الأعمال | وقائي | عالية | مالك المخاطر |
| نسخ احتياطي دوري | تصحيحي | متوسطة | مالك المخاطر |
| مراجعة الضوابط | كاشف | متوسطة | لجنة المخاطر |

## 7. مقاييس KRI للمراقبة
| المؤشر | الحد المقبول |
|---|---|
| نسبة المخاطر المعالجة | ≥ 90% |
| زمن التعافي | ≤ 4 ساعات |
"""

_CLEAN_ERM = """## 1. وصف السيناريو
سيناريو مخاطر تشغيلية يهدد استمرارية الأعمال ضمن شهية المخاطر.

## 3. جدول تقييم المخاطر — سجل المخاطر
| الخطر | الاحتمالية | التأثير | الدرجة |
|---|---|---|---|
| توقف الخدمة | متوسطة | عالٍ | مرتفع |

## 6. جدول استراتيجية المعالجة والضوابط
| الضابط | النوع | الأولوية | المالك |
|---|---|---|---|
| خطة استمرارية الأعمال | وقائي | عالية | مالك المخاطر |
| نسخ احتياطي دوري | تصحيحي | متوسطة | لجنة المخاطر |

## 7. مقاييس KRI للمراقبة
| المؤشر | الحد المقبول |
|---|---|
| نسبة المخاطر المعالجة | ≥ 90% |
"""

_CYBER_IN_RISK = """## 1. وصف السيناريو
سيناريو يتطلب حوكمة الأمن السيبراني ومركز العمليات الأمنية كعنصر أساسي للجهة.

## 6. جدول استراتيجية المعالجة والضوابط
| الضابط | المالك |
|---|---|
| مراجعة الضوابط | مالك المخاطر |
"""


def _norm(d):
    return normalize_domain_code(d, default='') or d


def _assemble(secs):
    return '\n\n'.join(str(v) for v in secs.values())


def _resolve(content, *, risk_id=1, domain='Enterprise Risk Management'):
    def _load(rid, uid):
        return {'id': rid, 'analysis': content, 'domain': domain,
                'document_type': 'risk'}

    def _load_strat(a, u, domain=''):
        return None

    return resolve_rel33_risk_export_artifact(
        artifact_id=risk_id, risk_id=risk_id, user_id=1, domain=domain,
        route='docx', client_content='',
        load_risk_row=_load, load_strategy_risk_row=_load_strat,
        assemble_sections=_assemble, normalize_domain_fn=_norm)


def _render_tree(md):
    return RenderTree(artifact_id='risk-1', canonical_hash='c' * 16,
                      render_tree_hash='r' * 16, nodes=[], markdown_view=md)


def _docx_backend():
    return {'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


def _pdf_backend():
    return {'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


class WidenedDetectionTests(unittest.TestCase):
    """Req 1-7 — heading-variant detection; risk-native never flagged."""

    def test_detect_vision_objectives_bold(self):
        self.assertTrue(detect_forbidden_strategy_sections(
            '## **الرؤية والأهداف الاستراتيجية**\nx'))

    def test_detect_roadmap_numbered(self):
        self.assertTrue(detect_forbidden_strategy_sections(
            '### 2. خارطة الطريق التنفيذية\nx'))

    def test_detect_strategy_kpi(self):
        self.assertTrue(detect_forbidden_strategy_sections(
            '## مؤشرات الأداء الرئيسية\nx'))

    def test_detect_governance_model(self):
        self.assertTrue(detect_forbidden_strategy_sections(
            '## نموذج الحوكمة والمسؤوليات\nx'))

    def test_detect_traceability_matrix(self):
        self.assertTrue(detect_forbidden_strategy_sections(
            '## مصفوفة تتبع الأطر المرجعية\nx'))
        self.assertTrue(detect_forbidden_strategy_sections(
            '## مصفوفة التتبع\nx'))

    def test_detect_english_variants(self):
        for h in ('## Implementation Roadmap\nx',
                  '## Key Performance Indicators\nx',
                  '## Strategic Objectives\nx',
                  '## Traceability Matrix\nx',
                  '## Governance Model\nx'):
            self.assertTrue(detect_forbidden_strategy_sections(h), h)

    def test_do_not_flag_treatment_strategy(self):
        self.assertEqual(detect_forbidden_strategy_sections(
            '## جدول استراتيجية المعالجة\n| الضابط | المالك |\n'), [])
        self.assertEqual(detect_forbidden_strategy_sections(
            '## خطة المعالجة\nx'), [])

    def test_do_not_flag_severity_and_risk_matrix(self):
        self.assertEqual(detect_forbidden_strategy_sections(
            '## مصفوفة تحديد مستوى الخطورة\nx'), [])
        self.assertEqual(detect_forbidden_strategy_sections(
            '## مصفوفة المخاطر\nx'), [])
        self.assertEqual(detect_forbidden_strategy_sections(
            '## سجل المخاطر\nx'), [])
        self.assertEqual(detect_forbidden_strategy_sections(
            '## مقاييس KRI للمراقبة\nx'), [])


class PreSaveGenerationContractTests(unittest.TestCase):
    """Req 8 — pre-save generation contract repairs strategy-shaped ERM."""

    def test_generation_contract_repairs_live_fixture(self):
        d = evaluate_risk_generation_contract(
            _LIVE_FAILING_ERM, domain='Enterprise Risk Management',
            route='generate-risk-async', emit=False)
        self.assertTrue(d['contract_passed'])
        self.assertEqual(detect_forbidden_strategy_sections(d['content']), [])
        self.assertNotIn('حوكمة الأمن السيبراني', d['content'])


class ExportPrepContractTests(unittest.TestCase):
    """Req 9-11 — export-prep contract repairs or fails closed."""

    def test_export_prep_repairs_saved_strategy_shaped(self):
        p = evaluate_risk_export_prep_contract(
            _LIVE_FAILING_ERM, domain='Enterprise Risk Management',
            route='docx', risk_id=1, emit=False)
        self.assertTrue(p['contract_passed'])
        self.assertTrue(p['risk_export_prep_repair_attempted'])
        self.assertTrue(p['risk_export_prep_repair_passed'])
        self.assertTrue(p['export_content_differs_from_saved'])
        self.assertEqual(
            detect_forbidden_strategy_sections(p['content']), [])
        self.assertEqual(p['blocking_errors'], [])

    def test_export_prep_clean_passes_without_repair(self):
        p = evaluate_risk_export_prep_contract(
            _CLEAN_ERM, domain='Enterprise Risk Management', route='docx',
            risk_id=1, emit=False)
        self.assertTrue(p['contract_passed'])
        self.assertFalse(p['forbidden_strategy_sections_detected'])
        self.assertFalse(p['risk_export_prep_repair_attempted'])
        self.assertFalse(p['export_content_differs_from_saved'])

    def test_export_prep_fails_closed_on_cyber_primary_in_risk_section(self):
        p = evaluate_risk_export_prep_contract(
            _CYBER_IN_RISK, domain='Enterprise Risk Management', route='docx',
            risk_id=2, emit=False)
        self.assertFalse(p['contract_passed'])
        self.assertIn('rel33_risk_export_prep_not_risk_native',
                      p['blocking_errors'])

    def test_export_prep_blockers_never_strategy_section_codes(self):
        p = evaluate_risk_export_prep_contract(
            _CYBER_IN_RISK, domain='Enterprise Risk Management', route='pdf',
            risk_id=2, emit=False)
        for b in p['blocking_errors']:
            self.assertNotIn(':vision:', b)
            self.assertNotIn('roadmap_visible_row_count', b)
            self.assertTrue(b.startswith('rel33_risk_export_prep'))


class ResolverIntegrationTests(unittest.TestCase):
    """Req 9-14 — resolver applies the export-prep contract end-to-end."""

    def test_resolver_repairs_strategy_shaped_saved_artifact(self):
        out = _resolve(_LIVE_FAILING_ERM)
        self.assertTrue(out['content'].strip())
        self.assertEqual(
            detect_forbidden_strategy_sections(out['content']), [])
        self.assertNotIn('حوكمة الأمن السيبراني', out['content'])
        self.assertEqual(out['diag'].get('blocking_errors') or [], [])

    def test_resolver_preserves_risk_register_and_treatments(self):
        out = _resolve(_LIVE_FAILING_ERM)
        self.assertIn('سجل المخاطر', out['content'])
        self.assertIn('استراتيجية المعالجة', out['content'])
        self.assertIn('مقاييس KRI', out['content'])
        # treatment rows preserved (semantic count > 0 via diag)
        self.assertGreater(out['diag'].get('treatment_rows_count', 0), 0)

    def test_resolver_fails_closed_on_cyber_primary(self):
        out = _resolve(_CYBER_IN_RISK, risk_id=2)
        self.assertEqual(out['content'], '')
        self.assertIn('rel33_risk_export_prep_not_risk_native',
                      out['diag'].get('blocking_errors') or [])

    def test_resolver_clean_passes(self):
        out = _resolve(_CLEAN_ERM, risk_id=3)
        self.assertTrue(out['content'].strip())
        self.assertEqual(
            detect_forbidden_strategy_sections(out['content']), [])


class RepairedExportTests(unittest.TestCase):
    """Req 12, 15, 16 — repaired export content exports DOCX/PDF, no vision."""

    def test_repaired_live_fixture_exports_docx_pdf(self):
        out = _resolve(_LIVE_FAILING_ERM)
        repaired = out['content']
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

    def test_repaired_export_passes_risk_domain_isolation(self):
        from release_engine_v3.rel33_domain_guard import (
            evaluate_pre_export_bytes_domain_guard,
        )
        out = _resolve(_LIVE_FAILING_ERM)
        blockers = evaluate_pre_export_bytes_domain_guard(
            out['sections'], domain='erm', route='docx', document_type='risk')
        self.assertEqual(blockers, [], blockers)


if __name__ == '__main__':
    unittest.main()
