"""REL3.3 — deterministic ERM risk-native compiler.

ERM risk must not depend on free-form LLM structure. These tests pin the
compiler: strategy/cyber-shaped raw input always compiles to a schema-locked,
risk-native artifact that passes risk-domain isolation, frozen completeness and
treatment evidence, and exports DOCX/PDF with no vision/roadmap strategy
blockers.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_native_compiler_')
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
from release_engine_v3.rel33_domain_guard import (
    evaluate_pre_export_bytes_domain_guard,
)
from release_engine_v3.rel33_frozen_completeness import (
    evaluate_risk_sections_complete,
)
from release_engine_v3.rel33_risk_artifact import (
    resolve_rel33_risk_export_artifact,
)
from release_engine_v3.rel33_risk_generation_contract import (
    detect_forbidden_strategy_sections,
)
from release_engine_v3.rel33_risk_native_compiler import (
    MIN_KRI_ROWS,
    MIN_REGISTER_ROWS,
    MIN_TREATMENT_ROWS,
    compile_risk_native_artifact,
)
from release_engine_v3.rel33_risk_treatment_evidence import (
    count_treatment_rows_from_sections,
    semantic_risk_treatment_counts,
)

_CTX = {'asset': 'الأنظمة المؤسسية', 'threat': 'توقف الخدمة',
        'category': 'تشغيلية', 'risk_level': 'HIGH', 'org_name': 'جهة',
        'sector': 'حكومي'}

_RAW_STRATEGY_CYBER = """## الرؤية والأهداف الاستراتيجية
الرؤية: بناء حوكمة الأمن السيبراني وتأسيس مركز العمليات الأمنية (SOC) بقيادة CISO.

## الركائز الاستراتيجية
| المبادرة | المالك |
|---|---|
| تشغيل SOC/SIEM | CISO |

## خارطة الطريق التنفيذية
| المرحلة | المبادرة | المالك |
|---|---|---|
| 1 | تطبيق IAM/PAM/MFA | CISO |

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

## جدول تقييم المخاطر
| الخطر | الاحتمالية | التأثير |
|---|---|---|
| توقف الخدمة | متوسطة | عالٍ |
| تأسيس CSIRT | عالية | عالٍ |

## جدول استراتيجية المعالجة
| الضابط | المالك |
|---|---|
| خطة استمرارية الأعمال | مالك المخاطر |
| بناء SOC/SIEM | CISO |
"""

_RAW_EMPTY = ''
_RAW_GARBAGE = 'نص عشوائي بدون بنية مخاطر واضحة.\n'


def _compile(raw):
    return compile_risk_native_artifact(
        raw, domain='erm', document_type='risk', lang='ar', context=_CTX,
        route='t', emit=False)


def _render_tree(md):
    return RenderTree(artifact_id='risk-1', canonical_hash='c' * 16,
                      render_tree_hash='r' * 16, nodes=[], markdown_view=md)


def _docx_backend():
    return {'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


def _pdf_backend():
    return {'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
            'split_sections': lambda _c: {}, 'document_type': 'risk'}


class CompilerStructureTests(unittest.TestCase):

    def test_strategy_input_compiles_risk_native(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        self.assertTrue(out['compiler_passed'], out['blocking_errors'])
        self.assertEqual(detect_forbidden_strategy_sections(out['content']), [])

    def test_roadmap_and_strategy_sections_discarded(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        c = out['content']
        for h in ('الرؤية والأهداف', 'الركائز الاستراتيجية', 'خارطة الطريق',
                  'مؤشرات الأداء الرئيسية', 'نموذج الحوكمة', 'مصفوفة تتبع'):
            self.assertNotIn('## ' + h, c, h)

    def test_cyber_primary_not_in_output(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        c = out['content']
        for m in ('CISO', 'SOC/SIEM', 'SIEM', 'CSIRT', 'IAM/PAM',
                  'حوكمة الأمن السيبراني', 'مركز العمليات الأمنية'):
            self.assertNotIn(m, c, m)

    def test_no_forbidden_final_headings(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        self.assertEqual(out['diag']['forbidden_final_headings_detected'], [])

    def test_min_register_rows(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        self.assertGreaterEqual(out['register_rows'], MIN_REGISTER_ROWS)

    def test_min_treatment_rows(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        self.assertGreaterEqual(out['treatment_rows'], MIN_TREATMENT_ROWS)

    def test_min_kri_rows(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        self.assertGreaterEqual(out['kri_rows'], MIN_KRI_ROWS)

    def test_empty_raw_compiles_with_fallback(self):
        out = _compile(_RAW_EMPTY)
        self.assertTrue(out['compiler_passed'])
        self.assertGreaterEqual(out['register_rows'], MIN_REGISTER_ROWS)
        self.assertGreaterEqual(out['treatment_rows'], MIN_TREATMENT_ROWS)
        self.assertGreaterEqual(out['kri_rows'], MIN_KRI_ROWS)

    def test_garbage_raw_compiles_risk_native(self):
        out = _compile(_RAW_GARBAGE)
        self.assertTrue(out['compiler_passed'])
        self.assertEqual(detect_forbidden_strategy_sections(out['content']), [])

    def test_diag_reports_extraction_and_fallback(self):
        out = _compile(_RAW_STRATEGY_CYBER)
        d = out['diag']
        self.assertIn('الرؤية والأهداف الاستراتيجية',
                      ' | '.join(d['raw_strategy_sections_detected']))
        self.assertTrue(d['raw_cyber_primary_terms_detected'])
        self.assertGreater(d['generated_fallback_treatment_rows']
                           + d['extracted_treatment_rows'], 0)


class CompilerGatePassTests(unittest.TestCase):
    """Compiled output passes isolation, frozen completeness, treatment ev."""

    def setUp(self):
        self.out = _compile(_RAW_STRATEGY_CYBER)
        self.secs = self.out['sections']

    def test_passes_risk_domain_isolation(self):
        blockers = evaluate_pre_export_bytes_domain_guard(
            self.secs, domain='erm', route='docx', document_type='risk')
        self.assertEqual(blockers, [], blockers)

    def test_passes_frozen_completeness(self):
        ok, present, missing = evaluate_risk_sections_complete(self.secs)
        self.assertTrue(ok, missing)

    def test_passes_treatment_evidence(self):
        rk, tk = count_treatment_rows_from_sections(self.secs)
        sem = semantic_risk_treatment_counts(self.secs)
        self.assertGreater(int(tk) + int(sem.get('treatment_rows') or 0), 0)


class CompilerExportTests(unittest.TestCase):
    """Compiled content exports DOCX/PDF with no vision/roadmap blockers."""

    def setUp(self):
        self.content = _compile(_RAW_STRATEGY_CYBER)['content']

    def test_docx_export_passes(self):
        res = export_docx(_render_tree(self.content), backend=_docx_backend(),
                          domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'PK-docx')
        for b in res.blocking_errors:
            self.assertNotIn(':vision:', b)

    def test_pdf_export_passes(self):
        res = export_pdf(_render_tree(self.content), backend=_pdf_backend(),
                         domain='erm', document_type='risk')
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'%PDF-bytes')

    def test_no_roadmap_model_drift_for_risk(self):
        from release_engine.export_evidence_validator import (
            validate_actual_export_evidence,
        )
        out = validate_actual_export_evidence(
            docx_text=self.content, domain='erm', lang='ar',
            document_type='risk', route_name='docx',
            canonical_sections=_compile(_RAW_STRATEGY_CYBER)['sections'])
        blk = out.get('blocking_errors') or []
        self.assertFalse(any('roadmap_visible_row_count' in b for b in blk), blk)
        self.assertFalse(any(':vision:' in b for b in blk), blk)


class CompilerExportPrepTests(unittest.TestCase):
    """Export-prep resolver receives compiled content and passes."""

    def test_resolver_on_compiled_content_passes(self):
        content = _compile(_RAW_STRATEGY_CYBER)['content']

        def _load(rid, uid):
            return {'id': rid, 'analysis': content,
                    'domain': 'Enterprise Risk Management',
                    'document_type': 'risk'}

        out = resolve_rel33_risk_export_artifact(
            artifact_id=1, risk_id=1, user_id=1,
            domain='Enterprise Risk Management', route='docx',
            client_content='', load_risk_row=_load,
            load_strategy_risk_row=lambda a, u, domain='': None,
            assemble_sections=lambda s: '\n\n'.join(str(v) for v in s.values()),
            normalize_domain_fn=lambda d: normalize_domain_code(d, default='') or d)
        self.assertTrue(out['content'].strip())
        self.assertTrue(out.get('export_prep_contract_passed'))
        self.assertEqual(
            detect_forbidden_strategy_sections(out['content']), [])


if __name__ == '__main__':
    unittest.main()
