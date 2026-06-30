"""Foundation tests for Enterprise Final Document Factory."""

from __future__ import annotations

import unittest

from release_engine.traceability_substance_model import TRACE_CANONICAL_REGISTRY
from release_engine_v3.document_excellence_gate import DocumentExcellenceGate
from release_engine_v3.factory import CanonicalDocumentFactory, DocumentRequestContext
from release_engine_v3.factory.post_render_guard import (
    verify_immutable_traceability_routes,
)
from release_engine_v3.golden_matrix import GOLDEN_MATRIX, matrix_cases
from release_engine_v3.registries.platform_registries import (
    immutable_traceability_row,
    normalize_canonical_family,
    resolve_registries,
)


class TestRegistryUnification(unittest.TestCase):
    def test_sensitive_handling_alias_resolves(self):
        self.assertEqual(
            normalize_canonical_family('sensitive_data_handling'),
            'sensitive_handling',
        )

    def test_immutable_sensitive_handling_row(self):
        row = immutable_traceability_row('sensitive_data_handling')
        self.assertIsNotNone(row)
        self.assertEqual(row['capability'], 'معالجة البيانات الحساسة')
        self.assertEqual(row['gap'], 'ضعف معالجة البيانات الحساسة')
        self.assertNotIn('تصنيف وجرد', row['gap'])

    def test_all_trace_registry_rows_immutable(self):
        for fam in TRACE_CANONICAL_REGISTRY:
            row = immutable_traceability_row(fam)
            self.assertIsNotNone(row, msg=fam)
            self.assertEqual(row['gap'], TRACE_CANONICAL_REGISTRY[fam]['expected_gap'])


class TestDocumentExcellenceGate(unittest.TestCase):
    def test_evaluate_returns_platform_scores(self):
        result = DocumentExcellenceGate.evaluate(
            legacy_sections={'vision': 'test'},
            domain='cyber',
            document_type='strategy',
            lang='ar',
        )
        for key in (
                'passed', 'quality_score', 'consulting_grade_score',
                'executive_readiness_score', 'content_substance_score',
                'blocking_errors', 'export_route_results'):
            self.assertIn(key, result)

    def test_pdf_fails_when_docx_traceability_fails(self):
        spec = TRACE_CANONICAL_REGISTRY['sensitive_handling']
        bad_gap = 'ضعف تصنيف وجرد البيانات الحساسة'
        good_cap = spec['capability']
        docx_blob = (
            f'الإطار المرجعي\nمجال القدرة\nالفجوة\n'
            f'NCA DCC\n{good_cap}\n{bad_gap}\n'
        )
        pdf_blob = docx_blob
        guard = verify_immutable_traceability_routes(
            docx_text=docx_blob, pdf_text=pdf_blob)
        self.assertFalse(guard['passed'])
        self.assertTrue(
            any('pdf_traceability_semantic_bypass' in e
                for e in guard['blocking_errors'])
            or any(
                'sensitive_handling' in e
                or 'trace_gap' in e
                or 'rel32_traceability_post_render_mutation' in e
                for e in guard['blocking_errors']))


class TestCanonicalDocumentFactory(unittest.TestCase):
    def test_compile_confidence_maturity_trajectory_deterministic(self):
        from release_engine_v3.rel32_compiler import (
            compile_canonical_strategy_document,
        )
        compiled = compile_canonical_strategy_document(
            {'confidence': 'درجة الثقة: 76%'},
            request_context={
                'lang': 'ar',
                'domain': 'cyber',
                'maturity_level': 'developing',
                'roadmap_horizon_months': 18,
            },
        )
        conf = (compiled.legacy_sections or {}).get('confidence') or ''
        self.assertIn('مستوى النضج الحالي', conf)
        self.assertIn('مستوى النضج المستهدف', conf)
        self.assertIn('خلال 18 شهر', conf)

    def test_compile_cyber_strategy_ar(self):
        factory = CanonicalDocumentFactory()
        ctx = DocumentRequestContext(
            domain='cyber',
            document_type='strategy',
            lang='ar',
            flags={'rel3': True, 'rel31': True, 'rel32': True},
        )
        sections = {
            'vision': '## الرؤية\n\nنص',
            'gaps': '## الفجوات\n\n| # | الفجوة | الوصف | الأولوية | الحالة |\n',
        }
        result = factory.compile(
            sections,
            domain='cyber',
            document_type='strategy',
            lang='ar',
            request_context=ctx,
        )
        self.assertTrue(result.legacy_sections)
        rows = result.export_evidence.get('immutable_traceability_rows') or []
        sh = next(
            (r for r in rows if r and r.get('family') == 'sensitive_handling'),
            None)
        if sh:
            self.assertEqual(sh['gap'], 'ضعف معالجة البيانات الحساسة')

    def test_resolve_registries_per_domain(self):
        for domain in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
            bundle = resolve_registries(
                domain=domain, document_type='strategy', lang='ar')
            self.assertEqual(bundle['domain'], domain)
            self.assertIn('traceability', bundle)


class TestGoldenMatrix(unittest.TestCase):
    def test_matrix_covers_required_domains(self):
        domains = {c['domain'] for c in GOLDEN_MATRIX}
        for required in ('cyber', 'data', 'ai', 'dt', 'erm', 'global'):
            self.assertIn(required, domains)

    def test_p0_cyber_strategy_present(self):
        p0 = matrix_cases(tier='P0')
        self.assertTrue(any(
            c['domain'] == 'cyber' and c['document_type'] == 'strategy'
            for c in p0))


if __name__ == '__main__':
    unittest.main()
