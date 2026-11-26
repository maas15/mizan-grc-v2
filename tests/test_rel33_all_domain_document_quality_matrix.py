"""PR-REL3.3 — all-domain document quality matrix tests."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_authority import (
    REL33_AUTHORITATIVE_DOMAINS,
    REL33_P1_ROUTES,
    is_rel33_compiler_first,
    is_rel33_domain_authoritative,
)
from release_engine_v3.rel33_quality_matrix import (
    build_rel33_matrix_cases,
    emit_rel33_matrix_report,
    ensure_test_env,
    run_rel33_quality_case,
    run_rel33_quality_matrix,
)

ensure_test_env()


class Rel33AuthorityTests(unittest.TestCase):

    def test_all_required_domains_authoritative(self):
        flags = {'rel3': True, 'rel31': True}
        for domain in REL33_AUTHORITATIVE_DOMAINS:
            self.assertTrue(
                is_rel33_domain_authoritative(
                    domain=domain, lang='ar', flags=flags),
                msg=domain,
            )

    def test_compiler_first_strategy_all_domains(self):
        flags = {'rel3': True, 'rel31': True}
        for domain in REL33_AUTHORITATIVE_DOMAINS:
            self.assertTrue(
                is_rel33_compiler_first(
                    domain=domain, lang='ar', flags=flags,
                    document_type='strategy'),
                msg=domain,
            )

    def test_compiler_first_not_policy(self):
        flags = {'rel3': True, 'rel31': True}
        self.assertFalse(
            is_rel33_compiler_first(
                domain='cyber', lang='ar', flags=flags,
                document_type='policy'))


class Rel33QualityMatrixTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from release_engine_v3.rel33_quality_matrix import _load_app_module
        # This is a mandatory export gate: an application that cannot load
        # cannot satisfy it by skipping the entire class.
        cls._app = _load_app_module()
        cls._report = None

    @classmethod
    def _matrix_report(cls):
        # Assertions share one real full-matrix execution within this class.
        if cls._report is None:
            cls._report = run_rel33_quality_matrix(app_mod=cls._app)
        return cls._report

    def test_matrix_cases_cover_required_domains(self):
        cases = build_rel33_matrix_cases()
        domains = {c['domain'] for c in cases}
        for domain in REL33_AUTHORITATIVE_DOMAINS:
            self.assertIn(domain, domains)

    def test_cyber_strategy_ar_accepted(self):
        case = {
            'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar',
            'doc_subtype': 'technical', 'tier': 'P0',
        }
        row = run_rel33_quality_case(case, app_mod=self._app)
        self.assertTrue(row['compiler_first'], row.get('blockers'))
        self.assertTrue(row['completeness_gate_passed'], row.get('blockers'))
        self.assertTrue(row['preview_dom_binding_passed'], row.get('blockers'))
        self.assertTrue(row['frozen_export_lock_passed'], row.get('blockers'))
        self.assertTrue(row['docx_returned_file_evidence_passed'])
        self.assertTrue(row['pdf_returned_file_evidence_passed'])
        self.assertTrue(row['canonical_hash_equal'])
        self.assertTrue(row['render_tree_hash_equal'])
        self.assertFalse(row['legacy_path_used'])
        self.assertTrue(row['accepted'], row.get('blockers'))

    def test_strategy_domains_compile_through_factory(self):
        flags = {'rel3': True, 'rel31': True, 'rel32': True}
        from release_engine_v3.factory import (
            CanonicalDocumentFactory,
            DocumentRequestContext,
        )
        factory = CanonicalDocumentFactory()
        for domain in ('data', 'ai', 'dt', 'erm', 'global'):
            from domains._registry import get_domain_pack
            pack = get_domain_pack(domain)
            sections = dict(pack['fixtures_ar'].technical_sections())
            ctx = DocumentRequestContext(
                domain=domain,
                document_type='strategy',
                lang='ar',
                flags=flags,
            )
            result = factory.compile(
                sections,
                domain=domain,
                document_type='strategy',
                lang='ar',
                request_context=ctx,
            )
            self.assertTrue(result.legacy_sections, msg=domain)

    def test_full_matrix_report_emits_tag(self):
        from release_engine_v3.golden_matrix import GOLDEN_MATRIX

        report = self._matrix_report()
        self.assertEqual(
            report['tag'], 'REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX')
        identity = lambda c: (
            c['domain'], c['document_type'], c.get('lang', 'ar'),
            c.get('doc_subtype', ''))
        # Compare with the registered catalog independently of the runner's
        # case builder, so a silently omitted case cannot disappear twice.
        expected = [
            (c['domain'], c['document_type'], c['lang'],
             'technical' if (c['domain'], c['document_type']) ==
             ('cyber', 'strategy') else c.get('doc_subtype', ''))
            for c in GOLDEN_MATRIX if c['lang'] == 'ar']
        self.assertCountEqual(
            [identity(c) for c in build_rel33_matrix_cases()], expected)
        actual = [identity(r) for r in report['rows']]
        self.assertIn(('dt', 'governance_model', 'ar', ''), expected)
        self.assertEqual(len(expected), len(set(expected)), 'duplicate cases')
        self.assertCountEqual(actual, expected)
        self.assertEqual(report['matrix_size'], len(expected))
        failures = [
            (identity(r), r.get('blockers')) for r in report['rows']
            if not r.get('accepted')]
        self.assertEqual(failures, [], 'full matrix must accept every row')
        self.assertTrue(report['all_rows_accepted'])
        self.assertEqual(report['accepted_count'], len(expected))

    def test_p1_strategy_routes_accepted(self):
        if os.environ.get('REL33_MATRIX_STRICT_P1') != '1':
            self.skipTest('REL33_MATRIX_STRICT_P1 not set')
        report = self._matrix_report()
        p1_strategy = [
            r for r in report['rows']
            if r.get('tier') == 'P1' and r.get('document_type') == 'strategy']
        for row in p1_strategy:
            self.assertTrue(row['accepted'], (row.get('route_key'), row.get('blockers')))

    def test_matrix_json_serializable(self):
        report = self._matrix_report()
        blob = json.dumps(report, ensure_ascii=False, default=str)
        self.assertIn('REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX', blob)


class Rel33P1RouteParamTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from release_engine_v3.rel33_quality_matrix import _load_app_module
        cls._app = _load_app_module()

    def test_p1_route_definitions(self):
        self.assertGreaterEqual(len(REL33_P1_ROUTES), 6)


if __name__ == '__main__':
    unittest.main()
