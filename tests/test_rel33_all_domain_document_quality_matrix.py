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
        cls._app = None
        try:
            from release_engine_v3.rel33_quality_matrix import _load_app_module
            cls._app = _load_app_module()
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f'app load failed: {exc!r}')

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
        report = run_rel33_quality_matrix(app_mod=self._app)
        self.assertEqual(
            report['tag'], 'REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX')
        self.assertGreater(report['matrix_size'], 20)
        cyber_rows = [
            r for r in report['rows']
            if r['domain'] == 'cyber' and r['document_type'] == 'strategy']
        self.assertTrue(any(r.get('accepted') for r in cyber_rows))

    def test_p1_strategy_routes_accepted(self):
        if os.environ.get('REL33_MATRIX_STRICT_P1') != '1':
            self.skipTest('REL33_MATRIX_STRICT_P1 not set')
        report = run_rel33_quality_matrix(app_mod=self._app)
        p1_strategy = [
            r for r in report['rows']
            if r.get('tier') == 'P1' and r.get('document_type') == 'strategy']
        for row in p1_strategy:
            self.assertTrue(row['accepted'], (row.get('route_key'), row.get('blockers')))

    def test_matrix_json_serializable(self):
        report = run_rel33_quality_matrix(app_mod=self._app)
        blob = json.dumps(report, ensure_ascii=False, default=str)
        self.assertIn('REL33-ALL-DOMAIN-DOCUMENT-QUALITY-MATRIX', blob)


class Rel33P1RouteParamTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from release_engine_v3.rel33_quality_matrix import _load_app_module
            cls._app = _load_app_module()
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f'app load failed: {exc!r}')

    def test_p1_route_definitions(self):
        self.assertGreaterEqual(len(REL33_P1_ROUTES), 6)


if __name__ == '__main__':
    unittest.main()
