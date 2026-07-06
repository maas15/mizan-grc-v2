"""REL3.3 P0 — export artifact load, risk treatment, gap_assessment gates."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_p0_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_document_gates import (
    audit_gap_assessment_sections,
    build_gate_routing_diag,
    strategy_gates_enabled,
)
from release_engine_v3.rel33_export_artifact import (
    resolve_rel33_complete_export_artifact,
    sections_dict_export_complete,
)
from release_engine_v3.rel33_gap_assessment_completeness import (
    emit_rel33_gap_assessment_completeness,
    repair_and_audit_gap_assessment,
    repair_gap_assessment_sections,
)
from release_engine_v3.rel33_domain_guard import (
    evaluate_export_domain_guard,
    filter_compiler_first_contamination,
)
from release_engine_v3.rel33_risk_artifact import resolve_rel33_risk_export_artifact
from release_engine_v3.rel33_risk_treatment_evidence import (
    evaluate_erm_risk_treatment_evidence,
    risk_treatment_defects_for_channel,
)

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _exc:  # noqa: BLE001
    raise SystemExit(f'Cannot load app: {_exc!r}')


def _strategy_sections(domain: str = 'data') -> dict:
    from domains._registry import get_domain_pack
    pack = get_domain_pack(domain)
    return dict(pack['fixtures_ar'].technical_sections())


def _assemble(sections: dict) -> str:
    return _APP._assemble_canonical_from_sections(sections)


class Rel33ExportArtifactTests(unittest.TestCase):

    def test_sections_dict_export_complete_data(self):
        secs = _strategy_sections('data')
        self.assertTrue(sections_dict_export_complete(secs))

    def test_resolve_loads_complete_sections_not_client_fragment(self):
        bundle = {
            'sections': _strategy_sections('data'),
            'contract_meta': {'domain': 'data', 'lang': 'ar'},
            'content_json': {},
            'final_hash': 'abc123',
            'sealed': True,
        }

        def _load(_sid, _uid):
            return bundle

        prep = resolve_rel33_complete_export_artifact(
            artifact_type='strategy',
            artifact_id=42,
            strategy_id=42,
            user_id=1,
            domain='data',
            document_type='strategy',
            route='docx-async',
            client_content='## kpis only fragment',
            load_bundle=_load,
            assemble_sections=_assemble,
            is_fragment=_APP._is_strategy_export_fragment,
            split_content=_APP._split_strategy_sections_by_h2,
        )
        self.assertTrue(prep['skip_fragment_gate'])
        self.assertTrue(prep['content'].strip())
        self.assertTrue(prep['diag']['complete_artifact_loaded'])
        self.assertFalse(prep['diag']['client_content_used_as_authority'])

    def test_data_ai_dt_domains_complete(self):
        for domain in ('data', 'ai', 'dt'):
            secs = _strategy_sections(domain)
            self.assertTrue(
                sections_dict_export_complete(secs), msg=domain)

    def test_sealed_stored_content_authority_over_client_fragment(self):
        secs = _strategy_sections('data')
        full = _assemble(secs)
        bundle = {
            'sections': {},
            'content': full,
            'stored_content': full,
            'contract_meta': {'domain': 'data', 'lang': 'ar', 'sealed': True},
            'final_hash': 'deadbeef',
            'sealed': True,
            'content_json': {},
        }

        def _load(_sid, _uid):
            return bundle

        prep = resolve_rel33_complete_export_artifact(
            artifact_type='strategy',
            artifact_id=7,
            strategy_id=7,
            user_id=1,
            domain='data',
            document_type='strategy',
            route='docx-async',
            client_content='## confidence only',
            load_bundle=_load,
            assemble_sections=_assemble,
            is_fragment=_APP._is_strategy_export_fragment,
            split_content=_APP._split_strategy_sections_by_h2,
        )
        self.assertTrue(prep['skip_fragment_gate'])
        self.assertIn(
            prep['diag']['loaded_from'],
            ('sealed_db_authority', 'strategies.content'))
        self.assertFalse(prep['diag']['client_content_used_as_authority'])

    def test_async_docx_diag_emitted_for_data_ai_dt(self):
        for domain in ('data', 'ai', 'dt'):
            bundle = {
                'sections': _strategy_sections(domain),
                'contract_meta': {'domain': domain, 'lang': 'ar'},
                'content_json': {},
                'final_hash': f'hash_{domain}',
                'sealed': True,
            }

            def _load(_sid, _uid, _b=bundle):
                return _b

            buf = io.StringIO()
            with redirect_stdout(buf):
                resolve_rel33_complete_export_artifact(
                    artifact_type='strategy',
                    artifact_id=1,
                    strategy_id=1,
                    user_id=1,
                    domain=domain,
                    document_type='strategy',
                    route='docx-async',
                    client_content='fragment',
                    load_bundle=_load,
                    assemble_sections=_assemble,
                    is_fragment=_APP._is_strategy_export_fragment,
                    split_content=_APP._split_strategy_sections_by_h2,
                )
            out = buf.getvalue()
            self.assertIn('[REL33-EXPORT-COMPLETE-ARTIFACT-LOAD]', out, msg=domain)
            diag = json.loads(out.split('[REL33-EXPORT-COMPLETE-ARTIFACT-LOAD] ')[1])
            self.assertTrue(diag['complete_artifact_loaded'], msg=domain)

    def test_client_content_authority_fails_when_no_db_artifact(self):
        def _load(_sid, _uid):
            return {}

        prep = resolve_rel33_complete_export_artifact(
            artifact_type='strategy',
            artifact_id=99,
            strategy_id=99,
            user_id=1,
            domain='data',
            document_type='strategy',
            route='docx-async',
            client_content='## kpis\nonly two sections',
            load_bundle=_load,
            assemble_sections=_assemble,
            is_fragment=_APP._is_strategy_export_fragment,
            split_content=_APP._split_strategy_sections_by_h2,
        )
        self.assertFalse(prep['skip_fragment_gate'])
        self.assertTrue(prep['diag']['client_content_used_as_authority'])


class Rel33RiskTreatmentTests(unittest.TestCase):

    def _risk_sections(self) -> dict:
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        return dict(REL33_TYPE_FIXTURES_AR['risk'])

    def test_docx_extracts_treatment_from_artifact_sections(self):
        sections = self._risk_sections()
        flat = '\n'.join(sections.values())
        diag = evaluate_erm_risk_treatment_evidence(
            flat, route='docx', canonical_sections=sections)
        self.assertGreater(diag['treatment_rows_count'], 0)
        self.assertGreater(diag['docx_treatment_rows_extracted'], 0)
        self.assertFalse(diag['empty_risk_treatment'])
        self.assertEqual(diag['blocking_errors'], [])

    def test_pdf_and_docx_same_artifact_rows(self):
        sections = self._risk_sections()
        blob = '\n'.join(sections.values())
        docx = evaluate_erm_risk_treatment_evidence(
            blob, route='docx', canonical_sections=sections)
        pdf = evaluate_erm_risk_treatment_evidence(
            blob, route='pdf', canonical_sections=sections)
        self.assertEqual(
            docx['treatment_rows_count'], pdf['treatment_rows_count'])
        self.assertFalse(risk_treatment_defects_for_channel(
            blob, route='docx', document_type='risk',
            canonical_sections=sections))

    def test_risk_treatment_diag_emitted(self):
        sections = self._risk_sections()
        blob = '\n'.join(sections.values())
        buf = io.StringIO()
        with redirect_stdout(buf):
            risk_treatment_defects_for_channel(
                blob, route='docx', document_type='risk',
                canonical_sections=sections)
        self.assertIn('[REL33-RISK-TREATMENT-EVIDENCE]', buf.getvalue())


class Rel33GapAssessmentGateTests(unittest.TestCase):

    def test_gap_assessment_skips_strategy_gates(self):
        diag = build_gate_routing_diag(
            domain='global',
            document_type='gap_assessment',
            route='save',
            document_type_source='parameter',
        )
        self.assertFalse(diag['strategy_gates_enabled'])
        self.assertTrue(diag['gap_assessment_gates_enabled'])
        self.assertFalse(diag['selected_framework_objective_required'])

    def test_gap_assessment_audit_passes_valid_fixture(self):
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['gap_assessment'])
        sections['_document_type'] = 'gap_assessment'
        defects = audit_gap_assessment_sections(
            sections,
            selected_frameworks=['ISO27001', 'NIST_CSF'],
            lang='ar',
            domain='global',
        )
        self.assertEqual(defects, [])

    def test_strategy_still_requires_strategy_gates(self):
        self.assertTrue(strategy_gates_enabled('strategy'))

    def test_missing_scope_repaired_before_audit(self):
        sections = {'vision': '## Vision\nshould not gate', 'gaps': ''}
        repaired = repair_gap_assessment_sections(
            sections,
            selected_frameworks=['ISO27001', 'NIST_CSF'],
            domain='global',
            lang='ar',
        )
        self.assertTrue((repaired.get('scope') or '').strip())
        self.assertGreater(
            sum(1 for ln in (repaired.get('gaps') or '').splitlines()
                if ln.strip().startswith('|') and '---' not in ln), 0)
        self.assertTrue((repaired.get('remediation') or '').strip())

    def test_repair_and_audit_clears_gap_blockers(self):
        sections = {'_document_type': 'gap_assessment', 'gaps': ''}
        repaired, defects = repair_and_audit_gap_assessment(
            sections,
            selected_frameworks=['ISO27001', 'NIST_CSF'],
            domain='global',
            lang='ar',
        )
        tags = {d[1] for d in defects}
        self.assertNotIn('gap_scope_missing', tags)
        self.assertNotIn('gap_remediation_missing', tags)
        self.assertTrue((repaired.get('scope') or '').strip())

    def test_gap_completeness_diagnostic_fields(self):
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['gap_assessment'])
        buf = io.StringIO()
        with redirect_stdout(buf):
            diag = emit_rel33_gap_assessment_completeness(
                sections,
                domain='global',
                selected_frameworks=['ISO27001', 'NIST_CSF'],
                blocking_errors=[],
            )
        self.assertTrue(diag['scope_present'])
        self.assertGreater(diag['gap_rows_count'], 0)
        self.assertGreater(diag['remediation_rows_count'], 0)
        self.assertFalse(diag['strategy_gates_enabled'])
        self.assertTrue(diag['gap_assessment_gates_enabled'])
        self.assertEqual(diag['blocking_errors'], [])
        self.assertIn('[REL33-GAP-ASSESSMENT-COMPLETENESS]', buf.getvalue())
        self.assertIn('phase', diag)
        self.assertIn('repair_applied', diag)


class Rel33CyberBaselineTests(unittest.TestCase):

    def test_cyber_strategy_fixture_complete(self):
        secs = _strategy_sections('cyber')
        self.assertTrue(sections_dict_export_complete(secs))


class Rel33DomainGuardTests(unittest.TestCase):

    def _domain_ctx(self, domain: str):
        return _APP.get_strategy_domain_context(domain, lang='ar')

    def test_data_allowed_control_reference_in_gaps(self):
        sections = _strategy_sections('data')
        sections['gaps'] = (
            '## Gaps\n\n| # | Gap | Control ref |\n|---|---|---|\n'
            '| 1 | IAM gap | NCA ECC control mapping |\n'
        )
        raw = _APP.validate_domain_isolation(
            sections, self._domain_ctx('data'))
        filtered = filter_compiler_first_contamination(
            raw, domain_code='data', sections=sections)
        self.assertEqual(filtered, [])

    def test_data_cyber_canonical_vision_still_blocks(self):
        from domains.cyber.fixtures_ar import technical_sections as cyber_secs
        sections = dict(cyber_secs())
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(_APP.DomainContaminationError):
                evaluate_export_domain_guard(
                    sections,
                    domain='Data Management',
                    language='ar',
                    artifact_type='strategy',
                    artifact_id=99,
                    route='data:strategy:ar',
                    validate_fn=_APP.validate_domain_isolation,
                    domain_context_fn=_APP.get_strategy_domain_context,
                    normalize_domain_fn=_APP.normalize_domain,
                    contamination_error_cls=_APP.DomainContaminationError,
                )
        self.assertIn('[REL33-DOMAIN-GUARD-DECISION]', buf.getvalue())

    def test_domain_guard_diag_emitted_on_pass(self):
        sections = _strategy_sections('data')
        buf = io.StringIO()
        with redirect_stdout(buf):
            diag = evaluate_export_domain_guard(
                sections,
                domain='Data Management',
                language='ar',
                artifact_type='strategy',
                artifact_id=2,
                route='data:strategy:ar',
                validate_fn=_APP.validate_domain_isolation,
                domain_context_fn=_APP.get_strategy_domain_context,
                normalize_domain_fn=_APP.normalize_domain,
                contamination_error_cls=_APP.DomainContaminationError,
            )
        self.assertTrue(diag['domain_guard_passed'])
        self.assertIn('[REL33-DOMAIN-GUARD-DECISION]', buf.getvalue())


class Rel33RiskArtifactTests(unittest.TestCase):

    def _risk_row(self) -> dict:
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['risk'])
        content = '\n\n'.join(sections.values())
        return {
            'id': 42,
            'content': content,
            'analysis': content,
            'sections': sections,
            'domain': 'Enterprise Risk Management',
        }

    def test_risk_loads_from_risks_table_not_strategy(self):
        row = self._risk_row()

        def _load_risk(rid, uid):
            return row if int(rid) == 42 else None

        def _load_strategy(sid, uid, domain=''):
            return {'id': 1, 'domain': 'Cyber Security', 'document_type': 'strategy',
                    'sections': {}, 'content': 'cyber'}

        buf = io.StringIO()
        with redirect_stdout(buf):
            prep = resolve_rel33_risk_export_artifact(
                artifact_id=42,
                risk_id=42,
                user_id=1,
                domain='Enterprise Risk Management',
                route='erm:risk:ar',
                load_risk_row=_load_risk,
                load_strategy_risk_row=_load_strategy,
                assemble_sections=_APP._assemble_risk_from_sections,
                normalize_domain_fn=_APP.normalize_domain,
            )
        self.assertGreater(prep['diag']['treatment_rows_count'], 0)
        self.assertFalse(prep['diag']['artifact_id_collision_detected'])
        self.assertEqual(prep['diag']['source_table_or_store'], 'risks')
        self.assertIn('[REL33-RISK-ARTIFACT-LOAD]', buf.getvalue())

    def test_cyber_strategy_id_collision_detected(self):
        def _load_risk(rid, uid):
            return None

        def _load_strategy(sid, uid, domain=''):
            return {'id': 1, 'domain': 'Cyber Security', 'document_type': 'strategy',
                    'sections': {}, 'content': 'cyber'}

        prep = resolve_rel33_risk_export_artifact(
            artifact_id=1,
            risk_id=1,
            user_id=1,
            domain='Enterprise Risk Management',
            route='erm:risk:ar',
            load_risk_row=_load_risk,
            load_strategy_risk_row=_load_strategy,
            assemble_sections=_APP._assemble_risk_from_sections,
            normalize_domain_fn=_APP.normalize_domain,
        )
        self.assertTrue(prep['diag']['artifact_id_collision_detected'])

    def test_docx_evidence_passes_with_canonical_rows_only(self):
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['risk'])
        diag = evaluate_erm_risk_treatment_evidence(
            '', route='docx', canonical_sections=sections)
        self.assertFalse(diag['empty_risk_treatment'])
        self.assertEqual(diag['blocking_errors'], [])


class Rel33GapPreAuditTests(unittest.TestCase):

    def test_pre_final_audit_repair_clears_blockers(self):
        sections = {'_document_type': 'gap_assessment', 'gaps': ''}
        buf = io.StringIO()
        with redirect_stdout(buf):
            repaired, defects = repair_and_audit_gap_assessment(
                sections,
                selected_frameworks=['ISO27001', 'NIST_CSF'],
                domain='global',
                lang='ar',
                phase='pre_final_audit',
            )
        tags = {d[1] for d in defects}
        self.assertNotIn('gap_scope_missing', tags)
        self.assertNotIn('gap_remediation_missing', tags)
        self.assertTrue((repaired.get('scope') or '').strip())
        self.assertTrue((repaired.get('remediation') or '').strip())
        out = buf.getvalue()
        self.assertIn('[REL33-GAP-ASSESSMENT-COMPLETENESS]', out)
        _line = out.split('[REL33-GAP-ASSESSMENT-COMPLETENESS] ')[1].split('\n')[0]
        diag = json.loads(_line)
        self.assertEqual(diag['phase'], 'pre_final_audit')
        self.assertTrue(diag['repair_applied'])
        self.assertTrue(diag['repaired_sections_persisted'])


class Rel33AcceptanceScriptRiskTests(unittest.TestCase):

    def test_risk_poll_endpoint_and_export_payload(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rel33_accept',
            ROOT / 'scripts' / '_rel33_all_domain_staging_acceptance.py',
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(
            mod._poll_endpoint_for('risk'), '/api/risk-status')
        self.assertEqual(
            mod._poll_endpoint_for('strategy'), '/api/strategy-status')
        case = {'domain': 'erm', 'document_type': 'risk', 'lang': 'ar'}
        payload = {}
        artifact_id = 42
        dtype = case['document_type']
        if dtype == 'risk':
            payload['risk_id'] = artifact_id
            payload['artifact_id'] = artifact_id
        else:
            payload['strategy_id'] = artifact_id
        self.assertEqual(payload.get('risk_id'), 42)
        self.assertNotIn('strategy_id', payload)


class Rel33DomainGuardGapTests(unittest.TestCase):

    def test_gap_assessment_skips_domain_guard(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            diag = evaluate_export_domain_guard(
                {'scope': '## Scope\nCISO CSIRT NCA ECC'},
                domain='Global',
                language='ar',
                artifact_type='gap_assessment',
                artifact_id=5,
                document_type='gap_assessment',
                route='global:gap_assessment:ar',
                validate_fn=_APP.validate_domain_isolation,
                domain_context_fn=_APP.get_strategy_domain_context,
                normalize_domain_fn=_APP.normalize_domain,
                contamination_error_cls=_APP.DomainContaminationError,
            )
        self.assertTrue(diag['domain_guard_passed'])
        out = buf.getvalue()
        self.assertIn('[REL33-DOMAIN-GUARD-DECISION]', out)
        self.assertIn('allowed_reference_terms', out)

    def test_data_flattened_reference_terms_allowed(self):
        sections = _strategy_sections('data')
        blob = '\n\n'.join(sections.values())
        blob += '\n## Gaps\n| # | Gap | Control |\n| 1 | IAM | NCA ECC |\n'
        raw = _APP.validate_domain_isolation(
            {'flattened': blob}, self._domain_ctx('data'))
        filtered = filter_compiler_first_contamination(
            raw, domain_code='data', sections={'flattened': blob})
        self.assertEqual(filtered, [])

    def _domain_ctx(self, domain: str):
        return _APP.get_strategy_domain_context(domain, lang='ar')


class Rel33FrozenCompletenessTests(unittest.TestCase):

    def test_risk_completeness_passes_with_treatment_rows(self):
        from release_engine_v3.rel33_frozen_completeness import (
            evaluate_frozen_completeness_by_document_type,
        )
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['risk'])
        buf = io.StringIO()
        with redirect_stdout(buf):
            complete, _, missing, diag = (
                evaluate_frozen_completeness_by_document_type(
                    document_type='risk',
                    artifact_type='risk',
                    artifact_id='42',
                    sections=sections,
                ))
        self.assertTrue(complete)
        self.assertNotIn('treatment_rows', missing)
        self.assertIn('[REL33-FROZEN-COMPLETENESS-BY-DOCUMENT-TYPE]', buf.getvalue())
        self.assertTrue(diag['complete_for_document_type'])

    def test_gap_assessment_completeness_passes(self):
        from release_engine_v3.rel33_frozen_completeness import (
            evaluate_frozen_completeness_by_document_type,
        )
        from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
        sections = dict(REL33_TYPE_FIXTURES_AR['gap_assessment'])
        complete, _, missing, diag = evaluate_frozen_completeness_by_document_type(
            document_type='gap_assessment',
            artifact_type='gap_assessment',
            artifact_id='5',
            sections=sections,
        )
        self.assertTrue(complete)
        self.assertFalse(missing)
        self.assertTrue(diag['complete_for_document_type'])

    def test_cyber_strategy_frozen_lock_unchanged(self):
        from release_engine_v3.rel32_frozen_export_lock import (
            _frozen_export_complete,
        )
        from release_engine_v3.contracts import (
            CanonicalSection, ExportManifest, FinalDocumentArtifact,
        )
        frozen = FinalDocumentArtifact(
            artifact_id='1',
            strategy_id='1',
            domain='cyber',
            language='ar',
            document_type='strategy',
            strategy_type='technical',
            selected_frameworks=['NCA ECC'],
            quality_repairs=[],
            quality_results={},
            frozen=True,
            canonical_hash='abc',
            render_tree_hash='def',
            export_manifest=ExportManifest(
                canonical_hash='abc', render_tree_hash='def'),
            blocking_errors=[],
            release_ready_final_passed=True,
            legacy_sections={
                'traceability': '| row |',
                'gaps': '| gap |',
            },
            canonical_sections={'vision': CanonicalSection(
                key='vision', title='Vision', narrative='v')},
        )
        complete, missing = _frozen_export_complete(
            frozen, document_type='strategy')
        self.assertTrue(complete)
        self.assertEqual(missing, [])

    def test_risk_export_rejects_strategy_id_collision(self):
        def _load_risk(rid, uid):
            return None

        def _load_strategy(sid, uid, domain=''):
            return {'id': 1, 'domain': 'Cyber Security',
                    'document_type': 'strategy', 'sections': {}, 'content': 'x'}

        prep = resolve_rel33_risk_export_artifact(
            artifact_id=1,
            risk_id=None,
            user_id=1,
            domain='Enterprise Risk Management',
            route='erm:risk:ar',
            load_risk_row=_load_risk,
            load_strategy_risk_row=_load_strategy,
            assemble_sections=_APP._assemble_risk_from_sections,
            normalize_domain_fn=_APP.normalize_domain,
        )
        self.assertTrue(prep['diag']['artifact_id_collision_detected'])


class Rel33ExportFrameworkParityTests(unittest.TestCase):
    """Preview (/api/strategy/latest) and export must share framework context."""

    def test_selected_frameworks_relaxed_forbidden_list(self):
        ctx_no = _APP.get_strategy_domain_context('Data Management', lang='ar')
        ctx_yes = _APP.get_strategy_domain_context(
            'Data Management', lang='ar',
            selected_frameworks=['ISO 27001', 'NIST CSF'])
        self.assertGreaterEqual(
            len(ctx_no['forbidden_terms']), len(ctx_yes['forbidden_terms']))

    def test_db_row_frameworks_from_content_json(self):
        import json as _json
        row = {
            'document_type': 'strategy',
            'content_json': _json.dumps({
                'selected_frameworks': ['ISO 27001', 'NIST CSF'],
                'document_type': 'strategy',
            }),
            'sections_json': _json.dumps({'_document_type': 'strategy'}),
        }
        keys = row.keys()
        fws, dtype = _APP._db_row_frameworks_and_document_type(row, keys)
        self.assertEqual(fws, ['ISO 27001', 'NIST CSF'])
        self.assertEqual(dtype, 'strategy')

    def test_gap_db_load_without_frozen_blob(self):
        from unittest.mock import patch
        gap_sections = {
            'scope': '## Scope\n\nAssessment scope for ISO 27001.',
            'gaps': (
                '| # | Gap | Framework |\n|---|---|---|\n'
                '| 1 | IAM gap | ISO 27001 |\n'),
            'remediation': '| # | Action |\n|---|---|\n| 1 | Fix IAM |\n',
        }
        bundle = {
            'sections': gap_sections,
            'content': '',
            'document_type': 'gap_assessment',
            'contract_meta': {
                'document_type': 'gap_assessment',
                'domain': 'global',
                'lang': 'ar',
            },
            'domain': 'Global / Cross-Domain',
            'content_json': {},
        }
        with patch.object(
                _APP, '_load_sealed_strategy_export_bundle', return_value=bundle):
            loaded = _APP._rel3_load_artifact_from_db_for_export('5', user_id=1)
        self.assertEqual(loaded['document_type'], 'gap_assessment')
        self.assertIn('ISO 27001', loaded['final_markdown'])


if __name__ == '__main__':
    unittest.main()
