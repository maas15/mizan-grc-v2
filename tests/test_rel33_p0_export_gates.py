"""REL3.3 P0 — export artifact load, risk treatment, gap_assessment gates."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
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
            assemble_sections=_APP._assemble_canonical_from_sections,
            is_fragment=_APP._is_strategy_export_fragment,
        )
        self.assertTrue(prep['skip_fragment_gate'])
        self.assertTrue(prep['content'].strip())
        self.assertTrue(prep['diag']['complete_artifact_loaded'])
        self.assertFalse(prep['diag']['client_content_used_as_authority'])
        self.assertTrue(prep['diag']['sections_json_loaded'])

    def test_data_ai_dt_domains_complete(self):
        for domain in ('data', 'ai', 'dt'):
            secs = _strategy_sections(domain)
            self.assertTrue(
                sections_dict_export_complete(secs), msg=domain)


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


class Rel33CyberBaselineTests(unittest.TestCase):

    def test_cyber_strategy_fixture_complete(self):
        secs = _strategy_sections('cyber')
        self.assertTrue(sections_dict_export_complete(secs))


if __name__ == '__main__':
    unittest.main()
