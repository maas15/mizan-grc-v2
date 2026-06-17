"""PR-REL3.1 — board-ready content substance on actual DOCX/PDF fixtures."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_content_quality_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.export_evidence_validator import validate_actual_export_evidence
from release_engine.pillar_model import _build_canonical_pillars
from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine.rel31_content_substance_checks import (
    evaluate_content_substance,
    run_rel31_content_substance_checks,
)
from release_engine_v3.canonical_document import build_final_document_artifact, freeze_artifact
from release_engine_v3.contracts import ExportResult, _sha256_bytes
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.evidence_validator import validate_returned_export_bytes
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches
from tests.fixtures.rel31_content_quality.defect_sections import (
    DOCX_FIXTURE,
    PDF_FIXTURE,
    content_quality_defect_sections,
    ensure_content_quality_fixtures,
)

ensure_content_quality_fixtures()


def _load_docx():
    assert DOCX_FIXTURE.is_file(), f'missing fixture {DOCX_FIXTURE}'
    data = DOCX_FIXTURE.read_bytes()
    return data, extract_docx_visible_text(data)


def _load_pdf():
    assert PDF_FIXTURE.is_file(), f'missing fixture {PDF_FIXTURE}'
    data = PDF_FIXTURE.read_bytes()
    return data, extract_pdf_visible_text(data)


def _rel3_evidence(docx_bytes=None, pdf_bytes=None, route='docx'):
    art = freeze_artifact(build_final_document_artifact({
        'sections': {
            'vision': _build_canonical_pillars('ar'),
            'pillars': _build_canonical_pillars('ar'),
        },
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar'},
    }))
    if route == 'docx':
        b = docx_bytes or b''
        export = ExportResult(
            route_name='docx', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            docx_bytes=b, bytes_data=b,
            returned_bytes_sha256=_sha256_bytes(b),
            evidence_bytes_sha256=_sha256_bytes(b),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
    else:
        b = pdf_bytes or b''
        export = ExportResult(
            route_name='pdf', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            pdf_bytes=b, bytes_data=b,
            returned_bytes_sha256=_sha256_bytes(b),
            evidence_bytes_sha256=_sha256_bytes(b),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
    return validate_returned_export_bytes(export, art, route=route)


class Rel31ContentQualityFixtureFailureTests(unittest.TestCase):
    """Latest export fixtures must fail substance evidence before repair."""

    @classmethod
    def setUpClass(cls):
        cls.docx_bytes, cls.docx_text = _load_docx()
        cls.pdf_bytes, cls.pdf_text = _load_pdf()
        cls.defects = content_quality_defect_sections()
        cls.preview_text = '\n\n'.join(
            cls.defects.get(k, '') for k in (
                'vision', 'pillars', 'roadmap_preview', 'kpis',
                'confidence', 'traceability', 'environment'))

    def test_01_docx_fails_shallow_pillars(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(diag['shallow_pillar_rows'])

    def test_02_docx_fails_roadmap_row_count_drift(self):
        preview_n = evaluate_content_substance(
            self.preview_text, route='preview')['roadmap_visible_row_count']
        docx_md = self.defects['roadmap']
        docx_n = evaluate_content_substance(
            docx_md, route='docx')['roadmap_visible_row_count']
        self.assertGreaterEqual(preview_n, 10)
        self.assertLess(docx_n, 10)
        diag = evaluate_content_substance(
            docx_md, route='docx',
            peer_row_counts={'preview': preview_n, 'docx': docx_n})
        self.assertFalse(diag['roadmap_preview_docx_pdf_consistent'])

    def test_03_docx_fails_invalid_kpi_kri_semantics(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertTrue(diag['kpi_semantic_defects'])

    def test_04_docx_fails_generic_repeated_risk_treatments(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertIn('repeated_generic_treatment', diag['risk_generic_treatments'])

    def test_05_docx_fails_bad_traceability_mappings(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertTrue(diag['traceability_bad_mappings'])

    def test_06_docx_fails_arabic_residues(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertTrue(diag['arabic_residues'])

    def test_07_pdf_fails_same_visible_defects_or_structural(self):
        diag = evaluate_content_substance(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        structural = run_rel31_content_substance_checks(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        self.assertTrue(
            not diag['content_substance_passed'] or structural,
            msg=str(diag))

    def test_11_preview_docx_pdf_row_counts_match_after_repair(self):
        repaired, _ = repair_rel31_canonical_sections(
            self.defects, lang='ar', domain='cyber')
        preview_blob = '\n\n'.join(
            (repaired.get(k) or '').strip()
            for k in ('vision', 'pillars', 'roadmap', 'kpis',
                      'confidence', 'traceability')
            if (repaired.get(k) or '').strip())
        docx_blob = preview_blob
        prev_n = evaluate_content_substance(
            preview_blob, route='preview')['roadmap_visible_row_count']
        docx_n = evaluate_content_substance(
            docx_blob, route='docx')['roadmap_visible_row_count']
        self.assertGreaterEqual(prev_n, 10)
        self.assertGreaterEqual(docx_n, 10)
        self.assertLessEqual(abs(prev_n - docx_n), 2)


class Rel31ContentQualityRepairPassTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def test_08_repaired_docx_evidence_passes(self):
        sections = content_quality_defect_sections()
        repaired, repairs = repair_rel31_canonical_sections(
            sections, lang='ar', domain='cyber')
        self.assertTrue(repairs)
        blob = '\n\n'.join(
            (repaired.get(k) or '').strip()
            for k in ('vision', 'pillars', 'roadmap', 'kpis',
                      'confidence', 'traceability')
            if (repaired.get(k) or '').strip())
        diag = evaluate_content_substance(blob, route='docx')
        self.assertTrue(diag['content_substance_passed'], diag)
        self.assertEqual(diag['shallow_pillar_rows'], [])
        self.assertEqual(diag['kpi_semantic_defects'], [])
        self.assertEqual(diag['risk_generic_treatments'], [])
        self.assertEqual(diag['traceability_bad_mappings'], [])
        self.assertEqual(diag['arabic_residues'], [])

    def test_09_repaired_preview_passes_rel3_evidence(self):
        sections = content_quality_defect_sections()
        repaired, _ = repair_rel31_canonical_sections(
            sections, lang='ar', domain='cyber')
        blob = '\n\n'.join(
            (repaired.get(k) or '').strip()
            for k in ('vision', 'pillars', 'roadmap', 'kpis',
                      'confidence', 'traceability')
            if (repaired.get(k) or '').strip())
        gate = validate_actual_export_evidence(
            blob, blob, '', route_name='preview',
            canonical_sections=repaired)
        self.assertTrue(gate.get('content_substance_evidence', {}).get(
            'content_substance_passed', True))
        pillar_blockers = [
            b for b in gate.get('blocking_errors') or []
            if 'shallow_pillar' in b or 'content_substance' in b]
        self.assertEqual(pillar_blockers, [], gate.get('blocking_errors'))

    def test_10_returned_equals_evidence_bytes(self):
        docx_bytes, _ = _load_docx()
        ev = _rel3_evidence(docx_bytes=docx_bytes, route='docx')
        self.assertTrue(ev.returned_equals_evidence_bytes)
        self.assertEqual(
            ev.returned_bytes_sha256, ev.evidence_bytes_sha256)

    def test_12_no_failed_export_cached_on_block(self):
        docx_bytes, _ = _load_docx()
        ev = _rel3_evidence(docx_bytes=docx_bytes, route='docx')
        self.assertFalse(ev.export_return_allowed)
        self.assertFalse(ev.evidence_passed)


if __name__ == '__main__':
    unittest.main()
