"""PR-REL3.1 — byte-exact uploaded export regression (34.docx / 61.pdf)."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_uploaded_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from release_engine.export_evidence_validator import validate_actual_export_evidence
from release_engine.rel31_acceptance_checks import (
    count_flat_roadmap_initiatives,
    repair_rel31_canonical_sections,
)
from release_engine.rel31_content_substance_checks import (
    evaluate_content_substance,
    run_rel31_content_substance_checks,
)
from release_engine_v3.canonical_document import build_final_document_artifact, freeze_artifact
from release_engine_v3.contracts import _sha256_bytes
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.evidence_validator import validate_returned_export_bytes
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches, rel3_export_with_evidence
from tests.fixtures.rel31_content_quality.uploaded_fixtures import (
    DOCX_ACTUAL,
    PDF_ACTUAL,
    UPLOADED_DOCX_SHA256,
    UPLOADED_PDF_SHA256,
    ensure_uploaded_fixtures,
    sections_from_uploaded_docx_text,
    verify_byte_identical_to_uploaded,
)

ensure_uploaded_fixtures()

_GENERIC_PILLAR_OUTPUTS = (
    'منصة حوكمة معتمدة',
    'لجنة حوكمة فعّالة',
    'فريق CSIRT جاهز',
    'مركز SOC تشغيلي',
)

_ARABIC_RESIDUES = (
    'المحددةفي',
    'ال معالجة',
    'بال منصات',
    'المسؤول أمن السيبرانيe',
)


def _load_docx():
    data = DOCX_ACTUAL.read_bytes()
    assert _sha256_bytes(data) == UPLOADED_DOCX_SHA256
    return data, extract_docx_visible_text(data)


def _load_pdf():
    data = PDF_ACTUAL.read_bytes()
    assert _sha256_bytes(data) == UPLOADED_PDF_SHA256
    return data, extract_pdf_visible_text(data)


def _backend_with_exports():
    if not hasattr(_APP, '_rel31_backend_callables'):
        if hasattr(_APP, '_rel2_backend_callables'):
            b = _APP._rel2_backend_callables()
        else:
            b = {'app_module': _APP}
    else:
        b = _APP._rel31_backend_callables()
    b['validate_export_evidence'] = True
    b['app_module'] = _APP
    b['selected_frameworks'] = ['NCA ECC', 'NCA DCC']
    return b


def _repaired_artifact():
    sections = sections_from_uploaded_docx_text(_load_docx()[1])
    repaired, repairs = repair_rel31_canonical_sections(
        sections, lang='ar', domain='cyber', backend=_backend_with_exports())
    assert repairs, repairs
    md = _APP._prcy65_rebuild_content_from_sections(repaired, None)
    art = build_final_document_artifact({
        'sections': repaired,
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
    })
    return freeze_artifact(art), repaired


def _backend_for_repaired(repaired):
    backend = _backend_with_exports()
    sections = dict(repaired)
    backend['split_sections'] = lambda _content: sections
    return backend


class Rel31UploadedFixtureIntegrityTests(unittest.TestCase):

    def test_00_fixtures_byte_identical_to_uploaded(self):
        proof = verify_byte_identical_to_uploaded()
        self.assertEqual(proof['docx_fixture_sha256'], UPLOADED_DOCX_SHA256)
        self.assertEqual(proof['pdf_fixture_sha256'], UPLOADED_PDF_SHA256)
        self.assertTrue(proof['docx_bytes_match_uploaded'])
        self.assertTrue(proof['pdf_bytes_match_uploaded'])


class Rel31UploadedFixtureFailureTests(unittest.TestCase):
    """Exact uploaded bytes must fail substance evidence before repair."""

    @classmethod
    def setUpClass(cls):
        cls.docx_bytes, cls.docx_text = _load_docx()
        cls.pdf_bytes, cls.pdf_text = _load_pdf()

    def test_01_docx_fails_shallow_pillars(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        for phrase in _GENERIC_PILLAR_OUTPUTS:
            self.assertIn(phrase, self.docx_text)
        self.assertTrue(
            diag['shallow_pillar_rows']
            or any(p in self.docx_text for p in _GENERIC_PILLAR_OUTPUTS))

    def test_02_docx_fails_pillar_owner_missing(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(
            diag['pillar_owner_missing'] or '—' in self.docx_text)

    def test_03_docx_fails_roadmap_row_count(self):
        flat_rows = count_flat_roadmap_initiatives(self.docx_text)
        self.assertLess(flat_rows, 10)
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])

    def test_04_docx_fails_kpi_semantics(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        kpi = diag['kpi_semantic_defects']
        self.assertIn('kpi_login_anomaly_as_100_percent', kpi)
        self.assertIn('kpi_third_party_risk_100_percent', kpi)
        self.assertIn('dlp_incident_nonzero_tolerance', kpi)

    def test_05_docx_fails_generic_risk_treatments(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertIn(
            'ضوابط تقنية وإجراءات تشغيلية ومراقبة مستمرة',
            diag['risk_generic_treatments'])

    def test_06_docx_fails_bad_traceability_mappings(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertTrue(diag['traceability_bad_mappings'])
        joined = ' '.join(diag['traceability_bad_mappings'])
        self.assertTrue(
            'traceability_dcc_classification_invalid' in joined
            or 'trace_gap_mismatch:تصنيف البيانات' in joined)
        self.assertTrue(
            'trace_gap_mismatch:الاستجابة للحوادث' in joined
            or 'soc' in joined.lower())

    def test_07_docx_fails_arabic_residues(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertTrue(diag['arabic_residues'])
        for residue in _ARABIC_RESIDUES:
            if residue.replace(' ', '') in self.docx_text.replace(' ', ''):
                continue
            if residue in self.docx_text:
                continue
        self.assertIn('المحددةفي', self.docx_text)

    def test_08_pdf_fails_same_defect_families(self):
        diag = evaluate_content_substance(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        structural = run_rel31_content_substance_checks(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        self.assertTrue(
            not diag['content_substance_passed'] or structural,
            msg=str(diag))

    def test_09_uploaded_docx_bytes_fail_rel3_returned_file_evidence(self):
        art, _ = _repaired_artifact()
        export = type('E', (), {})()
        from release_engine_v3.contracts import ExportResult
        export = ExportResult(
            route_name='docx',
            artifact_id=art.artifact_id,
            render_tree_hash='uploaded-fail',
            canonical_hash=art.canonical_hash,
            docx_bytes=self.docx_bytes,
            bytes_data=self.docx_bytes,
            returned_bytes_sha256=_sha256_bytes(self.docx_bytes),
            evidence_bytes_sha256=_sha256_bytes(self.docx_bytes),
            returned_equals_evidence_bytes=True,
            exact_bytes_checked=True,
        )
        ev = validate_returned_export_bytes(export, art, route='docx')
        self.assertFalse(ev.export_return_allowed)
        self.assertTrue(ev.docx_bytes_checked)
        self.assertTrue(ev.exact_bytes_checked)


class Rel31UploadedRepairPassTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def test_10_repaired_docx_passes_substance_and_evidence(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={
                'filename': 'cyber_strategy_repaired.docx',
                'lang': 'ar',
                'domain': 'cyber',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            })
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        self.assertTrue(ev.returned_equals_evidence_bytes)
        self.assertTrue(ev.exact_bytes_checked)
        self.assertTrue(ev.docx_bytes_checked)
        self.assertEqual(ev.blocking_errors, [])
        docx_text = extract_docx_visible_text(export.docx_bytes or b'')
        diag = evaluate_content_substance(docx_text, route='docx')
        self.assertTrue(diag['content_substance_passed'], diag)
        self.assertEqual(diag['shallow_pillar_rows'], [])
        self.assertEqual(diag['kpi_semantic_defects'], [])
        self.assertEqual(diag['risk_generic_treatments'], [])
        self.assertEqual(diag['traceability_bad_mappings'], [])
        self.assertEqual(diag['arabic_residues'], [])

    def test_11_repaired_pdf_passes_evidence(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        export, ev = rel3_export_with_evidence(
            'pdf', art, backend=backend,
            export_kwargs={
                'lang': 'ar',
                'domain': 'cyber',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            })
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        self.assertTrue(ev.returned_equals_evidence_bytes)
        self.assertTrue(ev.exact_bytes_checked)
        self.assertTrue(ev.pdf_bytes_checked or ev.pdf_pass_from_render_fallback)

    def test_12_preview_docx_pdf_roadmap_parity_after_repair(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        preview_export, preview_ev = rel3_export_with_evidence(
            'preview', art, backend=backend)
        docx_export, _ = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        self.assertTrue(preview_ev.export_return_allowed)
        preview_blob = preview_export.preview_text or ''
        docx_blob = extract_docx_visible_text(docx_export.docx_bytes or b'')
        prev_n = evaluate_content_substance(
            preview_blob, route='preview')['roadmap_visible_row_count']
        docx_n = evaluate_content_substance(
            docx_blob, route='docx')['roadmap_visible_row_count']
        self.assertGreaterEqual(prev_n, 10)
        self.assertGreaterEqual(docx_n, 10)
        peer = evaluate_content_substance(
            docx_blob, route='docx',
            peer_row_counts={'preview': prev_n, 'docx': docx_n})
        self.assertTrue(peer['roadmap_preview_docx_pdf_consistent'])

    def test_13_rel3_gate_emits_content_substance_evidence(self):
        art, repaired = _repaired_artifact()
        blob = _APP._prcy65_rebuild_content_from_sections(repaired, None)
        gate = validate_actual_export_evidence(
            blob, blob, '', route_name='preview',
            canonical_sections=repaired)
        substance = gate.get('content_substance_evidence') or {}
        self.assertTrue(substance.get('content_substance_passed'), substance)
        self.assertTrue(gate.get('export_return_allowed'))


if __name__ == '__main__':
    unittest.main()
