"""PR-REL3.1 — latest live export quality (36.docx / 63.pdf byte-exact fixtures)."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_latest_')
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

from release_engine.rel31_acceptance_checks import (
    arabic_glue_residue_present,
    repair_rel31_canonical_sections,
)
from release_engine.rel31_content_substance_checks import evaluate_content_substance
from release_engine_v3.canonical_document import build_final_document_artifact, freeze_artifact
from release_engine_v3.contracts import _sha256_bytes
from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches, rel3_export_with_evidence
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    LATEST_DOCX_SHA256,
    LATEST_PDF_SHA256,
    PDF_LATEST,
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
    verify_latest_byte_identical,
)

ensure_latest_live_fixtures()

_LIVE_ARABIC_RESIDUES = (
    'ال مناسب',
    'ال معنية',
    'المراقبة المست',
)


def _load_docx():
    data = DOCX_LATEST.read_bytes()
    assert _sha256_bytes(data) == LATEST_DOCX_SHA256
    return data, extract_docx_visible_text(data)


def _load_pdf():
    data = PDF_LATEST.read_bytes()
    assert _sha256_bytes(data) == LATEST_PDF_SHA256
    return data, extract_pdf_visible_text(data)


def _backend_with_exports():
    b = _APP._rel31_backend_callables()
    b['validate_export_evidence'] = True
    b['app_module'] = _APP
    b['selected_frameworks'] = ['NCA ECC', 'NCA DCC']
    return b


def _repaired_artifact():
    sections = sections_from_latest_docx_text(_load_docx()[1])
    backend = _backend_with_exports()
    repaired, repairs = repair_rel31_canonical_sections(
        sections, lang='ar', domain='cyber', backend=backend)
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
    backend['split_sections'] = lambda _content: dict(repaired)
    return backend


class Rel31LatestFixtureIntegrityTests(unittest.TestCase):

    def test_00_latest_fixtures_byte_identical(self):
        proof = verify_latest_byte_identical()
        self.assertEqual(proof['docx_fixture_sha256'], LATEST_DOCX_SHA256)
        self.assertEqual(proof['pdf_fixture_sha256'], LATEST_PDF_SHA256)


class Rel31LatestFailureTests(unittest.TestCase):
    """Latest live exports must fail positive quality spec before repair."""

    @classmethod
    def setUpClass(cls):
        cls.docx_bytes, cls.docx_text = _load_docx()
        cls.pdf_bytes, cls.pdf_text = _load_pdf()
        cls.docx_diag = evaluate_content_substance(cls.docx_text, route='docx')
        cls.pdf_diag = evaluate_content_substance(
            cls.pdf_text, route='pdf', pdf_bytes=cls.pdf_bytes,
            docx_reference=cls.docx_text)
        cls.dq_raw = evaluate_document_quality(
            extracted_docx_text=cls.docx_text,
            extracted_pdf_text=cls.pdf_text,
            pdf_bytes=cls.pdf_bytes)

    def test_01_fails_shallow_pillars_and_missing_owners(self):
        self.assertFalse(self.docx_diag['content_substance_passed'])
        self.assertTrue(self.docx_diag['shallow_pillar_rows'])
        self.assertTrue(self.docx_diag['pillar_owner_missing'])

    def test_02_fails_duplicate_pillar_narratives(self):
        self.assertTrue(self.docx_diag['pillar_duplicate_narratives'])

    def test_03_fails_roadmap_or_trace_gaps(self):
        has_road_issue = (
            self.docx_diag['roadmap_visible_row_count'] < 10
            or self.docx_diag['roadmap_required_families_missing']
            or 'المراقبة المست' in self.docx_text)
        has_trace = bool(self.docx_diag['traceability_bad_mappings'])
        self.assertTrue(has_road_issue or has_trace)

    def test_04_fails_duplicate_mttd_and_conflicting_kpi(self):
        block = ' '.join(self.docx_diag['blocking_errors'])
        self.assertIn('duplicate_mttd', block)
        self.assertIn('conflicting_kpi_targets', block)

    def test_05_fails_dlp_encryption_classification_mixing(self):
        self.assertTrue(
            self.docx_diag['mixed_metric_formulas']
            or 'dlp_encryption' in ' '.join(self.docx_diag['blocking_errors']))

    def test_06_fails_third_party_risk_as_kpi(self):
        self.assertIn(
            'third_party_risk_as_kpi',
            self.docx_diag['kpi_semantic_defects'])

    def test_07_fails_generic_or_weak_risk_treatments(self):
        self.assertTrue(self.docx_diag['risk_generic_treatments'])

    def test_08_fails_wrong_dcc_traceability_mapping(self):
        self.assertTrue(self.docx_diag['traceability_bad_mappings'])

    def test_09_fails_live_arabic_residues(self):
        self.assertTrue(self.docx_diag['arabic_residues'])
        self.assertTrue(self.docx_diag['arabic_role_corruption'])
        for residue in _LIVE_ARABIC_RESIDUES:
            self.assertIn(residue, self.docx_text)

    def test_10_fails_preview_docx_pdf_semantic_drift(self):
        self.assertFalse(self.dq_raw.get('passed'))
        blockers = self.dq_raw.get('blocking_errors') or []
        self.assertTrue(
            any('semantic_drift' in b or 'roadmap_drift' in b for b in blockers)
            or self.docx_diag['blocking_errors'] != self.pdf_diag['blocking_errors'])

    def test_11_pdf_fails_visible_defects(self):
        self.assertFalse(self.pdf_diag['content_substance_passed'])


class Rel31LatestRepairPassTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def test_12_repaired_docx_passes_substance_and_evidence(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 'cyber_strategy_repaired.docx', 'lang': 'ar'})
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        docx_text = extract_docx_visible_text(export.docx_bytes or b'')
        diag = evaluate_content_substance(
            docx_text, route='docx',
            canonical_kpis=repaired.get('kpis') or '')
        self.assertTrue(diag['content_substance_passed'], diag)
        for residue in _LIVE_ARABIC_RESIDUES:
            self.assertFalse(
                arabic_glue_residue_present(docx_text, residue),
                f'residue {residue!r} in exported docx')

    def test_13_repaired_pdf_passes_evidence(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        docx_export, _ = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        pdf_export, ev = rel3_export_with_evidence(
            'pdf', art, backend=backend,
            export_kwargs={'lang': 'ar', 'domain': 'cyber'})
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        pdf_text = extract_pdf_visible_text(pdf_export.pdf_bytes or b'')
        docx_text = extract_docx_visible_text(docx_export.docx_bytes or b'')
        diag = evaluate_content_substance(
            pdf_text, route='pdf', pdf_bytes=pdf_export.pdf_bytes or b'',
            docx_reference=docx_text)
        self.assertTrue(diag['content_substance_passed'], diag)

    def test_14_preview_docx_pdf_parity_after_repair(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        preview_export, preview_ev = rel3_export_with_evidence(
            'preview', art, backend=backend)
        docx_export, _ = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        pdf_export, _ = rel3_export_with_evidence(
            'pdf', art, backend=backend,
            export_kwargs={'lang': 'ar', 'domain': 'cyber'})
        self.assertTrue(preview_ev.export_return_allowed, preview_ev.blocking_errors)
        docx_blob = extract_docx_visible_text(docx_export.docx_bytes or b'')
        pdf_blob = extract_pdf_visible_text(pdf_export.pdf_bytes or b'')
        dq = evaluate_document_quality(
            canonical_artifact=art,
            legacy_sections=repaired,
            extracted_preview_text=preview_export.preview_text or '',
            extracted_docx_text=docx_blob,
            extracted_pdf_text=pdf_blob,
            pdf_bytes=pdf_export.pdf_bytes or b'',
        )
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(dq['evidence']['equivalence_ok'])

    def test_15_document_quality_compiler_passes_after_repair(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        preview_export, _ = rel3_export_with_evidence('preview', art, backend=backend)
        docx_export, _ = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        pdf_export, _ = rel3_export_with_evidence(
            'pdf', art, backend=backend,
            export_kwargs={'lang': 'ar', 'domain': 'cyber'})
        docx_text = extract_docx_visible_text(docx_export.docx_bytes or b'')
        pdf_text = extract_pdf_visible_text(pdf_export.pdf_bytes or b'')
        dq = evaluate_document_quality(
            canonical_artifact=art,
            legacy_sections=repaired,
            extracted_preview_text=preview_export.preview_text or '',
            extracted_docx_text=docx_text,
            extracted_pdf_text=pdf_text,
            pdf_bytes=pdf_export.pdf_bytes or b'',
        )
        self.assertTrue(dq['passed'], dq.get('blocking_errors'))


class Rel31LatestReleaseReadinessTests(unittest.TestCase):

    def test_16_release_readiness_and_compiler_authority(self):
        if os.environ.get('REL31_READINESS_REPORT'):
            self.skipTest('skipped during release_readiness_report subprocess')
        import json
        import subprocess

        env = dict(os.environ)
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'release_readiness_report.py')],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=7200,
            env=env,
        )
        self.assertEqual(
            proc.returncode, 0,
            (proc.stdout or '') + (proc.stderr or ''))
        stdout = proc.stdout or ''
        json_start = stdout.find('{"domains_covered"')
        if json_start < 0:
            json_start = stdout.rfind('{')
        self.assertGreaterEqual(json_start, 0, stdout[-2000:])
        report = json.loads(stdout[json_start:])
        self.assertTrue(report.get('national_launch_ready'))
        compiler = report.get('document_quality_compiler') or {}
        self.assertTrue(compiler.get('passed'), compiler)
        self.assertEqual(report.get('broad_suite_exit_code'), 0)


if __name__ == '__main__':
    unittest.main()
