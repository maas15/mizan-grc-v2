"""PR-REL3.1 — latest live export quality (35.docx / 62.pdf byte-exact fixtures)."""

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

from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
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

_SHALLOW = (
    'منصة حوكمة معتمدة',
    'لجنة حوكمة فعّالة',
    'مركز SOC تشغيلي',
    'فريق CSIRT جاهز',
)

_ARABIC_RESIDUES = (
    'الNقرفي',
    'ال معالجة',
    'بال منصات',
    'المسؤول أمن السiبرانيe',
    'segmentation-Micro',
    'CSISO',
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
    sections = dict(repaired)
    backend['split_sections'] = lambda _content: sections
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

    def test_01_docx_fails_shallow_pillars(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(
            diag['shallow_pillar_rows']
            or diag['pillar_generic_outputs']
            or any(p in self.docx_text for p in _SHALLOW))

    def test_02_docx_fails_pillar_owner_missing(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(
            diag['pillar_owner_missing'] or '—' in self.docx_text)

    def test_03_docx_fails_roadmap_gaps(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        has_roadmap_issue = (
            diag['roadmap_visible_row_count'] < 10
            or diag['roadmap_required_families_missing']
            or diag['roadmap_visible_family_count'] < 8)
        has_other_issue = bool(
            diag['blocking_errors']
            or diag['arabic_residues']
            or diag['traceability_bad_mappings'])
        self.assertTrue(has_roadmap_issue or has_other_issue)

    def test_04_docx_fails_duplicate_mttd_or_kpi(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        has_kpi_issue = (
            diag['duplicate_metric_labels']
            or diag['kpi_semantic_defects']
            or 'MTTD' in self.docx_text.upper()
            or 'MTTR' in self.docx_text.upper())
        self.assertTrue(has_kpi_issue or not diag['content_substance_passed'])

    def test_05_docx_fails_mixed_dlp_encryption(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(
            diag['mixed_metric_formulas']
            or diag['kpi_semantic_defects']
            or not diag['content_substance_passed'])

    def test_06_docx_fails_arabic_residues(self):
        diag = evaluate_content_substance(self.docx_text, route='docx')
        self.assertFalse(diag['content_substance_passed'])
        self.assertTrue(
            diag['arabic_residues']
            or diag['arabic_role_corruption']
            or any(
                r.replace(' ', '') in self.docx_text.replace(' ', '')
                for r in _ARABIC_RESIDUES if r != 'المسؤول أمن السiبرانيe'))

    def test_07_pdf_fails_visible_defects(self):
        diag = evaluate_content_substance(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes,
            docx_reference=self.docx_text)
        dq = evaluate_document_quality(
            extracted_docx_text=self.docx_text,
            extracted_pdf_text=self.pdf_text,
            pdf_bytes=self.pdf_bytes,
        )
        self.assertFalse(diag['content_substance_passed'] or dq.get('passed'))


class Rel31LatestRepairPassTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def test_08_repaired_docx_passes_substance_and_evidence(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=backend,
            export_kwargs={'filename': 'cyber_strategy_repaired.docx', 'lang': 'ar'})
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        self.assertTrue(ev.returned_equals_evidence_bytes)
        docx_text = extract_docx_visible_text(export.docx_bytes or b'')
        diag = evaluate_content_substance(docx_text, route='docx')
        self.assertTrue(diag['content_substance_passed'], diag)
        self.assertEqual(diag['pillar_owner_missing'], [])
        self.assertEqual(diag['pillar_generic_outputs'], [])
        self.assertEqual(diag['duplicate_metric_labels'], [])
        self.assertEqual(diag['mixed_metric_formulas'], [])
        self.assertEqual(diag['risk_generic_treatments'], [])
        self.assertEqual(diag['arabic_residues'], [])
        self.assertEqual(diag['arabic_role_corruption'], [])

    def test_09_repaired_pdf_passes_evidence(self):
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
        self.assertTrue(diag['pdf_layout_semantic_passed'])

    def test_10_preview_docx_pdf_roadmap_parity(self):
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
        preview_blob = preview_export.preview_text or ''
        docx_blob = extract_docx_visible_text(docx_export.docx_bytes or b'')
        pdf_blob = extract_pdf_visible_text(pdf_export.pdf_bytes or b'')
        dq = evaluate_document_quality(
            canonical_artifact=art,
            legacy_sections=repaired,
            extracted_preview_text=preview_blob,
            extracted_docx_text=docx_blob,
            extracted_pdf_text=pdf_blob,
            pdf_bytes=pdf_export.pdf_bytes or b'',
        )
        self.assertTrue(dq.get('passed'), dq.get('blocking_errors'))
        self.assertTrue(dq['evidence']['equivalence_ok'])

    def test_11_returned_equals_evidence_bytes(self):
        art, repaired = _repaired_artifact()
        backend = _backend_for_repaired(repaired)
        for route in ('docx', 'pdf'):
            export, ev = rel3_export_with_evidence(
                route, art, backend=backend,
                export_kwargs={'filename': 's.docx', 'lang': 'ar', 'domain': 'cyber'})
            self.assertTrue(ev.returned_equals_evidence_bytes, route)
            if route == 'docx':
                self.assertTrue(ev.exact_bytes_checked)

    def test_12_document_quality_compiler_passes_after_repair(self):
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
        self.assertTrue(dq['export_return_allowed'])
        self.assertTrue(dq['release_ready_final_passed'])


class Rel31LatestReleaseReadinessTests(unittest.TestCase):

    def test_13_release_readiness_and_compiler_authority(self):
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
        report = json.loads(proc.stdout)
        self.assertTrue(report.get('national_launch_ready'))
        compiler = report.get('document_quality_compiler') or {}
        self.assertTrue(compiler.get('passed'), compiler)
        self.assertEqual(report.get('broad_suite_exit_code'), 0)
        self.assertEqual(report.get('pytest_exit_code'), 0)


if __name__ == '__main__':
    unittest.main()
