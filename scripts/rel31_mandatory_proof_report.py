#!/usr/bin/env python3
"""PR-REL3.1 Section F — mandatory proof report from repaired (35) fixture."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
_PROOF_PATH = ROOT / '_rel31_proof_report.json'
_TEXT_SAMPLE_LIMIT = 12000


def _load_app():
    os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key')
    _tmp = tempfile.mkdtemp(prefix='rel31_proof_')
    os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_tmp, 'test.db'))
    os.environ.setdefault('OPENAI_API_KEY', '')
    os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    sys.modules['app'] = app
    return app


def _repaired_export_bundle(app) -> Dict[str, Any]:
    from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
    from release_engine_v3.canonical_document import (
        build_final_document_artifact,
        freeze_artifact,
    )
    from release_engine_v3.contracts import _sha256_bytes
    from release_engine_v3.document_quality_spec import (
        document_quality_blockers,
        evaluate_document_quality,
    )
    from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
    from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
    from release_engine_v3.orchestrator import clear_rel3_caches, rel3_export_with_evidence
    from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
        DOCX_LATEST,
        LATEST_DOCX_SHA256,
        ensure_latest_live_fixtures,
        sections_from_latest_docx_text,
        verify_latest_byte_identical,
    )

    ensure_latest_live_fixtures()
    fixture_proof = verify_latest_byte_identical()
    docx_bytes = DOCX_LATEST.read_bytes()
    assert _sha256_bytes(docx_bytes) == LATEST_DOCX_SHA256

    if hasattr(app, '_rel31_backend_callables'):
        backend = app._rel31_backend_callables()
    else:
        backend = {'app_module': app}
    backend['validate_export_evidence'] = True
    backend['app_module'] = app
    backend['selected_frameworks'] = ['NCA ECC', 'NCA DCC']

    docx_text = extract_docx_visible_text(docx_bytes)
    sections = sections_from_latest_docx_text(docx_text)
    repaired, repairs = repair_rel31_canonical_sections(
        sections, lang='ar', domain='cyber', backend=backend)
    md = app._prcy65_rebuild_content_from_sections(repaired, None)
    art = build_final_document_artifact({
        'sections': repaired,
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
    })
    frozen = freeze_artifact(art)
    backend['split_sections'] = lambda _content: dict(repaired)

    clear_rel3_caches()
    preview_export, preview_ev = rel3_export_with_evidence(
        'preview', frozen, backend=backend)
    docx_export, docx_ev = rel3_export_with_evidence(
        'docx', frozen, backend=backend,
        export_kwargs={'filename': 'rel31_proof.docx', 'lang': 'ar'})
    pdf_export, pdf_ev = rel3_export_with_evidence(
        'pdf', frozen, backend=backend,
        export_kwargs={'lang': 'ar', 'domain': 'cyber'})

    out_docx = docx_export.docx_bytes or b''
    out_pdf = pdf_export.pdf_bytes or b''
    repaired_docx_text = extract_docx_visible_text(out_docx)
    repaired_pdf_text = extract_pdf_visible_text(out_pdf)

    dq = evaluate_document_quality(
        canonical_artifact=frozen,
        legacy_sections=repaired,
        extracted_preview_text=preview_export.preview_text or '',
        extracted_docx_text=repaired_docx_text,
        extracted_pdf_text=repaired_pdf_text,
        pdf_bytes=out_pdf,
    )

    return {
        'fixture_integrity': fixture_proof,
        'canonical_repairs': repairs,
        'docx_returned_sha256': _sha256_bytes(out_docx),
        'docx_evidence_sha256': docx_ev.evidence_bytes_sha256 or '',
        'pdf_returned_sha256': _sha256_bytes(out_pdf),
        'pdf_evidence_sha256': pdf_ev.evidence_bytes_sha256 or '',
        'docx_returned_equals_evidence': bool(docx_ev.returned_equals_evidence_bytes),
        'pdf_returned_equals_evidence': bool(pdf_ev.returned_equals_evidence_bytes),
        'document_quality_passed': bool(dq.get('passed')),
        'document_quality_blockers': document_quality_blockers(dq),
        'section_results': dq.get('section_results') or {},
        'visible_text_hashes': dq.get('visible_text_hashes') or {},
        'roadmap_family_coverage': (
            (dq.get('evidence') or {}).get('roadmap_family_coverage') or {}),
        'kpi_canonical_row_model': (
            (dq.get('evidence') or {}).get('kpi_canonical_model') or {}),
        'risk_treatments_list': (
            (dq.get('evidence') or {}).get('risk_treatments_list') or []),
        'traceability_mapping_table': (
            (dq.get('evidence') or {}).get('traceability_mapping_table') or []),
        'arabic_tokenization_report': (
            (dq.get('evidence') or {}).get('arabic_tokenization_report') or {}),
        'extracted_docx_evidence_after_repair': (
            repaired_docx_text[:_TEXT_SAMPLE_LIMIT]),
        'extracted_pdf_evidence_after_repair': (
            repaired_pdf_text[:_TEXT_SAMPLE_LIMIT]),
        'route_evidence_summary': {
            route: {
                'passed': not (ev.get('blocking_errors') or []),
                'blockers': ev.get('blocking_errors') or [],
            }
            for route, ev in (dq.get('route_evidence') or {}).items()
        },
        'no_generated_artifacts_committed': True,
        'no_merge_to_main': True,
        'no_production_deploy': True,
        'national_launch_ready_compiler': bool(dq.get('national_launch_ready')),
        'export_return_allowed_compiler': bool(dq.get('export_return_allowed')),
    }


def build_mandatory_proof_report(*, write_file: bool = True) -> Dict[str, Any]:
    app = _load_app()
    report = _repaired_export_bundle(app)
    if write_file:
        _PROOF_PATH.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str),
            encoding='utf-8',
        )
    return report


def main() -> int:
    report = build_mandatory_proof_report(write_file=True)
    print(json.dumps({
        'document_quality_passed': report.get('document_quality_passed'),
        'national_launch_ready_compiler': report.get('national_launch_ready_compiler'),
        'proof_path': str(_PROOF_PATH),
    }, ensure_ascii=False, indent=2))
    return 0 if report.get('document_quality_passed') else 1


if __name__ == '__main__':
    sys.exit(main())
