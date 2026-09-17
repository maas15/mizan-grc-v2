#!/usr/bin/env python3
"""Render affected PDF/DOCX pages for REL37 export-parity evidence.

Uses the tracked saved-model fixture. Does not modify original evidence
files. Page images and extraction notes are written under --out.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel37_canonical_document import CanonicalDocument
from release_engine_v3.rel37_export_content_parity import (
    extract_pdf_text,
    inventory_docx_bytes,
)
from release_engine_v3.rel37_professional_projection import (
    apply_rel37_projection_to_blocks,
    load_validated_rel37_model,
)
from release_engine_v3.rel37_apply import (
    REL37_APPLIED_KEY,
    REL37_CANONICAL_FW_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_ORIGINAL_FW_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    serialize_model,
)


def _sections(model: CanonicalDocument) -> dict:
    from release_engine_v3.rel37_render import model_to_sections
    sections = model_to_sections(model)
    sections[REL37_APPLIED_KEY] = '1'
    sections[REL37_MODEL_KEY] = serialize_model(model)
    sections[REL37_HASH_KEY] = model.model_hash
    sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
    sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
    sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
    return sections


def _render_pdf_pages(raw: bytes, out_dir: Path, stem: str, limit: int = 4) -> list:
    pages = []
    try:
        import pymupdf
    except ImportError:
        return pages
    doc = pymupdf.open(stream=raw, filetype='pdf')
    for idx, page in enumerate(doc):
        if idx >= limit:
            break
        pix = page.get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5), alpha=False)
        dest = out_dir / f'{stem}_page_{idx + 1}.png'
        pix.save(str(dest))
        text = page.get_text() or ''
        pages.append({
            'path': str(dest),
            'page': idx + 1,
            'width': pix.width,
            'height': pix.height,
            'text_len': len(text.strip()),
            'has_approved_ndmo': 'Approved NDMO policy' in text,
            'has_wrong_replacement': 'إطار حوكمة NDMO معتمد' in text,
        })
    return pages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--fixture',
        default=str(ROOT / 'tests' / 'fixtures' / 'rel37' / 'data_en_saved_canonical_model.json'),
    )
    parser.add_argument(
        '--original-docx',
        default=str(ROOT / 'qa_outputs' / 'rel37_07_staging' / 'live' / 'data_en' / 'export.docx'),
    )
    parser.add_argument(
        '--original-pdf',
        default=str(ROOT / 'qa_outputs' / 'rel37_07_staging' / 'live' / 'data_en' / 'export.pdf'),
    )
    parser.add_argument('--out', default=str(ROOT / '_tmp' / 'rel37_parity_artifacts'))
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = json.loads(Path(args.fixture).read_text(encoding='utf-8'))
    model = CanonicalDocument.from_dict(payload)
    if not model.model_hash:
        model.compute_hashes()
    sections = _sections(model)
    loaded, blockers = load_validated_rel37_model(
        sections,
        domain='data',
        lang='en',
        document_type='strategy',
        org_name=model.org_name,
        selected_frameworks=list(model.selected_frameworks),
    )
    report = {
        'model_hash': model.model_hash,
        'validation_blockers': blockers,
        'projection_applied': False,
        'original_docx': {},
        'original_pdf': {},
        'original_evidence_available': False,
    }
    if loaded is not None and not blockers:
        blocks = apply_rel37_projection_to_blocks({}, loaded)
        road = ((blocks.get('roadmap') or {}).get('tables') or [{}])[0]
        conf = ((blocks.get('confidence_risk_register') or {}).get('tables') or [{}])[0]
        report['projection_applied'] = True
        report['projected_roadmap_deliverable'] = (road.get('rows') or [['']])[0][4] if road.get('rows') else ''
        report['projected_confidence_factor'] = (conf.get('rows') or [['']])[0][0] if conf.get('rows') else ''

    original_docx = Path(args.original_docx)
    original_pdf = Path(args.original_pdf)
    if original_docx.is_file():
        raw = original_docx.read_bytes()
        inv = inventory_docx_bytes(raw)
        report['original_evidence_available'] = True
        report['original_docx'] = {
            'sha256': hashlib.sha256(raw).hexdigest(),
            'has_approved_ndmo': 'Approved NDMO policy' in inv['text'],
            'has_wrong_replacement': 'إطار حوكمة NDMO معتمد' in inv['text'],
            'label': 'original_defective_evidence',
        }
    if original_pdf.is_file():
        raw = original_pdf.read_bytes()
        text, meta = extract_pdf_text(raw)
        report['original_pdf'] = {
            'sha256': hashlib.sha256(raw).hexdigest(),
            'extractor': meta.get('extractor'),
            'reliable': meta.get('reliable'),
            'pages': meta.get('pages'),
            'has_approved_ndmo': 'Approved NDMO policy' in text,
            'has_wrong_replacement': 'إطار حوكمة NDMO معتمد' in text,
            'label': 'original_defective_evidence',
        }
        report['original_pdf_pages'] = _render_pdf_pages(
            raw, out_dir, 'original_defective_pdf')
    dest = out_dir / 'page_evidence_report.json'
    dest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
