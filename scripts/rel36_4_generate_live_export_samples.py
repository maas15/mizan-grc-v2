#!/usr/bin/env python3
"""Generate REL36.4 live-shaped saved-export inspection samples."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_rel36_bilingual_preview_export_authority import (
    _ai_sections,
    _cyber_ar_sections,
    _cyber_en_live_saved_export_sections,
    _data_sections,
    _dt_dga_sections,
    _export_pair,
    _export_pair_live,
)
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    detect_visible_frameworks,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    bind_saved_preview_payload,
    sanitize_visible_preview_text,
)
from release_engine_v3.rel36_4_live_en_cyber_export_path_repair import (
    REL36_4_LIVE_EN_CYBER_EXPORT_DIAG_TAG,
    apply_rel36_4_to_artifact,
)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    out = Path('/opt/cursor/artifacts/rel36_4_samples')
    out.mkdir(parents=True, exist_ok=True)
    report = {}

    dirty = _cyber_en_live_saved_export_sections()
    exp = _export_pair_live(dirty, lang='en')
    docx = exp['docx_export'].docx_bytes or b''
    pdf = exp['pdf_export'].pdf_bytes or b''
    _write(out / 'cyber_en_live_saved_export.docx', docx)
    _write(out / 'cyber_en_live_saved_export.pdf', pdf)
    bound = bind_saved_preview_payload(
        {
            'id': 64,
            'sections': dirty,
            'domain': 'cyber',
            'language': 'en',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        },
        expected_domain='cyber',
        expected_lang='en',
    )
    preview = '\n'.join(str(v) for v in (bound.get('sections') or {}).values())
    (out / 'cyber_en_live_preview.txt').write_text(preview, encoding='utf-8')
    art, diag = apply_rel36_4_to_artifact(
        {
            'sections': dirty,
            'final_markdown': exp['markdown'],
            'domain': 'cyber',
            'lang': 'en',
            'document_type': 'strategy',
            'contract_meta': {
                'lang': 'en', 'domain': 'cyber',
                'document_type': 'strategy',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            },
        },
        lang='en', domain='cyber', export_type='docx',
        route='saved-export-sample')
    (out / 'rel36_4_diagnostic.json').write_text(
        json.dumps(diag, ensure_ascii=False, indent=2), encoding='utf-8')
    report['cyber_en_live'] = {
        'lang': 'en',
        'domain': 'cyber',
        'docx_bytes': len(docx),
        'pdf_bytes': len(pdf),
        'docx_allowed': bool(exp['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(exp['pdf_ev'].export_return_allowed),
        'docx_blockers': list(exp['docx_ev'].blocking_errors or []),
        'pdf_blockers': list(exp['pdf_ev'].blocking_errors or []),
        'family_markers': 'family:' in preview,
        'arabic_pillar_header': 'المبادرة' in preview,
        'evidence_input_matches_repaired': diag.get(
            'evidence_input_matches_repaired'),
        'diag_tag_in_log': REL36_4_LIVE_EN_CYBER_EXPORT_DIAG_TAG in (
            exp.get('log') or ''),
        'repaired_artifact_hash': diag.get('repaired_artifact_hash'),
    }

    for key, secs, lang, domain, fws in (
        ('cyber_ar', _cyber_ar_sections(), 'ar', 'cyber', ['NCA ECC', 'NCA DCC']),
        ('data_ar', _data_sections(), 'ar', 'data', ['NDMO', 'PDPL']),
        ('ai_ar', _ai_sections(), 'ar', 'ai', ['SDAIA']),
        ('dt_dga', _dt_dga_sections(), 'ar', 'dt', ['DGA']),
    ):
        repaired, _ = repair_sections_for_fidelity(
            secs, domain=domain, document_type='strategy',
            selected_frameworks=fws, lang=lang)
        if domain == 'dt':
            repaired, _ = repair_dga_interoperability_sections(
                repaired, lang=lang)
        pair = _export_pair(repaired, lang=lang, domain=domain)
        _write(out / f'{key}_strategy.docx', pair['docx_export'].docx_bytes or b'')
        _write(out / f'{key}_strategy.pdf', pair['pdf_export'].pdf_bytes or b'')
        prev = sanitize_visible_preview_text(
            '\n'.join(str(v) for v in repaired.values()), lang)
        (out / f'{key}_preview.txt').write_text(prev, encoding='utf-8')
        report[key] = {
            'lang': lang,
            'domain': domain,
            'docx_bytes': len(pair['docx_export'].docx_bytes or b''),
            'pdf_bytes': len(pair['pdf_export'].pdf_bytes or b''),
            'docx_allowed': bool(pair['docx_ev'].export_return_allowed),
            'pdf_allowed': bool(pair['pdf_ev'].export_return_allowed),
            'docx_blockers': list(pair['docx_ev'].blocking_errors or []),
            'pdf_blockers': list(pair['pdf_ev'].blocking_errors or []),
            'family_markers': 'family:' in prev,
            'frameworks': sorted(detect_visible_frameworks(prev)),
            'dga_interop': (
                dga_interoperability_covered(repaired)
                if domain == 'dt' else None),
        }
    (out / 'inspection.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
