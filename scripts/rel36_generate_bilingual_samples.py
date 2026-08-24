#!/usr/bin/env python3
"""Generate REL36 bilingual preview/export inspection samples."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_rel36_bilingual_preview_export_authority import (
    _ai_sections,
    _cyber_ar_sections,
    _cyber_en_live_pillar_sections,
    _cyber_en_sections,
    _data_sections,
    _dt_dga_sections,
    _export_pair,
)
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    detect_visible_frameworks,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    sanitize_visible_preview_text,
)
from release_engine_v3.rel36_dcc_traceability_en_repair import (
    repair_english_dcc_traceability_sections,
)
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    repair_english_cyber_export_evidence_sections,
)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    out = Path('/opt/cursor/artifacts/rel36_samples')
    out.mkdir(parents=True, exist_ok=True)
    report = {}
    for key, secs, lang, domain, fws in (
        ('cyber_ar', _cyber_ar_sections(), 'ar', 'cyber', ['NCA ECC', 'NCA DCC']),
        ('cyber_en', _cyber_en_live_pillar_sections(), 'en', 'cyber', ['NCA ECC', 'NCA DCC']),
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
        if domain == 'cyber' and lang == 'en':
            repaired, _ = repair_english_dcc_traceability_sections(
                repaired, lang=lang, domain=domain,
                selected_frameworks=fws)
            repaired, _ = repair_english_cyber_export_evidence_sections(
                repaired, lang=lang, domain=domain,
                selected_frameworks=fws, export_type='sample')
        exp = _export_pair(repaired, lang=lang, domain=domain)
        docx = exp['docx_export'].docx_bytes or b''
        pdf = exp['pdf_export'].pdf_bytes or b''
        _write(out / f'{key}_strategy.docx', docx)
        _write(out / f'{key}_strategy.pdf', pdf)
        preview = sanitize_visible_preview_text(
            '\n'.join(str(v) for v in repaired.values()), lang)
        (out / f'{key}_preview.txt').write_text(preview, encoding='utf-8')
        blob = preview
        report[key] = {
            'lang': lang,
            'domain': domain,
            'docx_bytes': len(docx),
            'pdf_bytes': len(pdf),
            'docx_allowed': bool(exp['docx_ev'].export_return_allowed),
            'pdf_allowed': bool(exp['pdf_ev'].export_return_allowed),
            'docx_blockers': list(exp['docx_ev'].blocking_errors or []),
            'pdf_blockers': list(exp['pdf_ev'].blocking_errors or []),
            'family_markers': 'family:' in blob,
            'frameworks': sorted(detect_visible_frameworks(blob)),
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
