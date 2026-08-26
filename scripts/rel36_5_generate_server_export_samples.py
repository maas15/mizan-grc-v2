#!/usr/bin/env python3
"""Generate REL36.5 last-mile saved-export samples and server diagnostics."""
from __future__ import annotations

import json
import sys
from io import StringIO
from contextlib import redirect_stdout
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
    _ownerless_en_cyber_evidence_blob,
)
from release_engine.export_evidence_validator import validate_actual_export_evidence
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_5_actual_server_export_evidence_hook import (
    REL36_5_ACTUAL_SERVER_EXPORT_EVIDENCE_HOOK_TAG,
)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    out = Path('/opt/cursor/artifacts/rel36_5_samples')
    out.mkdir(parents=True, exist_ok=True)
    report: dict = {}

    dirty = _cyber_en_live_saved_export_sections()
    exp = _export_pair_live(dirty, lang='en')
    _write(out / 'cyber_en_saved_export.docx', exp['docx_export'].docx_bytes or b'')
    _write(out / 'cyber_en_saved_export.pdf', exp['pdf_export'].pdf_bytes or b'')
    report['english_cyber'] = {
        'docx_allowed': bool(exp['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(exp['pdf_ev'].export_return_allowed),
        'docx_blockers': list(exp['docx_ev'].blocking_errors or []),
        'pdf_blockers': list(exp['pdf_ev'].blocking_errors or []),
        'hook_in_log': REL36_5_ACTUAL_SERVER_EXPORT_EVIDENCE_HOOK_TAG in exp['log'],
    }

    buf = StringIO()
    with redirect_stdout(buf):
        gate_docx = validate_actual_export_evidence(
            '', _ownerless_en_cyber_evidence_blob(), '',
            domain='cyber', lang='en', document_type='strategy',
            route_name='docx')
        gate_pdf = validate_actual_export_evidence(
            '', '', _ownerless_en_cyber_evidence_blob(),
            domain='cyber', lang='en', document_type='strategy',
            route_name='pdf', pdf_bytes_had=True)
    (out / 'cyber_en_server_export_diagnostic.json').write_text(
        json.dumps({
            'docx': gate_docx.get('rel36_5_actual_server_export_evidence_hook'),
            'pdf': gate_pdf.get('rel36_5_actual_server_export_evidence_hook'),
            'docx_blocking_errors': gate_docx.get('blocking_errors'),
            'pdf_blocking_errors': gate_pdf.get('blocking_errors'),
            'log': buf.getvalue(),
        }, ensure_ascii=False, indent=2),
        encoding='utf-8',
    )

    ar = _export_pair(_cyber_ar_sections(), lang='ar')
    _write(out / 'cyber_ar.docx', ar['docx_export'].docx_bytes or b'')
    _write(out / 'cyber_ar.pdf', ar['pdf_export'].pdf_bytes or b'')
    report['arabic_cyber'] = {
        'docx_allowed': bool(ar['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(ar['pdf_ev'].export_return_allowed),
    }

    data_secs, _ = repair_sections_for_fidelity(
        _data_sections(), domain='data', document_type='strategy',
        selected_frameworks=['NDMO', 'PDPL'], lang='ar')
    data = _export_pair(data_secs, lang='ar', domain='data')
    _write(out / 'data_ndmo_pdpl.docx', data['docx_export'].docx_bytes or b'')
    _write(out / 'data_ndmo_pdpl.pdf', data['pdf_export'].pdf_bytes or b'')
    report['data'] = {
        'docx_allowed': bool(data['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(data['pdf_ev'].export_return_allowed),
    }

    ai_secs, _ = repair_sections_for_fidelity(
        _ai_sections(), domain='ai', document_type='strategy',
        selected_frameworks=['SDAIA'], lang='ar')
    ai = _export_pair(ai_secs, lang='ar', domain='ai')
    _write(out / 'ai_sdaia.docx', ai['docx_export'].docx_bytes or b'')
    _write(out / 'ai_sdaia.pdf', ai['pdf_export'].pdf_bytes or b'')
    report['ai'] = {
        'docx_allowed': bool(ai['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(ai['pdf_ev'].export_return_allowed),
    }

    dt_secs, _ = repair_dga_interoperability_sections(_dt_dga_sections(), lang='ar')
    dt = _export_pair(dt_secs, lang='ar', domain='dt')
    _write(out / 'dt_dga.docx', dt['docx_export'].docx_bytes or b'')
    _write(out / 'dt_dga.pdf', dt['pdf_export'].pdf_bytes or b'')
    report['dt'] = {
        'docx_allowed': bool(dt['docx_ev'].export_return_allowed),
        'pdf_allowed': bool(dt['pdf_ev'].export_return_allowed),
        'dga_interoperability_covered': dga_interoperability_covered(dt_secs),
    }

    (out / 'rel36_5_sample_report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
