#!/usr/bin/env python3
"""REL3.3 staging smoke — Generate → Preview → DOCX → PDF for all P1 routes."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.rel33_authority import REL33_P1_ROUTES, route_key
from release_engine_v3.rel33_quality_matrix import (
    emit_rel33_matrix_report,
    ensure_test_env,
    run_rel33_quality_case,
    run_rel33_quality_matrix,
)


def main() -> int:
    ensure_test_env()
    cases = list(REL33_P1_ROUTES)
    rows = []
    for case in cases:
        row = run_rel33_quality_case(case)
        row['staging_smoke_passed'] = bool(row.get('accepted'))
        rows.append(row)

    full = run_rel33_quality_matrix()
    for row in full['rows']:
        for p1 in rows:
            if row.get('route_key') == p1.get('route_key'):
                row['staging_smoke_passed'] = p1.get('staging_smoke_passed')

    report = {
        'tag': 'REL33-ALL-DOMAIN-SMOKE',
        'p1_routes': [route_key(
            domain=c['domain'], document_type=c['document_type'],
            lang=c['lang'], doc_subtype=c.get('doc_subtype', ''))
            for c in cases],
        'p1_rows': rows,
        'matrix': full,
        'all_p1_accepted': all(r.get('accepted') for r in rows),
        'passed': all(r.get('accepted') for r in rows),
    }
    out = ROOT / 'qa_outputs' / 'smoke_all_domains_preview_docx_pdf.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                   encoding='utf-8')
    emit_rel33_matrix_report(full)
    print(json.dumps({
        'p1_accepted': {r['route_key']: r.get('accepted') for r in rows},
        'all_p1_accepted': report['all_p1_accepted'],
    }, ensure_ascii=False, indent=2))
    print('SMOKE_ALL_DOMAINS_PASS=1' if report['passed'] else 'SMOKE_ALL_DOMAINS_PASS=0')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
