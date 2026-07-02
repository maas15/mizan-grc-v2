#!/usr/bin/env python3
"""Smoke: Final Document Factory across all platform domains."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.factory import CanonicalDocumentFactory, DocumentRequestContext
from release_engine_v3.golden_matrix import GOLDEN_MATRIX, case_key

DOMAINS = sorted({c['domain'] for c in GOLDEN_MATRIX})


def main() -> int:
    factory = CanonicalDocumentFactory()
    report = {'domains': {}, 'passed': True}
    for domain in DOMAINS:
        ctx = DocumentRequestContext(
            domain=domain,
            document_type='strategy',
            lang='ar',
            flags={'rel3': True, 'rel31': True},
        )
        try:
            result = factory.compile(
                {'vision': f'## Strategy\n\n{domain} seed'},
                domain=domain,
                document_type='strategy',
                lang='ar',
                request_context=ctx,
            )
            ok = bool(result.legacy_sections) and not result.blocking_errors
            report['domains'][domain] = {
                'compile_ok': ok,
                'blocking_errors': result.blocking_errors,
                'case': case_key({'domain': domain, 'document_type': 'strategy', 'lang': 'ar'}),
            }
            if not ok:
                report['passed'] = False
        except Exception as exc:  # noqa: BLE001
            report['domains'][domain] = {'compile_ok': False, 'error': str(exc)}
            report['passed'] = False

    out = ROOT / 'qa_outputs' / 'smoke_all_domains_factory.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('SMOKE_ALL_DOMAINS_PASS=1' if report['passed'] else 'SMOKE_ALL_DOMAINS_PASS=0')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
