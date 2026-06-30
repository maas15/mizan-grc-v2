#!/usr/bin/env python3
"""Smoke: document-type matrix registry + P0 cyber strategy export path."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(
    tempfile.mkdtemp(prefix='matrix_smoke_'), 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from release_engine_v3.golden_matrix import GOLDEN_MATRIX, GOLDEN_ROUTES, matrix_cases
from release_engine_v3.registries.platform_registries import (
    DOCUMENT_TYPE_SCHEMA_REGISTRY,
    resolve_registries,
)


def main() -> int:
    report = {
        'matrix_size': len(GOLDEN_MATRIX),
        'document_types_registered': sorted(DOCUMENT_TYPE_SCHEMA_REGISTRY.keys()),
        'cases': [],
        'p0_export': None,
        'passed': True,
    }

    for case in GOLDEN_MATRIX:
        bundle = resolve_registries(
            domain=case['domain'],
            document_type=case['document_type'],
            lang=case['lang'],
        )
        entry = {
            'case': f"{case['domain']}:{case['document_type']}:{case['lang']}",
            'tier': case.get('tier'),
            'schema_present': bool(bundle.get('schema')),
            'routes': list(GOLDEN_ROUTES),
        }
        report['cases'].append(entry)

    # P0: full cyber AR strategy export smoke (existing gate).
    try:
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'rel32_cyber_ar_export_smoke.py')],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(ROOT),
        )
        p0_ok = proc.returncode == 0 and 'SMOKE_PASS=1' in (proc.stdout or '')
        report['p0_export'] = {
            'ok': p0_ok,
            'returncode': proc.returncode,
            'tail': (proc.stdout or '')[-2000:],
        }
        if not p0_ok:
            report['passed'] = False
    except Exception as exc:  # noqa: BLE001
        report['p0_export'] = {'ok': False, 'error': str(exc)}
        report['passed'] = False

    p0_cases = matrix_cases(tier='P0')
    report['p0_case_count'] = len(p0_cases)

    out = ROOT / 'qa_outputs' / 'smoke_document_type_matrix.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('SMOKE_MATRIX_PASS=1' if report['passed'] else 'SMOKE_MATRIX_PASS=0')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
