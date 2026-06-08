#!/usr/bin/env python3
"""PR-REL2 national launch readiness dashboard (pytest summary)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REL2_TESTS = [
    'tests/test_release_national_matrix_rel2.py',
    'tests/test_rel21_cy89_integration.py',
    'tests/test_rel22_so_canonical_model.py',
    'tests/test_rel23_live_artifact_parity_and_quality.py',
    'tests/test_rel24_substantive_quality_gate.py',
    'tests/test_legacy_gate_retirement_rel2.py',
    'tests/test_export_contract_rel2.py',
    'tests/test_domain_packs_rel2.py',
    'tests/test_policy_procedure_outputs_rel2.py',
    'tests/test_risk_audit_outputs_rel2.py',
    'tests/test_release_strategy_matrix.py',
    'tests/test_legacy_gate_retirement.py',
]

BROAD_FILTER = (
    'release or cyber or data or ai or digital or erm or global '
    'or policy or procedure or risk or audit or prcy'
)


def run_pytest(paths):
    cmd = [sys.executable, '-m', 'pytest', '-q', '--tb=no'] + paths
    proc = subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=3600)
    return proc.returncode, proc.stdout + proc.stderr


def run_pytest_k(expr):
    cmd = [
        sys.executable, '-m', 'pytest', '-q', '--tb=no', '-k', expr,
    ]
    proc = subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=7200)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    code, output = run_pytest(REL2_TESTS)
    broad_code, broad_output = run_pytest_k(BROAD_FILTER)
    passed = failed = skipped = 0
    for line in output.splitlines():
        if ' passed' in line and ' in ' in line:
            parts = line.strip().split()
            for i, p in enumerate(parts):
                if p == 'passed' and i > 0:
                    try:
                        passed = int(parts[i - 1].replace(',', ''))
                    except ValueError:
                        pass
        if ' failed' in line:
            for p in parts:
                if p.endswith('failed'):
                    try:
                        failed = int(p.replace('failed', '').strip(','))
                    except ValueError:
                        pass
        if ' skipped' in line:
            for p in parts:
                if p.endswith('skipped'):
                    try:
                        skipped = int(p.replace('skipped', '').strip(','))
                    except ValueError:
                        pass

    report = {
        'domains_covered': [
            'cyber', 'data_management', 'artificial_intelligence',
            'digital_transformation', 'enterprise_risk_management',
            'global_standards',
        ],
        'languages_covered': ['ar', 'en'],
        'document_types_covered': [
            'strategy', 'policy', 'procedure', 'risk_register',
            'audit', 'roadmap', 'executive_summary', 'kpi_kri',
            'gap_assessment', 'traceability_matrix',
        ],
        'exports_covered': ['preview', 'docx', 'pdf'],
        'tests_passed': passed,
        'tests_failed': failed,
        'tests_skipped': skipped,
        'pytest_exit_code': code,
        'export_readiness': code == 0 and broad_code == 0,
        'framework_coverage_granularity': 'capability_family',
        'framework_coverage_wording_ar': (
            'تغطي المنصة عائلات القدرات الرئيسية ضمن الأطر المختارة'),
        'framework_coverage_wording_en': (
            'Platform covers principal capability families within selected frameworks'),
        'broad_suite_exit_code': broad_code,
        'broad_suite_tail': broad_output[-3000:] if broad_output else '',
        'national_launch_ready': (
            code == 0 and failed == 0 and broad_code == 0),
        'pilot_cyber_ready': code == 0,
        'positioning': (
            'Consultant-grade first drafts; human final approval required.'),
        'pytest_tail': output[-2000:] if output else '',
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report['national_launch_ready'] else 1


if __name__ == '__main__':
    sys.exit(main())
