#!/usr/bin/env python3

"""PR-REL2 national launch readiness dashboard (pytest summary)."""



from __future__ import annotations



import contextlib

import json

import os

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

    'tests/test_rel25_rendered_evidence_quality.py',

    'tests/test_rel26_actual_export_evidence_gate.py',

    'tests/test_rel27_actual_export_fail_closed.py',

    'tests/test_rel28_route_bound_export_evidence.py',

    'tests/test_rel3_unified_document_engine.py',

    'tests/test_rel3_returned_file_evidence.py',

    'tests/test_rel3_legacy_route_retirement.py',

    'tests/test_rel3_cyber_arabic_actual_export_quality.py',

    'tests/test_rel31_authoritative_generation_contract.py',

    'tests/test_rel31_legacy_gate_retirement.py',

    'tests/test_rel31_source_authority.py',

    'tests/test_rel31_actual_export_acceptance_failure.py',

    'tests/test_rel31_actual_export_content_quality.py',

    'tests/test_rel31_actual_uploaded_export_quality.py',

    'tests/test_rel31_latest_live_export_quality.py',

    'tests/test_rel31_kpi_canonical_dedup.py',

    'tests/test_rel31_traceability_route_equivalence.py',

    'tests/test_rel31_arabic_canonical_repair.py',

    'tests/test_rel31_live_export_authority_and_dqs.py',

    'tests/test_rel32_compiler_first_strategy.py',

    'tests/test_enterprise_document_factory_foundation.py',

    'tests/test_rel32_frozen_artifact_export_lock.py',

    'tests/test_legacy_gate_retirement_rel2.py',

    'tests/test_export_contract_rel2.py',

    'tests/test_domain_packs_rel2.py',

    'tests/test_policy_procedure_outputs_rel2.py',

    'tests/test_risk_audit_outputs_rel2.py',

    'tests/test_release_strategy_matrix.py',

    'tests/test_legacy_gate_retirement.py',

]



BROAD_K_FILTER = (
    '(release or cyber or data or ai or digital or erm or global '
    'or policy or procedure or risk or audit or prcy) '
    'and not test_13_release_readiness_and_compiler_authority')

# Keep alias for callers; broad suite must also use `-m not slow` so `-k ai`
# does not select meta gates like test_17_broad_suite_zero_failures ("failures").
BROAD_FILTER = BROAD_K_FILTER

REL2_K_FILTER = (
    'not slow and not test_13_release_readiness_and_compiler_authority')





def _rel3_authority_flags():

    """Read live REL3.1 authority flags from app without full import side-effects."""

    app_py = ROOT / 'app.py'

    text = app_py.read_text(encoding='utf-8')

    rel3 = "'rel3': True" in text or '"rel3": True' in text

    rel31 = "'rel31': True" in text or '"rel31": True' in text

    return {

        'rel3': rel3,

        'rel31': rel31,

        'rel3_authoritative': rel3 and rel31,

        'legacy_rel2_authoritative': not (rel3 and rel31),

        'legacy_prcy_export_contract_authoritative': not (rel3 and rel31),

    }





def run_pytest(paths, *, k_expr: str = ''):

    cmd = [sys.executable, '-m', 'pytest', '-q', '--tb=no']
    if k_expr:
        cmd.extend(['-k', k_expr])
    cmd.extend(paths)

    env = dict(os.environ)
    env['REL31_READINESS_REPORT'] = '1'

    proc = subprocess.run(

        cmd, cwd=str(ROOT), capture_output=True, text=True,
        timeout=7200, env=env)

    return proc.returncode, proc.stdout + proc.stderr





def run_pytest_k(expr):

    cmd = [
        sys.executable, '-m', 'pytest', '-m', 'not slow', '-q', '--tb=no',
        '-k', expr,
    ]

    env = dict(os.environ)
    env['REL31_READINESS_REPORT'] = '1'

    proc = subprocess.run(

        cmd, cwd=str(ROOT), capture_output=True, text=True,
        timeout=7200, env=env)

    return proc.returncode, proc.stdout + proc.stderr





def _run_rel31_compiler_proof():

    """Mandatory Section F compiler authority on repaired (35) fixture."""

    sys.path.insert(0, str(ROOT))

    from scripts.rel31_mandatory_proof_report import build_mandatory_proof_report

    return build_mandatory_proof_report(write_file=True)





def main():

    authority = _rel3_authority_flags()

    code, output = run_pytest(REL2_TESTS, k_expr=REL2_K_FILTER)

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



    rel_gate_ready = code == 0 and failed == 0

    compiler_proof = {}
    compiler_passed = False
    try:
        # Compiler proof imports app and emits diagnostics; keep stdout
        # JSON-only so subprocess callers can json.loads(proc.stdout).
        with contextlib.redirect_stdout(sys.stderr):
            compiler_proof = _run_rel31_compiler_proof()
        compiler_passed = bool(compiler_proof.get('document_quality_passed'))
    except Exception as exc:  # noqa: BLE001
        compiler_proof = {'error': str(exc), 'document_quality_passed': False}

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

        'rel3_authority': authority,

        'release_engine': (

            'rel3_unified_document_engine'

            if authority.get('rel3_authoritative') else 'rel2_legacy'),

        'tests_passed': passed,

        'tests_failed': failed,

        'tests_skipped': skipped,

        'pytest_exit_code': code,

        'export_readiness': rel_gate_ready and broad_code == 0,

        'framework_coverage_granularity': 'capability_family',

        'framework_coverage_wording_ar': (

            'تغطي المنصة عائلات القدرات الرئيسية ضمن الأطر المختارة'),

        'framework_coverage_wording_en': (

            'Platform covers principal capability families within selected frameworks'),

        'broad_suite_exit_code': broad_code,

        'broad_suite_tail': broad_output[-3000:] if broad_output else '',

        'document_quality_compiler': {
            'passed': compiler_passed,
            'national_launch_ready_compiler': compiler_proof.get(
                'national_launch_ready_compiler'),
            'visible_text_hashes': compiler_proof.get('visible_text_hashes'),
            'section_results': compiler_proof.get('section_results'),
            'blockers': compiler_proof.get('document_quality_blockers'),
            'proof_path': str(ROOT / '_rel31_proof_report.json'),
        },

        'national_launch_ready': (
            rel_gate_ready and broad_code == 0 and compiler_passed),

        'pilot_cyber_ready': rel_gate_ready and compiler_passed,

        'positioning': (

            'Consultant-grade first drafts; human final approval required.'),

        'pytest_tail': output[-2000:] if output else '',

    }

    print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0 if report['national_launch_ready'] else 1





if __name__ == '__main__':

    sys.exit(main())

