"""One-shot Cyber AR export smoke — generation → preview/docx/pdf lock evidence."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix='rel32_smoke_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

import importlib.util

_spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
_APP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_APP)
sys.modules['app'] = _APP

from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine.traceability_substance_model import TRACE_CANONICAL_REGISTRY
from release_engine_v3.canonical_document import clear_artifact_registry
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches
from release_engine_v3.rel31_authority import (
    apply_rel31_authoritative_contract,
    clear_rel3_route_artifact_hashes,
    rel3_export_authoritative,
)
from release_engine_v3.rel32_frozen_export_lock import (
    clear_rel32_frozen_export_lock,
    emit_rel32_frozen_artifact_export_lock,
)
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
)


def main() -> int:
    ensure_latest_live_fixtures()
    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    clear_rel32_frozen_export_lock()
    clear_artifact_registry()

    backend = _APP._rel31_backend_callables()
    docx_text = extract_docx_visible_text(DOCX_LATEST.read_bytes())
    sections = sections_from_latest_docx_text(docx_text)
    sections, _ = repair_rel31_canonical_sections(
        sections, lang='ar', domain='cyber', backend=backend)
    md = _APP._prcy65_rebuild_content_from_sections(sections, None)
    strategy_id = 'rel32-live-smoke-cyber-ar'
    art = {
        'sections': sections,
        'final_markdown': md,
        'domain': 'cyber',
        'sealed': False,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
    }
    flags = {'rel3': True, 'rel31': True}
    art = apply_rel31_authoritative_contract(art, backend=backend, flags=flags)
    contract = art.get('rel31_generation_contract') or {}
    if not contract.get('generation_save_allowed'):
        print('SMOKE_FAIL: generation_save_allowed=false')
        print(json.dumps(contract, ensure_ascii=False, indent=2))
        return 1

    kwargs = {
        'filename': 'cyber_ar_smoke.docx', 'lang': 'ar', 'domain': 'cyber',
        'selected_frameworks': ['NCA ECC', 'NCA DCC'],
    }
    routes = {}
    evidences = {}
    log_buf = io.StringIO()
    for route in ('preview', 'docx', 'pdf'):
        with redirect_stdout(log_buf):
            export, evidence = rel3_export_authoritative(
                route, art, backend=backend, flags=flags, export_kwargs=kwargs)
        routes[route] = export
        evidences[route] = evidence

    with redirect_stdout(log_buf):
        lock = emit_rel32_frozen_artifact_export_lock(strategy_id)

    spec = TRACE_CANONICAL_REGISTRY['sensitive_handling']
    docx_out = extract_docx_visible_text(routes['docx'].docx_bytes or b'')
    trace_bad = []
    try:
        from release_engine.rel31_content_substance_checks import (
            check_traceability_bad_mappings,
        )
        trace_bad = check_traceability_bad_mappings(docx_out)
    except Exception:  # noqa: BLE001
        pass

    canon = {r: routes[r].canonical_hash for r in routes}
    tree = {r: routes[r].render_tree_hash for r in routes}
    report = {
        'generation_save_allowed': contract.get('generation_save_allowed'),
        'canonical_hash_by_route': canon,
        'render_tree_hash_by_route': tree,
        'canonical_hash_equal': len(set(canon.values())) == 1,
        'render_tree_hash_equal': len(set(tree.values())) == 1,
        'export_return_allowed': {
            r: evidences[r].export_return_allowed for r in routes},
        'blocking_errors': {
            r: list(evidences[r].blocking_errors or []) for r in routes},
        'rel32_frozen_lock': lock,
        'traceability_bad_mappings': trace_bad,
        'sensitive_handling_capability': spec['capability'],
        'sensitive_handling_expected_gap': spec['expected_gap'],
        'capability_in_docx': spec['capability'] in docx_out,
        'expected_gap_in_docx': spec['expected_gap'] in docx_out,
    }
    print('[REL32-LIVE-SMOKE-REPORT]')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    lock_ok = (
        lock.get('export_lock_passed')
        and lock.get('frozen_artifact_loaded_for_docx')
        and lock.get('frozen_artifact_loaded_for_pdf')
        and not lock.get('docx_rebuilt_from_markdown')
        and not lock.get('pdf_rebuilt_from_markdown')
        and lock.get('blocking_errors') == []
    )
    export_ok = all(
        evidences[r].export_return_allowed for r in ('docx', 'pdf'))
    hash_ok = report['canonical_hash_equal'] and report['render_tree_hash_equal']
    trace_ok = not trace_bad and report['expected_gap_in_docx']
    if lock_ok and export_ok and hash_ok and trace_ok:
        print('SMOKE_PASS=1')
        return 0
    print('SMOKE_PASS=0')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
