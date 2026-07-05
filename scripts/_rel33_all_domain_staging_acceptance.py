#!/usr/bin/env python3
"""REL3.3 all-domain P1 live staging acceptance (staging only).

Usage:
  $env:RENDER_STAGING_DEPLOY_HOOK_URL = '<staging-hook-only>'
  $env:STAGING_PASSWORD = '<staging ADMIN_PASSWORD>'
  python scripts/_rel33_all_domain_staging_acceptance.py

Does NOT merge main. Does NOT deploy production.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def _resolve_target_commit() -> str:
    env = (os.environ.get('STAGING_TARGET_COMMIT') or '').strip()
    if env:
        return env[:7]
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short=7', 'HEAD'],
            cwd=ROOT,
            text=True,
        ).strip()
    except Exception:
        return '0d965df'


TARGET_COMMIT = _resolve_target_commit()
TARGET_BRANCH = 'feature/rel33-all-domain-quality'
BASE = (os.environ.get('STAGING_URL') or 'https://mizan-grc-rel21-staging.onrender.com').rstrip('/')
OUT = Path(os.environ.get(
    'STAGING_OUTPUT_DIR', f'qa_outputs/staging_rel33_{TARGET_COMMIT}'))
GEN_TIMEOUT = int(os.environ.get('STAGING_GEN_TIMEOUT', '1200'))

EXPECTED_KPI_HEADERS = [
    '#', 'وصف المؤشر', 'النوع', 'القيمة المستهدفة',
    'صيغة الاحتساب', 'مصدر', 'التكرار', 'المالك',
]

DOMAIN_LABELS = {
    'cyber': 'Cyber Security',
    'data': 'Data Management',
    'ai': 'Artificial Intelligence',
    'dt': 'Digital Transformation',
    'erm': 'Enterprise Risk Management',
    'global': 'Global',
}

DOC_TYPE_LABELS = {
    'strategy': 'Strategy Document',
    'risk': 'Risk Assessment',
    'gap_assessment': 'Gap Assessment',
}

P1_ROUTES: List[Dict[str, str]] = [
    {'domain': 'cyber', 'document_type': 'strategy', 'lang': 'ar',
     'doc_subtype': 'technical'},
    {'domain': 'data', 'document_type': 'strategy', 'lang': 'ar'},
    {'domain': 'ai', 'document_type': 'strategy', 'lang': 'ar'},
    {'domain': 'dt', 'document_type': 'strategy', 'lang': 'ar'},
    {'domain': 'erm', 'document_type': 'risk', 'lang': 'ar'},
    {'domain': 'global', 'document_type': 'gap_assessment', 'lang': 'ar'},
]


def _route_key(case: Dict[str, str]) -> str:
    base = f"{case['domain']}:{case['document_type']}:{case['lang']}"
    if case.get('doc_subtype'):
        return f"{base}:{case['doc_subtype']}"
    return base


def _trigger_deploy() -> Dict[str, Any]:
    hook = (os.environ.get('RENDER_STAGING_DEPLOY_HOOK_URL') or '').strip()
    prod = (os.environ.get('RENDER_DEPLOY_HOOK_URL') or '').strip()
    if not hook:
        return {'triggered': False, 'reason': 'RENDER_STAGING_DEPLOY_HOOK_URL unset'}
    if prod and hook == prod:
        return {'triggered': False, 'reason': 'hook matches production — blocked'}
    sep = '&' if '?' in hook else '?'
    url = f'{hook}{sep}ref={TARGET_COMMIT}'
    r = requests.post(url, timeout=90)
    return {
        'triggered': True,
        'http_status': r.status_code,
        'url_ref': TARGET_COMMIT,
        'branch': TARGET_BRANCH,
        'service': 'mizan-grc-rel21-staging',
    }


def _verify_deployed() -> Dict[str, Any]:
    login = requests.get(f'{BASE}/login', timeout=90)
    html = login.text or ''
    m = re.search(r'rel32-preview-table-schema\.js\?v=([^"\']+)', html)
    ver = m.group(1) if m else None
    commit_match = bool(ver and str(ver).startswith(TARGET_COMMIT))
    return {
        'static_version': ver,
        'commit_match': commit_match,
        'ready': commit_match,
        'login_status': login.status_code,
    }


def _poll_deploy(timeout_s: int = 1200) -> Dict[str, Any]:
    deadline = time.time() + timeout_s
    last = _verify_deployed()
    while time.time() < deadline:
        last = _verify_deployed()
        print('[deploy-poll]', json.dumps(last), flush=True)
        if last.get('ready'):
            return last
        time.sleep(30)
    return last


def _csrf_from_html(html: str) -> Optional[str]:
    for pat in (
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
        r'content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token',
    ):
        m = re.search(pat, html or '', re.I)
        if m:
            return m.group(1)
    return None


def _login(session: requests.Session, *, retries: int = 4, force: bool = False) -> None:
    pwd = os.environ.get('STAGING_PASSWORD', '').strip()
    if not pwd:
        raise RuntimeError('STAGING_PASSWORD unset')
    user = os.environ.get('STAGING_USERNAME', 'admin').strip()
    if not force:
        try:
            probe = session.get(
                f'{BASE}/api/strategy-status/00000000-0000-0000-0000-000000000000',
                timeout=30)
            if probe.status_code != 401:
                dash = session.get(f'{BASE}/dashboard', timeout=90, allow_redirects=True)
                csrf = _csrf_from_html(dash.text)
                if csrf:
                    session.headers['X-CSRFToken'] = csrf
                    session.headers['Content-Type'] = 'application/json'
                    session.headers['Referer'] = f'{BASE}/dashboard'
                    return
        except Exception:  # noqa: BLE001
            pass
    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            login_page = session.get(f'{BASE}/login', timeout=90)
            r = session.post(
                f'{BASE}/login', data={'username': user, 'password': pwd},
                timeout=90, allow_redirects=True)
            text = r.text or ''
            if '/login' in r.url and (
                    'Invalid username' in text or 'Invalid password' in text):
                raise RuntimeError('staging login failed')
            dash = session.get(f'{BASE}/dashboard', timeout=90, allow_redirects=True)
            csrf = _csrf_from_html(dash.text)
            if not csrf:
                csrf = _csrf_from_html(login_page.text)
            if not csrf:
                raise RuntimeError('csrf-token missing')
            session.headers['X-CSRFToken'] = csrf
            session.headers['Content-Type'] = 'application/json'
            session.headers['Referer'] = f'{BASE}/dashboard'
            probe = session.get(
                f'{BASE}/api/strategy-status/00000000-0000-0000-0000-000000000000',
                timeout=30)
            if probe.status_code == 401:
                raise RuntimeError('session not authenticated')
            return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            print(f'[login-retry] attempt {attempt + 1}/{retries}: {exc}', flush=True)
            session.cookies.clear()
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(str(last_err) if last_err else 'login failed')


def _poll_gen(session: requests.Session, tid: str) -> Dict[str, Any]:
    deadline = time.time() + GEN_TIMEOUT
    null_streak = 0
    while time.time() < deadline:
        r = session.get(f'{BASE}/api/strategy-status/{tid}', timeout=90)
        if r.status_code == 401:
            raise RuntimeError('session expired during generation poll')
        data = r.json()
        status = data.get('status')
        print('[gen]', tid[:8], status, data.get('progress_percent'), flush=True)
        if status in ('done', 'error', 'not_found'):
            return data
        if status is None:
            null_streak += 1
            if null_streak >= 8:
                return {'status': 'error', 'error': f'status_lost:{tid}'}
        else:
            null_streak = 0
        time.sleep(15)
    raise TimeoutError(f'generation {tid}')


def _poll_export(session: requests.Session, task_id: str) -> Dict[str, Any]:
    deadline = time.time() + 600
    while time.time() < deadline:
        r = session.get(f'{BASE}/api/export-status/{task_id}', timeout=90)
        data = r.json()
        if data.get('status') in ('done', 'error'):
            return data
        time.sleep(3)
    raise TimeoutError(task_id)


def _base_payload(case: Dict[str, str]) -> Dict[str, Any]:
    domain = case['domain']
    label = DOMAIN_LABELS.get(domain, domain)
    payload: Dict[str, Any] = {
        'domain': label,
        'language': 'ar',
        'org_name': f'REL33 P1 {label} Org',
        'sector': 'Government',
        'size': '500-1000',
        'budget': '2M SAR',
        'frameworks': (
            ['NCA ECC (Essential Cybersecurity Controls)',
             'NCA DCC (Data Cybersecurity Controls)']
            if domain == 'cyber'
            else ['ISO 27001', 'NIST CSF']),
        'org_structure': 'CISO reports to CIO',
        'technologies': ['SIEM', 'IAM'],
        'additional_tech': '',
        'maturity_level': 'developing',
        'challenges': f'REL3.3 P1 staging acceptance for {label}.',
        'generation_mode': os.environ.get('STAGING_GENERATION_MODE', 'drafting'),
        'document_type': case['document_type'],
        'doc_type': DOC_TYPE_LABELS.get(
            case['document_type'], case['document_type']),
    }
    if case.get('doc_subtype'):
        payload['doc_subtype'] = case['doc_subtype']
    return payload


def _generate_live(session: requests.Session, case: Dict[str, str]) -> Dict[str, Any]:
    payload = _base_payload(case)
    dtype = case['document_type']
    endpoint = '/api/generate-strategy-async'
    if dtype == 'risk':
        endpoint = '/api/generate-risk-async'
    r = session.post(f'{BASE}{endpoint}', json=payload, timeout=90)
    if r.status_code >= 400 and dtype == 'risk':
        r = session.post(f'{BASE}/api/generate-strategy-async', json=payload, timeout=90)
    r.raise_for_status()
    start = r.json()
    if start.get('limit_reached'):
        return {'status': 'error', 'error': start.get('error') or 'limit_reached'}
    tid = start.get('task_id')
    if not tid:
        return {'status': 'error', 'error': f'no task_id: {start}'}
    return _poll_gen(session, tid)


def _export_live(
        session: requests.Session,
        *,
        fmt: str,
        content: str,
        case: Dict[str, str],
        artifact_id: Any,
        out_path: Path,
) -> Dict[str, Any]:
    payload = {
        'content': content,
        'filename': f"rel33_{case['domain']}_{case['document_type']}",
        'language': 'ar',
        'org_name': f"REL33 P1 {DOMAIN_LABELS.get(case['domain'], case['domain'])}",
        'sector': 'Government',
        'doc_type': DOC_TYPE_LABELS.get(
            case['document_type'], 'Strategy Document'),
        'domain': DOMAIN_LABELS.get(case['domain'], case['domain']),
        'selected_frameworks': (
            ['NCA ECC (Essential Cybersecurity Controls)',
             'NCA DCC (Data Cybersecurity Controls)']
            if case['domain'] == 'cyber'
            else ['ISO 27001']),
        'artifact_id': artifact_id,
        'artifact_type': case['document_type'],
        'document_type': case['document_type'],
        'generation_mode': os.environ.get('STAGING_GENERATION_MODE', 'drafting'),
    }
    r = session.post(f'{BASE}/api/generate-{fmt}-async', json=payload, timeout=90)
    r.raise_for_status()
    tid = r.json().get('task_id')
    done = _poll_export(session, tid)
    meta: Dict[str, Any] = {'task_id': tid, 'export_status': done}
    if done.get('status') == 'error':
        meta['export_return_allowed'] = False
        meta['blocking_errors'] = [done.get('error')]
        return meta
    dr = session.get(f'{BASE}/api/export-download/{tid}', timeout=180)
    raw = dr.content
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)
    meta.update({
        'export_return_allowed': dr.status_code == 200 and len(raw) > 100,
        'bytes': len(raw),
        'path': str(out_path),
        'http_status': dr.status_code,
    })
    return meta


def _kpi_schema_from_bytes(fmt: str, raw: bytes) -> Dict[str, Any]:
    if fmt == 'docx':
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            evaluate_kpi_main_schema_from_docx_bytes,
        )
        return evaluate_kpi_main_schema_from_docx_bytes(raw, route_name='docx')
    from release_engine_v3.rel32_kpi_main_schema_evidence import (
        evaluate_kpi_main_schema_from_pdf_bytes,
    )
    return evaluate_kpi_main_schema_from_pdf_bytes(raw, route_name='pdf')


def _local_hash_lock(
        sections: dict,
        content: str,
        strategy_id: str,
        case: Dict[str, str],
) -> Dict[str, Any]:
    _tmp = tempfile.mkdtemp(prefix='rel33_lock_')
    os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key')
    os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_tmp, 'test.db'))
    os.environ.setdefault('OPENAI_API_KEY', '')
    os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
    spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    app_mod = importlib.util.module_from_spec(spec)
    buf = io.StringIO()
    with redirect_stdout(buf):
        spec.loader.exec_module(app_mod)
        from release_engine_v3.canonical_document import clear_artifact_registry
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
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            evaluate_kpi_main_schema_from_export_text,
        )
        clear_rel3_caches()
        clear_rel3_route_artifact_hashes()
        clear_rel32_frozen_export_lock()
        clear_artifact_registry()
        backend = app_mod._rel31_backend_callables()
        art = {
            'sections': sections,
            'final_markdown': content,
            'domain': case['domain'],
            'document_type': case['document_type'],
            'sealed': False,
            'strategy_id': strategy_id,
            'contract_meta': {
                'lang': 'ar',
                'domain': case['domain'],
                'document_type': case['document_type'],
            },
        }
        flags = {'rel3': True, 'rel31': True, 'rel32': True, 'rel33': True}
        if case['document_type'] == 'strategy':
            from release_engine_v3.rel32_complete_strategy_compiler import (
                compile_complete_cyber_ar_technical_strategy,
            )
            compiled = compile_complete_cyber_ar_technical_strategy(
                dict(sections or {}),
                request_context={
                    'lang': 'ar',
                    'domain': case['domain'],
                    'document_type': case['document_type'],
                    'flags': flags,
                    'backend': backend,
                    'maturity_level': 'developing',
                    'roadmap_horizon_months': 18,
                },
            )
            if compiled.legacy_sections:
                sections = dict(compiled.legacy_sections)
                art['sections'] = sections
                content = '\n\n'.join(
                    v for v in sections.values() if isinstance(v, str) and v.strip())
                art['final_markdown'] = content
        art = apply_rel31_authoritative_contract(art, backend=backend, flags=flags)
        contract = art.get('rel31_generation_contract') or {}
        kwargs = {
            'filename': f"{case['domain']}.docx",
            'lang': 'ar',
            'domain': DOMAIN_LABELS.get(case['domain'], case['domain']),
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            'doc_type': DOC_TYPE_LABELS.get(
                case['document_type'], 'Strategy Document'),
        }
        routes, evidences = {}, {}
        for route in ('preview', 'docx', 'pdf'):
            export, evidence = rel3_export_authoritative(
                route, art, backend=backend, flags=flags, export_kwargs=kwargs)
            routes[route] = export
            evidences[route] = evidence
        lock = emit_rel32_frozen_artifact_export_lock(strategy_id)
        canon = {r: routes[r].canonical_hash for r in routes}
        tree = {r: routes[r].render_tree_hash for r in routes}
        kpi_diag: Dict[str, Any] = {}
        if case['document_type'] == 'strategy':
            kpi_text = (sections or {}).get('kpis') or content
            kpi_diag = evaluate_kpi_main_schema_from_export_text(
                kpi_text, route_name='preview')
        preview_dom_passed = True
        preview_html = routes['preview'].preview_html or ''
        if case['document_type'] == 'strategy' and preview_html:
            from release_engine_v3.rel33_quality_matrix import (
                evaluate_preview_dom_for_document,
            )
            dom = evaluate_preview_dom_for_document(
                preview_html, case['document_type'], sections=sections)
            preview_dom_passed = bool(dom.get('preview_dom_binding_passed'))
            from release_engine_v3.rel32_kpi_main_schema_evidence import (
                evaluate_kpi_main_schema_from_preview_html,
            )
            prev = evaluate_kpi_main_schema_from_preview_html(
                preview_html, route_name='preview')
            if prev.get('kpi_main_schema_passed'):
                kpi_diag = prev
            elif dom.get('preview_dom_binding_passed'):
                kpi_diag = prev
        legacy = False
        for ev in evidences.values():
            gate = getattr(ev, 'gate', None) or {}
            if gate.get('legacy_path_used') is True:
                legacy = True
        return {
            'generation_save_allowed': bool(
                contract.get('generation_save_allowed', True)),
            'canonical_hash_by_route': canon,
            'render_tree_hash_by_route': tree,
            'canonical_hash_equal': len(set(canon.values())) == 1,
            'render_tree_hash_equal': len(set(tree.values())) == 1,
            'export_return_allowed': {
                r: evidences[r].export_return_allowed for r in routes},
            'blocking_errors': {
                r: list(evidences[r].blocking_errors or []) for r in routes},
            'export_lock_passed': bool(lock.get('export_lock_passed')),
            'rel32_frozen_lock': lock,
            'kpi_main_schema': kpi_diag,
            'preview_dom_binding_passed': preview_dom_passed,
            'legacy_path_used': legacy,
        }


def _run_route(session: requests.Session, case: Dict[str, str]) -> Dict[str, Any]:
    key = _route_key(case)
    row: Dict[str, Any] = {
        'domain': case['domain'],
        'document_type': case['document_type'],
        'doc_subtype': case.get('doc_subtype', ''),
        'route': key,
        'route_key': key,
        'deployed_commit': TARGET_COMMIT,
        'generation_saved_real': False,
        'strategy_id': None,
        'artifact_id': None,
        'preview_rendered': False,
        'generation_save_allowed': False,
        'preview_dom_binding_passed': False,
        'docx_export_return_allowed': False,
        'pdf_export_return_allowed': False,
        'kpi_main_schema_passed': None,
        'kpi_owner_consistency_passed': None,
        'frozen_export_lock_passed': False,
        'frozen_lock_passed': False,
        'canonical_hash_equal': False,
        'render_tree_hash_equal': False,
        'legacy_path_used': True,
        'evidence_extractor_source': '',
        'app_blockers': [],
        'script_blockers': [],
        'accepted': False,
        'blockers': [],
    }
    app_blockers: List[str] = []
    script_blockers: List[str] = []
    try:
        gen = _generate_live(session, case)
    except Exception as exc:  # noqa: BLE001
        row['app_blockers'] = [f'generation_failed:{exc}']
        row['blockers'] = row['app_blockers']
        return row

    if gen.get('status') != 'done':
        row['app_blockers'] = [
            f"generation_status:{gen.get('status')}:{gen.get('error')}"]
        row['blockers'] = row['app_blockers']
        row['generation'] = gen
        return row

    result = gen.get('result') or gen
    sections = result.get('sections') or {}
    content = result.get('content') or result.get('analysis') or ''
    if isinstance(content, dict):
        content = json.dumps(content, ensure_ascii=False)
    if not str(content).strip() and sections:
        content = '\n\n'.join(str(v) for v in sections.values() if v)
    artifact_id = (
        result.get('strategy_id')
        or result.get('risk_id')
        or result.get('artifact_id')
        or gen.get('task_id'))
    row['strategy_id'] = artifact_id
    row['artifact_id'] = artifact_id
    row['generation_saved_real'] = bool(artifact_id)
    row['generation_save_allowed'] = bool(
        result.get('success', True) and artifact_id)
    row['preview_rendered'] = bool(str(content).strip() or sections)

    lock = _local_hash_lock(sections, str(content), str(artifact_id or key), case)
    if not row['generation_save_allowed'] and lock.get('generation_save_allowed'):
        script_blockers.append('local_replay_save_mismatch_live_saved')
    row['frozen_export_lock_passed'] = bool(lock.get('export_lock_passed'))
    row['frozen_lock_passed'] = row['frozen_export_lock_passed']
    row['canonical_hash_equal'] = bool(lock.get('canonical_hash_equal'))
    row['render_tree_hash_equal'] = bool(lock.get('render_tree_hash_equal'))
    row['legacy_path_used'] = bool(lock.get('legacy_path_used'))
    row['preview_dom_binding_passed'] = bool(lock.get('preview_dom_binding_passed'))

    kpi = lock.get('kpi_main_schema') or {}
    if case['document_type'] == 'strategy':
        row['kpi_main_schema'] = kpi
        owner = kpi.get('kpi_owner_consistency') or {}
        row['kpi_owner_consistency_passed'] = bool(
            owner.get('kpi_owner_consistency_passed'))

    dash = session.get(f'{BASE}/dashboard', timeout=90)
    csrf = _csrf_from_html(dash.text)
    if csrf:
        session.headers['X-CSRFToken'] = csrf

    route_dir = OUT / key.replace(':', '_')
    try:
        docx = _export_live(
            session, fmt='docx', content=str(content), case=case,
            artifact_id=artifact_id, out_path=route_dir / 'export.docx')
        pdf = _export_live(
            session, fmt='pdf', content=str(content), case=case,
            artifact_id=artifact_id, out_path=route_dir / 'export.pdf')
    except Exception as exc:  # noqa: BLE001
        row['app_blockers'] = [f'export_failed:{exc}']
        row['blockers'] = row['app_blockers']
        return row
    row['docx_export_return_allowed'] = bool(docx.get('export_return_allowed'))
    row['pdf_export_return_allowed'] = bool(pdf.get('export_return_allowed'))
    if not row['docx_export_return_allowed']:
        app_blockers.extend(docx.get('blocking_errors') or [
            'docx_export_return_allowed=false'])
    if not row['pdf_export_return_allowed']:
        app_blockers.extend(pdf.get('blocking_errors') or [
            'pdf_export_return_allowed=false'])

    live_kpi_pass = {'docx': None, 'pdf': None}
    if case['document_type'] == 'strategy':
        for fmt, meta in (('docx', docx), ('pdf', pdf)):
            path = meta.get('path')
            if path and Path(path).exists():
                live_kpi = _kpi_schema_from_bytes(fmt, Path(path).read_bytes())
                live_kpi_pass[fmt] = bool(live_kpi.get('kpi_main_schema_passed'))
                row['evidence_extractor_source'] = (
                    'docx_structured_table' if fmt == 'docx' else 'pdf_structured_table')
                if not live_kpi_pass[fmt]:
                    script_blockers.extend(
                        live_kpi.get('blocking_errors')
                        or [f'live_{fmt}_kpi_schema_failed'])
                owner = live_kpi.get('kpi_owner_consistency') or {}
                if owner and not owner.get('kpi_owner_consistency_passed'):
                    script_blockers.extend(
                        owner.get('blocking_errors') or [f'live_{fmt}_kpi_owner_failed'])
                    row['kpi_owner_consistency_passed'] = False
                elif owner.get('kpi_owner_consistency_passed'):
                    row['kpi_owner_consistency_passed'] = True
                row[f'kpi_main_schema_{fmt}'] = live_kpi
        row['kpi_main_schema_passed'] = all(
            live_kpi_pass.get(fmt) for fmt in ('docx', 'pdf')
            if live_kpi_pass.get(fmt) is not None)

    if not row['generation_save_allowed']:
        app_blockers.append('generation_save_allowed=false')
    if case['document_type'] == 'strategy' and not row['preview_dom_binding_passed']:
        script_blockers.append('preview_dom_binding_passed=false')
    if not row['docx_export_return_allowed']:
        app_blockers.append('docx_export_return_allowed=false')
    if not row['pdf_export_return_allowed']:
        app_blockers.append('pdf_export_return_allowed=false')
    if case['document_type'] == 'strategy' and not row['frozen_export_lock_passed']:
        script_blockers.append('frozen_export_lock_passed=false')
    if case['document_type'] == 'strategy' and not row['canonical_hash_equal']:
        script_blockers.append('canonical_hash_equal=false')
    if case['document_type'] == 'strategy' and not row['render_tree_hash_equal']:
        script_blockers.append('render_tree_hash_equal=false')
    if case['document_type'] == 'strategy' and row['legacy_path_used']:
        script_blockers.append('legacy_path_used=true')

    row['app_blockers'] = list(dict.fromkeys(app_blockers))
    row['script_blockers'] = list(dict.fromkeys(script_blockers))
    row['blockers'] = list(dict.fromkeys(app_blockers + script_blockers))
    row['accepted'] = not row['blockers']
    return row


def _git_guards() -> Dict[str, Any]:
    branch = subprocess.check_output(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=ROOT, text=True).strip()
    head = subprocess.check_output(
        ['git', 'rev-parse', '--short=12', 'HEAD'], cwd=ROOT, text=True).strip()
    main_head = subprocess.check_output(
        ['git', 'rev-parse', '--short=12', 'origin/main'], cwd=ROOT, text=True).strip()
    merged = subprocess.run(
        ['git', 'merge-base', '--is-ancestor', head, 'origin/main'],
        cwd=ROOT, capture_output=True).returncode == 0
    return {
        'branch': branch,
        'head_commit': head,
        'origin_main_commit': main_head,
        'merged_to_main': merged,
        'production_deploy': False,
        'staging_service': 'mizan-grc-rel21-staging',
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        'tag': 'REL33-ALL-DOMAIN-STAGING-ACCEPTANCE',
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'staging_url': BASE,
        'target_commit': TARGET_COMMIT,
        'target_branch': TARGET_BRANCH,
        'merge_to_main': False,
        'production_deploy': False,
        'git': _git_guards(),
        'routes': [],
        'all_p1_accepted': False,
        'passed': False,
    }

    skip_deploy = os.environ.get('STAGING_SKIP_DEPLOY', '').strip().lower() in (
        '1', 'true', 'yes')
    if skip_deploy:
        deploy = {'triggered': False, 'reason': 'STAGING_SKIP_DEPLOY=1'}
        report['deploy_verify'] = _verify_deployed()
    else:
        deploy = _trigger_deploy()
        if deploy.get('triggered'):
            report['deploy_verify'] = _poll_deploy()
        else:
            report['deploy_verify'] = _verify_deployed()
    report['deploy'] = deploy
    print('[deploy]', deploy, flush=True)
    print('[deploy-verify]', report['deploy_verify'], flush=True)

    if not report['deploy_verify'].get('ready'):
        report['blocker'] = (
            f'staging not on {TARGET_COMMIT} — deploy {TARGET_BRANCH} @ {TARGET_COMMIT}')
        out = OUT / 'rel33_all_domain_staging_acceptance.json'
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('[REL33-ALL-DOMAIN-STAGING-ACCEPTANCE]')
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    if not os.environ.get('STAGING_PASSWORD', '').strip():
        report['blocker'] = 'STAGING_PASSWORD unset — cannot run live P1 smoke'
        out = OUT / 'rel33_all_domain_staging_acceptance.json'
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('[REL33-ALL-DOMAIN-STAGING-ACCEPTANCE]')
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2

    out = OUT / 'rel33_all_domain_staging_acceptance.json'

    def _flush_report() -> None:
        report['routes'] = rows
        report['all_p1_accepted'] = bool(rows) and all(r.get('accepted') for r in rows)
        report['passed'] = report['all_p1_accepted'] and not report['git'].get('merged_to_main')
        out.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str),
            encoding='utf-8')

    rows: List[Dict[str, Any]] = []
    session = requests.Session()
    session.headers['User-Agent'] = 'REL33-all-domain-staging/1.0'
    for case in P1_ROUTES:
        print(f"[route] {_route_key(case)}", flush=True)
        try:
            _login(session)
            row = _run_route(session, case)
        except Exception as exc:  # noqa: BLE001
            row = {
                'route': _route_key(case),
                'route_key': _route_key(case),
                'deployed_commit': TARGET_COMMIT,
                'accepted': False,
                'app_blockers': [f'route_runner_failed:{exc}'],
                'script_blockers': [],
                'blockers': [f'route_runner_failed:{exc}'],
            }
        rows.append(row)
        _flush_report()

    report['routes'] = rows
    report['all_p1_accepted'] = all(r.get('accepted') for r in rows)
    report['passed'] = report['all_p1_accepted'] and not report['git'].get('merged_to_main')

    out = OUT / 'rel33_all_domain_staging_acceptance.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    print('[REL33-ALL-DOMAIN-STAGING-ACCEPTANCE]')
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    print('REL33_STAGING_ACCEPTANCE_PASS=1' if report['passed'] else 'REL33_STAGING_ACCEPTANCE_PASS=0')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
