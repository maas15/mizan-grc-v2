#!/usr/bin/env python3
"""PR-REL3.3 staging live smoke @ d897273 — Cyber AR Technical Preview/DOCX/PDF."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
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
TARGET_COMMIT = os.environ.get(
    'STAGING_TARGET_COMMIT',
    'a910455582d518d20726e9f096fb2827406679be',
)
TARGET_BRANCH = 'release-hardening/rel2-national-launch'
DEFAULT_OUT = ROOT / 'qa_outputs' / 'staging_rel33_d897273'
GEN_TIMEOUT = int(os.environ.get('STAGING_GEN_TIMEOUT', '1200'))

# Explicit framework labels + challenges text to steer environment section.
CYBER_PAYLOAD = {
    'domain': 'Cyber Security',
    'language': 'ar',
    'org_name': 'REL33 Staging Validation Org',
    'sector': 'Government',
    'size': '500-1000',
    'budget': '2M SAR',
    'frameworks': [
        'NCA ECC (Essential Cybersecurity Controls)',
        'NCA DCC (Data Cybersecurity Controls)',
    ],
    'org_structure': 'CISO reports to CIO',
    'technologies': ['SIEM', 'IAM'],
    'additional_tech': '',
    'maturity_level': 'developing',
    'challenges': (
        'الامتثال لـ NCA ECC و NCA DCC مع تعزيز الحوكمة والمراقبة '
        'وحماية البيانات الحساسة. مستوى النضج الحالي تطويري والمستهدف '
        'مُدار خلال 18 شهر مع مسار نضج واضح في قسم الثقة.'
    ),
    'doc_subtype': 'technical',
    'generation_mode': os.environ.get('STAGING_GENERATION_MODE', 'consulting'),
}

PREVIEW_BANNER_PATTERNS = [
    'preview-quality-warning',
    'quality-warning-banner',
    'الجدول يحتوي على صف واحد فقط',
    'Table has only 1 substantive row',
    'صفوف نائبة:',
    'Placeholder rows:',
]


def _base_url() -> str:
    return (os.environ.get('STAGING_URL') or
            'https://mizan-grc-rel21-staging.onrender.com').rstrip('/')


def _csrf_from_html(html: str) -> Optional[str]:
    for pat in (
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
        r'content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token',
    ):
        m = re.search(pat, html or '', re.I)
        if m:
            return m.group(1)
    return None


def _login(session: requests.Session, base: str) -> str:
    pwd = os.environ.get('STAGING_PASSWORD', '').strip()
    if not pwd:
        print('ERROR: STAGING_PASSWORD not set', file=sys.stderr)
        sys.exit(2)
    user = os.environ.get('STAGING_USERNAME', 'admin').strip()
    session.get(f'{base}/login', timeout=90)
    r = session.post(
        f'{base}/login',
        data={'username': user, 'password': pwd},
        timeout=90,
        allow_redirects=True,
    )
    if '/login' in r.url and 'Invalid username' in r.text:
        raise RuntimeError('staging login failed')
    dash = session.get(f'{base}/dashboard', timeout=90, allow_redirects=True)
    if '/login' in dash.url:
        raise RuntimeError('redirected to login after auth')
    csrf = _csrf_from_html(dash.text)
    if not csrf:
        raise RuntimeError('csrf-token missing')
    session.headers['X-CSRFToken'] = csrf
    session.headers['Content-Type'] = 'application/json'
    session.headers['Referer'] = f'{base}/dashboard'
    return csrf


def _refresh_csrf(session: requests.Session, base: str) -> None:
    dash = session.get(f'{base}/dashboard', timeout=90, allow_redirects=True)
    csrf = _csrf_from_html(dash.text)
    if csrf:
        session.headers['X-CSRFToken'] = csrf


def _poll_gen(session: requests.Session, base: str, tid: str) -> Dict[str, Any]:
    deadline = time.time() + GEN_TIMEOUT
    while time.time() < deadline:
        r = session.get(f'{base}/api/strategy-status/{tid}', timeout=90)
        data = r.json()
        print('[poll]', data.get('status'), data.get('progress_percent'),
              data.get('stage'), flush=True)
        if data.get('status') in ('done', 'error', 'not_found'):
            return data
        time.sleep(15)
    raise TimeoutError('generation')


def _poll_export(session: requests.Session, base: str, task_id: str) -> Dict[str, Any]:
    deadline = time.time() + 600
    while time.time() < deadline:
        r = session.get(f'{base}/api/export-status/{task_id}', timeout=90)
        if r.status_code == 404:
            raise RuntimeError(f'export task not found: {task_id}')
        data = r.json()
        if data.get('status') in ('done', 'error'):
            return data
        time.sleep(3)
    raise TimeoutError(task_id)


def _export_bytes(
        session: requests.Session,
        base: str,
        *,
        fmt: str,
        content: str,
        artifact_id,
        out_path: Path,
) -> Dict[str, Any]:
    payload = {
        'content': content,
        'filename': 'rel33_cyber_ar',
        'language': 'ar',
        'org_name': CYBER_PAYLOAD['org_name'],
        'sector': CYBER_PAYLOAD['sector'],
        'doc_type': 'Strategy Document',
        'domain': CYBER_PAYLOAD['domain'],
        'selected_frameworks': CYBER_PAYLOAD['frameworks'],
        'artifact_id': artifact_id,
        'artifact_type': 'strategy',
        'generation_mode': 'consulting',
    }
    r = session.post(f'{base}/api/generate-{fmt}-async', json=payload, timeout=90)
    r.raise_for_status()
    tid = r.json().get('task_id')
    if not tid:
        raise RuntimeError(r.json())
    done = _poll_export(session, base, tid)
    meta: Dict[str, Any] = {'task_id': tid, 'export_status': done}
    if done.get('status') == 'error':
        meta['export_return_allowed'] = False
        meta['blocking_errors'] = [done.get('error') or f'{fmt}_export_failed']
        return meta
    dr = session.get(f'{base}/api/export-download/{tid}', timeout=180)
    if dr.status_code != 200:
        raise RuntimeError(f'{fmt} download HTTP {dr.status_code}')
    raw = dr.content
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)
    meta.update({
        'export_return_allowed': True,
        'bytes': len(raw),
        'path': str(out_path),
    })
    if fmt == 'docx':
        from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
        from release_engine_v3.rel32_docx_traceability_evidence import (
            evaluate_docx_traceability_evidence,
        )
        text = extract_docx_visible_text(raw)
        trace_defects, trace_diag = evaluate_docx_traceability_evidence(text)
        meta['traceability_bad_mappings'] = trace_defects
        meta['docx_traceability_evidence'] = trace_diag
    return meta


def _local_hash_lock(
        sections: dict,
        content: str,
        strategy_id: str,
) -> Dict[str, Any]:
    """Local rel3 export parity + REL32 lock (mirrors rel32_cyber_ar_export_smoke)."""
    _tmp = tempfile.mkdtemp(prefix='rel33_staging_lock_')
    os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key')
    os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_tmp, 'test.db'))
    os.environ.setdefault('OPENAI_API_KEY', '')
    os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

    spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    app_mod = importlib.util.module_from_spec(spec)
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

    clear_rel3_caches()
    clear_rel3_route_artifact_hashes()
    clear_rel32_frozen_export_lock()
    clear_artifact_registry()

    backend = app_mod._rel31_backend_callables()
    art = {
        'sections': sections,
        'final_markdown': content,
        'domain': 'cyber',
        'sealed': False,
        'strategy_id': strategy_id,
        'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
    }
    flags = {'rel3': True, 'rel31': True}
    art = apply_rel31_authoritative_contract(art, backend=backend, flags=flags)
    kwargs = {
        'filename': 'rel33_staging.docx',
        'lang': 'ar',
        'domain': 'cyber',
        'selected_frameworks': CYBER_PAYLOAD['frameworks'],
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

    preview_html = routes.get('preview').preview_html or ''
    canon = {r: routes[r].canonical_hash for r in routes}
    tree = {r: routes[r].render_tree_hash for r in routes}
    return {
        'canonical_hash_by_route': canon,
        'render_tree_hash_by_route': tree,
        'canonical_hash_equal': len(set(canon.values())) == 1,
        'render_tree_hash_equal': len(set(tree.values())) == 1,
        'export_return_allowed': {
            r: evidences[r].export_return_allowed for r in routes},
        'rel32_frozen_lock': lock,
        'export_lock_passed': bool(lock.get('export_lock_passed')),
        'preview_html': preview_html,
    }


def _preview_banner_check(html: str) -> Dict[str, Any]:
    hits = [p for p in PREVIEW_BANNER_PATTERNS if p in (html or '')]
    return {'preview_quality_banners_absent': not hits, 'banner_hits': hits}


def _playwright_screenshots(
        base: str,
        out_dir: Path,
        *,
        preview_html: Optional[str] = None,
) -> List[str]:
    if os.environ.get('STAGING_PLAYWRIGHT', '').strip() not in ('1', 'true', 'yes'):
        return []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return []

    paths: List[str] = []
    user = os.environ.get('STAGING_USERNAME', 'admin')
    pwd = os.environ.get('STAGING_PASSWORD', '')
    shot_dir = out_dir / 'screenshots'
    shot_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1400, 'height': 900})
        page.goto(f'{base}/login', wait_until='networkidle', timeout=120000)
        page.fill('input[name="username"]', user)
        page.fill('input[name="password"]', pwd)
        page.click('button[type="submit"]')
        page.wait_for_url('**/dashboard**', timeout=120000)
        p1 = shot_dir / '01_dashboard.png'
        page.screenshot(path=str(p1), full_page=True)
        paths.append(str(p1))

        page.goto(f'{base}/domain/cyber', wait_until='networkidle', timeout=120000)
        p2 = shot_dir / '02_cyber_domain.png'
        page.screenshot(path=str(p2), full_page=True)
        paths.append(str(p2))

        if preview_html:
            prev_path = out_dir / 'preview_render.html'
            prev_path.write_text(preview_html, encoding='utf-8')
            page.goto(prev_path.as_uri(), wait_until='load', timeout=60000)
            p3 = shot_dir / '03_preview.png'
            page.screenshot(path=str(p3), full_page=True)
            paths.append(str(p3))

        browser.close()
    return paths


def main() -> int:
    base = _base_url()
    out_dir = Path(os.environ.get('STAGING_OUTPUT_DIR', str(DEFAULT_OUT)))
    out_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'staging_url': base,
        'target_commit': TARGET_COMMIT,
        'target_branch': TARGET_BRANCH,
        'merge_to_main': False,
        'production_deploy': False,
        'render_logs_note': (
            'Grep Render Dashboard for [RUNTIME-BUILD-FINGERPRINT] '
            f'app_commit_hash starting with {TARGET_COMMIT[:7]}'),
        'passed': False,
    }

    session = requests.Session()
    session.headers['User-Agent'] = 'REL3.3-staging-live-smoke/1.0'
    print(f'[REL33-STAGING] login {base}', flush=True)
    _login(session, base)

    print('[REL33-STAGING] generate Cyber AR Technical ...', flush=True)
    r = session.post(f'{base}/api/generate-strategy-async', json=CYBER_PAYLOAD, timeout=90)
    r.raise_for_status()
    tid = r.json().get('task_id')
    if not tid:
        raise RuntimeError(r.json())
    report['generation_task_id'] = tid

    gen = _poll_gen(session, base, tid)
    if gen.get('status') != 'done':
        err = gen.get('error') or gen
        report['generation_error'] = err
        (out_dir / 'generation_error.json').write_text(
            json.dumps(gen, ensure_ascii=False, indent=2), encoding='utf-8')
        print('GEN_FAIL', json.dumps(gen, ensure_ascii=False), file=sys.stderr)
        report_path = out_dir / 'rel33_staging_report.json'
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('SMOKE_PASS=0')
        return 1

    result = (gen.get('result') or {})
    sections = result.get('sections') or {}
    content = ''
    for key in ('vision', 'environment', 'gaps', 'initiatives', 'roadmap', 'kpis', 'traceability'):
        if sections.get(key):
            content += str(sections[key]) + '\n\n'
    if not content.strip():
        content = result.get('content') or gen.get('content') or ''
    if not content.strip() and sections:
        content = json.dumps(sections, ensure_ascii=False)

    artifact_id = result.get('strategy_id')
    report['generation'] = {
        'strategy_id': artifact_id,
        'section_keys': sorted(k for k, v in sections.items() if v),
    }

    # Build preview HTML via local authoritative renderer for banner check + screenshot.
    preview_html = ''
    preview_check = {'preview_quality_banners_absent': True, 'banner_hits': []}
    lock_report = _local_hash_lock(sections, content, str(artifact_id or tid))
    report['hash_lock'] = lock_report
    preview_html = lock_report.get('preview_html') or ''
    if preview_html:
        for pat in PREVIEW_BANNER_PATTERNS:
            if pat in preview_html:
                preview_check['banner_hits'].append(pat)
        preview_check['preview_quality_banners_absent'] = not preview_check['banner_hits']
        prev_path = out_dir / 'preview_render.html'
        prev_path.write_text(preview_html, encoding='utf-8')
        report['preview_html_path'] = str(prev_path)

    report['preview'] = preview_check

    _refresh_csrf(session, base)
    docx_meta = _export_bytes(
        session, base, fmt='docx', content=content,
        artifact_id=artifact_id,
        out_path=out_dir / 'cyber_ar_technical.docx',
    )
    pdf_meta = _export_bytes(
        session, base, fmt='pdf', content=content,
        artifact_id=artifact_id,
        out_path=out_dir / 'cyber_ar_technical.pdf',
    )
    report['docx'] = docx_meta
    report['pdf'] = pdf_meta

    report['screenshots'] = _playwright_screenshots(
        base, out_dir, preview_html=preview_html)

    checks = {
        'preview_no_quality_banners': preview_check.get('preview_quality_banners_absent'),
        'docx_export_return_allowed': bool(docx_meta.get('export_return_allowed')),
        'pdf_export_return_allowed': bool(pdf_meta.get('export_return_allowed')),
        'traceability_bad_mappings_empty': not (docx_meta.get('traceability_bad_mappings') or []),
        'export_lock_passed': lock_report.get('export_lock_passed'),
        'canonical_hash_equal': lock_report.get('canonical_hash_equal'),
        'render_tree_hash_equal': lock_report.get('render_tree_hash_equal'),
    }
    report['acceptance_checks'] = checks
    report['passed'] = all(v for v in checks.values() if v is not None)

    report_path = out_dir / 'rel33_staging_report.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('[REL33-STAGING-REPORT]')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('SMOKE_PASS=1' if report['passed'] else 'SMOKE_PASS=0')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
