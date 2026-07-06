"""REL3.3 — load ERM risk artifacts for export (not strategy rows)."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from release_engine_v3.rel33_risk_treatment_evidence import (
    count_treatment_rows_from_sections,
)


def emit_rel33_risk_artifact_load(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-RISK-ARTIFACT-LOAD] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def normalize_risk_export_sections(sections: Dict[str, str]) -> Dict[str, str]:
    """Map strategy-shaped ERM keys to canonical risk register/treatment."""
    out = dict(sections or {})
    if not out.get('register'):
        out['register'] = (
            out.get('risk_register')
            or out.get('confidence')
            or '')
    if not out.get('treatments'):
        out['treatments'] = (
            out.get('treatment')
            or out.get('risk_treatment')
            or '')
    return out


def _split_risk_markdown(content: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current = '_body'
    buf: List[str] = []
    for ln in (content or '').splitlines():
        if ln.strip().startswith('##'):
            if buf:
                sections[current] = '\n'.join(buf).strip()
            head = ln.strip().lstrip('#').strip().lower()
            if any(m in head for m in ('register', 'سجل', 'مخاطر', 'risk')):
                current = 'register'
            elif any(m in head for m in ('treatment', 'معالج', 'معالجة')):
                current = 'treatments'
            else:
                current = re.sub(r'\W+', '_', head)[:40] or '_body'
            buf = [ln]
        else:
            buf.append(ln)
    if buf:
        sections[current] = '\n'.join(buf).strip()
    return sections


def resolve_rel33_risk_export_artifact(
        *,
        artifact_id,
        risk_id,
        user_id: int,
        domain: str = '',
        route: str = '',
        client_content: str = '',
        load_risk_row: Callable[..., Optional[Dict[str, Any]]],
        load_strategy_risk_row: Callable[..., Optional[Dict[str, Any]]],
        assemble_sections: Callable[[Dict[str, Any]], str],
        normalize_domain_fn: Callable[[str], str],
) -> Dict[str, Any]:
    """Load authoritative risk export content; detect strategy id collision."""
    diag: Dict[str, Any] = {
        'route': route,
        'domain': domain,
        'artifact_type': 'risk',
        'artifact_id': str(artifact_id or risk_id or ''),
        'source_table_or_store': 'none',
        'loaded_sections_keys': [],
        'risk_rows_count': 0,
        'treatment_rows_count': 0,
        'loaded_from_strategy_id': '',
        'loaded_from_risk_id': '',
        'artifact_id_collision_detected': False,
        'blocking_errors': [],
    }
    out: Dict[str, Any] = {
        'content': '',
        'sections': {},
        'diag': diag,
        'skip_client_authority': False,
    }

    req_domain = ''
    try:
        req_domain = normalize_domain_fn(domain or '')
    except Exception:  # noqa: BLE001
        req_domain = str(domain or '').strip().lower()

    row = None
    rid = risk_id or artifact_id
    if rid:
        row = load_risk_row(rid, user_id)
        if row:
            diag['source_table_or_store'] = 'risks'
            diag['loaded_from_risk_id'] = str(row.get('id') or rid)

    if not row and (artifact_id or risk_id):
        row = load_strategy_risk_row(artifact_id or risk_id, user_id, domain=domain)
        if row:
            diag['source_table_or_store'] = 'strategies'
            diag['loaded_from_strategy_id'] = str(row.get('id') or artifact_id or '')
            row_domain = str(row.get('domain') or '')
            try:
                row_code = normalize_domain_fn(row_domain)
            except Exception:  # noqa: BLE001
                row_code = row_domain.strip().lower()
            if req_domain and row_code and row_code not in ('erm', req_domain):
                if row_code == 'cyber' and req_domain == 'erm':
                    diag['artifact_id_collision_detected'] = True
                    diag['blocking_errors'] = [
                        'artifact_id_collision:cyber_strategy_on_erm_risk_export']
                    emit_rel33_risk_artifact_load(diag)
                    return out
            dtype = str(
                row.get('document_type')
                or (row.get('sections') or {}).get('_document_type')
                or '').strip().lower()
            if dtype and dtype not in ('risk', 'risk_assessment'):
                diag['artifact_id_collision_detected'] = True
                diag['blocking_errors'] = [
                    f'artifact_type_mismatch:{dtype}']
                emit_rel33_risk_artifact_load(diag)
                return out

    if not row:
        if (client_content or '').strip():
            diag['blocking_errors'] = ['risk_artifact_not_found']
        emit_rel33_risk_artifact_load(diag)
        return out

    sections = dict(row.get('sections') or {})
    content = str(row.get('content') or row.get('analysis') or '')
    if not sections and content.strip():
        sections = _split_risk_markdown(content)
    sections = normalize_risk_export_sections(sections)
    if not content.strip() and sections:
        content = assemble_sections(sections)

    risk_n, treat_n = count_treatment_rows_from_sections(sections)
    diag['loaded_sections_keys'] = sorted(
        k for k in sections if not str(k).startswith('_'))
    diag['risk_rows_count'] = risk_n
    diag['treatment_rows_count'] = treat_n

    if treat_n <= 0:
        diag['blocking_errors'] = ['empty_risk_treatment_in_artifact']

    out.update({
        'content': content,
        'sections': sections,
        'skip_client_authority': bool(content.strip()),
    })
    emit_rel33_risk_artifact_load(diag)
    return out
