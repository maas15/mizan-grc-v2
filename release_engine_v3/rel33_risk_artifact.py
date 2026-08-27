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


def _emit_rel36_6_from_resolve(
        diag: Dict[str, Any],
        out: Dict[str, Any],
        *,
        route: str = '',
        domain: str = '',
        risk_id='',
        strategy_id='',
        source_artifact_type: str = '',
        loaded_artifact_type: str = '',
        loaded_domain: str = '',
        loaded_document_type: str = '',
        content: str = '',
        sections: Optional[Dict[str, Any]] = None,
        repair_applied: bool = False,
        extra_blockers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Emit [REL36.6-ERM-RISK-DOMAIN-ISOLATION] and attach it to the result."""
    try:
        from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
            evaluate_rel36_6_erm_risk_domain_isolation,
            emit_rel36_6_erm_risk_domain_isolation,
            risk_cache_key,
        )
        iso = evaluate_rel36_6_erm_risk_domain_isolation(
            route=route,
            domain=domain or 'erm',
            document_type='risk',
            lang=str((out.get('diag') or {}).get('lang') or 'ar'),
            risk_id=risk_id,
            strategy_id=strategy_id if not str(risk_id or '').strip() else '',
            cache_key=risk_cache_key(risk_id, domain=domain or 'erm'),
            source_artifact_type=source_artifact_type,
            loaded_artifact_type=loaded_artifact_type,
            loaded_domain=loaded_domain,
            loaded_document_type=loaded_document_type,
            content=content,
            sections=sections,
            contamination_before=list(diag.get('blocking_errors') or []),
            contamination_after=list(extra_blockers or []),
            repair_applied=repair_applied,
            blocking_errors=list(diag.get('blocking_errors') or []) + list(
                extra_blockers or []),
        )
        emit_rel36_6_erm_risk_domain_isolation(iso)
        out['rel36_6'] = iso
        diag['rel36_6_passed'] = bool(iso.get('passed'))
        diag['rel36_6_cache_key'] = iso.get('cache_key')
        return iso
    except Exception:  # noqa: BLE001
        return {}


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
    colliding_strategy = None
    if rid:
        row = load_risk_row(rid, user_id)
        if row:
            diag['source_table_or_store'] = 'risks'
            diag['loaded_from_risk_id'] = str(row.get('id') or rid)
            try:
                row_code = normalize_domain_fn(str(row.get('domain') or ''))
            except Exception:  # noqa: BLE001
                row_code = str(row.get('domain') or '').strip().lower()
            if (req_domain == 'erm' and row_code == 'cyber'):
                diag['artifact_id_collision_detected'] = True
                diag['blocking_errors'] = [
                    'artifact_id_collision:cyber_strategy_on_erm_risk_export']
                _emit_rel36_6_from_resolve(
                    diag, out, route=route, domain=domain,
                    risk_id=rid, strategy_id=artifact_id or '',
                    source_artifact_type='risk',
                    loaded_artifact_type='risk',
                    loaded_domain=row_code,
                    loaded_document_type='risk',
                    content='',
                )
                emit_rel33_risk_artifact_load(diag)
                return out

    # REL36.6 — probe strategies table only to detect id collision.
    # Never use a strategy row as ERM risk content authority.
    if artifact_id or risk_id:
        colliding_strategy = load_strategy_risk_row(
            artifact_id or risk_id, user_id, domain=domain)
        if colliding_strategy:
            _sid = str(colliding_strategy.get('id') or artifact_id or '')
            if row:
                diag['overlapping_strategy_id'] = _sid
            else:
                diag['loaded_from_strategy_id'] = _sid
            row_domain = str(colliding_strategy.get('domain') or '')
            try:
                row_code = normalize_domain_fn(row_domain)
            except Exception:  # noqa: BLE001
                row_code = row_domain.strip().lower()
            dtype = str(
                colliding_strategy.get('document_type')
                or (colliding_strategy.get('sections') or {}).get('_document_type')
                or '').strip().lower()
            # REL36.6 — any strategies-table hit is a fallback, never content.
            is_collision = True
            if is_collision and not row:
                diag['source_table_or_store'] = 'strategies'
                diag['artifact_id_collision_detected'] = True
                if req_domain == 'erm' and row_code == 'cyber':
                    diag['blocking_errors'] = [
                        'artifact_id_collision:cyber_strategy_on_erm_risk_export']
                elif dtype and dtype not in ('risk', 'risk_assessment'):
                    diag['blocking_errors'] = [f'artifact_type_mismatch:{dtype}']
                else:
                    diag['blocking_errors'] = [
                        'strategy_id_fallback_blocked']
                _emit_rel36_6_from_resolve(
                    diag, out, route=route, domain=domain,
                    risk_id=rid, strategy_id=colliding_strategy.get('id'),
                    source_artifact_type='strategy',
                    loaded_artifact_type='strategy',
                    loaded_domain=row_code,
                    loaded_document_type=dtype or 'strategy',
                    content=str(
                        colliding_strategy.get('content')
                        or colliding_strategy.get('analysis') or ''),
                    sections=dict(colliding_strategy.get('sections') or {}),
                )
                emit_rel33_risk_artifact_load(diag)
                return out
            # Risk row remains the authority; overlapping strategy id is
            # recorded but not used and is not a blocking collision.

    if not row:
        if (client_content or '').strip():
            diag['blocking_errors'] = ['risk_artifact_not_found']
        _emit_rel36_6_from_resolve(
            diag, out, route=route, domain=domain,
            risk_id=rid, strategy_id='',
            source_artifact_type='none',
            loaded_artifact_type='none',
            loaded_domain='',
            loaded_document_type='',
            content=client_content or '',
        )
        emit_rel33_risk_artifact_load(diag)
        return out

    sections = dict(row.get('sections') or {})
    content = str(row.get('content') or row.get('analysis') or '')
    if not sections and content.strip():
        sections = _split_risk_markdown(content)
    sections = normalize_risk_export_sections(sections)
    if not content.strip() and sections:
        content = assemble_sections(sections)

    # ── REL3.3 export-prep risk-native contract (second hard boundary) ──
    # A strategy-shaped saved risk artifact must never reach the exporters.
    # Detect strategy-shaped sections → one deterministic risk_native_repair →
    # re-validate (structure + cyber-primary). Use the repaired content for
    # export when the contract passes; fail closed otherwise (never emit a
    # strategy vision/roadmap blocker). Risk export-prep uses only the
    # risk-native splitter/normalizer here — no strategy compiler/synthesizer.
    try:
        from release_engine_v3.rel33_risk_generation_contract import (
            evaluate_risk_export_prep_contract,
        )
        _dl = str(domain or '').lower()
        _prep = evaluate_risk_export_prep_contract(
            content,
            domain=domain,
            route=route or 'export-prep',
            risk_id=str(row.get('id') or risk_id or artifact_id or ''),
            source_stage='resolve_rel33_risk_export_artifact',
            allow_cyber_context=('cyber' in _dl or 'سيبران' in _dl),
            emit=True,
        )
        # Expose the full export-prep diagnostic to callers (for the gated
        # export-status debug echo). Strip the heavy content field.
        out['export_prep_diag'] = {
            k: v for k, v in _prep.items() if k != 'content'}
        diag['export_prep_contract_passed'] = bool(_prep.get('contract_passed'))
        diag['export_prep_forbidden_sections'] = list(
            _prep.get('forbidden_strategy_section_keys') or [])
        if not _prep.get('contract_passed'):
            _prep_blk = list(_prep.get('blocking_errors') or [])
            diag['blocking_errors'] = list(dict.fromkeys(
                (diag.get('blocking_errors') or []) + _prep_blk))
            emit_rel33_risk_artifact_load(diag)
            # Fail closed before building the export artifact — return no
            # content so the exporter cannot ship strategy-shaped bytes, and
            # surface the export-prep blockers so the caller hard-blocks
            # instead of reverting to client/original content.
            out.update({'content': '', 'sections': {},
                        'skip_client_authority': False,
                        'export_prep_contract_passed': False,
                        'blocking_errors': _prep_blk or [
                            'rel33_risk_export_prep_not_risk_native']})
            return out
        _repaired = _prep.get('content') or content
        if _repaired != content:
            content = _repaired
            sections = normalize_risk_export_sections(
                _split_risk_markdown(content))
        out['export_prep_contract_passed'] = True
    except Exception as _prep_e:  # noqa: BLE001
        # REL3.3 — fail CLOSED on an unexpected export-prep contract exception.
        # Never continue with unrepaired content (it could ship strategy-shaped
        # or cyber-primary bytes). Surface a prep-specific exception blocker.
        diag['export_prep_contract_error'] = str(_prep_e)
        diag['blocking_errors'] = list(dict.fromkeys(
            (diag.get('blocking_errors') or [])
            + ['rel33_risk_export_prep_contract_exception']))
        out['export_prep_diag'] = {
            'tag': '[REL33-RISK-EXPORT-PREP-CONTRACT]',
            'contract_passed': False,
            'exception_type': type(_prep_e).__name__,
            'exception_message_safe': str(_prep_e)[:200],
            'blocking_errors': ['rel33_risk_export_prep_contract_exception'],
        }
        emit_rel33_risk_artifact_load(diag)
        out.update({'content': '', 'sections': {},
                    'skip_client_authority': False,
                    'export_prep_contract_passed': False,
                    'blocking_errors': [
                        'rel33_risk_export_prep_contract_exception']})
        return out

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
    iso = _emit_rel36_6_from_resolve(
        diag, out, route=route, domain=domain,
        risk_id=diag.get('loaded_from_risk_id') or rid,
        strategy_id='',
        source_artifact_type='risk',
        loaded_artifact_type='risk',
        loaded_domain=str(row.get('domain') or domain or ''),
        loaded_document_type='risk',
        content=content,
        sections=sections,
        repair_applied=bool(out.get('export_prep_contract_passed')),
    )
    if iso and iso.get('passed') is False:
        _iso_blk = list(iso.get('blocking_errors') or [])
        diag['blocking_errors'] = list(dict.fromkeys(
            (diag.get('blocking_errors') or []) + _iso_blk))
        out.update({
            'content': '',
            'sections': {},
            'skip_client_authority': False,
            'blocking_errors': _iso_blk,
        })
    emit_rel33_risk_artifact_load(diag)
    return out
