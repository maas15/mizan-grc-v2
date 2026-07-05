"""REL3.3 — document-type gate routing (strategy vs gap_assessment vs risk)."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

GateDefect = Tuple[str, str, int, int]


def strategy_gates_enabled(document_type: str) -> bool:
    dtype = str(document_type or 'strategy').strip().lower()
    return dtype in ('strategy', '')


def gap_assessment_gates_enabled(document_type: str) -> bool:
    return str(document_type or '').strip().lower() == 'gap_assessment'


def selected_framework_objective_required(document_type: str) -> bool:
    return strategy_gates_enabled(document_type)


def emit_rel33_document_type_gate_routing(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-DOCUMENT-TYPE-GATE-ROUTING] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def audit_gap_assessment_sections(
        sections: Dict[str, str],
        *,
        selected_frameworks: Optional[List[str]] = None,
        lang: str = 'ar',
        domain: str = 'global',
        count_gap_rows: Optional[Callable[[str], int]] = None,
) -> List[GateDefect]:
    """Gap-assessment save audit — no strategy vision/objective gates."""
    defects: List[GateDefect] = []
    if not isinstance(sections, dict):
        return [('gaps', 'gap_sections_missing', 0, 1)]

    scope = (sections.get('scope') or '').strip()
    if not scope:
        defects.append(('scope', 'gap_scope_missing', 0, 1))

    gaps_text = sections.get('gaps') or ''
    n_gap = 0
    if callable(count_gap_rows):
        try:
            n_gap = int(count_gap_rows(gaps_text) or 0)
        except Exception:  # noqa: BLE001
            n_gap = 0
    if n_gap < 1:
        # Fallback: pipe-table row heuristic
        n_gap = sum(
            1 for ln in gaps_text.splitlines()
            if ln.strip().startswith('|') and '---' not in ln
            and not any(h in ln for h in ('الفجوة', 'Gap', 'الأولوية')))
    if n_gap < 1:
        defects.append(('gaps', 'gap_rows_insufficient', n_gap, 1))

    blob = '\n'.join(
        str(v) for v in sections.values() if isinstance(v, str))
    blob_upper = blob.upper()
    fws = list(selected_frameworks or [])
    if fws:
        refs = 0
        for fw in fws:
            fw_s = str(fw or '').strip()
            if not fw_s:
                continue
            candidates = {fw_s, fw_s.replace('_', ' '), fw_s.replace('_', '-')}
            parts = fw_s.replace('-', '_').split('_')
            if parts:
                candidates.add(parts[0])
            fw_u = fw_s.upper()
            if fw_u.startswith('ISO'):
                candidates.add('ISO')
            if 'NIST' in fw_u:
                candidates.add('NIST')
            if fw_u.startswith('PDPL') or fw_u == 'NDMO':
                candidates.add(fw_u[:4] if len(fw_u) >= 4 else fw_u)
            if any(c and c.upper() in blob_upper for c in candidates):
                refs += 1
        if refs < 1:
            defects.append(('gaps', 'gap_framework_reference_missing', refs, 1))

    remediation = (
        sections.get('remediation')
        or sections.get('recommendations')
        or sections.get('guides')
        or '')
    if not str(remediation).strip():
        defects.append(('remediation', 'gap_remediation_missing', 0, 1))

    return defects


def audit_risk_document_sections(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'erm',
) -> List[GateDefect]:
    """ERM risk document save audit — no strategy SO/vision gates."""
    defects: List[GateDefect] = []
    register = (sections.get('register') or sections.get('risk_register') or '')
    treatments = (
        sections.get('treatments')
        or sections.get('treatment')
        or sections.get('risk_treatment')
        or '')
    if not register.strip():
        defects.append(('register', 'risk_register_missing', 0, 1))
    if not treatments.strip():
        defects.append(('treatments', 'risk_treatment_missing', 0, 1))
    return defects


def build_gate_routing_diag(
        *,
        domain: str,
        document_type: str,
        route: str,
        document_type_source: str,
        blocking_errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    dtype = str(document_type or 'strategy').strip().lower()
    return {
        'domain': domain,
        'document_type': dtype,
        'route': route,
        'strategy_gates_enabled': strategy_gates_enabled(dtype),
        'gap_assessment_gates_enabled': gap_assessment_gates_enabled(dtype),
        'selected_framework_objective_required': (
            selected_framework_objective_required(dtype)),
        'document_type_source': document_type_source,
        'blocking_errors': list(blocking_errors or []),
    }
