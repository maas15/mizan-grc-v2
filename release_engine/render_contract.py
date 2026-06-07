"""PR-REL2 render contract — layout-only gates after seal."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def layout_only_issues(
        artifact: Dict[str, Any],
        *,
        route: str,
        backend: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Export-only layout validation. Never mutates sealed content.
    pdf_table_vertical_stack_* and docmodel_* run here only.
    """
    if not artifact.get('sealed'):
        return []
    issues: List[str] = []
    backend = backend or {}
    if route == 'pdf':
        gate = backend.get('pdf_vertical_stack_gate')
        if callable(gate):
            try:
                raw = gate(artifact) or []
                for item in raw:
                    code = item if isinstance(item, str) else str(item)
                    if 'vertical_stack_unresolved' in code:
                        issues.append(code)
            except Exception:  # noqa: BLE001
                pass
    if route in ('docx', 'preview'):
        gate = backend.get('docmodel_quality')
        if callable(gate) and route == 'docx':
            try:
                raw = gate(artifact) or []
                for item in raw:
                    if 'docmodel_professional_quality' in str(item):
                        issues.append(str(item))
            except Exception:  # noqa: BLE001
                pass
    return issues
