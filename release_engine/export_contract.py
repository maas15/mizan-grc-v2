"""PR-REL2 export contract — sealed read-only, hash parity."""

from __future__ import annotations

from typing import Any, Dict, List


def assert_export_hash_parity(
        artifact: Dict[str, Any],
        *,
        route: str,
        content_hash: str,
) -> List[str]:
    """Preview/DOCX/PDF must match sealed final_hash without mutation."""
    issues: List[str] = []
    if not artifact.get('sealed'):
        issues.append(f'rel2_export_unsealed:{route}')
        return issues
    fh = artifact.get('final_hash') or ''
    if not fh:
        issues.append(f'rel2_export_missing_final_hash:{route}')
    elif content_hash and content_hash != fh:
        issues.append(f'rel2_export_hash_mismatch:{route}')
    if artifact.get('post_seal_mutation_detected'):
        issues.append(f'rel2_post_seal_mutation:{route}')
    return issues


def read_only_export_meta(artifact: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'sealed': bool(artifact.get('sealed')),
        'final_hash': artifact.get('final_hash') or '',
        'display_hash': artifact.get('final_hash') or '',
        'mutates_content': False,
        'route': 'read_only',
    }
