"""PR-REL2.3 — Arabic final language gate (scoped section repair)."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple

REL2_ARABIC_SPECIFIC_FIXES: Tuple[Tuple[str, str], ...] = (
    ('للتعاملمع', 'للتعامل مع'),
    ('الاجتماعيةضد', 'الاجتماعية ضد'),
    ('الاستعادةفي', 'الاستعادة في'),
)

_GLUE_PREPOSITIONS = ('مع', 'ضد', 'في', 'على', 'عن', 'من', 'إلى', 'لدى')
# Only split when the letter before the preposition is a typical word ending
# (e.g. للتعاملمع, الاجتماعيةضد) — avoids breaking الزمني, التشفير, etc.
_GLUE_RE = re.compile(
    r'([\u0600-\u06FF]*[لتةاءى])('
    + '|'.join(re.escape(p) for p in _GLUE_PREPOSITIONS)
    + r')(?=[\u0600-\u06FF])')


def _find_residues(text: str) -> List[str]:
    residues: List[str] = []
    blob = text or ''
    for bad, _ in REL2_ARABIC_SPECIFIC_FIXES:
        if bad in blob:
            residues.append(bad)
    for m in _GLUE_RE.finditer(blob):
        token = m.group(0)
        if token not in residues:
            residues.append(token)
    return residues


def _repair_text(text: str) -> str:
    if not text:
        return text or ''
    out = text
    for bad, good in REL2_ARABIC_SPECIFIC_FIXES:
        out = out.replace(bad, good)
    out = _GLUE_RE.sub(r'\1 \2', out)
    return out


def apply_arabic_final_gate(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
) -> Tuple[Dict[str, str], Dict[str, object]]:
    """Repair glued Arabic tokens in legacy sections only."""
    if str(lang or '').lower() == 'en':
        return sections, {
            'arabic_quality_passed': True,
            'residues_after': [],
            'action_taken': 'skipped_en',
        }
    residues_before: List[str] = []
    out = dict(sections)
    for key, val in sections.items():
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        residues_before.extend(_find_residues(val))
        out[key] = _repair_text(val)
    residues_after: List[str] = []
    for val in out.values():
        if isinstance(val, str):
            residues_after.extend(_find_residues(val))
    residues_after = list(dict.fromkeys(residues_after))
    passed = not residues_after
    blocking = ''
    if not passed:
        blocking = f'rel2_arabic_quality_failed:{residues_after[0]}'
    return out, {
        'arabic_quality_passed': passed,
        'residues_before': list(dict.fromkeys(residues_before)),
        'residues_after': residues_after,
        'action_taken': (
            'arabic_repaired' if residues_before else 'validated'),
        'blocking_error_if_any': blocking,
    }


def emit_arabic_final_language_gate(payload: Dict[str, object]) -> None:
    try:
        print(
            '[REL2-ARABIC-FINAL-LANGUAGE-GATE] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
