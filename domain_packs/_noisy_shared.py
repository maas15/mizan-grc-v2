"""Deterministic noisy fixtures — missing sections, dupes, KPI issues."""

from __future__ import annotations

from copy import deepcopy
from typing import Dict


def apply_noisy_mutations(clean: Dict[str, str]) -> Dict[str, str]:
    s = deepcopy(clean)
    v = s.get('vision', '') or ''
    if '| 2 |' in v and '| 3 |' not in v:
        v += '| 2 | Duplicate objective row | dup | dup | dup |\n'
    s['vision'] = v
    k = s.get('kpis', '') or ''
    if '| 1 |' in k:
        k += '| 9 | Bad numbering | x | x |\n| 11 | Bad numbering | x | x |\n'
    s['kpis'] = k
    if 'confidence' in s:
        s['confidence'] = s['confidence'].replace('80%', '').replace('82%', '')
    s.pop('pillars', None)
    return s
