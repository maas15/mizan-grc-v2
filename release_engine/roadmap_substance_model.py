"""PR-REL2.4 — roadmap depth substance model."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from release_engine.roadmap_model import (
    ROADMAP_FAMILIES,
    finalize_roadmap,
    _parse_rows,
    _detect_families,
    _apply_roadmap_repairs,
    _rerender_rows,
)

_WEAK_OUTPUTS = frozenset({
    'هيكل', 'مركز', 'ضوابط', 'برنامج', 'تقرير', 'جرد', 'مراقبة',
    'إجراءات', 'نضج', 'output', 'plan', 'team',
})

_WEAK_OUTPUT_ENRICH = {
    'هيكل': 'هيكل CISO ولجنة حوكمة معتمدة',
    'مركز': 'مركز SOC تشغيلي مع تغطية SIEM',
    'ضوابط': 'ضوابط IAM/PAM/MFA مطبقة على الحسابات الحرجة',
    'برنامج': 'برنامج CSIRT وخطط استجابة معتمدة',
    'جرد': 'سجل بيانات مصنفة ومعتمد',
    'مراقبة': 'منصة DLP وقواعد مراقبة تسرب مفعّلة',
    'إجراءات': 'إجراءات معالجة بيانات حساسة معتمدة',
}


def _weak_output_rows(rows: List[Dict[str, str]]) -> List[str]:
    weak = []
    for r in rows:
        out = (r.get('output') or '').strip()
        if out in _WEAK_OUTPUTS or len(out) < 10:
            weak.append(out or r.get('initiative', ''))
    return weak


def _enrich_weak_outputs(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out = []
    for r in rows:
        row = dict(r)
        o = (row.get('output') or '').strip()
        if o in _WEAK_OUTPUT_ENRICH:
            row['output'] = _WEAK_OUTPUT_ENRICH[o]
        elif len(o) < 10 and row.get('initiative'):
            row['output'] = (
                f'مخرج تشغيلي معتمد: {row["initiative"]}')
        out.append(row)
    return out


def finalize_roadmap_substance(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        domain: str = 'cyber',
        selected_frameworks: Optional[List[str]] = None,
        backend: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    backend = backend or {}
    dcode = (domain or '').strip().lower()
    if dcode not in ('cyber', 'cyber_security'):
        return sections, {'roadmap_depth_passed': True}

    sections, base_diag = finalize_roadmap(
        sections, lang=lang, domain=dcode,
        selected_frameworks=selected_frameworks, backend=backend)

    text = sections.get('roadmap', '') or ''
    parsed = _parse_rows(text, backend, lang)
    weak_before = _weak_output_rows(parsed)
    parsed = _enrich_weak_outputs(parsed)
    parsed, _ = _apply_roadmap_repairs(parsed)
    weak_after = _weak_output_rows(parsed)
    present = _detect_families(parsed)
    missing_after = [f for f in ROADMAP_FAMILIES if not present.get(f)]
    row_count = len(parsed)

    new_text = _rerender_rows(text, parsed, backend, lang)
    out = dict(sections)
    out['roadmap'] = new_text

    passed = (
        10 <= row_count <= 14
        and not missing_after
        and not weak_after
        and not base_diag.get('blocking_error_if_any'))
    blocking = ''
    if row_count < 10:
        blocking = 'rel2_substantive_quality_failed:roadmap:row_count_low'
    elif row_count > 14:
        blocking = 'rel2_substantive_quality_failed:roadmap:row_count_high'
    elif missing_after:
        blocking = f'rel2_substantive_quality_failed:roadmap:{missing_after[0]}'
    elif weak_after:
        blocking = 'rel2_substantive_quality_failed:roadmap:weak_outputs'
    elif base_diag.get('blocking_error_if_any'):
        blocking = base_diag['blocking_error_if_any']

    diag = {
        'row_count_after': row_count,
        'missing_families_after': missing_after,
        'weak_owners_after': base_diag.get('weak_owners_after', []),
        'weak_outputs_before': weak_before,
        'weak_outputs_after': weak_after,
        'roadmap_depth_passed': passed,
        'action_taken': (
            'roadmap_substance_repaired' if weak_before else 'validated'),
        'blocking_error_if_any': blocking,
    }
    return out, diag


def emit_roadmap_substance_model(payload: Dict[str, Any]) -> None:
    try:
        print(
            '[REL2-ROADMAP-SUBSTANCE-MODEL] '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
