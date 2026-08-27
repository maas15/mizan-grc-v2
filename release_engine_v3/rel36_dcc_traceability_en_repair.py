"""REL36.1 — English cyber DCC traceability repair.

Repairs missing or invalid English NCA DCC traceability rows before
PRCY69 validation. Does not change the PRCY69 gate, suppress blockers,
or bypass export evidence.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY_EN,
    _DCC_REGISTRY_ORDER,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_DCC_TRACE_DIAG_TAG = '[REL36-DCC-TRACEABILITY-EN-REPAIR]'

REL36_DCC_TRACE_HEADER_EN: Tuple[str, ...] = (
    'Reference Framework',
    'Capability / Control',
    'Related Gap',
    'Initiative / Activity',
    'Metric',
    'Related Risk',
)

# Capability tokens used only for detection. Visible labels stay English.
_REL36_DCC_CAPABILITY_TOKENS: Dict[str, Tuple[str, ...]] = {
    'data_classification': ('classification', 'تصنيف', 'inventory'),
    'encryption': ('encrypt', 'key-management', 'key management', 'تشفير'),
    'dlp': ('dlp', 'leak', 'تسرب'),
    'sensitive_handling': (
        'sensitive data handling', 'sensitive-data handling',
        'handling of sensitive', 'معالجة البيانات',
    ),
    'data_protection': (
        'transit', 'at rest', 'data protection', 'حماية البيانات',
    ),
}

_DLP_GAP_REQUIRED = ('تسرب', 'DLP', 'dlp', 'فقدان', 'leak')
_INVALID_GAP_PATTERNS = (
    'الأشهر', '1–4', '1-4', '2–6', '2-6', '6–12', '6-12', '7–18', '7-18',
    '9–12', '9-12', 'phase', 'المرحلة 1', 'المرحلة 2', 'المرحلة 3',
    'months', 'month',
)


def dcc_selected(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = ' '.join(str(x) for x in (selected_frameworks or [])).upper()
    return 'DCC' in blob


def expected_dcc_capabilities() -> List[str]:
    return list(_DCC_REGISTRY_ORDER)


def canonical_english_dcc_row(family: str) -> List[str]:
    spec = TRACE_CANONICAL_REGISTRY_EN[family]
    return [
        spec['framework'],
        spec['capability'],
        spec['expected_gap'],
        spec['initiative'],
        spec['metric'],
        spec['risk'],
    ]


def _parse_table_rows(text: str) -> List[List[str]]:
    rows: List[List[str]] = []
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|') or set(s.replace('|', '').replace(':', '')) <= set('- '):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if cells:
            rows.append(cells)
    return rows


def detect_dcc_capabilities(text: str) -> List[str]:
    blob = str(text or '').lower()
    found: List[str] = []
    for fam, tokens in _REL36_DCC_CAPABILITY_TOKENS.items():
        if any(tok.lower() in blob for tok in tokens):
            found.append(fam)
    return found


def _gap_invalid(gap: str) -> bool:
    g = str(gap or '').strip()
    if not g or g == '—':
        return False
    g_lc = g.lower()
    if any(p in g or p in g_lc for p in _INVALID_GAP_PATTERNS):
        return True
    if len(g) < 8 and any(c.isdigit() for c in g):
        return True
    return False


def _row_dcc_family(row: Sequence[str]) -> str:
    cap = str(row[1] if len(row) > 1 else '').lower()
    blob = ' '.join(str(c) for c in row).lower()
    for fam, tokens in _REL36_DCC_CAPABILITY_TOKENS.items():
        if any(tok.lower() in cap or tok.lower() in blob for tok in tokens):
            return fam
    return ''


def _row_mapping_invalid(row: Sequence[str]) -> bool:
    if len(row) < 3:
        return True
    cap = str(row[1] or '')
    gap = str(row[2] or '')
    gap_lc = gap.lower()
    if _gap_invalid(gap):
        return True
    if 'dlp' in cap.lower() or 'تسرب' in cap or 'منع' in cap:
        if any(t in gap_lc or t in gap for t in (
                'ثغر', 'vulnerability', 'vuln', 'patch', 'ترقيع')):
            return True
        if not any(t in gap for t in _DLP_GAP_REQUIRED):
            return True
    if 'تشفير' in cap or 'encrypt' in cap.lower():
        if any(t in gap_lc or t in gap for t in (
                'ثغر', 'vulnerability', 'vuln')):
            return True
    return False


def _emit_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    cols = max(len(header), max((len(r) for r in rows), default=0), 6)
    hdr = list(header) + [''] * (cols - len(header))
    lines = [
        '| ' + ' | '.join(hdr[:cols]) + ' |',
        '|' + '|'.join(['---'] * cols) + '|',
    ]
    for row in rows:
        cells = list(row) + [''] * (cols - len(row))
        lines.append('| ' + ' | '.join(str(c) for c in cells[:cols]) + ' |')
    return '\n'.join(lines)


def inventory_dcc_rows(text: str) -> Dict[str, Any]:
    rows = _parse_table_rows(text)
    detected: List[str] = []
    invalid: List[str] = []
    for row in rows:
        fam = _row_dcc_family(row)
        if not fam:
            continue
        if fam not in detected:
            detected.append(fam)
        if _row_mapping_invalid(row) and fam not in invalid:
            invalid.append(fam)
    expected = expected_dcc_capabilities()
    missing = [f for f in expected if f not in detected]
    return {
        'detected': detected,
        'missing': missing,
        'invalid': invalid,
        'row_count': sum(1 for r in rows if _row_dcc_family(r)),
    }


def repair_english_dcc_traceability_text(text: str) -> Tuple[str, List[str]]:
    """Insert or replace English DCC rows. Keeps non-DCC rows."""
    existing = _parse_table_rows(text)
    header: List[str] = list(REL36_DCC_TRACE_HEADER_EN)
    body: List[List[str]] = []
    if existing:
        first = existing[0]
        first_blob = ' '.join(first).lower()
        if 'framework' in first_blob or 'capability' in first_blob or 'إطار' in first_blob:
            header = first
            existing = existing[1:]
        for row in existing:
            fam = _row_dcc_family(row)
            if fam and _row_mapping_invalid(row):
                continue
            body.append(list(row))
    have = { _row_dcc_family(r) for r in body }
    added: List[str] = []
    for fam in expected_dcc_capabilities():
        if fam in have:
            continue
        body.append(canonical_english_dcc_row(fam))
        added.append(fam)
    if not added and existing:
        return str(text or ''), []
    return _emit_table(header, body), added


def repair_english_dcc_traceability_sections(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    out = dict(sections or {})
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or str(domain or '').strip().lower()
    selected = [str(x) for x in (selected_frameworks or []) if x]
    dcc_on = dcc_selected(selected)
    before = inventory_dcc_rows(str(out.get('traceability') or ''))
    diag: Dict[str, Any] = {
        'tag': 'REL36-DCC-TRACEABILITY-EN-REPAIR',
        'lang': nlang,
        'domain': dcode,
        'selected_frameworks': selected,
        'dcc_selected': dcc_on,
        'dcc_traceability_rows_before': before['row_count'],
        'dcc_traceability_rows_after': before['row_count'],
        'expected_dcc_capabilities': expected_dcc_capabilities(),
        'detected_dcc_capabilities': list(before['detected']),
        'missing_dcc_capabilities': list(before['missing']),
        'repaired': False,
        'prcy69_gate_passed': None,
        'blocking_errors': [],
        'passed': False,
    }
    if nlang != 'en' or dcode != 'cyber' or not dcc_on:
        diag['passed'] = True
        return out, diag
    repaired_text, added = repair_english_dcc_traceability_text(
        str(out.get('traceability') or ''))
    if added or repaired_text != str(out.get('traceability') or ''):
        out['traceability'] = repaired_text
        diag['repaired'] = bool(added) or repaired_text != str(
            (sections or {}).get('traceability') or '')
    after = inventory_dcc_rows(str(out.get('traceability') or ''))
    diag['dcc_traceability_rows_after'] = after['row_count']
    diag['detected_dcc_capabilities'] = list(after['detected'])
    diag['missing_dcc_capabilities'] = list(after['missing'])
    return out, diag


def evaluate_rel36_dcc_traceability_en(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        selected_frameworks: Optional[Iterable[Any]] = None,
        prcy69_gate_passed: Optional[bool] = None,
        blocking_errors: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    _repaired, diag = repair_english_dcc_traceability_sections(
        sections, lang=lang, domain=domain,
        selected_frameworks=selected_frameworks)
    blockers = [str(b) for b in (blocking_errors or []) if b]
    if prcy69_gate_passed is None:
        inv = inventory_dcc_rows(str((_repaired or {}).get('traceability') or ''))
        prcy69_gate_passed = (
            diag.get('dcc_selected') is False
            or (not inv['missing'] and not inv['invalid'])
        )
    diag['prcy69_gate_passed'] = bool(prcy69_gate_passed)
    diag['blocking_errors'] = blockers
    diag['passed'] = bool(prcy69_gate_passed) and not blockers and not (
        diag.get('missing_dcc_capabilities') if diag.get('dcc_selected') else [])
    return diag


def emit_rel36_dcc_traceability_en_repair(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_DCC_TRACE_DIAG_TAG} {json.dumps(diag, ensure_ascii=False)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        print(f'{REL36_DCC_TRACE_DIAG_TAG} emit_failed', flush=True)
