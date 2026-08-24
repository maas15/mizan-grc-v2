"""REL36.2 — English cyber export-evidence repair.

English Cyber pillar tables are generated as 3-column
Initiative / Description / Expected Deliverable (sometimes remapped to
المبادرة / الوصف / المخرج المتوقع) with no owner column. Schema binding
then pads Owner/المسؤول with em-dash, and export evidence fail-closes
on pillar_owner_missing. PDF fails with the same evidence, wrapped as
"actual PDF evidence validation failed".

This repair inserts non-empty domain-appropriate English owners before
the evidence gate. It does not weaken pillar_owner_missing, suppress
blockers, or bypass export evidence.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_2_EN_CYBER_EXPORT_DIAG_TAG = '[REL36.2-EN-CYBER-EXPORT-EVIDENCE-REPAIR]'

REL36_2_PILLAR_HEADER_EN: Tuple[str, ...] = (
    'Initiative',
    'Description',
    'Expected Deliverable',
    'Owner',
)

REL36_2_OWNER_ALIASES = (
    'owner', 'responsible owner', 'accountable owner',
    'المسؤول', 'المالك',
)

REL36_2_ALLOWED_OWNERS = (
    'CISO',
    'SOC Manager',
    'CSIRT Lead',
    'IAM/PAM Manager',
    'Data Protection Officer',
    'Vulnerability Manager',
    'Business Continuity Manager',
    'Security Awareness Manager',
    'Cybersecurity Governance Manager',
)

_EMPTY_OWNERS = ('', '—', '-', '–', 'n/a', 'N/A', 'na', 'NA', 'tbd', 'TBD')

_OWNER_RULES: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (('soc', 'siem', 'soar', 'monitoring', 'detection'), 'SOC Manager'),
    (('csirt', 'incident', 'playbook', 'استجابة'), 'CSIRT Lead'),
    (('iam', 'pam', 'mfa', 'privileged', 'identity', 'هوية'), 'IAM/PAM Manager'),
    (('dlp', 'classif', 'encrypt', 'data protection', 'sensitive data',
      'leak', 'تسرب', 'تصنيف', 'تشفير'), 'Data Protection Officer'),
    (('vulnerab', 'patch', 'cve', 'ثغر'), 'Vulnerability Manager'),
    (('bcp', 'disaster', 'backup', 'continuity', 'تعافي', 'نسخ'),
     'Business Continuity Manager'),
    (('aware', 'phish', 'training', 'توعية'), 'Security Awareness Manager'),
    (('govern', 'policy', 'committee', 'charter', 'حوكمة', 'سياسة'),
     'Cybersecurity Governance Manager'),
)


def _is_empty_owner(value: Any) -> bool:
    return str(value or '').strip() in _EMPTY_OWNERS


def _header_has_owner(header: Sequence[str]) -> bool:
    blob = ' '.join(str(c) for c in header).strip().lower()
    return any(alias in blob for alias in REL36_2_OWNER_ALIASES)


def _is_header_row(cells: Sequence[str]) -> bool:
    blob = ' '.join(str(c) for c in cells).lower()
    return any(tok in blob for tok in (
        'initiative', 'description', 'expected deliverable', 'owner',
        'responsible owner', 'accountable owner',
        'المبادرة', 'الوصف', 'المخرج', 'المسؤول', 'المالك',
    ))


def _is_sep_row(cells: Sequence[str]) -> bool:
    if not cells:
        return False
    return all(
        set(str(c).strip()) <= set('-: ')
        for c in cells if str(c).strip()
    ) and any(str(c).strip() for c in cells)


def infer_english_cyber_owner(initiative: str, description: str = '') -> str:
    blob = f'{initiative} {description}'.lower()
    for tokens, owner in _OWNER_RULES:
        if any(tok in blob for tok in tokens):
            return owner
    return 'CISO'


def inventory_english_cyber_pillar_rows(text: str) -> Dict[str, Any]:
    rows = _extract_pillar_data_rows(text)
    missing = [
        r['initiative'] for r in rows if _is_empty_owner(r.get('owner'))]
    header = _first_table_header(text)
    return {
        'row_count': len(rows),
        'missing_owner_rows': missing,
        'owner_values': [r.get('owner') or '' for r in rows],
        'owner_header_detected': _header_has_owner(header),
        'header': header,
        'rows': rows,
    }


def _first_table_header(text: str) -> List[str]:
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not s.startswith('|'):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if _is_header_row(cells) and not _is_sep_row(cells):
            return cells
    return []


def _extract_pillar_data_rows(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    header: List[str] = []
    for cells in _iter_table_rows(text):
        if _is_sep_row(cells):
            continue
        if _is_header_row(cells):
            header = cells
            continue
        parsed = _cells_to_row(cells, header)
        if parsed.get('initiative'):
            rows.append(parsed)
    return rows


def _iter_table_rows(text: str) -> List[List[str]]:
    """Yield logical table rows, including mashed single-line tables."""
    out: List[List[str]] = []
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if '|' not in s:
            continue
        raw = [c.strip() for c in s.strip().strip('|').split('|')]
        if not raw:
            continue
        if _is_header_row(raw) or _is_sep_row(raw) or len(raw) <= 6:
            out.append(raw)
            continue
        # Mashed tables: |---|---|---| | 1 | init | desc | out | | 2 | ...
        chunk: List[str] = []
        for cell in raw:
            if cell == '' and chunk:
                if _is_header_row(chunk) or _is_sep_row(chunk) or len(chunk) >= 3:
                    out.append(chunk)
                chunk = []
                continue
            chunk.append(cell)
        if chunk:
            out.append(chunk)
    return out


def _cells_to_row(cells: Sequence[str], header: Sequence[str]) -> Dict[str, str]:
    vals = [str(c).strip() for c in cells]
    if vals and re.fullmatch(r'\d+', vals[0] or ''):
        vals = vals[1:]
    owner_idx = -1
    if header:
        for i, h in enumerate(header):
            if str(h).strip().lower() in REL36_2_OWNER_ALIASES or str(h).strip() in (
                    'المسؤول', 'المالك'):
                owner_idx = i
                if header and re.fullmatch(r'#', str(header[0]).strip() or ''):
                    owner_idx = max(owner_idx - 1, -1)
                break
    initiative = vals[0] if vals else ''
    description = vals[1] if len(vals) > 1 else ''
    deliverable = vals[2] if len(vals) > 2 else ''
    owner = ''
    if owner_idx >= 0 and owner_idx < len(vals):
        owner = vals[owner_idx]
    elif len(vals) >= 4:
        owner = vals[-1]
    return {
        'initiative': initiative,
        'description': description,
        'deliverable': deliverable,
        'owner': owner,
    }


def _emit_pillar_tables(text: str) -> Tuple[str, int, int]:
    """Rebuild English cyber pillar tables with Owner column filled."""
    src = str(text or '')
    if not src.strip():
        return src, 0, 0
    chunks = re.split(r'(?=^###\s+)', src, flags=re.MULTILINE)
    if len(chunks) == 1 and '### ' not in src:
        chunks = [src]
    missing_before = 0
    missing_after = 0
    out_parts: List[str] = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        rows = _extract_pillar_data_rows(chunk)
        if not rows:
            out_parts.append(chunk.rstrip())
            continue
        heading = ''
        narrative: List[str] = []
        seen_table = False
        for ln in chunk.splitlines():
            if ln.startswith('###'):
                heading = ln.split('|', 1)[0].strip()
                continue
            if '|' in ln:
                seen_table = True
                continue
            if not seen_table:
                narrative.append(ln)
        before_missing = sum(1 for r in rows if _is_empty_owner(r.get('owner')))
        missing_before += before_missing
        repaired_rows: List[List[str]] = []
        for row in rows:
            owner = str(row.get('owner') or '').strip()
            if _is_empty_owner(owner):
                owner = infer_english_cyber_owner(
                    row.get('initiative') or '', row.get('description') or '')
            repaired_rows.append([
                row.get('initiative') or '',
                row.get('description') or '',
                row.get('deliverable') or '',
                owner,
            ])
        missing_after += sum(1 for r in repaired_rows if _is_empty_owner(r[3]))
        parts: List[str] = []
        if heading:
            parts.append(heading)
            parts.append('')
        narr = '\n'.join(narrative).strip()
        if narr:
            parts.append(narr)
            parts.append('')
        parts.append('| ' + ' | '.join(REL36_2_PILLAR_HEADER_EN) + ' |')
        parts.append('|' + '|'.join(['---'] * 4) + '|')
        for row in repaired_rows:
            parts.append('| ' + ' | '.join(row) + ' |')
        out_parts.append('\n'.join(parts).rstrip())
    return '\n\n'.join(out_parts).rstrip() + ('\n' if out_parts else ''), missing_before, missing_after


def repair_english_cyber_export_evidence_sections(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    out = dict(sections or {})
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or str(domain or '').strip().lower()
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    selected = [str(x) for x in (selected_frameworks or []) if x]
    before = inventory_english_cyber_pillar_rows(str(out.get('pillars') or ''))
    diag: Dict[str, Any] = {
        'tag': 'REL36.2-EN-CYBER-EXPORT-EVIDENCE-REPAIR',
        'lang': nlang,
        'domain': dcode,
        'document_type': dtype,
        'selected_frameworks': selected,
        'strategy_id': strategy_id,
        'export_type': export_type,
        'pillar_rows_before': before['row_count'],
        'pillar_rows_after': before['row_count'],
        'missing_owner_rows_before': list(before['missing_owner_rows']),
        'missing_owner_rows_after': list(before['missing_owner_rows']),
        'owner_header_detected': before['owner_header_detected'],
        'owner_alias_used': 'Owner',
        'docx_evidence_before': None,
        'docx_evidence_after': None,
        'pdf_evidence_before': None,
        'pdf_evidence_after': None,
        'repaired': False,
        'blocking_errors': [],
        'passed': False,
    }
    if nlang != 'en' or dcode != 'cyber' or dtype not in ('strategy', 'strategy_document', ''):
        diag['passed'] = True
        return out, diag
    repaired_text, miss_b, miss_a = _emit_pillar_tables(str(out.get('pillars') or ''))
    after = inventory_english_cyber_pillar_rows(repaired_text)
    diag['pillar_rows_after'] = after['row_count']
    diag['missing_owner_rows_before'] = list(before['missing_owner_rows']) or (
        ['empty_owner'] * miss_b if miss_b else [])
    diag['missing_owner_rows_after'] = list(after['missing_owner_rows'])
    diag['owner_header_detected'] = after['owner_header_detected']
    if repaired_text.strip() and repaired_text != str(out.get('pillars') or ''):
        out['pillars'] = repaired_text
        diag['repaired'] = True
    diag['passed'] = (
        after['row_count'] == 0
        or (not after['missing_owner_rows'] and after['owner_header_detected'])
    )
    if after['missing_owner_rows']:
        diag['blocking_errors'].append('pillar_owner_missing')
    return out, diag


def evaluate_rel36_2_en_cyber_export_evidence(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
        docx_evidence_before: Optional[Iterable[Any]] = None,
        docx_evidence_after: Optional[Iterable[Any]] = None,
        pdf_evidence_before: Optional[Iterable[Any]] = None,
        pdf_evidence_after: Optional[Iterable[Any]] = None,
        blocking_errors: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    _repaired, diag = repair_english_cyber_export_evidence_sections(
        sections, lang=lang, domain=domain, document_type=document_type,
        selected_frameworks=selected_frameworks, strategy_id=strategy_id,
        export_type=export_type)
    diag['docx_evidence_before'] = list(docx_evidence_before or []) or None
    diag['docx_evidence_after'] = list(docx_evidence_after or []) or None
    diag['pdf_evidence_before'] = list(pdf_evidence_before or []) or None
    diag['pdf_evidence_after'] = list(pdf_evidence_after or []) or None
    blockers = [str(b) for b in (blocking_errors or []) if b]
    diag['blocking_errors'] = list(dict.fromkeys(
        list(diag.get('blocking_errors') or []) + blockers))
    diag['passed'] = bool(diag.get('passed')) and not diag['blocking_errors']
    return diag


def emit_rel36_2_en_cyber_export_evidence_repair(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_2_EN_CYBER_EXPORT_DIAG_TAG} "
            f"{json.dumps(diag, ensure_ascii=False, default=str)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        print(f'{REL36_2_EN_CYBER_EXPORT_DIAG_TAG} emit_failed', flush=True)
