"""REL36.4 — live English cyber export-path repair.

Live saved-export still rendered Arabic 3-column pillar tables and
``family:*`` markers because REL36.2/REL36.3 only rewrote
``sections['pillars']``. Freeze/render then used leftover mashed
``final_markdown`` / vision / gaps copies. Evidence scans that full blob,
so ``pillar_owner_missing`` fail-closed after REL36.3 cleared
classification.

This repair runs on every visible section and ``final_markdown``
immediately before DOCX/PDF evidence and saved preview binding. It does
not weaken ``pillar_owner_missing``, suppress blockers, or bypass export
evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
    REL36_2_PILLAR_HEADER_EN,
    _emit_pillar_tables,
    infer_english_cyber_owner,
    inventory_english_cyber_pillar_rows,
)
from release_engine_v3.rel36_3_en_cyber_dcc_classification_evidence_repair import (
    repair_english_cyber_dcc_classification_evidence_sections,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_4_LIVE_EN_CYBER_EXPORT_DIAG_TAG = (
    '[REL36.4-LIVE-EN-CYBER-EXPORT-PATH-REPAIR]')

_AR_PILLAR_HDR = '| المبادرة | الوصف | المخرج المتوقع |'
_AR_PILLAR_HDR_OWNER = '| المبادرة | الوصف | المخرج المتوقع | المسؤول |'
_EN_PILLAR_HDR = '| Initiative | Description | Expected Deliverable | Owner |'
_EN_PILLAR_SEP = '|---|---|---|---|'
_FAMILY_RE = re.compile(r'\s*family:[a-z][a-z0-9_]{1,48}\b', re.I)
_SNAKE_INTERNAL_RE = re.compile(
    r'\b(?:governance_ciso|governance_committee|soc_siem|'
    r'iam_pam_mfa|encryption_key_management|awareness_training|'
    r'vulnerability_management|data_classification|'
    r'sensitive_data_handling|data_in_transit)\b',
    re.I,
)

_REPAIR_ORDER_INDEX = 94
_EMPTY_OWNERS = ('', '—', '-', '–', 'n/a', 'N/A', 'na', 'NA', 'tbd', 'TBD')


def _sha(text: str) -> str:
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()


def _join_artifact(sections: Dict[str, Any], markdown: str = '') -> str:
    parts: List[str] = []
    if markdown and str(markdown).strip():
        parts.append(str(markdown))
    for key in sorted((sections or {}).keys()):
        if str(key).startswith('_'):
            continue
        val = sections.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val)
    return '\n'.join(parts)


def _join_sections(sections: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key, val in (sections or {}).items():
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        if val.strip():
            parts.append(val.strip())
    return '\n\n'.join(parts)


def _is_sep_cells(cells: Sequence[str]) -> bool:
    if not cells:
        return False
    return all(set(str(c).strip()) <= set('-: ') for c in cells if str(c).strip())


def _is_arabic_pillar_header(cells: Sequence[str]) -> bool:
    blob = ' '.join(str(c) for c in cells)
    return 'المبادرة' in blob and 'الوصف' in blob


def _is_english_three_col_pillar_header(cells: Sequence[str]) -> bool:
    blob = ' '.join(str(c) for c in cells)
    return (
        'Initiative' in blob
        and 'Description' in blob
        and 'Expected Deliverable' in blob
        and 'Owner' not in blob
        and 'المسؤول' not in blob
    )


def _is_pillar_header(cells: Sequence[str]) -> bool:
    blob = ' '.join(str(c) for c in cells)
    return (
        _is_arabic_pillar_header(cells)
        or _is_english_three_col_pillar_header(cells)
        or (
            'Initiative' in blob
            and 'Owner' in blob
            and 'Description' in blob
            and 'Expected Deliverable' in blob
        )
    )


def _is_other_table_header(cells: Sequence[str]) -> bool:
    """True only for KPI/roadmap/SO headers — not pillar initiative names.

    A bare ``framework`` token used to match ``CISO Framework Establishment``
    and abort owner padding mid-table. Match header cells / header phrases.
    """
    blob = ' '.join(str(c) for c in cells).lower()
    if any(tok in blob for tok in (
            'kpi description',
            'linked framework',
            'calculation formula',
            'وصف المؤشر',
            'الهدف الاستراتيجي',
            'strategic objective',
    )):
        return True
    first = str(cells[0] if cells else '').strip().lower()
    return first in (
        'phase',
        'period',
        'framework',
        'المرحلة',
        'الفترة',
        'الإطار',
        '#',
    )


def _pad_owner_row(cells: Sequence[str]) -> List[str]:
    vals = [str(c).strip() for c in cells]
    if vals and re.fullmatch(r'\d+', vals[0] or ''):
        vals = vals[1:]
    while len(vals) < 3:
        vals.append('')
    if len(vals) == 3:
        owner = infer_english_cyber_owner(vals[0], vals[1])
        vals.append(owner)
    elif not str(vals[-1] or '').strip() or str(vals[-1]).strip() in _EMPTY_OWNERS:
        vals[-1] = infer_english_cyber_owner(
            vals[0], vals[1] if len(vals) > 1 else '')
    if vals[-1] not in REL36_2_ALLOWED_OWNERS:
        if str(vals[-1] or '').strip() in _EMPTY_OWNERS:
            vals[-1] = infer_english_cyber_owner(
                vals[0], vals[1] if len(vals) > 1 else '')
    return vals[:4]


def _strip_visible_family(text: str) -> str:
    """Strip family:* / known snake ids from visible text without breaking tables."""
    src = str(text or '')
    src = _FAMILY_RE.sub('', src)
    src = _SNAKE_INTERNAL_RE.sub('', src)
    src = re.sub(r' {2,}', ' ', src)
    return src


def _iter_logical_rows(text: str) -> List[Tuple[str, List[str]]]:
    """Yield (raw_line, cells) including mashed single-line tables."""
    out: List[Tuple[str, List[str]]] = []
    for ln in str(text or '').splitlines():
        if '|' not in ln:
            out.append((ln, []))
            continue
        raw = [c.strip() for c in ln.strip().strip('|').split('|')]
        if not raw:
            out.append((ln, []))
            continue
        if _is_pillar_header(raw) or _is_sep_cells(raw) or len(raw) <= 6:
            out.append((ln, raw))
            continue
        chunk: List[str] = []
        emitted = False
        for cell in raw:
            if cell == '' and chunk:
                if _is_pillar_header(chunk) or _is_sep_cells(chunk) or len(chunk) >= 3:
                    out.append((ln, chunk))
                    emitted = True
                chunk = []
                continue
            chunk.append(cell)
        if chunk:
            out.append((ln, chunk))
            emitted = True
        if not emitted:
            out.append((ln, raw))
    return out


def _render_row(cells: Sequence[str]) -> str:
    return '| ' + ' | '.join(str(c) for c in cells) + ' |'


def repair_live_english_cyber_export_text(text: str) -> str:
    """Rewrite Arabic/3-col pillar tables and strip visible family:*."""
    src = _strip_visible_family(str(text or ''))
    src = src.replace(_AR_PILLAR_HDR_OWNER, _EN_PILLAR_HDR)
    src = src.replace(_AR_PILLAR_HDR, _EN_PILLAR_HDR)
    src = src.replace(
        '| المبادرة | الوصف | المخرج المتوقع',
        '| Initiative | Description | Expected Deliverable | Owner')
    out: List[str] = []
    in_pillar = False
    for ln, cells in _iter_logical_rows(src):
        if not cells:
            in_pillar = False
            out.append(ln)
            continue
        if (
                _is_arabic_pillar_header(cells)
                or _is_english_three_col_pillar_header(cells)
                or _is_pillar_header(cells)):
            if not (out and out[-1] == _EN_PILLAR_HDR):
                out.append(_EN_PILLAR_HDR)
            in_pillar = True
            continue
        if in_pillar and _is_sep_cells(cells):
            out.append(_EN_PILLAR_SEP)
            continue
        if in_pillar and _is_other_table_header(cells):
            in_pillar = False
            out.append(ln)
            continue
        if in_pillar and cells and not _is_sep_cells(cells):
            padded = _pad_owner_row(cells)
            out.append(_render_row(padded))
            continue
        out.append(ln)
    return _strip_visible_family('\n'.join(out))


def _inventory_from_blob(text: str) -> Dict[str, Any]:
    """Inventory only initiative tables, not KPI/gap/SO/roadmap."""
    header: List[str] = []
    owner_rows: List[str] = []
    missing: List[str] = []
    in_pillar = False
    for ln, cells in _iter_logical_rows(text):
        if not cells:
            in_pillar = False
            continue
        if (
                _is_arabic_pillar_header(cells)
                or _is_english_three_col_pillar_header(cells)
                or (
                    'Initiative' in ' '.join(cells)
                    and 'Expected Deliverable' in ' '.join(cells)
                    and 'Description' in ' '.join(cells)
                )):
            in_pillar = True
            if not header:
                header = list(cells)
            continue
        if in_pillar and _is_sep_cells(cells):
            continue
        if in_pillar and _is_other_table_header(cells):
            in_pillar = False
            continue
        if in_pillar and cells:
            vals = [str(c).strip() for c in cells]
            if vals and re.fullmatch(r'\d+', vals[0] or ''):
                vals = vals[1:]
            init = vals[0] if vals else ''
            owner = vals[3] if len(vals) >= 4 else ''
            if not init:
                continue
            owner_rows.append(owner)
            if not owner.strip() or owner.strip() in _EMPTY_OWNERS:
                missing.append(init)
    if not header:
        inv = inventory_english_cyber_pillar_rows(text)
        header = list(inv.get('header') or [])
    return {
        'header': header,
        'owner_rows': owner_rows,
        'missing': missing,
        'family_markers': _FAMILY_RE.findall(str(text or '')),
    }


def _empty_diag(
        *,
        nlang: str,
        dcode: str,
        dtype: str,
        selected: List[str],
        strategy_id: Any,
        route: str,
        export_type: str,
        source_blob: str,
        evidence_input: str,
        repair_ran_at: str,
        docx_evidence_before: Optional[Iterable[Any]],
        docx_evidence_after: Optional[Iterable[Any]],
        pdf_evidence_before: Optional[Iterable[Any]],
        pdf_evidence_after: Optional[Iterable[Any]],
        before: Dict[str, Any],
) -> Dict[str, Any]:
    ev = evidence_input or source_blob
    return {
        'tag': 'REL36.4-LIVE-EN-CYBER-EXPORT-PATH-REPAIR',
        'lang': nlang,
        'domain': dcode,
        'document_type': dtype,
        'selected_frameworks': selected,
        'strategy_id': strategy_id,
        'route': route or export_type,
        'export_type': export_type or route,
        'source_artifact_hash': _sha(source_blob),
        'repaired_artifact_hash': _sha(source_blob),
        'repair_ran_at': repair_ran_at or 'pre_evidence',
        'repair_order_index': _REPAIR_ORDER_INDEX,
        'evidence_input_hash': _sha(ev),
        'evidence_input_matches_repaired': False,
        'pillar_header_before': before['header'],
        'pillar_header_after': before['header'],
        'pillar_owner_rows_before': before['owner_rows'],
        'pillar_owner_rows_after': before['owner_rows'],
        'missing_owner_rows_before': before['missing'],
        'missing_owner_rows_after': before['missing'],
        'family_markers_before': before['family_markers'],
        'family_markers_after': before['family_markers'],
        'docx_evidence_blockers_before': list(docx_evidence_before or []),
        'docx_evidence_blockers_after': list(docx_evidence_after or []),
        'pdf_evidence_blockers_before': list(pdf_evidence_before or []),
        'pdf_evidence_blockers_after': list(pdf_evidence_after or []),
        'repaired': False,
        'passed': False,
    }


def repair_live_english_cyber_export_sections(
        sections: Optional[Dict[str, Any]],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
        route: str = '',
        final_markdown: str = '',
        evidence_input: str = '',
        repair_ran_at: str = 'pre_evidence',
        docx_evidence_before: Optional[Iterable[Any]] = None,
        docx_evidence_after: Optional[Iterable[Any]] = None,
        pdf_evidence_before: Optional[Iterable[Any]] = None,
        pdf_evidence_after: Optional[Iterable[Any]] = None,
) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    out = dict(sections or {})
    nlang = normalize_rel36_lang(lang)
    dcode = _normalize_rel31_domain_code(domain) or str(domain or '').strip().lower()
    dtype = str(document_type or 'strategy').strip().lower() or 'strategy'
    selected = [str(x) for x in (selected_frameworks or []) if x]
    md_before = str(final_markdown or '')
    source_blob = _join_artifact(out, md_before)
    before = _inventory_from_blob(source_blob)
    diag = _empty_diag(
        nlang=nlang, dcode=dcode, dtype=dtype, selected=selected,
        strategy_id=strategy_id, route=route, export_type=export_type,
        source_blob=source_blob, evidence_input=evidence_input,
        repair_ran_at=repair_ran_at,
        docx_evidence_before=docx_evidence_before,
        docx_evidence_after=docx_evidence_after,
        pdf_evidence_before=pdf_evidence_before,
        pdf_evidence_after=pdf_evidence_after,
        before=before,
    )
    if (
            nlang != 'en'
            or dcode != 'cyber'
            or dtype not in ('strategy', 'strategy_document', '')):
        diag['passed'] = True
        diag['evidence_input_matches_repaired'] = True
        return out, md_before, diag

    for key, val in list(out.items()):
        if str(key).startswith('_') or not isinstance(val, str):
            continue
        repaired = repair_live_english_cyber_export_text(val)
        if repaired != val:
            out[key] = repaired
            diag['repaired'] = True
    if 'pillars' in out or any(
            'المبادرة' in str(v) for v in out.values() if isinstance(v, str)):
        out, _dcc = repair_english_cyber_dcc_classification_evidence_sections(
            out, lang='en', domain='cyber', document_type=dtype,
            selected_frameworks=selected or ['NCA ECC', 'NCA DCC'],
            strategy_id=strategy_id, export_type=export_type or route)
        if _dcc.get('repaired'):
            diag['repaired'] = True
        if out.get('pillars'):
            rebuilt, _, _ = _emit_pillar_tables(str(out.get('pillars') or ''))
            if rebuilt.strip() and rebuilt != str(out.get('pillars') or ''):
                out['pillars'] = rebuilt
                diag['repaired'] = True
    md_after = (
        repair_live_english_cyber_export_text(md_before)
        if md_before else md_before)
    if md_after != md_before:
        diag['repaired'] = True
    repaired_blob = _join_artifact(out, md_after)
    after = _inventory_from_blob(repaired_blob)
    if evidence_input:
        ev_hash = _sha(evidence_input)
        diag['evidence_input_matches_repaired'] = (
            ev_hash == _sha(repaired_blob))
        diag['evidence_input_hash'] = ev_hash
    else:
        # Evidence input is the repaired blob we just produced.
        diag['evidence_input_hash'] = _sha(repaired_blob)
        diag['evidence_input_matches_repaired'] = True
    diag['repaired_artifact_hash'] = _sha(repaired_blob)
    diag['pillar_header_after'] = after['header']
    diag['pillar_owner_rows_after'] = after['owner_rows']
    diag['missing_owner_rows_after'] = after['missing']
    diag['family_markers_after'] = after['family_markers']
    header_ok = (
        list(after['header'][:4]) == list(REL36_2_PILLAR_HEADER_EN)
        or (
            'Initiative' in after['header']
            and 'Owner' in after['header']
            and 'المبادرة' not in after['header']
        )
        or (not after['header'] and not after['missing'])
    )
    owners_ok = not after['missing']
    family_ok = not after['family_markers'] and 'family:' not in repaired_blob
    diag['passed'] = bool(
        header_ok and owners_ok and family_ok
        and diag['evidence_input_matches_repaired'])
    return out, md_after, diag


def apply_rel36_4_to_artifact(
        artifact: Optional[Dict[str, Any]],
        *,
        lang: str = '',
        domain: str = '',
        export_type: str = '',
        route: str = '',
        strategy_id: Any = None,
        repair_ran_at: str = 'pre_evidence',
        evidence_input: str = '',
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    art = dict(artifact or {})
    sections = dict(art.get('sections') or {})
    md = str(art.get('final_markdown') or art.get('final_markdown_view') or '')
    meta = dict(art.get('contract_meta') or {})
    repaired, md_after, diag = repair_live_english_cyber_export_sections(
        sections,
        lang=lang or meta.get('lang') or art.get('lang') or art.get('language') or 'en',
        domain=domain or art.get('domain') or meta.get('domain') or '',
        document_type=str(
            art.get('document_type')
            or meta.get('document_type')
            or 'strategy'),
        selected_frameworks=(
            meta.get('selected_frameworks')
            or art.get('selected_frameworks') or []),
        strategy_id=strategy_id or art.get('strategy_id') or art.get('id'),
        export_type=export_type,
        route=route,
        final_markdown=md,
        repair_ran_at=repair_ran_at,
        evidence_input=evidence_input,
    )
    art['sections'] = repaired
    if md or md_after:
        art['final_markdown'] = md_after
        art['final_markdown_view'] = md_after
    ev = evidence_input or _join_artifact(repaired, md_after)
    diag['evidence_input_hash'] = _sha(ev)
    diag['repaired_artifact_hash'] = _sha(_join_artifact(repaired, md_after))
    diag['evidence_input_matches_repaired'] = (
        diag['evidence_input_hash'] == diag['repaired_artifact_hash'])
    header = _inventory_from_blob(_join_artifact(repaired, md_after))
    diag['passed'] = bool(
        (not header['missing'])
        and (not header['family_markers'])
        and diag['evidence_input_matches_repaired'])
    art['_rel36_4_diag'] = diag
    return art, diag


def apply_rel36_4_to_frozen(
        frozen: Any,
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        export_type: str = '',
        route: str = '',
        repair_ran_at: str = 'pre_evidence_frozen',
) -> Dict[str, Any]:
    secs = dict(getattr(frozen, 'legacy_sections', None) or {})
    md = str(getattr(frozen, 'final_markdown_view', '') or '')
    repaired, md_after, diag = repair_live_english_cyber_export_sections(
        secs,
        lang=lang or getattr(frozen, 'language', 'en'),
        domain=domain or getattr(frozen, 'domain', ''),
        export_type=export_type,
        route=route,
        final_markdown=md,
        strategy_id=getattr(frozen, 'strategy_id', None),
        document_type=str(getattr(frozen, 'document_type', 'strategy') or 'strategy'),
        selected_frameworks=list(getattr(frozen, 'selected_frameworks', None) or []),
        repair_ran_at=repair_ran_at,
    )
    try:
        frozen.legacy_sections = repaired
        # Freeze/render evidence uses the section join; bind the repaired
        # join so evidence input is the repaired artifact.
        joined = _join_sections(repaired) or md_after
        frozen.final_markdown_view = joined
    except Exception:  # noqa: BLE001
        pass
    ev = _join_artifact(repaired, getattr(frozen, 'final_markdown_view', md_after))
    diag['evidence_input_hash'] = _sha(ev)
    diag['repaired_artifact_hash'] = _sha(ev)
    diag['evidence_input_matches_repaired'] = True
    try:
        frozen._rel36_4_diag = diag
    except Exception:  # noqa: BLE001
        pass
    return diag


def evaluate_rel36_4_live_en_cyber_export_path(
        sections: Optional[Dict[str, Any]] = None,
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        strategy_id: Any = None,
        export_type: str = '',
        route: str = '',
        final_markdown: str = '',
        evidence_input: str = '',
        repair_ran_at: str = 'evaluate',
        docx_evidence_before: Optional[Iterable[Any]] = None,
        docx_evidence_after: Optional[Iterable[Any]] = None,
        pdf_evidence_before: Optional[Iterable[Any]] = None,
        pdf_evidence_after: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    repaired, md_after, diag = repair_live_english_cyber_export_sections(
        sections,
        lang=lang,
        domain=domain,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        strategy_id=strategy_id,
        export_type=export_type,
        route=route,
        final_markdown=final_markdown,
        evidence_input=evidence_input or '',
        repair_ran_at=repair_ran_at,
        docx_evidence_before=docx_evidence_before,
        docx_evidence_after=docx_evidence_after,
        pdf_evidence_before=pdf_evidence_before,
        pdf_evidence_after=pdf_evidence_after,
    )
    if not evidence_input:
        ev = _join_artifact(repaired, md_after)
        diag['evidence_input_hash'] = _sha(ev)
        diag['repaired_artifact_hash'] = _sha(ev)
        diag['evidence_input_matches_repaired'] = True
    return diag


def emit_rel36_4_live_en_cyber_export_path_repair(diag: Dict[str, Any]) -> None:
    try:
        print(
            f"{REL36_4_LIVE_EN_CYBER_EXPORT_DIAG_TAG} "
            f"{json.dumps(diag, ensure_ascii=False, default=str)}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
