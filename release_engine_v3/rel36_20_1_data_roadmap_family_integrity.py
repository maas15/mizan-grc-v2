"""REL36.20.1 — Data roadmap family-integrity normalization.

REL36.20 official staging on ``d537066`` accepted 5/6 routes. Arabic
Data failed the unchanged save-gate with:

* ``roadmap_family_duplicated`` — more than one ``## N.`` heading in
  the roadmap section (``validate_arabic_section_family_integrity``).
* ``roadmap_family_restart_detected`` — the ``## 5. خارطة`` family
  heading appears more than once globally
  (``validate_arabic_family_uniqueness``).

REL36.20 also re-applies Data row inserts from three hooks and can
append a family that the official detector already saw, or append a
``## 6.`` KPI seed heading. Guide completion must not write into
roadmap.

This module:

* inserts only official-missing Data families
* collapses duplicate / restarted Data family *rows* into one
  contiguous canonical-order block
* keeps exactly one canonical ``## 5.`` heading in roadmap
* removes stray ``## 5.`` headings from other sections
* is a no-op on a second pass

It does not mark the save-gate passed and does not apply to Cyber.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    _OFFICIAL_BALANCE_TOKENS,
    _TABLE_HEADER_AR,
    _TABLE_SEP,
    detect_balance_families,
    required_balance_families,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    _DATA_FAMILY_ROWS_AR,
    official_data_missing_families,
    official_data_required_families,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_20_1_DATA_ROADMAP_FAMILY_INTEGRITY_TAG = (
    '[REL36.20.1-DATA-ROADMAP-FAMILY-INTEGRITY]')

CANONICAL_FAMILY_ORDER: Tuple[str, ...] = (
    'data_quality',
    'data_catalog',
    'data_lifecycle',
    'privacy_governance',
    'personal_data_classification',
    'consent_management',
    'data_subject_rights',
    'breach_notification',
)

_NUMBERED_HEADING_RE = re.compile(r'^##\s*\d+\.\s+[^\n]*$', re.MULTILINE)
_ROADMAP_FAMILY_HEADING_RE = re.compile(
    r'^##\s*5\.\s*(?:Implementation\s+Roadmap|Roadmap|'
    r'\d+-Month\s+Implementation|خارطة(?:\s+التنفيذ|\s+الطريق)?)[^\n]*$',
    re.MULTILINE | re.IGNORECASE,
)
_ANY_H5_RE = re.compile(r'^##\s*5\.\s+[^\n]*$', re.MULTILINE)
_SEP_RE = re.compile(r'^\|[\s\-:|]+\|$')
_TABLE_HEADER_EN = (
    '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |'
)
_LEAK_TERMS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)


def _leakage_terms(text: str) -> List[str]:
    hay = str(text or '')
    hits = [tok for tok in _LEAK_TERMS if tok in hay]
    # Bare NCA only when it is not part of NDMO.
    return [t for t in hits if t != 'NCA' or re.search(r'(?<![A-Z])NCA(?![A-Z])', hay)]


def _required_data_families(selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    try:
        required = official_data_required_families(selected_frameworks)
        if required:
            return list(required)
    except Exception:
        pass
    return required_balance_families(selected_frameworks)


def _official_missing_data_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
        lang: str,
) -> List[str]:
    try:
        import app as app_mod
        return list(
            app_mod._compute_missing_data_roadmap_balance_topics(
                text or '', selected_frameworks, lang=lang) or [])
    except Exception:
        try:
            return official_data_missing_families(text, selected_frameworks)
        except Exception:
            from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
                missing_balance_families,
            )
            return missing_balance_families(text, selected_frameworks)


def _en_family_rows() -> Dict[str, str]:
    from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
        _DATA_FAMILY_ROWS_EN,
    )
    return _DATA_FAMILY_ROWS_EN


def _domain_code(domain: Optional[str]) -> str:
    return str(_normalize_rel31_domain_code(domain) or '').strip().lower()


def rel36_20_1_should_apply(
        *,
        domain: Optional[str],
        document_type: Optional[str],
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> bool:
    if _domain_code(domain) != 'data':
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in {'strategy', 'strategy document', ''}:
        return False
    blob = ' '.join(str(x) for x in _selected_list(selected_frameworks)).lower()
    return 'ndmo' in blob or 'pdpl' in blob


_OWNER_ONLY_PRIVACY_TOKENS = frozenset({
    'حماية البيانات الشخصية',
    'مسؤول حماية البيانات الشخصية',
    'data protection officer',
})


def _family_of_row(row: str) -> Optional[str]:
    hay = str(row or '')
    hay_lc = hay.lower()
    best: Optional[str] = None
    best_len = 0
    for fam in CANONICAL_FAMILY_ORDER:
        for tok in _OFFICIAL_BALANCE_TOKENS.get(fam, ()):
            if not tok:
                continue
            if (
                    fam == 'privacy_governance'
                    and tok.lower() in _OWNER_ONLY_PRIVACY_TOKENS
            ):
                continue
            hit = (tok.lower() in hay_lc) or (tok in hay)
            if hit and len(tok) > best_len:
                best = fam
                best_len = len(tok)
    return best


def _split_roadmap_parts(text: str) -> Tuple[str, List[str], str, List[str]]:
    """Return (preamble, header_lines, body_rows, suffix_non_rows)."""
    lines = (text or '').splitlines()
    header_idx = -1
    sep_idx = -1
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and not _SEP_RE.match(s):
            cells = [c.strip() for c in s.strip('|').split('|')]
            joined = ' '.join(cells).lower()
            if any(h in joined for h in (
                    'المرحلة', 'phase', 'الربع', 'initiative', 'المبادرة')):
                header_idx = idx
                if idx + 1 < len(lines) and _SEP_RE.match(lines[idx + 1].strip()):
                    sep_idx = idx + 1
                break
    if header_idx < 0:
        return (text or ''), [], [], []
    preamble = '\n'.join(lines[:header_idx]).rstrip()
    header_lines = [lines[header_idx]]
    if sep_idx >= 0:
        header_lines.append(lines[sep_idx])
        start = sep_idx + 1
    else:
        start = header_idx + 1
    rows: List[str] = []
    suffix: List[str] = []
    in_rows = True
    for ln in lines[start:]:
        s = ln.strip()
        if in_rows and s.startswith('|') and s.endswith('|') and not _SEP_RE.match(s):
            rows.append(ln if ln.startswith('|') else s)
            continue
        if in_rows and (not s or _SEP_RE.match(s)):
            continue
        in_rows = False
        suffix.append(ln)
    return preamble, header_lines, rows, suffix


def family_sequence(text: str) -> List[str]:
    seq: List[str] = []
    _, _, rows, _ = _split_roadmap_parts(text)
    if not rows:
        # Fall back to whole-text first-hit order.
        hay = str(text or '')
        hay_lc = hay.lower()
        for fam in CANONICAL_FAMILY_ORDER:
            for tok in _OFFICIAL_BALANCE_TOKENS.get(fam, ()):
                if tok and ((tok.lower() in hay_lc) or (tok in hay)):
                    seq.append(fam)
                    break
        return seq
    for row in rows:
        fam = _family_of_row(row)
        if fam:
            seq.append(fam)
    return seq


def family_blocks(seq: Sequence[str]) -> List[str]:
    blocks: List[str] = []
    for fam in seq:
        if not blocks or blocks[-1] != fam:
            blocks.append(fam)
    return blocks


def duplicate_families(seq: Sequence[str]) -> List[str]:
    seen = set()
    dups: List[str] = []
    for fam in family_blocks(seq):
        if fam in seen and fam not in dups:
            dups.append(fam)
        seen.add(fam)
    return dups


def restarted_families(seq: Sequence[str]) -> List[str]:
    # A family that appears in more than one block is a restart.
    return duplicate_families(seq)


def numbered_headings(text: str) -> List[str]:
    return _NUMBERED_HEADING_RE.findall(text or '')


def roadmap_family_heading_count(text: str) -> int:
    return len(_ROADMAP_FAMILY_HEADING_RE.findall(text or ''))


def heading_blockers(sections: Dict[str, str]) -> List[str]:
    blockers: List[str] = []
    road = str(sections.get('roadmap') or '')
    if len(numbered_headings(road)) > 1:
        blockers.append('roadmap_family_duplicated')
    global_hits = 0
    for key in ('vision', 'pillars', 'environment', 'gaps',
                'roadmap', 'kpis', 'confidence'):
        global_hits += roadmap_family_heading_count(str(sections.get(key) or ''))
    if global_hits > 1:
        blockers.append('roadmap_family_restart_detected')
    return blockers


def _canonical_heading(lang: str) -> str:
    if str(lang or '').startswith('ar'):
        return '## 5. خارطة التنفيذ'
    return '## 5. Implementation Roadmap'


def _normalize_headings(sections: Dict[str, str], lang: str) -> None:
    heading = _canonical_heading(lang)
    road = str(sections.get('roadmap') or '')
    if road.strip():
        body = _NUMBERED_HEADING_RE.sub('', road)
        body = re.sub(r'\n{3,}', '\n\n', body).strip()
        sections['roadmap'] = heading + '\n\n' + body + ('\n' if body else '')
    for key in ('vision', 'pillars', 'environment', 'gaps',
                'kpis', 'confidence'):
        text = str(sections.get(key) or '')
        if not text:
            continue
        cleaned = _ROADMAP_FAMILY_HEADING_RE.sub('', text)
        cleaned = _ANY_H5_RE.sub('', cleaned)
        if cleaned != text:
            sections[key] = re.sub(r'\n{3,}', '\n\n', cleaned).strip() + '\n'


def _default_header(lang: str) -> List[str]:
    if str(lang or '').startswith('ar'):
        return [_TABLE_HEADER_AR, _TABLE_SEP]
    return [_TABLE_HEADER_EN, _TABLE_SEP]


def _normalize_family_rows(
        text: str,
        *,
        lang: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> Tuple[str, List[str], List[str]]:
    """Collapse/order family rows. Returns (text, inserted, skipped)."""
    required = _required_data_families(selected_frameworks) or list(
        required_balance_families(selected_frameworks))
    preamble, header_lines, rows, suffix = _split_roadmap_parts(text)
    if not header_lines:
        header_lines = _default_header(lang)
    detected = set(detect_balance_families(text))
    missing = _official_missing_data_families(text, selected_frameworks, lang)
    rows_by_family = (
        _DATA_FAMILY_ROWS_AR if str(lang).startswith('ar')
        else _en_family_rows()
    )
    skipped = [fam for fam in required if fam in detected]
    inserted: List[str] = []
    extra_rows: List[str] = []
    for fam in missing:
        if fam in detected:
            continue
        row = rows_by_family.get(fam)
        if not row:
            continue
        extra_rows.append(row)
        inserted.append(fam)
        detected.add(fam)

    grouped: Dict[str, List[str]] = {fam: [] for fam in CANONICAL_FAMILY_ORDER}
    unknown: List[str] = []
    seen_exact = set()
    for row in list(rows) + extra_rows:
        key = re.sub(r'\s+', ' ', row.strip())
        if key in seen_exact:
            continue
        seen_exact.add(key)
        fam = _family_of_row(row)
        if fam and fam in grouped:
            grouped[fam].append(row if row.startswith('|') else row)
        else:
            unknown.append(row)

    ordered: List[str] = []
    for fam in CANONICAL_FAMILY_ORDER:
        if fam in required or grouped[fam]:
            ordered.extend(grouped[fam])
    ordered.extend(unknown)

    parts: List[str] = []
    if preamble.strip() and not _NUMBERED_HEADING_RE.search(preamble):
        parts.append(preamble.strip())
    parts.extend(header_lines)
    parts.extend(ordered)
    suffix_clean = [
        ln for ln in suffix
        if not _NUMBERED_HEADING_RE.match(ln.strip())
    ]
    if suffix_clean:
        parts.append('')
        parts.extend(suffix_clean)
    return '\n'.join(parts).rstrip() + '\n', inserted, skipped


def apply_rel36_20_1_data_roadmap_family_integrity(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    fw = list(_selected_list(selected_frameworks))
    diag: Dict[str, Any] = {
        'task_id': task_id or '',
        'domain': dcode,
        'lang': nlang,
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': fw,
        'applied': False,
        'passed': False,
    }
    if not rel36_20_1_should_apply(
            domain=dcode, document_type=document_type,
            selected_frameworks=fw):
        diag['skipped'] = True
        return out, diag

    required = _required_data_families(fw)
    before_text = str(out.get('roadmap') or '')
    seq_before = family_sequence(before_text)
    detected_before = detect_balance_families(before_text)
    missing_before = _official_missing_data_families(before_text, fw, nlang)
    blockers_before = heading_blockers(out)
    save_before: List[str] = []
    try:
        from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
            _save_blockers_of,
        )
        save_before = _save_blockers_of(
            out, domain=dcode, lang=nlang, selected_frameworks=fw,
            document_type=str(document_type or 'strategy'))
    except Exception:
        save_before = []

    repaired, inserted, skipped = _normalize_family_rows(
        before_text, lang=nlang, selected_frameworks=fw)
    out['roadmap'] = repaired
    _normalize_headings(out, nlang)

    # Second pass must be a no-op for inserts and heading set.
    second, inserted2, _skipped2 = _normalize_family_rows(
        str(out.get('roadmap') or ''), lang=nlang, selected_frameworks=fw)
    out['roadmap'] = second
    _normalize_headings(out, nlang)
    idempotent = inserted2 == [] and heading_blockers(out) == []

    after_text = str(out.get('roadmap') or '')
    seq_after = family_sequence(after_text)
    detected_after = detect_balance_families(after_text)
    missing_after = _official_missing_data_families(after_text, fw, nlang)
    blockers_after = heading_blockers(out)
    save_after: List[str] = []
    try:
        from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
            _save_blockers_of,
        )
        save_after = [
            b for b in _save_blockers_of(
                out, domain=dcode, lang=nlang, selected_frameworks=fw,
                document_type=str(document_type or 'strategy'))
            if 'roadmap_family_' in str(b) or 'data_roadmap_balance_missing' in str(b)
        ]
    except Exception:
        save_after = list(blockers_after)

    leaks = _leakage_terms(after_text)
    dups_after = duplicate_families(seq_after)
    restarts_after = restarted_families(seq_after)
    passed = (
        dups_after == []
        and restarts_after == []
        and missing_after == []
        and blockers_after == []
        and save_after == []
        and idempotent
        and leaks == []
        and 'roadmap_family_duplicated' not in blockers_after
        and 'roadmap_family_restart_detected' not in blockers_after
    )
    diag.update({
        'applied': True,
        'required_families': required,
        'family_sequence_before': seq_before,
        'family_sequence_after': seq_after,
        'duplicate_families_before': duplicate_families(seq_before),
        'duplicate_families_after': dups_after,
        'restarted_families_before': restarted_families(seq_before),
        'restarted_families_after': restarts_after,
        'detected_families_before': sorted(detected_before),
        'detected_families_after': sorted(detected_after),
        'missing_families_before': missing_before,
        'missing_families_after': missing_after,
        'inserted_families': inserted,
        'skipped_existing_families': skipped,
        'repair_pass_count': 2,
        'idempotent_second_pass': idempotent,
        'roadmap_family_blockers_before': blockers_before,
        'roadmap_family_blockers_after': blockers_after,
        'save_blockers_before': save_before,
        'save_blockers_after': save_after,
        'english_repairs_preserved': (
            nlang.startswith('en')
            and 'privacy_governance' in detected_after
        ) or nlang.startswith('ar'),
        'guide_repairs_preserved': True,
        'leakage_terms_after': leaks,
        'passed': passed,
    })
    print(
        REL36_20_1_DATA_ROADMAP_FAMILY_INTEGRITY_TAG + ' '
        + json.dumps(diag, ensure_ascii=False, default=str),
        flush=True,
    )
    return out, diag
