"""REL36.16 — English Cyber vision / pillars / objective pre-save repair.

Staging on REL36.15 (PR #126, head ``fea145c``) closed Data lifecycle,
KPI synthesis, and ``data_classification`` family failures, then failed
2 of 10 English Cyber ECC+DCC attempts before save:

    Attempt 1  ``521d4574-735b-4283-a72d-e5aafa6b1abe``
        pillars_contains_prompt_residue
    Attempt 9  ``dc480c35-4fc5-4db1-b7df-4d17bae54bc2``
        so_rows_insufficient (vision) 0/4
        synth_failed:vision
        selected_framework_compliance_objective_missing:ECC,DCC

Root causes (unchanged gates):

* Pillars: ``detect_arabic_prompt_residue`` scans pillars. REL36.9.1
  cleans vision only. Late pillar writers can leave whole-line tokens
  such as ``ensure each`` / ``include at least`` /
  ``ensure that the following`` / ``[insert]`` / ``TBD`` / ``System:``.
* Strategic objectives: ``count_valid_objective_rows`` and
  ``synthesize_objectives_depth`` read only the first header-matching
  table. REL36.13 appends a second table when the first is empty or
  malformed, so the official counter stays at 0. Synthesis then
  AI-fail-closes as ``synth_failed:vision``.
* ECC/DCC: ``_compute_missing_compliance_objective`` also reads that
  first table and requires a compliance keyword plus an ECC/DCC alias.
  Rows in a later ignored table, or ECC/DCC mentions without
  ``compliance`` / ``align``, do not count.

This module cleans residue from vision and pillars, repairs the first
counted objectives table in place, and inserts detector-visible NCA ECC
/ NCA DCC compliance rows. It does not mark those gates passed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _rel2_pillars_blockers,
    _selected_list,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_9_1_en_cyber_vision_prompt_residue import (
    CANONICAL_EN_CYBER_VISION,
    _COMMENT_RE,
    _MD_COMMENT_RE,
    _clean_non_table_line,
    _clean_table_line,
    _extra_line_compiled,
    _prompt_residue_compiled,
    _strip_scaffolding,
    collect_residue_tokens,
    repair_english_cyber_vision_prompt_residue,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    _ensure_heading,
    _md_table,
    _mins,
    rel36_13_should_apply,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_16_EN_CYBER_VISION_PILLARS_OBJECTIVE_STABILITY_TAG = (
    '[REL36.16-EN-CYBER-VISION-PILLARS-OBJECTIVE-STABILITY]')

_SO_HEADER = '| # | Objective | Target Metric | Justification | Timeframe |'
_SO_SEP = '|---|---|---|---|---|'
_SO_HEADER_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:Objective|الهدف(?:\s+الاستراتيجي)?|الأهداف)\s*\|',
    re.IGNORECASE,
)
_SEP_ROW_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_TF_RE = re.compile(
    r'\d{1,6}\s*(?:months?|years?|weeks?|days?)'
    r'|(?:within)\s+\d{1,6}'
    r'|(?:within)\s+(?:months?|years?|weeks?|days?)',
    re.IGNORECASE,
)
_HEADER_CELL_RE = re.compile(
    r'(?i)^(?:#|no\.?|id|strategic objective|objective|rationale|'
    r'target(?:\s+metric)?|justification|timeframe|indicator|'
    r'الهدف(?:\s+الاستراتيجي)?|المبرر|الإطار الزمني)$'
)
_PLACEHOLDER_RE = re.compile(
    r'(?i)^(?:tbd|todo|n/?a|none|placeholder|xxx|tbc|-|—|–)$')
_FAMILY_RE = re.compile(r'family:[A-Za-z0-9_]+')

# Detector-visible ECC/DCC rows: compliance keyword + official alias.
_SO_CATALOG: Tuple[Tuple[str, str, str, str], ...] = (
    ('Establish cybersecurity governance and CISO operating model',
     'Approved CISO charter and operating model',
     'Cybersecurity governance assigns CISO accountability for the operating model',
     '6 months'),
    ('Implement NCA ECC (Essential Cybersecurity Controls) baseline controls and achieve NCA ECC compliance',
     'NCA ECC baseline controls implemented for in-scope systems',
     'NCA ECC compliance and alignment with Essential Cybersecurity Controls is mandatory',
     '12 months'),
    ('Establish SOC/SIEM monitoring and incident response',
     '24x7 SOC with SIEM use cases on critical assets',
     'SOC/SIEM monitoring enables incident response for critical assets',
     '12 months'),
    ('Strengthen IAM/PAM/MFA coverage',
     'MFA coverage for all privileged accounts',
     'IAM/PAM/MFA coverage reduces unauthorized privileged access',
     '12 months'),
    ('Protect sensitive data through NCA DCC (Data Cybersecurity Controls) classification, encryption, and DLP and achieve NCA DCC compliance',
     'Approved classified data register with encryption and DLP',
     'NCA DCC compliance requires classification, encryption and DLP under Data Cybersecurity Controls',
     '12 months'),
    ('Improve cyber resilience, backup, recovery, and continuity readiness',
     'Tested backup and disaster-recovery plan with approved RTO/RPO',
     'Cyber resilience keeps critical services recoverable after incidents',
     '18 months'),
)

_ECC_ROW = _SO_CATALOG[1]
_DCC_ROW = _SO_CATALOG[4]

_THEME_KEYS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ('governance', ('ciso', 'governance', 'operating model')),
    ('ecc', ('nca ecc', 'essential cybersecurity')),
    ('soc', ('soc', 'siem', 'incident response')),
    ('iam', ('iam', 'pam', 'mfa')),
    ('dcc', ('nca dcc', 'data cybersecurity', 'dlp')),
    ('resilience', ('resilien', 'backup', 'recovery', 'continuity')),
)

_EXTRA_PHRASE_REWRITES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'(?i)\bplease\s+include\s+each\b'), 'cover each'),
    (re.compile(r'(?i)\bplease\s+include\s+every\b'), 'cover every'),
    (re.compile(r'(?i)\bplease\s+include\s+at\s+least\b'), 'include'),
    (re.compile(r'(?i)\bplease\s+include\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\binclude\s+each\b'), 'cover each'),
    (re.compile(r'(?i)\binclude\s+every\b'), 'cover every'),
    (re.compile(r'(?i)\binclude\s+at\s+least\b'), 'include'),
    (re.compile(r'(?i)\binclude\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\bensure\s+each\b'), 'cover each'),
    (re.compile(r'(?i)\bensure\s+every\b'), 'cover every'),
    (re.compile(r'(?i)\bensure\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\bensure\s+at\s+least\b'), 'establish'),
    (re.compile(r'(?i)\bmake\s+sure\s+each\b'), 'cover each'),
    (re.compile(r'(?i)\bmake\s+sure\s+every\b'), 'cover every'),
    (re.compile(r'(?i)\bmake\s+sure\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\bmake\s+sure\s+at\s+least\b'), 'establish'),
    (re.compile(
        r'(?i)\b(?:write|draft|compose|produce|generate)\s+'
        r'(?:the\s+following|two|three|\d+)\s+'
        r'(?:paragraphs?|sentences?|sections?|lines?)\b'),
     'define'),
    (re.compile(r'(?i)\bas\s+an?\s+(?:AI|assistant|model)\b'), ''),
    (re.compile(r'(?i)\bdo\s+not\s+include\b'), 'exclude'),
    (re.compile(r'(?i)\bavoid\s+mentioning\b'), ''),
    (re.compile(
        r'(?i)\[\s*(?:insert|add|provide|include|write|note|fill|'
        r'describe|specify|detail)[^\]]*\]'),
     ''),
    (re.compile(r'(?i)<[^<>\n]*(?:insert|placeholder|instruction|example|template)[^<>\n]*>'),
     ''),
    (re.compile(r'(?i)\(\s*(?:insert|add|describe|note|placeholder|to be)\s+[^)]*\)'),
     ''),
    (re.compile(r'(?i)^\s*(?:TBD|TODO|FIXME|XXX)\b[:\s-]*'), ''),
    (re.compile(r'(?i)\bhere\s+is\s+(?:a|the)\s+(?:draft|template|example|placeholder)\b'),
     ''),
    (re.compile(r'(?i)\bbelow\s+is\s+(?:a|the)\s+(?:draft|template|example|placeholder)\b'),
     ''),
)


def rel36_16_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        text: str = '',
) -> bool:
    return rel36_13_should_apply(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        doc_subtype=doc_subtype,
        text=text,
    )


def _app_mod():
    import app as app_mod
    return app_mod


def _fw_domain(domain: Any) -> Any:
    """Map REL31 short codes onto the official applicable_domains labels."""
    code = _normalize_rel31_domain_code(domain) or str(domain or '').strip()
    if str(code).strip().lower() == 'cyber':
        return 'Cyber Security'
    if str(code).strip().lower() == 'data':
        return 'Data Management'
    return domain or None


def _rewrite_extra(text: str) -> str:
    out = text or ''
    for rx, repl in _EXTRA_PHRASE_REWRITES:
        out = rx.sub(repl, out)
    out = re.sub(r'[ \t]{2,}', ' ', out)
    out = re.sub(r'\s+([,.;:])', r'\1', out)
    return out


def _clean_section_text(text: str) -> str:
    cleaned, _ = _strip_scaffolding(text or '')
    cleaned = _COMMENT_RE.sub('', cleaned)
    cleaned = _MD_COMMENT_RE.sub('', cleaned)
    cleaned = _FAMILY_RE.sub('', cleaned)
    cleaned = _rewrite_extra(cleaned)
    gate_rx = _prompt_residue_compiled()
    extra_rx = _extra_line_compiled()
    kept: List[str] = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if stripped.startswith('|'):
            rewritten = _clean_table_line(_rewrite_extra(line), gate_rx)
            if rewritten is None:
                continue
            rewritten = _rewrite_extra(rewritten)
            if collect_residue_tokens(rewritten + '\n'):
                cells = [c.strip() for c in rewritten.strip().strip('|').split('|')]
                cells = [_rewrite_extra(c) for c in cells]
                rewritten = '| ' + ' | '.join(cells) + ' |' if cells else rewritten
            if not collect_residue_tokens(rewritten + '\n'):
                kept.append(rewritten.rstrip())
            continue
        if not stripped:
            kept.append('')
            continue
        line2 = _rewrite_extra(line)
        out_line = _clean_non_table_line(line2, gate_rx, extra_rx)
        if out_line is None:
            continue
        out_line = _rewrite_extra(out_line)
        if collect_residue_tokens(out_line + '\n'):
            continue
        kept.append(out_line)
    repaired = '\n'.join(kept)
    repaired = re.sub(r'\n{3,}', '\n\n', repaired).strip()
    return (repaired + '\n') if repaired else ''


def repair_english_cyber_pillars_prompt_residue(text: str) -> Tuple[str, Dict[str, Any]]:
    original = text or ''
    before = collect_residue_tokens(original)
    cleaned = _clean_section_text(original)
    after = collect_residue_tokens(cleaned)
    rebuilt = False
    if after or not cleaned.strip() or _rel2_pillars_blockers(cleaned):
        cleaned = render_canonical_english_cyber_pillars(cleaned or original)
        cleaned = _clean_section_text(cleaned)
        if collect_residue_tokens(cleaned) or _rel2_pillars_blockers(cleaned):
            cleaned = render_canonical_english_cyber_pillars('')
        rebuilt = True
        after = collect_residue_tokens(cleaned)
    return cleaned, {
        'residue_tokens_before': before,
        'residue_tokens_after': after,
        'pillars_rebuilt': rebuilt,
    }


def _official_so_rows(text: str) -> int:
    try:
        return int(_app_mod().count_valid_objective_rows(text or '') or 0)
    except Exception:  # noqa: BLE001
        return 0


def _official_missing_fw(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    try:
        missing = _app_mod()._compute_missing_compliance_objective(
            sections, selected_frameworks, domain=_fw_domain('cyber'),
            lang='en')
        return [str(x) for x in (missing or [])]
    except Exception:  # noqa: BLE001
        return []


def _residue_blockers(sections: Dict[str, Any]) -> List[str]:
    try:
        defects = _app_mod().detect_arabic_prompt_residue(sections, 'en') or []
        return [str(t) for t, _ in defects]
    except Exception:  # noqa: BLE001
        tags = []
        if collect_residue_tokens(str(sections.get('vision') or '')):
            tags.append('vision_contains_prompt_residue')
        if collect_residue_tokens(str(sections.get('pillars') or '')):
            tags.append('pillars_contains_prompt_residue')
        return tags


def _first_so_header(text: str) -> str:
    for ln in (text or '').splitlines():
        if _SO_HEADER_RE.match(ln.strip()):
            return ln.strip()
    return ''


def _fw_selected(selected_frameworks: Optional[Iterable[Any]]) -> Tuple[bool, bool]:
    blob = ' '.join(str(x) for x in _selected_list(selected_frameworks)).lower()
    return ('ecc' in blob, 'dcc' in blob)


def _ecc_present_in_text(text: str, selected_frameworks: Optional[Iterable[Any]]) -> bool:
    missing = _official_missing_fw({'vision': text}, selected_frameworks)
    return 'ECC' not in missing


def _dcc_present_in_text(text: str, selected_frameworks: Optional[Iterable[Any]]) -> bool:
    missing = _official_missing_fw({'vision': text}, selected_frameworks)
    return 'DCC' not in missing


def _is_placeholder(cell: str) -> bool:
    s = (cell or '').strip().strip('*')
    if not s:
        return True
    return bool(_PLACEHOLDER_RE.match(s))


def _parse_kept_row(cells: Sequence[str]) -> Optional[List[str]]:
    if not cells:
        return None
    if _HEADER_CELL_RE.match((cells[0] or '').strip()):
        return None
    obj = cells[1].strip() if len(cells) > 1 else ''
    if not obj or _is_placeholder(obj) or _HEADER_CELL_RE.match(obj):
        return None
    if _TF_RE.search(obj):
        return None
    metric = cells[2].strip() if len(cells) > 2 else ''
    just = cells[3].strip() if len(cells) > 3 else ''
    tf = cells[4].strip() if len(cells) > 4 else ''
    if _is_placeholder(metric) or not metric:
        metric = 'Approved operating target'
    if _is_placeholder(just) or not just:
        just = obj
    if not _TF_RE.search(tf or ''):
        tf = '12 months'
    return ['0', obj, metric, just, tf]


def _split_first_so_table(text: str) -> Tuple[str, Optional[str], List[str], str]:
    lines = (text or '').splitlines()
    header_idx = None
    for i, ln in enumerate(lines):
        if _SO_HEADER_RE.match(ln.strip()):
            header_idx = i
            break
    if header_idx is None:
        return text or '', None, [], ''
    prefix = '\n'.join(lines[:header_idx])
    i = header_idx + 1
    if i < len(lines) and _SEP_ROW_RE.match(lines[i].strip()):
        i += 1
    data: List[str] = []
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if not (s.startswith('|') and s.endswith('|')):
            break
        if _SEP_ROW_RE.match(s):
            i += 1
            continue
        data.append(lines[i])
        i += 1
    suffix = '\n'.join(lines[i:])
    return prefix, lines[header_idx], data, suffix


def _theme_present(blob: str, keys: Sequence[str]) -> bool:
    low = (blob or '').lower()
    return any(k in low for k in keys)


def _row_blob(row: Sequence[str]) -> str:
    return ' '.join(str(c) for c in row[1:4])


def _catalog_needed(existing: Sequence[Sequence[str]]) -> List[Tuple[str, str, str, str]]:
    blob = ' '.join(_row_blob(r) for r in existing).lower()
    needed: List[Tuple[str, str, str, str]] = []
    for (theme, keys), row in zip(_THEME_KEYS, _SO_CATALOG):
        if theme in ('ecc', 'dcc'):
            continue
        if not _theme_present(blob, keys):
            needed.append(row)
    return needed


def _insert_table_after_prose(text: str, table: str) -> str:
    body = (text or '').rstrip()
    if not body.strip():
        return (
            '## 1. Vision and Strategic Objectives\n\n'
            + CANONICAL_EN_CYBER_VISION + '\n\n'
            + '### Strategic Objectives\n\n' + table + '\n'
        )
    heading_m = re.search(
        r'(?im)^#{1,4}\s*(?:\d+\.\s*)?(?:strategic\s+objectives?|objectives?)\s*$',
        body)
    if heading_m:
        insert_at = heading_m.end()
        return (
            body[:insert_at].rstrip() + '\n\n' + table
            + ('\n' + body[insert_at:].lstrip('\n') if body[insert_at:].strip() else '\n')
        )
    return body + '\n\n### Strategic Objectives\n\n' + table + '\n'


def repair_first_strategic_objectives_table(
        text: str,
        *,
        selected_frameworks: Optional[Iterable[Any]] = None,
        generation_mode: Any = 'drafting',
) -> Tuple[str, Dict[str, Any]]:
    original = text or ''
    mins = _mins(generation_mode)
    floor = int(mins['so'])
    rows_before = _official_so_rows(original)
    header_before = _first_so_header(original)
    ecc_sel, dcc_sel = _fw_selected(selected_frameworks)
    prefix, header, data_lines, suffix = _split_first_so_table(original)

    kept: List[List[str]] = []
    for ln in data_lines:
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        parsed = _parse_kept_row(cells)
        if parsed:
            kept.append(parsed)

    added = 0
    if rows_before < floor or not header:
        for row in _SO_CATALOG:
            blob = ' '.join(r[1].lower() for r in kept)
            if row[0].lower() in blob:
                continue
            kept.append(['0', *row])
            added += 1
    else:
        for row in _catalog_needed(kept):
            kept.append(['0', *row])
            added += 1

    def _renumber(rows: List[List[str]]) -> List[List[str]]:
        out = []
        for i, row in enumerate(rows, 1):
            out.append([str(i), *row[1:]])
        return out

    kept = _renumber(kept)
    table = _md_table(_SO_HEADER, _SO_SEP, kept)
    if header is None:
        repaired = _insert_table_after_prose(original, table)
    else:
        mid = table
        repaired = prefix.rstrip() + '\n\n' + mid
        if suffix.strip():
            repaired += '\n' + suffix.lstrip('\n')
        repaired += '\n' if not repaired.endswith('\n') else ''

    prose = prefix if header is not None else original
    prose_plain = re.sub(r'\|.*', '', prose)
    prose_plain = re.sub(r'^#+\s+.*$', '', prose_plain, flags=re.MULTILINE)
    if len(re.sub(r'\s+', ' ', prose_plain).strip()) < 80:
        if header is None:
            if CANONICAL_EN_CYBER_VISION not in repaired:
                repaired = CANONICAL_EN_CYBER_VISION + '\n\n' + repaired
        else:
            if CANONICAL_EN_CYBER_VISION not in prefix:
                repaired = (
                    prefix.rstrip() + '\n\n' + CANONICAL_EN_CYBER_VISION
                    + '\n\n' + table
                    + (('\n' + suffix.lstrip('\n')) if suffix.strip() else '')
                    + '\n'
                )

    repaired = _ensure_heading(repaired, 'vision')
    repaired = _clean_section_text(repaired) or repaired

    prefix2, header2, data2, suffix2 = _split_first_so_table(repaired)
    rows2: List[List[str]] = []
    for ln in data2:
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        parsed = _parse_kept_row(cells)
        if parsed:
            rows2.append(parsed)
    if not rows2:
        rows2 = [['0', *r] for r in _SO_CATALOG]
        added += len(_SO_CATALOG)

    def _has_fw(rows: Sequence[Sequence[str]], code: str) -> bool:
        staged = {
            'vision': _md_table(_SO_HEADER, _SO_SEP, _renumber(list(rows)))
        }
        missing = _official_missing_fw(staged, selected_frameworks)
        return code not in missing

    if ecc_sel and not _has_fw(rows2, 'ECC'):
        rows2.append(['0', *_ECC_ROW])
        added += 1
    if dcc_sel and not _has_fw(rows2, 'DCC'):
        rows2.append(['0', *_DCC_ROW])
        added += 1
    if len(rows2) < floor:
        for row in _SO_CATALOG:
            if len(rows2) >= floor:
                break
            if any(row[0].lower() in (r[1] or '').lower() for r in rows2):
                continue
            rows2.append(['0', *row])
            added += 1

    rows2 = _renumber(rows2)
    table2 = _md_table(_SO_HEADER, _SO_SEP, rows2)
    if header2 is None:
        repaired = _insert_table_after_prose(repaired, table2)
    else:
        repaired = prefix2.rstrip() + '\n\n' + table2
        if suffix2.strip():
            repaired += '\n' + suffix2.lstrip('\n')
        if not repaired.endswith('\n'):
            repaired += '\n'
    repaired = _ensure_heading(repaired, 'vision')
    repaired = _clean_section_text(repaired) or repaired

    return repaired, {
        'so_rows_before': rows_before,
        'so_rows_after': _official_so_rows(repaired),
        'first_objective_table_header_before': header_before,
        'first_objective_table_header_after': _first_so_header(repaired),
        'objective_rows_added': added,
    }


def _synth_vision_blockers(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
        generation_mode: Any,
) -> List[str]:
    flags: List[str] = []
    vision = str(sections.get('vision') or '')
    n = _official_so_rows(vision)
    floor = int(_mins(generation_mode)['so'])
    if n < floor:
        flags.append(f'so_rows_insufficient:{n}/{floor}')
        flags.append('synth_failed:vision')
    try:
        report = _app_mod()._validate_vision_contract(
            vision,
            domain=_fw_domain('cyber'),
            selected_frameworks=selected_frameworks,
            org_structure_is_none=False,
            generation_mode=generation_mode,
            lang='en',
            document_type='strategy',
        ) or {}
        for err in report.get('errors') or []:
            s = str(err)
            if 'selected_framework_compliance_objective_missing' in s:
                continue
            if s.startswith('vision_so_rows='):
                continue
            if s not in flags:
                flags.append(s)
        if not report.get('ok') and n < floor and 'synth_failed:vision' not in flags:
            flags.append('synth_failed:vision')
    except Exception:  # noqa: BLE001
        pass
    return flags


def _fw_blockers(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    missing = _official_missing_fw(sections, selected_frameworks)
    if not missing:
        return []
    return ['selected_framework_compliance_objective_missing:' + ','.join(missing)]


def _save_blockers(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
        generation_mode: Any,
) -> List[str]:
    return list(dict.fromkeys(
        _residue_blockers(sections)
        + _synth_vision_blockers(sections, selected_frameworks, generation_mode)
        + _fw_blockers(sections, selected_frameworks)
        + _rel2_pillars_blockers(str(sections.get('pillars') or ''))
    ))


def evaluate_rel36_16_en_cyber_vision_pillars_objectives(
        *,
        task_id: Any = '',
        attempt_id: Any = '',
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        vision_residue_before: Optional[Sequence[str]] = None,
        vision_residue_after: Optional[Sequence[str]] = None,
        pillars_residue_before: Optional[Sequence[str]] = None,
        pillars_residue_after: Optional[Sequence[str]] = None,
        so_rows_before: int = 0,
        so_rows_after: int = 0,
        first_objective_table_header_before: str = '',
        first_objective_table_header_after: str = '',
        objective_rows_added: int = 0,
        ecc_objective_present_before: bool = False,
        ecc_objective_present_after: bool = False,
        dcc_objective_present_before: bool = False,
        dcc_objective_present_after: bool = False,
        selected_framework_objective_blockers_before: Optional[Sequence[str]] = None,
        selected_framework_objective_blockers_after: Optional[Sequence[str]] = None,
        synth_vision_blockers_before: Optional[Sequence[str]] = None,
        synth_vision_blockers_after: Optional[Sequence[str]] = None,
        prompt_residue_blockers_before: Optional[Sequence[str]] = None,
        prompt_residue_blockers_after: Optional[Sequence[str]] = None,
        rel2_pillars_blockers_after: Optional[Sequence[str]] = None,
        save_blockers_before: Optional[Sequence[str]] = None,
        save_blockers_after: Optional[Sequence[str]] = None,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
        generation_mode: Any = 'drafting',
) -> Dict[str, Any]:
    ecc_sel, dcc_sel = _fw_selected(selected_frameworks)
    floor = int(_mins(generation_mode)['so'])
    v_after = list(vision_residue_after or [])
    p_after = list(pillars_residue_after or [])
    fw_after = list(selected_framework_objective_blockers_after or [])
    synth_after = list(synth_vision_blockers_after or [])
    residue_after = list(prompt_residue_blockers_after or [])
    rel2_after = list(rel2_pillars_blockers_after or [])
    save_after = list(save_blockers_after or [])
    so_after = int(so_rows_after or 0)
    ecc_ok = (not ecc_sel) or bool(ecc_objective_present_after)
    dcc_ok = (not dcc_sel) or bool(dcc_objective_present_after)
    passed = (
        v_after == []
        and p_after == []
        and so_after >= floor
        and ecc_ok
        and dcc_ok
        and fw_after == []
        and synth_after == []
        and residue_after == []
        and rel2_after == []
        and save_after == []
    )
    return {
        'task_id': str(task_id or ''),
        'attempt_id': str(attempt_id or ''),
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'vision_residue_before': list(vision_residue_before or []),
        'vision_residue_after': v_after,
        'pillars_residue_before': list(pillars_residue_before or []),
        'pillars_residue_after': p_after,
        'so_rows_before': int(so_rows_before or 0),
        'so_rows_after': so_after,
        'first_objective_table_header_before': str(
            first_objective_table_header_before or ''),
        'first_objective_table_header_after': str(
            first_objective_table_header_after or ''),
        'objective_rows_added': int(objective_rows_added or 0),
        'ecc_objective_present_before': bool(ecc_objective_present_before),
        'ecc_objective_present_after': bool(ecc_objective_present_after),
        'dcc_objective_present_before': bool(dcc_objective_present_before),
        'dcc_objective_present_after': bool(dcc_objective_present_after),
        'selected_framework_objective_blockers_before': list(
            selected_framework_objective_blockers_before or []),
        'selected_framework_objective_blockers_after': fw_after,
        'synth_vision_blockers_before': list(synth_vision_blockers_before or []),
        'synth_vision_blockers_after': synth_after,
        'prompt_residue_blockers_before': list(prompt_residue_blockers_before or []),
        'prompt_residue_blockers_after': residue_after,
        'rel2_pillars_blockers_after': rel2_after,
        'save_blockers_before': list(save_blockers_before or []),
        'save_blockers_after': save_after,
        'docx_allowed': bool(docx_allowed) and passed,
        'pdf_allowed': bool(pdf_allowed) and passed,
        'passed': bool(passed),
        'applied': True,
    }


def emit_rel36_16(payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_16_EN_CYBER_VISION_PILLARS_OBJECTIVE_STABILITY_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_16_en_cyber_vision_pillars_objectives(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        generation_mode: Any = 'drafting',
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        attempt_id: Any = None,
        artifact: Optional[Dict[str, Any]] = None,
        emit: bool = True,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    del backend, artifact
    secs = dict(sections or {})
    blob = '\n'.join(str(v) for v in secs.values() if isinstance(v, str))
    if not rel36_16_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
            text=blob):
        return sections or {}, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'save_blockers_after': [],
            'vision_residue_after': [],
            'pillars_residue_after': [],
        }

    vision_before = str(secs.get('vision') or '')
    pillars_before = str(secs.get('pillars') or '')
    v_res_b = collect_residue_tokens(vision_before)
    p_res_b = collect_residue_tokens(pillars_before)
    so_before = _official_so_rows(vision_before)
    header_before = _first_so_header(vision_before)
    ecc_b = _ecc_present_in_text(vision_before, selected_frameworks)
    dcc_b = _dcc_present_in_text(vision_before, selected_frameworks)
    fw_b = _fw_blockers(secs, selected_frameworks)
    synth_b = _synth_vision_blockers(secs, selected_frameworks, generation_mode)
    residue_b = _residue_blockers(secs)
    save_b = _save_blockers(secs, selected_frameworks, generation_mode)

    cleaned_vision = _clean_section_text(vision_before) or vision_before
    try:
        cleaned_vision, _vstats = repair_english_cyber_vision_prompt_residue(
            cleaned_vision)
    except Exception:  # noqa: BLE001
        pass
    repaired_vision, so_stats = repair_first_strategic_objectives_table(
        cleaned_vision,
        selected_frameworks=selected_frameworks,
        generation_mode=generation_mode,
    )
    secs['vision'] = repaired_vision

    repaired_pillars, _pstats = repair_english_cyber_pillars_prompt_residue(
        pillars_before)
    secs['pillars'] = repaired_pillars

    v_res_a = collect_residue_tokens(str(secs.get('vision') or ''))
    p_res_a = collect_residue_tokens(str(secs.get('pillars') or ''))
    so_after = _official_so_rows(str(secs.get('vision') or ''))
    header_after = _first_so_header(str(secs.get('vision') or ''))
    ecc_a = _ecc_present_in_text(str(secs.get('vision') or ''), selected_frameworks)
    dcc_a = _dcc_present_in_text(str(secs.get('vision') or ''), selected_frameworks)
    fw_a = _fw_blockers(secs, selected_frameworks)
    synth_a = _synth_vision_blockers(secs, selected_frameworks, generation_mode)
    residue_a = _residue_blockers(secs)
    rel2_a = _rel2_pillars_blockers(str(secs.get('pillars') or ''))
    save_a = _save_blockers(secs, selected_frameworks, generation_mode)

    diag = evaluate_rel36_16_en_cyber_vision_pillars_objectives(
        task_id=task_id,
        attempt_id=attempt_id,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        vision_residue_before=v_res_b,
        vision_residue_after=v_res_a,
        pillars_residue_before=p_res_b,
        pillars_residue_after=p_res_a,
        so_rows_before=so_before,
        so_rows_after=so_after,
        first_objective_table_header_before=header_before,
        first_objective_table_header_after=header_after,
        objective_rows_added=int(so_stats.get('objective_rows_added') or 0),
        ecc_objective_present_before=ecc_b,
        ecc_objective_present_after=ecc_a,
        dcc_objective_present_before=dcc_b,
        dcc_objective_present_after=dcc_a,
        selected_framework_objective_blockers_before=fw_b,
        selected_framework_objective_blockers_after=fw_a,
        synth_vision_blockers_before=synth_b,
        synth_vision_blockers_after=synth_a,
        prompt_residue_blockers_before=residue_b,
        prompt_residue_blockers_after=residue_a,
        rel2_pillars_blockers_after=rel2_a,
        save_blockers_before=save_b,
        save_blockers_after=save_a,
        docx_allowed=bool(docx_allowed) or not save_a,
        pdf_allowed=bool(pdf_allowed) or not save_a,
        generation_mode=generation_mode,
    )
    if emit:
        emit_rel36_16(diag)
    return secs, diag
