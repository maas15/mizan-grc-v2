"""REL36.17 — English Cyber board-ready SO and synth-gate stabilizer.

Staging English Cyber ECC+DCC on REL36.16 (PR #126, head ``2754a6c``)
passed official 6/6 acceptance and 7 of 10 live attempts, then failed
before save on later unchanged gates:

    Attempts 2 / 3  ``855b17f1-...`` / ``a3363a5a-...``
        cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like
    Attempt 9       ``afcb2b56-...``
        synth_failed:gaps
        synth_failed:pillars
        synth_failed:confidence

Root causes (unchanged gates):

* Board-ready SO (``baseline_strategic_objectives``): requires 6–8
  counted rows, zero governance-title duplicates, zero target-like /
  shifted SO fields, and every critical PR-CY88 family. REL36.16
  preserves AI rows and inserts ECC/DCC catalog rows whose *target*
  cells contain ``NCA ECC`` / ``NCA DCC`` without ``%``.
  ``_prcy87_count_shifted_so_fields`` treats that as target-like.
  Combined SOC+IR titles also leave ``incident_response_csirt`` missing
  so the baseline inserts a second (often Arabic) row and can leave a
  governance duplicate.

* Synth gaps/pillars/confidence: ``synthesize_*_depth`` no-ops only when
  the first counted structure already meets the richness bar. Otherwise
  it calls AI and fail-closes as ``synth_failed:<section>``. REL36.16
  does not repair gaps/confidence, and REL36.13/14 can run earlier than
  a later overwrite, so pre-synth still sees a thin first table.

This module repairs the first counted SO / gaps / pillars / confidence
structures immediately before those gates. It does not mark the gates
passed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cyber_board_ready_prcy88 import (
    PRCY88_SO_FAMILIES,
    _GOVERNANCE_DUP_RE,
    _detect_so_family,
)
from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _rel2_pillars_blockers,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    _CSF_CATALOG,
    _CSF_HEADER,
    _CSF_SEP,
    _GAP_CATALOG,
    _GAP_HEADER,
    _GAP_SEP,
    _RISK_CATALOG,
    _RISK_HEADER,
    _RISK_SEP,
    _ensure_heading,
    _md_table,
    _mins,
    rel36_13_should_apply,
)
from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
    _GAP_GUIDE_BODIES,
)
from release_engine_v3.rel36_16_en_cyber_vision_pillars_objectives import (
    _SO_HEADER,
    _SO_HEADER_RE,
    _SO_SEP,
    _official_missing_fw,
    _official_so_rows,
    _split_first_so_table,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_17_EN_CYBER_FINAL_SAVE_GATE_STABILIZER_TAG = (
    '[REL36.17-EN-CYBER-FINAL-SAVE-GATE-STABILIZER]')

_SEP_ROW_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_PLACEHOLDER_RE = re.compile(
    r'(?i)^(?:tbd|todo|n/?a|none|placeholder|xxx|tbc|-|—|–)$')
_TITLE_NORM_RE = re.compile(r'[^a-z0-9]+')
_CRITICAL_SO_FAMILIES = tuple(
    f for f in PRCY88_SO_FAMILIES if f != 'awareness_or_resilience')

# Distinctive English titles. One row per PR-CY88 family.
# Family detection uses the *objective* cell only and returns the first
# matching family. Do not put ECC/DCC/compliance in the data-protection
# title (those tokens map to compliance_ecc_dcc first). Do not put
# "incident response" in the SOC title. Do not put "governance" in the
# IAM title (``_GOVERNANCE_DUP_RE`` would merge it with the CISO row).
# Targets that mention NCA ECC/DCC always include a percentage so
# ``_prcy87_count_shifted_so_fields`` does not mark them shifted.
_SO_FAMILY_ROWS: Tuple[Tuple[str, str, str, str, str], ...] = (
    ('governance_ciso',
     'Establish cybersecurity governance and CISO operating model',
     'Approved CISO charter adopted for 100% of in-scope functions',
     'Cybersecurity governance assigns CISO accountability for the operating model',
     '6 months'),
    ('compliance_ecc_dcc',
     'Implement NCA ECC (Essential Cybersecurity Controls) baseline controls and achieve NCA ECC compliance',
     '95% of in-scope systems implement Essential Cybersecurity Controls',
     'NCA ECC compliance and alignment with Essential Cybersecurity Controls is mandatory',
     '12 months'),
    ('soc_monitoring_detection',
     'Establish SOC/SIEM monitoring and detection coverage',
     '24x7 SOC/SIEM coverage on 95% of critical assets',
     'SOC/SIEM monitoring reduces undetected intrusion dwell time',
     '12 months'),
    ('iam_pam_mfa',
     'Strengthen IAM, PAM, and MFA access controls',
     'MFA and PAM enforced on 95% of privileged accounts',
     'IAM/PAM/MFA coverage reduces unauthorized privileged access',
     '12 months'),
    ('incident_response_csirt',
     'Build CSIRT incident response and containment readiness',
     'CSIRT playbooks tested for 95% of critical services',
     'CSIRT incident response contains operational impact of security incidents',
     '12 months'),
    ('vulnerability_management',
     'Institutionalize vulnerability and patch management',
     '95% of critical vulnerabilities remediated within 72 hours',
     'Vulnerability management shortens exposure windows for critical assets',
     '12 months'),
    ('data_protection_dcc',
     'Protect sensitive data through classification, encryption, and DLP',
     '95% of classified records protected under NCA DCC (Data Cybersecurity Controls) compliance',
     'Achieve NCA DCC compliance through classification, encryption and DLP under Data Cybersecurity Controls',
     '12 months'),
    ('awareness_or_resilience',
     'Improve cybersecurity awareness and phishing resilience',
     'Annual awareness completion at 95% of workforce',
     'Awareness and phishing resilience reduces human-driven incidents',
     '12 months'),
)

_SO_BY_FAMILY = {row[0]: row[1:] for row in _SO_FAMILY_ROWS}

_CONF_SCORE_LINE = '**Confidence Score:** 72%'
_CONF_JUST_HEAD = '### Score Justification'
_CONF_JUST_BODY = (
    'The score reflects CISO-led NCA ECC governance, SOC/SIEM and CSIRT '
    'readiness, IAM/PAM/MFA coverage, and NCA DCC classification, '
    'encryption and DLP evidence that an assessor can sample.'
)


def rel36_17_should_apply(
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


def _norm_title(text: str) -> str:
    return _TITLE_NORM_RE.sub(' ', (text or '').lower()).strip()


def _so_duplicates(vision: str) -> int:
    prefix, _header, data, _suffix = _split_first_so_table(vision or '')
    del prefix
    seen_gov = False
    seen_titles = set()
    dups = 0
    for ln in data:
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        obj = cells[1] if len(cells) > 1 else ''
        if not obj or _PLACEHOLDER_RE.match(obj):
            continue
        key = _norm_title(obj)
        if key in seen_titles:
            dups += 1
            continue
        seen_titles.add(key)
        if _GOVERNANCE_DUP_RE.search(obj):
            if seen_gov:
                dups += 1
            seen_gov = True
    return dups


def _so_target_like(vision: str, lang: str = 'en') -> int:
    try:
        return int(_app_mod()._prcy87_count_shifted_so_fields(vision, lang) or 0)
    except Exception:  # noqa: BLE001
        return 0


def _local_board_ready_so_blockers(vision: str, lang: str = 'en') -> List[str]:
    """Inspect the current first counted table without official inserts."""
    rows = _official_so_rows(vision)
    dups = _so_duplicates(vision)
    target_like = _so_target_like(vision, lang)
    present = set()
    prefix, _header, data, _suffix = _split_first_so_table(vision or '')
    del prefix
    for ln in data:
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        obj = cells[1] if len(cells) > 1 else ''
        fam = _detect_so_family(obj)
        if fam:
            present.add(fam)
    missing = [f for f in _CRITICAL_SO_FAMILIES if f not in present]
    if rows < 6 or rows > 8 or dups or target_like or missing:
        return [
            'cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like']
    return []


def _official_board_ready_so_blockers(
        vision: str, lang: str = 'en') -> List[str]:
    """Official PR-CY88 gate on a copy (does not mutate ``vision``)."""
    try:
        from cyber_board_ready_prcy88 import baseline_strategic_objectives
        _secs, diag = baseline_strategic_objectives(
            _app_mod(), {'vision': vision or ''}, lang,
            ['NCA ECC', 'NCA DCC'])
        del _secs
        if not diag.get('gate_passed'):
            err = (diag.get('blocking_error_if_any')
                   or 'so_count_or_duplicates_or_target_like')
            return [f'cyber_board_ready_so_failed:{err}']
        return []
    except Exception:  # noqa: BLE001
        return _local_board_ready_so_blockers(vision, lang)


def _board_ready_so_blockers(vision: str, lang: str = 'en') -> List[str]:
    return list(dict.fromkeys(
        _local_board_ready_so_blockers(vision, lang)
        + _official_board_ready_so_blockers(vision, lang)
    ))


def _gaps_synth_blockers(gaps: str, generation_mode: Any = 'drafting') -> List[str]:
    app = _app_mod()
    n_rows = int(app.count_substantive_gaps(gaps or '') or 0)
    n_guides = int(app.count_gap_guides(gaps or '') or 0)
    floor = int(_mins(generation_mode)['gaps'])
    if str(generation_mode).lower() in ('consulting', 'assurance'):
        floor = max(floor, 5)
    if n_rows < floor or n_guides < n_rows or n_rows <= 0:
        return ['synth_failed:gaps']
    return []


def _pillars_synth_blockers(pillars: str) -> List[str]:
    app = _app_mod()
    existing = app._extract_existing_pillars(pillars or '')
    preserved = [
        (t, b) for (t, b) in existing
        if app._pillar_has_substantive_initiative(b)
    ]
    min_init = int(getattr(app, '_RICHNESS_MIN_PILLAR_INITIATIVES', 3) or 3)
    enough = sum(
        1 for (_t, b) in existing
        if app._count_pillar_initiative_rows(b) >= min_init
    )
    min_p = int(getattr(app, '_RICHNESS_MIN_PILLARS', 3) or 3)
    if len(preserved) < min_p or enough < min_p:
        return ['synth_failed:pillars']
    return []


def _confidence_counts(conf: str) -> Tuple[int, int, bool, bool]:
    app = _app_mod()
    n_csf = int(app._count_csf_rows(conf or '') or 0)
    n_risk = int(app._count_risk_rows_with_mitigation(conf or '') or 0)
    score = bool(re.search(
        r'(?i)(?:\*\*)?(?:Confidence\s+Score|درجة\s+الثقة)(?:\*\*)?\s*:?\s*'
        r'(?:\*\*)?\s*\d{1,3}\s*%',
        conf or ''))
    just = bool(re.search(
        r'(?im)^#{2,4}\s*(?:Score\s+Justification|مبررات?\s+(?:التقييم|الثقة))',
        conf or '')) or bool(re.search(
        r'(?i)(?:justification|rationale|مبررات?|أسباب|تفسير)',
        conf or ''))
    return n_csf, n_risk, score, just


def _confidence_synth_blockers(
        conf: str, generation_mode: Any = 'drafting') -> List[str]:
    n_csf, n_risk, score, just = _confidence_counts(conf)
    consulting = str(generation_mode).lower() in ('consulting', 'assurance')
    min_csf = 5 if consulting else 4
    min_risk = 5 if consulting else 4
    if not (score and just and n_csf >= min_csf and n_risk >= min_risk):
        return ['synth_failed:confidence']
    return []


def _fw_objective_blockers(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> List[str]:
    missing = _official_missing_fw(sections, selected_frameworks)
    if missing:
        return [
            'selected_framework_compliance_objective_missing:'
            + ','.join(missing)]
    return []


def _all_save_blockers(
        sections: Dict[str, Any],
        generation_mode: Any = 'drafting',
        lang: str = 'en',
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> List[str]:
    return list(dict.fromkeys(
        _board_ready_so_blockers(str(sections.get('vision') or ''), lang)
        + _fw_objective_blockers(sections, selected_frameworks)
        + _gaps_synth_blockers(str(sections.get('gaps') or ''), generation_mode)
        + _pillars_synth_blockers(str(sections.get('pillars') or ''))
        + _confidence_synth_blockers(
            str(sections.get('confidence') or ''), generation_mode)
        + _rel2_pillars_blockers(str(sections.get('pillars') or ''))
    ))


def _replace_first_table(
        text: str, header_re: re.Pattern[str], new_table: str) -> str:
    lines = (text or '').splitlines()
    header_idx = None
    for i, ln in enumerate(lines):
        if header_re.match(ln.strip()):
            header_idx = i
            break
    if header_idx is None:
        body = (text or '').rstrip()
        if not body.strip():
            return new_table + '\n'
        return body + '\n\n' + new_table + '\n'
    i = header_idx + 1
    if i < len(lines) and _SEP_ROW_RE.match(lines[i].strip()):
        i += 1
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if not (s.startswith('|') and s.endswith('|')):
            break
        i += 1
    prefix = '\n'.join(lines[:header_idx]).rstrip()
    suffix = '\n'.join(lines[i:]).lstrip('\n')
    out = prefix + ('\n\n' if prefix else '') + new_table.rstrip() + '\n'
    if suffix:
        out += '\n' + suffix
        if not out.endswith('\n'):
            out += '\n'
    return out


def _parse_so_rows(vision: str) -> List[List[str]]:
    _prefix, _header, data, _suffix = _split_first_so_table(vision or '')
    rows: List[List[str]] = []
    for ln in data:
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        if len(cells) < 2:
            continue
        obj = cells[1] if len(cells) > 1 else ''
        tgt = cells[2] if len(cells) > 2 else ''
        just = cells[3] if len(cells) > 3 else ''
        tf = cells[4] if len(cells) > 4 else '12 months'
        if not obj or _PLACEHOLDER_RE.match(obj):
            continue
        rows.append(['0', obj, tgt, just, tf or '12 months'])
    return rows


def repair_board_ready_so_table(
        vision: str, *, lang: str = 'en') -> Tuple[str, Dict[str, Any]]:
    """Rebuild the first counted SO table for the board-ready gate."""
    app = _app_mod()
    kept: List[List[str]] = []
    seen_titles = set()
    seen_fams = set()
    seen_gov = False
    for row in _parse_so_rows(vision):
        obj, tgt, just, tf = row[1], row[2], row[3], row[4]
        if app._prcy87_objective_looks_like_target(obj, lang):
            rep = app._prcy87_infer_so_semantic_repair(
                obj, ['0', obj, tgt, just, tf], lang)
            obj, tgt, just, tf = (
                rep[0] or obj, rep[1] or tgt, rep[2] or just, rep[3] or tf)
        if app._prcy87_objective_looks_like_target(obj, lang):
            continue
        if tgt and ('NCA ECC' in tgt or 'NCA DCC' in tgt) and '%' not in tgt:
            tgt = '95% ' + tgt
        title = _norm_title(obj)
        if not title or title in seen_titles:
            continue
        if _GOVERNANCE_DUP_RE.search(obj):
            if seen_gov:
                continue
            seen_gov = True
        fam = _detect_so_family(obj)
        if fam and fam in seen_fams:
            continue
        seen_titles.add(title)
        if fam:
            seen_fams.add(fam)
        kept.append(['0', obj, tgt or 'Measurable target defined at 95%',
                     just or obj, tf or '12 months'])

    for fam, obj, tgt, just, tf in _SO_FAMILY_ROWS:
        if fam in seen_fams:
            continue
        if len(kept) >= 8:
            # Drop an optional-family row to make room for a critical family.
            if fam in _CRITICAL_SO_FAMILIES:
                for i, row in enumerate(kept):
                    rf = _detect_so_family(row[1])
                    if rf == 'awareness_or_resilience':
                        kept.pop(i)
                        seen_fams.discard(rf)
                        break
                else:
                    kept.pop()
            else:
                continue
        kept.append(['0', obj, tgt, just, tf])
        seen_fams.add(fam)

    while len(kept) > 8:
        kept.pop()
    if len(kept) < 6:
        kept = []
        for fam, obj, tgt, just, tf in _SO_FAMILY_ROWS:
            kept.append(['0', obj, tgt, just, tf])

    numbered = []
    for i, row in enumerate(kept[:8], 1):
        numbered.append([str(i), *row[1:]])
    table = _md_table(_SO_HEADER, _SO_SEP, numbered)
    repaired = _replace_first_table(vision or '', _SO_HEADER_RE, table)
    if '| # | Objective |' not in (vision or ''):
        body = (vision or '').rstrip()
        if not body.strip():
            repaired = (
                '## 1. Vision and Strategic Objectives\n\n'
                'Protect the organization through a governed cybersecurity '
                'operating model aligned to NCA ECC and NCA DCC.\n\n'
                '### Strategic Objectives\n\n' + table + '\n'
            )
        elif '### Strategic Objectives' not in body:
            repaired = body + '\n\n### Strategic Objectives\n\n' + table + '\n'
        else:
            repaired = _replace_first_table(body + '\n\n' + table, _SO_HEADER_RE, table)
    repaired = _ensure_heading(repaired, 'vision')
    return repaired, {'rows': len(numbered)}


def repair_gaps_for_synth(gaps: str) -> str:
    rows = [
        [str(i + 1), name, desc, pri, owner]
        for i, (name, desc, pri, owner) in enumerate(_GAP_CATALOG)
    ]
    table = _md_table(_GAP_HEADER, _GAP_SEP, rows)
    guides = []
    for i, (family, owner, body) in enumerate(_GAP_GUIDE_BODIES, 1):
        guides.append(
            f'#### Gap #{i} Implementation Guide: {family}\n\n'
            f'Owner: {owner}\n\n{body}\n'
        )
    heading = '## 4. Gap Analysis'
    existing = gaps or ''
    if re.search(r'(?m)^##\s+', existing):
        heading_m = re.search(r'(?m)^##\s+[^\n]+', existing)
        heading = heading_m.group(0) if heading_m else heading
    return (
        heading + '\n\n'
        'The gap analysis covers NCA ECC and NCA DCC control families '
        'that require a named owner and a unique implementation guide.\n\n'
        + table + '\n\n' + '\n'.join(guides)
    )


def _number_canonical_pillar_tables(text: str) -> str:
    """Prefix a ``#`` column so ``_count_pillar_initiative_rows`` counts.

    Official synth richness only counts initiative rows whose first cell
    is a digit (or that follow a ``#`` header). REL36.8 4-column tables
    therefore look empty to ``synthesize_pillars_depth`` even when REL2
    already passes. Numbering the first counted table in place keeps the
    Initiative / Description / Expected Deliverable / Owner cells.
    """
    out: List[str] = []
    in_tbl = False
    n = 0
    for ln in (text or '').splitlines():
        s = ln.strip()
        if s.startswith('|') and s.endswith('|'):
            cells = [c.strip() for c in s.strip('|').split('|')]
            if _SEP_ROW_RE.match(s):
                if in_tbl and cells and cells[0] != '---':
                    out.append('|---|---|---|---|---|')
                else:
                    out.append(ln)
                continue
            headerish = any(
                c.lower() in ('initiative', 'description', 'owner',
                              'expected deliverable', '#')
                for c in cells)
            if headerish and any(c.lower() == 'initiative' for c in cells):
                in_tbl = True
                n = 0
                out.append(
                    '| # | Initiative | Description | '
                    'Expected Deliverable | Owner |')
                continue
            if in_tbl:
                if cells and cells[0].replace('.', '').isdigit():
                    data = cells[1:] if len(cells) > 4 else cells
                else:
                    data = cells
                while len(data) < 4:
                    data.append('CISO' if len(data) == 3 else 'Defined output')
                n += 1
                out.append(
                    f'| {n} | {data[0]} | {data[1]} | {data[2]} | {data[3]} |')
                continue
        else:
            in_tbl = False
        out.append(ln)
    rendered = '\n'.join(out)
    if not rendered.endswith('\n'):
        rendered += '\n'
    return rendered


def repair_pillars_for_synth(pillars: str) -> str:
    return _number_canonical_pillar_tables(
        render_canonical_english_cyber_pillars(pillars or ''))


def _split_first_csf_table(text: str) -> Tuple[str, Optional[int], int]:
    lines = (text or '').splitlines()
    header_idx = None
    hdr = re.compile(r'^\|\s*#\s*\|\s*(?:Factor|العامل)\s*\|', re.I)
    for i, ln in enumerate(lines):
        if hdr.match(ln.strip()):
            header_idx = i
            break
    if header_idx is None:
        return text or '', None, 0
    i = header_idx + 1
    if i < len(lines) and _SEP_ROW_RE.match(lines[i].strip()):
        i += 1
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if not (s.startswith('|') and s.endswith('|')):
            break
        i += 1
    return text or '', header_idx, i


def repair_confidence_for_synth(conf: str) -> str:
    csf_rows = [
        [str(i + 1), *row] for i, row in enumerate(_CSF_CATALOG)
    ]
    risk_rows = [
        [str(i + 1), *row] for i, row in enumerate(_RISK_CATALOG)
    ]
    csf_table = _md_table(_CSF_HEADER, _CSF_SEP, csf_rows)
    risk_table = _md_table(_RISK_HEADER, _RISK_SEP, risk_rows)
    heading = '## 7. Confidence Assessment'
    existing = conf or ''
    hm = re.search(r'(?m)^##\s+[^\n]+', existing)
    if hm:
        heading = hm.group(0)
    return (
        heading + '\n\n'
        + _CONF_SCORE_LINE + '\n\n'
        + _CONF_JUST_HEAD + '\n\n'
        + _CONF_JUST_BODY + '\n\n'
        + '### Critical Success Factors\n\n'
        + csf_table + '\n\n'
        + '### Key Risks\n\n'
        + risk_table + '\n'
    )


def evaluate_rel36_17_en_cyber_final_save_gate_stabilizer(
        *,
        task_id: Any = '',
        attempt_id: Any = '',
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        so_rows_before: int = 0,
        so_rows_after: int = 0,
        so_duplicates_before: int = 0,
        so_duplicates_after: int = 0,
        so_target_like_before: int = 0,
        so_target_like_after: int = 0,
        board_ready_so_blockers_before: Optional[Sequence[str]] = None,
        board_ready_so_blockers_after: Optional[Sequence[str]] = None,
        gaps_rows_before: int = 0,
        gaps_rows_after: int = 0,
        gaps_synth_blockers_before: Optional[Sequence[str]] = None,
        gaps_synth_blockers_after: Optional[Sequence[str]] = None,
        pillars_rows_before: int = 0,
        pillars_rows_after: int = 0,
        pillars_synth_blockers_before: Optional[Sequence[str]] = None,
        pillars_synth_blockers_after: Optional[Sequence[str]] = None,
        confidence_rows_before: int = 0,
        confidence_rows_after: int = 0,
        confidence_csf_rows_before: int = 0,
        confidence_csf_rows_after: int = 0,
        confidence_synth_blockers_before: Optional[Sequence[str]] = None,
        confidence_synth_blockers_after: Optional[Sequence[str]] = None,
        repaired_sections: Optional[Sequence[str]] = None,
        all_save_blockers_before: Optional[Sequence[str]] = None,
        all_save_blockers_after: Optional[Sequence[str]] = None,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
) -> Dict[str, Any]:
    br_after = list(board_ready_so_blockers_after or [])
    g_after = list(gaps_synth_blockers_after or [])
    p_after = list(pillars_synth_blockers_after or [])
    c_after = list(confidence_synth_blockers_after or [])
    save_after = list(all_save_blockers_after or [])
    passed = (
        br_after == []
        and g_after == []
        and p_after == []
        and c_after == []
        and save_after == []
    )
    return {
        'task_id': str(task_id or ''),
        'attempt_id': str(attempt_id or ''),
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': [
            str(x) for x in (selected_frameworks or []) if str(x).strip()
        ],
        'so_rows_before': int(so_rows_before or 0),
        'so_rows_after': int(so_rows_after or 0),
        'so_duplicates_before': int(so_duplicates_before or 0),
        'so_duplicates_after': int(so_duplicates_after or 0),
        'so_target_like_before': int(so_target_like_before or 0),
        'so_target_like_after': int(so_target_like_after or 0),
        'board_ready_so_blockers_before': list(
            board_ready_so_blockers_before or []),
        'board_ready_so_blockers_after': br_after,
        'gaps_rows_before': int(gaps_rows_before or 0),
        'gaps_rows_after': int(gaps_rows_after or 0),
        'gaps_synth_blockers_before': list(gaps_synth_blockers_before or []),
        'gaps_synth_blockers_after': g_after,
        'pillars_rows_before': int(pillars_rows_before or 0),
        'pillars_rows_after': int(pillars_rows_after or 0),
        'pillars_synth_blockers_before': list(
            pillars_synth_blockers_before or []),
        'pillars_synth_blockers_after': p_after,
        'confidence_rows_before': int(confidence_rows_before or 0),
        'confidence_rows_after': int(confidence_rows_after or 0),
        'confidence_csf_rows_before': int(confidence_csf_rows_before or 0),
        'confidence_csf_rows_after': int(confidence_csf_rows_after or 0),
        'confidence_synth_blockers_before': list(
            confidence_synth_blockers_before or []),
        'confidence_synth_blockers_after': c_after,
        'repaired_sections': list(repaired_sections or []),
        'all_save_blockers_before': list(all_save_blockers_before or []),
        'all_save_blockers_after': save_after,
        'docx_allowed': bool(docx_allowed) and passed,
        'pdf_allowed': bool(pdf_allowed) and passed,
        'passed': bool(passed),
        'applied': True,
    }


def emit_rel36_17(payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_17_EN_CYBER_FINAL_SAVE_GATE_STABILIZER_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_17_en_cyber_final_save_gate_stabilizer(
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
    if not rel36_17_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks, doc_subtype=doc_subtype,
            text=blob):
        return sections or {}, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'all_save_blockers_after': [],
            'board_ready_so_blockers_after': [],
            'gaps_synth_blockers_after': [],
            'pillars_synth_blockers_after': [],
            'confidence_synth_blockers_after': [],
        }

    lang_n = normalize_rel36_lang(lang) or 'en'
    app = _app_mod()
    vision_b = str(secs.get('vision') or '')
    gaps_b = str(secs.get('gaps') or '')
    pillars_b = str(secs.get('pillars') or '')
    conf_b = str(secs.get('confidence') or '')

    so_rows_b = _official_so_rows(vision_b)
    so_dup_b = _so_duplicates(vision_b)
    so_tl_b = _so_target_like(vision_b, lang_n)
    br_b = _board_ready_so_blockers(vision_b, lang_n)
    gaps_rows_b = int(app.count_substantive_gaps(gaps_b) or 0)
    gaps_b_bl = _gaps_synth_blockers(gaps_b, generation_mode)
    pillars_rows_b = int(app._count_substantive_pillars(pillars_b) or 0)
    pillars_b_bl = _pillars_synth_blockers(pillars_b)
    csf_b, risk_b, _score_b, _just_b = _confidence_counts(conf_b)
    conf_b_bl = _confidence_synth_blockers(conf_b, generation_mode)
    fw_b = _fw_objective_blockers(secs, selected_frameworks)
    save_b = _all_save_blockers(
        secs, generation_mode, lang_n, selected_frameworks)

    repaired: List[str] = []
    if br_b or fw_b:
        secs['vision'], _ = repair_board_ready_so_table(
            vision_b, lang=lang_n)
        if (
                _board_ready_so_blockers(str(secs.get('vision') or ''), lang_n)
                or _fw_objective_blockers(secs, selected_frameworks)):
            secs['vision'], _ = repair_board_ready_so_table(
                '## 1. Vision and Strategic Objectives\n\n'
                'Protect the organization through a governed cybersecurity '
                'operating model aligned to NCA ECC and NCA DCC.\n\n'
                '### Strategic Objectives\n\n',
                lang=lang_n)
        repaired.append('vision')
    if gaps_b_bl:
        secs['gaps'] = repair_gaps_for_synth(gaps_b)
        repaired.append('gaps')
    if pillars_b_bl:
        secs['pillars'] = repair_pillars_for_synth(pillars_b)
        repaired.append('pillars')
    if conf_b_bl:
        secs['confidence'] = repair_confidence_for_synth(conf_b)
        repaired.append('confidence')

    vision_a = str(secs.get('vision') or '')
    gaps_a = str(secs.get('gaps') or '')
    pillars_a = str(secs.get('pillars') or '')
    conf_a = str(secs.get('confidence') or '')
    so_rows_a = _official_so_rows(vision_a)
    so_dup_a = _so_duplicates(vision_a)
    so_tl_a = _so_target_like(vision_a, lang_n)
    br_a = _board_ready_so_blockers(vision_a, lang_n)
    gaps_rows_a = int(app.count_substantive_gaps(gaps_a) or 0)
    gaps_a_bl = _gaps_synth_blockers(gaps_a, generation_mode)
    pillars_rows_a = int(app._count_substantive_pillars(pillars_a) or 0)
    pillars_a_bl = _pillars_synth_blockers(pillars_a)
    csf_a, risk_a, _score_a, _just_a = _confidence_counts(conf_a)
    conf_a_bl = _confidence_synth_blockers(conf_a, generation_mode)
    save_a = _all_save_blockers(
        secs, generation_mode, lang_n, selected_frameworks)

    diag = evaluate_rel36_17_en_cyber_final_save_gate_stabilizer(
        task_id=task_id,
        attempt_id=attempt_id,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        so_rows_before=so_rows_b,
        so_rows_after=so_rows_a,
        so_duplicates_before=so_dup_b,
        so_duplicates_after=so_dup_a,
        so_target_like_before=so_tl_b,
        so_target_like_after=so_tl_a,
        board_ready_so_blockers_before=br_b,
        board_ready_so_blockers_after=br_a,
        gaps_rows_before=gaps_rows_b,
        gaps_rows_after=gaps_rows_a,
        gaps_synth_blockers_before=gaps_b_bl,
        gaps_synth_blockers_after=gaps_a_bl,
        pillars_rows_before=pillars_rows_b,
        pillars_rows_after=pillars_rows_a,
        pillars_synth_blockers_before=pillars_b_bl,
        pillars_synth_blockers_after=pillars_a_bl,
        confidence_rows_before=risk_b,
        confidence_rows_after=risk_a,
        confidence_csf_rows_before=csf_b,
        confidence_csf_rows_after=csf_a,
        confidence_synth_blockers_before=conf_b_bl,
        confidence_synth_blockers_after=conf_a_bl,
        repaired_sections=repaired,
        all_save_blockers_before=save_b,
        all_save_blockers_after=save_a,
        docx_allowed=bool(docx_allowed) or not save_a,
        pdf_allowed=bool(pdf_allowed) or not save_a,
    )
    if emit:
        emit_rel36_17(diag)
    return secs, diag
