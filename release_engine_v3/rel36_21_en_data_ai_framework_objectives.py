"""REL36.21 — English Data/AI selected-framework objective coverage.

REL36.20 repairs English Data/AI vision richness and guide completeness,
but the official selected-framework compliance-objective gate still
fails before save:

* ``selected_framework_compliance_objective_missing:NDMO,PDPL (vision) 0/1``
* ``selected_framework_compliance_objective_missing:SDAIA (vision) 0/1``

Two stacked causes:

1. REL36.19 / REL36.20 emit the counted canonical header
   ``| # | Strategic Objective | Measurable Target | Rationale | Timeframe |``.
   ``count_valid_objective_rows`` already accepts that header. The
   compliance-objective detector previously matched only
   ``| # | Objective |``, so it inspected zero counted rows.
2. Even after the detector sees the first counted table, English Data
   (and REL36.19 AI catalog) rows name NDMO / PDPL / SDAIA without a
   detector-recognized compliance / alignment keyword. Mentions in
   environment / roadmap / gaps are ignored. A later appended SO table
   is not a substitute for the first counted table.

This module inserts detector-visible selected-framework rows into the
first counted Strategic Objectives table and canonicalizes English SO
headers. It does not mark the gate passed and does not apply to Arabic
document generation except for a test-harness guide-heading helper.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_21_EN_DATA_AI_FRAMEWORK_OBJECTIVE_COVERAGE_TAG = (
    '[REL36.21-EN-DATA-AI-FRAMEWORK-OBJECTIVE-COVERAGE]')

CANONICAL_SO_HEADER_EN = (
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |')
_SO_SEP = '|---|---|---|---|---|'

_VISION_ALIASES = (
    'vision', 'strategic_objectives', 'vision_mission_objectives',
    'objectives',
)

_SO_COL2_ALIASES = frozenset({
    'strategic objective', 'objective',
    'الهدف', 'الهدف الاستراتيجي', 'الأهداف',
})
_SO_COL3_ALIASES = frozenset({
    'measurable target', 'target metric', 'target',
    'المستهدف القابل للقياس', 'المقياس المستهدف', 'المؤشر المستهدف',
})
_SO_COL4_ALIASES = frozenset({
    'rationale', 'justification', 'المبرر', 'التبرير',
})

_SEP_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_ARABIC_CHAR_RE = re.compile(r'[\u0600-\u06FF]')
_ARABIC_HEADER_RE = re.compile(r'(?m)^#{1,4}\s*.*[\u0600-\u06FF]')
_TF_RE = re.compile(
    r'\d{1,6}\s*(?:months?|years?|weeks?|days?)'
    r'|(?:within)\s+\d{1,6}',
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r'(?i)^(?:tbd|todo|n/?a|none|placeholder|xxx|tbc|-|—|–)$')

_COMPLIANCE_KEYWORDS_EN = (
    'compliance', 'comply', 'compliant',
    'align', 'alignment', 'aligned',
    'selected framework', 'selected controls', 'selected frameworks',
    'close framework compliance gaps',
)

_DATA_LEAKS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_AI_LEAKS = _DATA_LEAKS + ('IAM', 'PAM', 'MFA')

NDMO_ROW = (
    'Align enterprise data governance with NDMO requirements',
    '100% of priority data domains governed under approved '
    'NDMO-aligned data governance controls',
    'Ensures compliance and alignment with NDMO data governance '
    'obligations, including ownership, metadata, quality, lifecycle, '
    'and stewardship controls',
    '12 months',
)
PDPL_ROW = (
    'Achieve PDPL compliance for personal data protection',
    '100% of personal data processing activities documented, '
    'classified, and governed under PDPL-aligned controls',
    'Ensures compliance and alignment with PDPL privacy, consent, '
    'data-subject rights, breach notification, and personal data '
    'protection obligations',
    '12 months',
)
SDAIA_ROW = (
    'Align artificial intelligence governance with SDAIA '
    'responsible AI requirements',
    '100% of high-impact AI use cases assessed, approved, and '
    'monitored under SDAIA-aligned governance controls',
    'Ensures compliance and alignment with SDAIA expectations for '
    'responsible AI, human oversight, model risk management, '
    'transparency, and accountability',
    '12 months',
)

FRAMEWORK_ROWS = {
    'NDMO': NDMO_ROW,
    'PDPL': PDPL_ROW,
    'SDAIA': SDAIA_ROW,
}

ARABIC_GAP_GUIDE_PHRASES = (
    'دليل تنفيذ الفجوة',
    'دليل تطبيق الفجوة',
)
ARABIC_GAP_GUIDE_HEADING_RE = re.compile(
    r'^#{1,4}\s*دليل (?:تنفيذ|تطبيق) الفجوة',
    re.MULTILINE,
)
ARABIC_KPI_GUIDE_PHRASES = (
    'دليل تقييم المؤشر',
    'أدلة تقييم مؤشرات',
    'أدلة تقييم مؤشرات الأداء',
)


def _domain_code(domain: Any) -> str:
    return _normalize_rel31_domain_code(domain) or ''


def _norm_dtype(document_type: Any) -> str:
    raw = str(document_type or 'strategy').strip().lower()
    if raw in ('', 'strategy document', 'strategy_document'):
        return 'strategy'
    return raw


def rel36_21_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = 'strategy',
        header_only: bool = False,
) -> bool:
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    dtype = _norm_dtype(document_type)
    if nlang != 'en' or dtype != 'strategy':
        return False
    if header_only:
        return dcode in {'cyber', 'data', 'ai'}
    return dcode in {'data', 'ai'}


def _cells(line: str) -> List[str]:
    raw = str(line or '').strip()
    if not (raw.startswith('|') and raw.endswith('|')):
        return []
    return [c.strip() for c in raw.strip('|').split('|')]


def _join(cells: Sequence[str]) -> str:
    return '| ' + ' | '.join(str(c) for c in cells) + ' |'


def is_english_so_header_line(line: str) -> bool:
    cells = _cells(line)
    if len(cells) < 4:
        return False
    col2 = (cells[1] or '').strip().lower()
    if col2 in _SO_COL2_ALIASES:
        return True
    col3 = (cells[2] or '').strip().lower() if len(cells) > 2 else ''
    col4 = (cells[3] or '').strip().lower() if len(cells) > 3 else ''
    return col3 in _SO_COL3_ALIASES and col4 in _SO_COL4_ALIASES


def first_so_header(text: str) -> str:
    for ln in str(text or '').splitlines():
        if is_english_so_header_line(ln) or _is_arabic_so_header(ln):
            return ln.strip()
    return ''


def _is_arabic_so_header(line: str) -> bool:
    cells = _cells(line)
    if len(cells) < 2:
        return False
    return any(tok in (cells[1] or '') for tok in (
        'الهدف الاستراتيجي', 'الهدف', 'الأهداف'))


def count_so_tables(text: str) -> int:
    return sum(
        1 for ln in str(text or '').splitlines()
        if is_english_so_header_line(ln) or _is_arabic_so_header(ln)
    )


def _split_first_so_table(text: str) -> Tuple[str, Optional[str], List[str], str]:
    lines = str(text or '').splitlines()
    header_idx = None
    for i, ln in enumerate(lines):
        if is_english_so_header_line(ln) or _is_arabic_so_header(ln):
            header_idx = i
            break
    if header_idx is None:
        return text or '', None, [], ''
    prefix = '\n'.join(lines[:header_idx])
    i = header_idx + 1
    if i < len(lines) and _SEP_RE.match(lines[i].strip()):
        i += 1
    data: List[str] = []
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1
            continue
        if not (s.startswith('|') and s.endswith('|')):
            break
        if _SEP_RE.match(s):
            i += 1
            continue
        data.append(lines[i])
        i += 1
    suffix = '\n'.join(lines[i:])
    return prefix, lines[header_idx], data, suffix


def _parse_kept_row(cells: Sequence[str]) -> Optional[List[str]]:
    if not cells:
        return None
    obj = cells[1].strip() if len(cells) > 1 else ''
    if not obj or _PLACEHOLDER_RE.match(obj):
        return None
    if obj.lower() in _SO_COL2_ALIASES:
        return None
    if _TF_RE.search(obj):
        return None
    metric = cells[2].strip() if len(cells) > 2 else ''
    rationale = cells[3].strip() if len(cells) > 3 else ''
    tf = cells[4].strip() if len(cells) > 4 else ''
    if not metric or _PLACEHOLDER_RE.match(metric):
        metric = 'Approved operating target'
    if not rationale or _PLACEHOLDER_RE.match(rationale):
        rationale = obj
    if not _TF_RE.search(tf or ''):
        tf = '12 months'
    return ['0', obj, metric, rationale, tf]


def _row_blob(row: Sequence[str]) -> str:
    return ' '.join(str(c) for c in row[1:4])


def _has_compliance_kw(blob: str) -> bool:
    low = (blob or '').lower()
    return any(kw in low for kw in _COMPLIANCE_KEYWORDS_EN)


def _framework_aliases(fw: str) -> Tuple[str, ...]:
    key = str(fw or '').strip().upper()
    if key == 'NDMO':
        return ('ndmo', 'data governance')
    if key == 'PDPL':
        return ('pdpl', 'personal data protection')
    if key == 'SDAIA':
        return ('sdaia',)
    return (key.lower(),)


def row_covers_framework(row: Sequence[str], fw: str) -> bool:
    blob = _row_blob(row)
    if not _has_compliance_kw(blob):
        return False
    low = blob.lower()
    return any(alias in low for alias in _framework_aliases(fw))


def frameworks_covered_in_first_table(text: str) -> List[str]:
    _prefix, _header, data_lines, _suffix = _split_first_so_table(text)
    covered: List[str] = []
    rows = []
    for ln in data_lines:
        parsed = _parse_kept_row(_cells(ln))
        if parsed:
            rows.append(parsed)
    for fw in ('NDMO', 'PDPL', 'SDAIA'):
        if any(row_covers_framework(r, fw) for r in rows):
            covered.append(fw)
    return covered


def required_frameworks(
        domain: str, selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    selected = [str(x).strip().upper() for x in _selected_list(selected_frameworks)]
    blob = ' '.join(selected).upper()
    out: List[str] = []
    dcode = _domain_code(domain)
    if dcode == 'data':
        if 'NDMO' in blob:
            out.append('NDMO')
        if 'PDPL' in blob:
            out.append('PDPL')
    if dcode == 'ai' and 'SDAIA' in blob:
        out.append('SDAIA')
    return out


def _renumber(rows: Sequence[Sequence[str]]) -> List[List[str]]:
    out: List[List[str]] = []
    for i, row in enumerate(rows, 1):
        out.append([str(i), *list(row[1:5])])
    return out


def _md_table(rows: Sequence[Sequence[str]]) -> str:
    body = [CANONICAL_SO_HEADER_EN, _SO_SEP]
    for row in rows:
        body.append(_join(row))
    return '\n'.join(body)


def canonicalize_english_so_header(text: str) -> Tuple[str, bool]:
    """Rewrite the first English SO header to the canonical labels."""
    prefix, header, data_lines, suffix = _split_first_so_table(text)
    if header is None:
        return text or '', False
    if header.strip() == CANONICAL_SO_HEADER_EN:
        return text or '', False
    if _is_arabic_so_header(header) and not is_english_so_header_line(header):
        # Arabic-only header is not rewritten here (Arabic routes stay Arabic).
        return text or '', False
    kept = []
    for ln in data_lines:
        parsed = _parse_kept_row(_cells(ln))
        if parsed:
            kept.append(parsed)
    kept = _renumber(kept)
    table = _md_table(kept)
    repaired = prefix.rstrip()
    if repaired:
        repaired += '\n\n'
    repaired += table
    if suffix.strip():
        repaired += '\n' + suffix.lstrip('\n')
    if not repaired.endswith('\n'):
        repaired += '\n'
    return repaired, True


def insert_framework_objectives(
        text: str,
        *,
        domain: str,
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    required = required_frameworks(domain, selected_frameworks)
    prefix, header, data_lines, suffix = _split_first_so_table(text)
    kept: List[List[str]] = []
    for ln in data_lines:
        parsed = _parse_kept_row(_cells(ln))
        if parsed:
            kept.append(parsed)
    present_before = [
        fw for fw in required if any(row_covers_framework(r, fw) for r in kept)
    ]
    inserted: List[str] = []
    for fw in required:
        if fw in present_before:
            continue
        spec = FRAMEWORK_ROWS.get(fw)
        if not spec:
            continue
        kept.append(['0', *spec])
        inserted.append(fw)
    kept = _renumber(kept)
    table = _md_table(kept)
    if header is None:
        body = (text or '').rstrip()
        heading = '### Strategic Objectives'
        if body:
            repaired = body + '\n\n' + heading + '\n\n' + table + '\n'
        else:
            repaired = (
                '## 1. Vision and Strategic Objectives\n\n'
                + heading + '\n\n' + table + '\n'
            )
    else:
        repaired = prefix.rstrip()
        if repaired:
            repaired += '\n\n'
        repaired += table
        if suffix.strip():
            repaired += '\n' + suffix.lstrip('\n')
        if not repaired.endswith('\n'):
            repaired += '\n'
    present_after = [
        fw for fw in required if any(row_covers_framework(r, fw) for r in kept)
    ]
    return repaired, {
        'frameworks_required': required,
        'framework_objectives_present_before': present_before,
        'framework_objectives_present_after': present_after,
        'missing_framework_objectives_before': [
            fw for fw in required if fw not in present_before
        ],
        'missing_framework_objectives_after': [
            fw for fw in required if fw not in present_after
        ],
        'inserted_framework_objectives': inserted,
    }


def _count_valid_so_rows(text: str) -> int:
    try:
        from app import count_valid_objective_rows
        return int(count_valid_objective_rows(text or '') or 0)
    except Exception:
        return 0


_FW_DOMAIN_LABEL = {
    'data': 'Data Management',
    'ai': 'Artificial Intelligence',
    'cyber': 'Cyber Security',
}


def _official_missing(
        sections: Dict[str, Any],
        selected_frameworks: Optional[Iterable[Any]],
        domain: str,
        lang: str,
) -> List[str]:
    try:
        from app import _compute_missing_compliance_objective
        label = _FW_DOMAIN_LABEL.get(_domain_code(domain), domain)
        missing = _compute_missing_compliance_objective(
            sections, selected_frameworks, domain=label, lang=lang)
        return [str(x) for x in (missing or [])]
    except Exception:
        return []


def _save_blockers_of(
        sections: Dict[str, Any],
        *,
        domain: str,
        lang: str,
        selected_frameworks: Optional[Iterable[Any]],
        document_type: str = 'strategy',
) -> List[str]:
    try:
        from app import _audit_doc_quality
        result = _audit_doc_quality(
            {k: str(v or '') for k, v in (sections or {}).items()},
            domain=domain,
            lang=lang,
            selected_frameworks=list(_selected_list(selected_frameworks)),
            document_type=document_type,
        ) or {}
        blockers = list(result.get('blockers') or result.get('errors') or [])
        return [str(b) for b in blockers]
    except Exception:
        missing = _official_missing(
            sections, selected_frameworks, domain, lang)
        if missing:
            return [
                'selected_framework_compliance_objective_missing:'
                + ','.join(missing)
            ]
        return []


def _arabic_hits(text: str, org_name: str = '') -> Tuple[List[str], List[str]]:
    blob = str(text or '')
    if org_name:
        blob = blob.replace(org_name, '')
    headers = _ARABIC_HEADER_RE.findall(blob)
    prose = []
    for ln in blob.splitlines():
        if _ARABIC_CHAR_RE.search(ln) and not ln.strip().startswith('|---'):
            if not is_english_so_header_line(ln):
                prose.append(ln.strip())
    return headers, prose


def _leakage_terms(text: str, domain: str) -> List[str]:
    hay = str(text or '')
    terms = _AI_LEAKS if domain == 'ai' else _DATA_LEAKS
    found: List[str] = []
    for tok in terms:
        if tok == 'NCA':
            if re.search(r'(?<![A-Z])NCA(?![A-Z])', hay) and tok not in found:
                found.append(tok)
            continue
        if tok in hay and tok not in found:
            found.append(tok)
    return found


def _canonical_vision(sections: Dict[str, str]) -> str:
    for key in _VISION_ALIASES:
        if str(sections.get(key) or '').strip():
            return str(sections[key])
    return ''


def _set_vision(sections: Dict[str, str], text: str) -> None:
    for key in _VISION_ALIASES:
        if str(sections.get(key) or '').strip():
            sections[key] = text
            if key != 'vision':
                sections['vision'] = text
            return
    sections['vision'] = text


def count_accepted_arabic_gap_guides(text: str) -> int:
    """Test-harness counter. Accepts app/compiler guide heading aliases.

    Does not change ``app.count_gap_guides`` (the save-gate counter).
    """
    return len(ARABIC_GAP_GUIDE_HEADING_RE.findall(text or ''))


def arabic_gap_guide_aliases_present(text: str) -> List[str]:
    blob = str(text or '')
    return [p for p in ARABIC_GAP_GUIDE_PHRASES if p in blob]


def classify_arabic_ai_5_shape(
        attempts: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify Arabic AI 5-shape using accepted guide aliases.

    A failed save or export stays failed. Guide headings may use either
    ``دليل تنفيذ الفجوة`` or ``دليل تطبيق الفجوة``.
    """
    summary = []
    pass_count = 0
    for i, rec in enumerate(attempts or [], 1):
        saved = bool(rec.get('saved') or rec.get('save_ok'))
        exported = bool(
            rec.get('exported')
            or rec.get('export_ok')
            or (rec.get('docx_allowed') and rec.get('pdf_allowed'))
        )
        gaps = str(rec.get('gaps') or rec.get('gaps_text') or '')
        guides = rec.get('guide_count')
        if guides is None:
            guides = count_accepted_arabic_gap_guides(gaps)
        guides_ok = int(guides or 0) >= int(rec.get('min_guides') or 1)
        aliases = arabic_gap_guide_aliases_present(gaps)
        ok = saved and exported and guides_ok
        if ok:
            pass_count += 1
        summary.append({
            'shape': i,
            'saved': saved,
            'exported': exported,
            'guide_count': int(guides or 0),
            'guide_aliases': aliases,
            'passed': ok,
        })
    return {
        'attempts': summary,
        'pass_count': pass_count,
        'required': 5,
        'passed': pass_count == 5 and all(r['passed'] for r in summary),
    }


def apply_rel36_21_en_data_ai_framework_objectives(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Optional[str] = None,
        lang: Optional[str] = None,
        document_type: Optional[str] = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Optional[str] = None,
        org_name: Optional[str] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    out = {str(k): str(v or '') for k, v in (sections or {}).items()}
    dcode = _domain_code(domain)
    nlang = normalize_rel36_lang(lang)
    doc_type = _norm_dtype(document_type)
    fw = list(_selected_list(selected_frameworks))
    diagnostics: Dict[str, Any] = {
        'task_id': task_id or '',
        'domain': dcode,
        'lang': nlang,
        'document_type': doc_type,
        'selected_frameworks': fw,
        'applied': False,
        'passed': False,
    }
    header_only = dcode == 'cyber'
    if not rel36_21_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            header_only=header_only):
        diagnostics['skipped'] = True
        return out, diagnostics

    vision_before = _canonical_vision(out)
    tables_before = count_so_tables(vision_before)
    header_before = first_so_header(vision_before)
    rows_before = _count_valid_so_rows(vision_before)
    required = required_frameworks(dcode, fw)
    present_before = [
        x for x in frameworks_covered_in_first_table(vision_before)
        if x in required
    ]
    missing_before = [x for x in required if x not in present_before]
    official_before = _official_missing(out, fw, dcode, nlang)
    blockers_before = _save_blockers_of(
        out, domain=dcode, lang=nlang, selected_frameworks=fw,
        document_type=doc_type)

    vision = vision_before
    inserted: List[str] = []
    insert_stats: Dict[str, Any] = {}
    if dcode in {'data', 'ai'} and required:
        vision, insert_stats = insert_framework_objectives(
            vision, domain=dcode, selected_frameworks=fw)
        inserted = list(insert_stats.get('inserted_framework_objectives') or [])
    vision, _hdr_changed = canonicalize_english_so_header(vision)
    _set_vision(out, vision)

    vision_after = _canonical_vision(out)
    header_after = first_so_header(vision_after)
    rows_after = _count_valid_so_rows(vision_after)
    present_after = [
        x for x in frameworks_covered_in_first_table(vision_after)
        if x in required
    ]
    missing_after = [x for x in required if x not in present_after]
    official_after = _official_missing(out, fw, dcode, nlang)
    official_relevant = [x for x in official_after if x in required]
    blockers_after = _save_blockers_of(
        out, domain=dcode, lang=nlang, selected_frameworks=fw,
        document_type=doc_type)
    fw_blockers_before = [
        b for b in blockers_before
        if 'selected_framework_compliance_objective_missing' in b
    ]
    fw_blockers_after = [
        b for b in blockers_after
        if 'selected_framework_compliance_objective_missing' in b
    ]
    tables_after = count_so_tables(vision_after)
    ar_headers, ar_prose = _arabic_hits(vision_after, org_name or '')
    leaks = [] if dcode == 'cyber' else _leakage_terms(vision_after, dcode)
    header_canonical = (
        'Strategic Objective' in header_after
        and 'Measurable Target' in header_after
        and 'Rationale' in header_after
        and 'Timeframe' in header_after
    )
    duplicate = tables_after > max(tables_before, 1)
    compliance_missing = bool(official_relevant) or bool(missing_after)
    passed = (
        header_canonical
        and missing_after == []
        and official_relevant == []
        and fw_blockers_after == []
        and duplicate is False
        and ar_headers == []
        and ar_prose == []
        and leaks == []
        and not compliance_missing
    )
    if compliance_missing:
        passed = False

    diagnostics.update({
        'applied': True,
        'first_so_header_before': header_before,
        'first_so_header_after': header_after,
        'so_rows_before': rows_before,
        'so_rows_after': rows_after,
        'frameworks_required': required,
        'framework_objectives_present_before': present_before,
        'framework_objectives_present_after': present_after,
        'missing_framework_objectives_before': missing_before,
        'missing_framework_objectives_after': missing_after,
        'inserted_framework_objectives': inserted,
        'selected_framework_objective_blockers_before': official_before,
        'selected_framework_objective_blockers_after': official_relevant,
        'duplicate_so_table_after': duplicate,
        'arabic_header_hits_after': ar_headers,
        'arabic_prose_hits_after': ar_prose,
        'leakage_terms_after': leaks,
        'save_blockers_before': blockers_before,
        'save_blockers_after': blockers_after,
        'docx_allowed': passed,
        'pdf_allowed': passed,
        'passed': passed,
        'insert_stats': insert_stats,
        'header_changed': _hdr_changed,
        'so_tables_before': tables_before,
        'so_tables_after': tables_after,
    })
    if emit:
        print(
            REL36_21_EN_DATA_AI_FRAMEWORK_OBJECTIVE_COVERAGE_TAG + ' '
            + json.dumps(diagnostics, ensure_ascii=False, default=str),
            flush=True,
        )
    return out, diagnostics
