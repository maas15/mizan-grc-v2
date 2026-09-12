"""REL36.20.2 — preserve countable Arabic Data roadmap rows.

REL36.20.1 official staging on ``62acc73`` cleared
``roadmap_family_duplicated`` / ``roadmap_family_restart_detected`` but
Arabic Data failed the unchanged richness save-gate with
``roadmap_rows_insufficient (roadmap) 0/4``.

Root cause: after family-collapse the roadmap often has pipe rows that
start with ``| المرحلة 1:`` and no separate header. REL36.20.1 treated
that first data row as the table header. The official counter
(``_count_substantive_roadmap_rows``) requires ≥2 header-token cells
before it counts any row, so it stayed at 0/4 even though pipe rows
existed.

This module (Arabic Data + NDMO/PDPL strategy only):

* keeps the REL36.20.1 family-heading cleanup
* emits exactly one canonical ``## 5.`` heading
* emits the canonical Arabic roadmap header the official counter
  recognizes
* guarantees ≥4 countable pipe rows (prefer all official families)
* is a no-op on a second pass when the table is already countable
* does not write Gap/KPI guide headings into roadmap

It does not mark the save-gate passed and does not suppress
``roadmap_rows_insufficient``.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    _TABLE_HEADER_AR,
    _TABLE_SEP,
    detect_balance_families,
    required_balance_families,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    official_data_required_families,
)
from release_engine_v3.rel36_20_1_data_roadmap_family_integrity import (
    CANONICAL_FAMILY_ORDER,
    _canonical_heading,
    _family_of_row,
    _is_pipe_data_row,
    _is_recognized_roadmap_header,
    _leakage_terms,
    _normalize_headings,
    _official_missing_data_families,
    _required_data_families,
    _split_roadmap_parts,
    duplicate_families,
    family_sequence,
    heading_blockers,
    numbered_headings,
    restarted_families,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_20_2_DATA_AR_COUNTABLE_ROADMAP_TAG = (
    '[REL36.20.2-DATA-AR-COUNTABLE-ROADMAP]')

CANONICAL_AR_HEADER = _TABLE_HEADER_AR
CANONICAL_AR_SEP = _TABLE_SEP

_GUIDE_HEADING_RE = re.compile(
    r'^#{2,4}\s*(?:'
    r'دليل تنفيذ الفجوة|أدلة تقييم مؤشرات|'
    r'دليل تقييم المؤشر|'
    r'Gap\s*#?\d+\s*Implementation Guide|'
    r'KPI Assessment Guidelines|'
    r'KPI\s*#\s*\d+\s*Assessment Guide'
    r')',
    re.IGNORECASE | re.MULTILINE,
)

# Detector-visible 6-column rows. Catalog is 6-col so the official
# counter sees a recognized header plus real initiative rows.
_COUNTABLE_FAMILY_ROWS_AR: Dict[str, str] = {
    'data_quality': (
        '| المرحلة 1: تأسيس | 1-6 أشهر | '
        'إطلاق برنامج إدارة جودة البيانات ومقاييس الجودة | '
        'مدير جودة البيانات | مقاييس جودة البيانات المعتمدة ولوحة جودة البيانات | NDMO |'
    ),
    'data_catalog': (
        '| المرحلة 1: تأسيس | 1-6 أشهر | '
        'إنشاء كتالوج البيانات المؤسسي وجرد أصول البيانات وربطها بمالكي البيانات | '
        'مالك كتالوج البيانات | كتالوج بيانات مؤسسي وسجل أصول بيانات محدث | NDMO |'
    ),
    'data_lifecycle': (
        '| المرحلة 1: تأسيس | 1-6 أشهر | '
        'اعتماد دورة حياة البيانات من الإنشاء إلى الإتاحة والأرشفة والإتلاف | '
        'مدير حوكمة البيانات | نموذج دورة حياة بيانات معتمد ومطبق | NDMO |'
    ),
    'privacy_governance': (
        '| المرحلة 1: تأسيس | 1-6 أشهر | '
        'تأسيس حوكمة الخصوصية وحماية البيانات الشخصية | '
        'مسؤول حماية البيانات | ميثاق حوكمة خصوصية وأدوار ومسؤوليات معتمدة | PDPL |'
    ),
    'personal_data_classification': (
        '| المرحلة 2: تفعيل | 7-12 شهر | '
        'تصنيف وجرد البيانات الشخصية والحساسة | '
        'مسؤول حماية البيانات | سجل تصنيف البيانات الشخصية والحساسة | PDPL |'
    ),
    'consent_management': (
        '| المرحلة 2: تفعيل | 7-12 شهر | '
        'تفعيل إدارة الموافقات وسجل الموافقات | '
        'مسؤول حماية البيانات | سجل موافقات معتمد ومفعل | PDPL |'
    ),
    'data_subject_rights': (
        '| المرحلة 2: تفعيل | 7-12 شهر | '
        'تفعيل قنوات طلبات أصحاب البيانات والرد عليها ضمن المهلة النظامية | '
        'مسؤول حماية البيانات | سجل طلبات أصحاب البيانات وإغلاقها | PDPL |'
    ),
    'breach_notification': (
        '| المرحلة 3: تحسين | 13-18 شهر | '
        'تفعيل آلية الإبلاغ عن الانتهاكات ومعالجة انتهاكات البيانات | '
        'مسؤول حماية البيانات | سجل بلاغات الإبلاغ عن الانتهاكات وإجراءات معالجة | PDPL |'
    ),
}


def _domain_code(domain: Optional[str]) -> str:
    return str(_normalize_rel31_domain_code(domain) or '').strip().lower()


def rel36_20_2_should_apply(
        *,
        domain: Optional[str],
        lang: Optional[str],
        document_type: Optional[str],
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> bool:
    if _domain_code(domain) != 'data':
        return False
    if not str(normalize_rel36_lang(lang) or '').startswith('ar'):
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in {'strategy', 'strategy document', ''}:
        return False
    blob = ' '.join(str(x) for x in _selected_list(selected_frameworks)).lower()
    return 'ndmo' in blob or 'pdpl' in blob


def _official_count(text: str) -> int:
    try:
        import app as app_mod
        return int(app_mod._count_substantive_roadmap_rows(text or '') or 0)
    except Exception:
        n = 0
        in_tbl = False
        for ln in str(text or '').splitlines():
            s = ln.strip()
            if not (s.startswith('|') and s.endswith('|')):
                in_tbl = False
                continue
            if re.match(r'^\|[\s\-:|]+\|$', s):
                continue
            if _is_recognized_roadmap_header(s) and not in_tbl:
                in_tbl = True
                continue
            if in_tbl and _is_pipe_data_row(s):
                n += 1
        return n


def _first_header(text: str) -> str:
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and not re.match(r'^\|[\s\-:|]+\|$', s):
            return s
    return ''


def _sha(text: str) -> str:
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()[:16]


def _guide_headings(text: str) -> List[str]:
    return [m.group(0).strip() for m in _GUIDE_HEADING_RE.finditer(text or '')]


def _row_blockers(count: int) -> List[str]:
    if count < 4:
        return [f'roadmap_rows_insufficient:{count}/4']
    return []


def _collect_existing_rows(text: str) -> List[str]:
    _preamble, _header, rows, _suffix = _split_roadmap_parts(text)
    if rows:
        return list(rows)
    harvested: List[str] = []
    for ln in str(text or '').splitlines():
        if _is_pipe_data_row(ln):
            harvested.append(ln if ln.startswith('|') else ln.strip())
    return harvested


def _order_rows(rows: List[str], required: List[str]) -> List[str]:
    grouped: Dict[str, List[str]] = {fam: [] for fam in CANONICAL_FAMILY_ORDER}
    unknown: List[str] = []
    seen = set()
    for row in rows:
        key = re.sub(r'\s+', ' ', row.strip())
        if key in seen:
            continue
        seen.add(key)
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
    return ordered


def _table_blob(rows: List[str]) -> str:
    return (
        CANONICAL_AR_HEADER + '\n' + CANONICAL_AR_SEP + '\n'
        + '\n'.join(rows) + '\n'
    )


def _ensure_countable_rows(
        rows: List[str],
        *,
        required: List[str],
        missing: List[str],
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> List[str]:
    ordered = _order_rows(rows, required)
    have = set(detect_balance_families('\n'.join(ordered)))
    still_missing = list(missing) + [
        fam for fam in required if fam not in have]
    for fam in list(dict.fromkeys(still_missing)):
        if fam in have:
            continue
        seed = _COUNTABLE_FAMILY_ROWS_AR.get(fam)
        if not seed:
            continue
        ordered.append(seed)
        have.add(fam)
    ordered = _order_rows(ordered, required)
    official_missing = _official_missing_data_families(
        _table_blob(ordered), selected_frameworks, 'ar')
    for fam in official_missing:
        seed = _COUNTABLE_FAMILY_ROWS_AR.get(fam)
        if not seed:
            continue
        if any(seed.strip() == r.strip() for r in ordered):
            continue
        ordered.append(seed)
    ordered = _order_rows(ordered, required)
    if _official_count(_table_blob(ordered)) < 4:
        for fam in CANONICAL_FAMILY_ORDER:
            seed = _COUNTABLE_FAMILY_ROWS_AR.get(fam)
            if not seed:
                continue
            if any(seed.strip() == r.strip() for r in ordered):
                continue
            ordered.append(seed)
            if _official_count(_table_blob(ordered)) >= 4:
                break
    return _order_rows(ordered, required)


def _rebuild(rows: List[str]) -> str:
    heading = _canonical_heading('ar')
    parts = [heading, '', CANONICAL_AR_HEADER, CANONICAL_AR_SEP]
    parts.extend(rows)
    return '\n'.join(parts).rstrip() + '\n'


def _already_countable(
        text: str,
        sections: Dict[str, str],
        selected_frameworks: Optional[Iterable[Any]],
) -> bool:
    count = _official_count(text)
    header = _first_header(text)
    return bool(
        count >= 4
        and _is_recognized_roadmap_header(header)
        and heading_blockers(sections) == []
        and not _official_missing_data_families(
            text, selected_frameworks, 'ar')
        and _guide_headings(text) == []
        and _leakage_terms(text) == []
        and _row_blockers(count) == []
    )


def apply_rel36_20_2_data_ar_countable_roadmap(
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
    doc_type = str(document_type or 'strategy')
    before_text = str(out.get('roadmap') or '')
    count_before = _official_count(before_text)
    header_before = _first_header(before_text)
    seq_before = family_sequence(before_text)
    row_blockers_before = _row_blockers(count_before)
    save_before: List[str] = []
    try:
        from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
            _save_blockers_of,
        )
        save_before = [
            b for b in _save_blockers_of(
                out, domain=dcode, lang=nlang, selected_frameworks=fw,
                document_type=doc_type)
            if 'roadmap_rows_insufficient' in str(b)
            or 'roadmap_family_' in str(b)
            or 'data_roadmap_balance_missing' in str(b)
        ]
    except Exception:
        save_before = list(row_blockers_before)

    diag: Dict[str, Any] = {
        'task_id': task_id or '',
        'domain': dcode,
        'lang': nlang,
        'document_type': doc_type,
        'selected_frameworks': fw,
        'applied': False,
        'passed': False,
        'roadmap_text_before': before_text,
        'roadmap_text_after_hash': _sha(before_text),
        'roadmap_header_before': header_before,
        'roadmap_header_after': header_before,
        'roadmap_rows_count_before': count_before,
        'roadmap_rows_count_after': count_before,
        'countable_rows_before': count_before,
        'countable_rows_after': count_before,
        'family_sequence_before': seq_before,
        'family_sequence_after': seq_before,
        'duplicate_families_after': duplicate_families(seq_before),
        'restarted_families_after': restarted_families(seq_before),
        'missing_families_after': [],
        'roadmap_family_blockers_after': heading_blockers(out),
        'roadmap_rows_blockers_before': row_blockers_before,
        'roadmap_rows_blockers_after': row_blockers_before,
        'guide_headings_inside_roadmap_after': _guide_headings(before_text),
        'idempotent_second_pass': False,
        'save_blockers_before': save_before,
        'save_blockers_after': save_before,
        'leakage_terms_after': _leakage_terms(before_text),
    }
    if not rel36_20_2_should_apply(
            domain=dcode, lang=nlang, document_type=doc_type,
            selected_frameworks=fw):
        diag['skipped'] = True
        return out, diag

    required = _required_data_families(fw) or list(
        official_data_required_families(fw) or required_balance_families(fw))
    missing_before = _official_missing_data_families(before_text, fw, nlang)

    snapshot = before_text
    if not _already_countable(before_text, out, fw):
        existing = _collect_existing_rows(before_text)
        rebuilt_rows = _ensure_countable_rows(
            existing, required=required, missing=missing_before,
            selected_frameworks=fw)
        out['roadmap'] = _rebuild(rebuilt_rows)
        _normalize_headings(out, 'ar')
        # Drop any guide headings that leaked into roadmap.
        road = str(out.get('roadmap') or '')
        if _guide_headings(road):
            cleaned_lines = [
                ln for ln in road.splitlines()
                if not _GUIDE_HEADING_RE.match(ln.strip())
            ]
            out['roadmap'] = '\n'.join(cleaned_lines).rstrip() + '\n'
            _normalize_headings(out, 'ar')

    first_text = str(out.get('roadmap') or '')
    second_rows = _collect_existing_rows(first_text)
    second = _rebuild(_ensure_countable_rows(
        second_rows, required=required,
        missing=_official_missing_data_families(first_text, fw, nlang),
        selected_frameworks=fw))
    tmp = dict(out)
    tmp['roadmap'] = second
    _normalize_headings(tmp, 'ar')
    idempotent = (
        _official_count(first_text) == _official_count(tmp.get('roadmap') or '')
        and _official_count(first_text) >= 4
        and heading_blockers(tmp) == []
        and _guide_headings(str(tmp.get('roadmap') or '')) == []
    )
    # Second pass must not change a countable first pass.
    if idempotent:
        out['roadmap'] = first_text
    else:
        out['roadmap'] = str(tmp.get('roadmap') or first_text)

    after_text = str(out.get('roadmap') or '')
    count_after = _official_count(after_text)
    header_after = _first_header(after_text)
    seq_after = family_sequence(after_text)
    missing_after = _official_missing_data_families(after_text, fw, nlang)
    family_blockers_after = heading_blockers(out)
    row_blockers_after = _row_blockers(count_after)
    guides_after = _guide_headings(after_text)
    leaks = _leakage_terms(after_text)
    save_after: List[str] = []
    try:
        from release_engine_v3.rel36_20_data_ai_guide_save_stability import (
            _save_blockers_of,
        )
        save_after = [
            b for b in _save_blockers_of(
                out, domain=dcode, lang=nlang, selected_frameworks=fw,
                document_type=doc_type)
            if 'roadmap_rows_insufficient' in str(b)
            or 'roadmap_family_' in str(b)
            or 'data_roadmap_balance_missing' in str(b)
        ]
    except Exception:
        save_after = list(row_blockers_after) + list(family_blockers_after)
    if row_blockers_after:
        for tok in row_blockers_after:
            if tok not in save_after:
                save_after.append(tok)

    dups_after = duplicate_families(seq_after)
    restarts_after = restarted_families(seq_after)
    passed = (
        count_after >= 4
        and _is_recognized_roadmap_header(header_after)
        and dups_after == []
        and restarts_after == []
        and missing_after == []
        and family_blockers_after == []
        and row_blockers_after == []
        and guides_after == []
        and idempotent
        and save_after == []
        and leaks == []
        and 'roadmap_rows_insufficient' not in ' '.join(save_after)
        and 'roadmap_family_duplicated' not in family_blockers_after
        and 'roadmap_family_restart_detected' not in family_blockers_after
    )
    if row_blockers_after:
        passed = False

    diag.update({
        'applied': True,
        'passed': passed,
        'roadmap_text_before': snapshot,
        'roadmap_text_after_hash': _sha(after_text),
        'roadmap_header_before': header_before,
        'roadmap_header_after': header_after,
        'roadmap_rows_count_before': count_before,
        'roadmap_rows_count_after': count_after,
        'countable_rows_before': count_before,
        'countable_rows_after': count_after,
        'family_sequence_before': seq_before,
        'family_sequence_after': seq_after,
        'duplicate_families_after': dups_after,
        'restarted_families_after': restarts_after,
        'missing_families_after': missing_after,
        'roadmap_family_blockers_after': family_blockers_after,
        'roadmap_rows_blockers_before': row_blockers_before,
        'roadmap_rows_blockers_after': row_blockers_after,
        'guide_headings_inside_roadmap_after': guides_after,
        'idempotent_second_pass': idempotent,
        'save_blockers_before': save_before,
        'save_blockers_after': save_after,
        'leakage_terms_after': leaks,
    })
    print(
        REL36_20_2_DATA_AR_COUNTABLE_ROADMAP_TAG + ' '
        + json.dumps(diag, ensure_ascii=False, default=str),
        flush=True,
    )
    return out, diag
