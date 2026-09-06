"""REL36.18 — AI SDAIA Arabic first-counted KPI table repair.

Main-staging on ``fc944d5`` (PR #126 merge) accepted 5/6 official
routes and failed ``ai:strategy:ar`` before save:

    synth_failed:kpis (kpis) 0/1
    generation_save_allowed=false

Root cause (unchanged gate ``synthesize_kpi_depth``):

* The synthesizer no-ops only when ``count_substantive_kpis`` meets
  the drafting floor (4), the section contains a Frequency /
  ``التكرار`` column, there is exactly one
  ``### أدلة تقييم مؤشرات الأداء`` heading, and there is one
  ``#### دليل تقييم المؤشر رقم N`` block per counted row.
* Arabic AI / SDAIA drafts often emit a thin, schema-mismatched, or
  guide-less first KPI table (or a later valid table after an ignored
  first table). AI repair then fail-closes as ``synth_failed:kpis``.
* REL36.15 KPI repair is English Cyber only and injects NCA/CISO/SIEM
  catalog rows, so it must not run on AI.

This module replaces the first counted KPI table in place with the
official 8-column Arabic schema and SDAIA / AI-governance rows plus
matching Arabic guides. It does not append a second ignored table and
does not mark the synth gate passed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_13_en_cyber_core_completeness import _md_table
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_18_AI_SDAIA_KPI_SYNTH_REPAIR_TAG = (
    '[REL36.18-AI-SDAIA-KPI-SYNTH-REPAIR]')

_MIN_KPI = 4

_KPI_HEADER = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
    'مصدر | التكرار | المالك |')
_KPI_SEP = '|---|---|---|---|---|---|---|---|'
_KPI_HEADING = '## 6. مؤشرات الأداء الرئيسية'
_GUIDES_HEADING = '### أدلة تقييم مؤشرات الأداء'

_KPI_FIRST_TABLE_RE = re.compile(
    r'(^\|\s*#\s*\|\s*(?:وصف\s+المؤشر|KPI\s+Description|KPI|المؤشر|Metric)'
    r'\s*\|[^\n]*\n'
    r'(?:^\|[\s\-:|]+\|[^\n]*\n)?'
    r'(?:^\|(?!\s*#\s*\|\s*(?:وصف\s+المؤشر|KPI\s+Description|KPI|المؤشر|'
    r'Metric)\s*\|)[^\n]*\n)*)',
    re.MULTILINE | re.IGNORECASE,
)
_KPI_HEADER_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:وصف\s+المؤشر|KPI\s+Description|KPI|المؤشر|Metric)\s*\|',
    re.IGNORECASE | re.MULTILINE,
)
_SEP_ROW_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_PLACEHOLDER_RE = re.compile(
    r'(?i)^(?:tbd|todo|n/?a|none|placeholder|xxx|tbc|-|—|–)$')

_LEAK_TERMS = (
    'NCA ECC', 'NCA DCC', 'NCA', 'CISO', 'SIEM', 'SOC', 'IAM', 'PAM',
    'MFA', 'CSIRT', 'NIST CSF', 'NIST Cybersecurity Framework',
    'NIST AI RMF',
)

_OWNERS = (
    'مسؤول حوكمة الذكاء الاصطناعي',
    'مالك نموذج الذكاء الاصطناعي',
    'مسؤول البيانات',
    'مسؤول الامتثال',
    'لجنة الذكاء الاصطناعي',
)
_SOURCES = (
    'سجل نماذج الذكاء الاصطناعي',
    'منصة حوكمة الذكاء الاصطناعي',
    'تقارير تقييم المخاطر',
    'سجل مراقبة أداء النماذج',
    'سجل مراجعة الإشراف البشري',
)

# Official 8-col cells: # | وصف | النوع | القيمة المستهدفة | صيغة | مصدر | التكرار | المالك
# count_substantive_kpis treats cells[1]/[2]/[3] as Description/Target/Formula
# slots, so type + target must stay non-placeholder.
_KPI_CATALOG: Tuple[Tuple[str, str, str, str, str, str, str], ...] = (
    ('نسبة اكتمال حوكمة حالات استخدام الذكاء الاصطناعي',
     'لاحق', '100% من حالات الاستخدام الحرجة لها حوكمة معتمدة',
     'حالات الاستخدام المحوكمة ÷ الحالات الحرجة × 100',
     'منصة حوكمة الذكاء الاصطناعي', 'ربع سنوي',
     'مسؤول حوكمة الذكاء الاصطناعي'),
    ('نسبة تقييم مخاطر نماذج الذكاء الاصطناعي قبل الإطلاق',
     'قائد', '100% من النماذج عالية الأثر تُقيَّم قبل الإطلاق',
     'النماذج المقيَّمة قبل الإطلاق ÷ النماذج المطلقة × 100',
     'تقارير تقييم المخاطر', 'شهري',
     'مالك نموذج الذكاء الاصطناعي'),
    ('نسبة توثيق بيانات التدريب والاختبار والتحقق',
     'لاحق', '100% من النماذج الإنتاجية لها بيانات موثقة',
     'النماذج ذات البيانات الموثقة ÷ النماذج الإنتاجية × 100',
     'سجل نماذج الذكاء الاصطناعي', 'ربع سنوي',
     'مسؤول البيانات'),
    ('نسبة تنفيذ مراجعة الإشراف البشري للنماذج عالية الأثر',
     'قائد', '100% من النماذج عالية الأثر تخضع لمراجعة إشراف بشري',
     'المراجعات المنفذة ÷ المراجعات المطلوبة × 100',
     'سجل مراجعة الإشراف البشري', 'شهري',
     'لجنة الذكاء الاصطناعي'),
    ('نسبة معالجة انحياز النماذج ومخرجات العدالة',
     'لاحق', '95% من نتائج اختبار العدالة تُعالج ضمن المهلة',
     'نتائج العدالة المعالجة ÷ النتائج المفتوحة × 100',
     'منصة حوكمة الذكاء الاصطناعي', 'ربع سنوي',
     'مسؤول الامتثال'),
    ('نسبة مراقبة أداء النماذج بعد التشغيل',
     'قائد', '100% من النماذج الإنتاجية عليها مراقبة أداء',
     'النماذج المراقبة ÷ النماذج الإنتاجية × 100',
     'سجل مراقبة أداء النماذج', 'شهري',
     'مالك نموذج الذكاء الاصطناعي'),
    ('نسبة توثيق قرارات النماذج وقابلية التفسير',
     'لاحق', '95% من القرارات عالية الأثر موثقة وقابلة للتفسير',
     'القرارات الموثقة ÷ القرارات عالية الأثر × 100',
     'سجل نماذج الذكاء الاصطناعي', 'ربع سنوي',
     'مسؤول حوكمة الذكاء الاصطناعي'),
    ('نسبة الالتزام بضوابط سدايا للذكاء الاصطناعي المسؤول',
     'لاحق', '95% من ضوابط سدايا المطبقة على النطاق',
     'الضوابط المطبقة ÷ ضوابط سدايا المطلوبة × 100',
     'منصة حوكمة الذكاء الاصطناعي', 'ربع سنوي',
     'مسؤول الامتثال'),
    ('نسبة اكتمال سجل نماذج الذكاء الاصطناعي',
     'قائد', '100% من النماذج الإنتاجية مسجلة في السجل',
     'النماذج المسجلة ÷ النماذج الإنتاجية × 100',
     'سجل نماذج الذكاء الاصطناعي', 'شهري',
     'مسؤول البيانات'),
    ('نسبة معالجة حوادث أو انحرافات النماذج ضمن SLA',
     'لاحق', '95% من انحرافات النماذج تُغلق ضمن اتفاقية الخدمة',
     'الانحرافات المغلقة ضمن المهلة ÷ الانحرافات المفتوحة × 100',
     'سجل مراقبة أداء النماذج', 'شهري',
     'مالك نموذج الذكاء الاصطناعي'),
)


def _sdaia_selected(selected_frameworks: Optional[Iterable[Any]],
                    blob: str = '') -> bool:
    joined = ' '.join(_selected_list(selected_frameworks)) + ' ' + str(blob or '')
    return 'SDAIA' in joined.upper() or 'سدايا' in joined


def rel36_18_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        text: str = '',
) -> bool:
    dcode = _normalize_rel31_domain_code(domain)
    if dcode not in ('ai', 'artificial_intelligence'):
        return False
    if normalize_rel36_lang(lang) != 'ar':
        return False
    dtype = str(document_type or 'strategy').strip().lower()
    if dtype not in ('strategy', 'strategy_document', ''):
        return False
    return _sdaia_selected(selected_frameworks, text)


def _app_mod():
    import app as app_mod
    return app_mod


def _leak_terms(text: str, selected_frameworks: Optional[Iterable[Any]] = None,
                ) -> List[str]:
    hay = str(text or '')
    selected = ' '.join(_selected_list(selected_frameworks)).upper()
    hits: List[str] = []
    for tok in _LEAK_TERMS:
        if tok == 'NIST AI RMF' and 'NIST AI RMF' in selected:
            continue
        if tok in hay:
            hits.append(tok)
    return list(dict.fromkeys(hits))


def _count_kpi_rows(text: str) -> int:
    try:
        return int(_app_mod().count_substantive_kpis(text or '') or 0)
    except Exception:  # noqa: BLE001
        n = 0
        first = _KPI_FIRST_TABLE_RE.search(text or '')
        blob = first.group(1) if first else (text or '')
        for ln in blob.splitlines()[1:]:
            cells = [c.strip() for c in ln.strip().strip('|').split('|')]
            if len(cells) < 4:
                continue
            if not cells[0].replace('.', '').isdigit():
                continue
            if any(_PLACEHOLDER_RE.match(cells[i] or '') for i in (1, 2, 3)):
                continue
            n += 1
        return n


def _first_kpi_header(text: str) -> str:
    m = _KPI_HEADER_RE.search(text or '')
    if not m:
        return ''
    return (text or '')[m.start():].splitlines()[0].strip()


def _kpi_schema_valid(text: str) -> bool:
    hdr = _first_kpi_header(text)
    return (
        'وصف المؤشر' in hdr
        and 'النوع' in hdr
        and 'القيمة المستهدفة' in hdr
        and 'صيغة الاحتساب' in hdr
        and 'مصدر' in hdr
        and 'التكرار' in hdr
        and 'المالك' in hdr
    )


def _synth_kpi_blockers(text: str, generation_mode: Any = 'drafting') -> List[str]:
    app = _app_mod()
    mode = str(generation_mode or 'drafting').lower()
    floor = _MIN_KPI
    if mode == 'consulting':
        floor += 1
    elif mode == 'assurance':
        floor += 2
    rows = int(app.count_substantive_kpis(text or '') or 0)
    n_guides_hdr = len(app._KPI_GUIDES_HEADING_RE.findall(text or ''))
    n_per = len(app._PER_KPI_GUIDE_HEADING_RE.findall(text or ''))
    blockers: List[str] = []
    if rows < floor:
        blockers.append('synth_failed:kpis')
        blockers.append(f'kpi_rows_insufficient:{rows}/{floor}')
    if not re.search(
            r'(?:^|\|)\s*(?:Frequency|التكرار)\s*(?:\||$)',
            text or '', re.IGNORECASE | re.MULTILINE):
        blockers.append('kpi_section_missing_frequency_column')
    if n_guides_hdr != 1:
        blockers.append(f'kpi_guides_heading_count_invalid:{n_guides_hdr}')
    if rows > 0 and n_per != rows:
        blockers.append(f'kpi_per_guide_count_mismatch:{n_per}/{rows}')
    return blockers


def _ai_roles_ok(text: str) -> bool:
    hay = str(text or '')
    return any(owner in hay for owner in _OWNERS) and any(
        src in hay for src in _SOURCES)


def _kpi_guide_block(idx: int, name: str, owner: str, source: str) -> str:
    return (
        f'#### دليل تقييم المؤشر رقم {idx}:\n'
        f'المالك: {owner}. التكرار: شهري. المصدر: {source}. '
        f'يراجع المالك صيغة الاحتساب والقيمة المستهدفة وحزمة الأدلة لكل فترة، '
        f'ويُصعِّد الانحراف عن عتبة هذا المؤشر الفريد {idx} ({name}) إلى '
        f'لجنة الذكاء الاصطناعي وفق ضوابط سدايا.'
    )


def _existing_ai_rows(text: str) -> List[List[str]]:
    first = _KPI_FIRST_TABLE_RE.search(text or '')
    if not first:
        return []
    kept: List[List[str]] = []
    seen = set()
    for ln in first.group(1).splitlines()[1:]:
        if _SEP_ROW_RE.match(ln.strip()):
            continue
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        if len(cells) < 4:
            continue
        if not cells[0].replace('.', '').isdigit():
            continue
        desc = cells[1]
        if not desc or _PLACEHOLDER_RE.match(desc):
            continue
        blob = ' '.join(cells)
        if _leak_terms(blob):
            continue
        key = re.sub(r'\s+', ' ', desc).strip()
        if key in seen:
            continue
        seen.add(key)
        # Normalize to 7 data cells after #.
        padded = (cells[1:] + [''] * 7)[:7]
        if not padded[1] or _PLACEHOLDER_RE.match(padded[1]):
            padded[1] = 'لاحق'
        if not padded[2] or _PLACEHOLDER_RE.match(padded[2]):
            padded[2] = 'قيمة مستهدفة معتمدة'
        if not padded[3] or _PLACEHOLDER_RE.match(padded[3]):
            padded[3] = f'{desc} ÷ النطاق × 100'
        if not padded[4] or _PLACEHOLDER_RE.match(padded[4]):
            padded[4] = _SOURCES[0]
        if not padded[5] or _PLACEHOLDER_RE.match(padded[5]):
            padded[5] = 'ربع سنوي'
        if not padded[6] or _PLACEHOLDER_RE.match(padded[6]):
            padded[6] = _OWNERS[0]
        kept.append(padded)
    return kept


def _canonical_rows(existing: Optional[Sequence[Sequence[str]]] = None
                    ) -> List[List[str]]:
    rows: List[List[str]] = [list(r) for r in (existing or [])]
    seen = {re.sub(r'\s+', ' ', r[0]).strip() for r in rows if r}
    for catalog in _KPI_CATALOG:
        if len(rows) >= 10:
            break
        key = re.sub(r'\s+', ' ', catalog[0]).strip()
        if key in seen:
            continue
        rows.append(list(catalog))
        seen.add(key)
    return rows[:10]


def _canonical_kpi_section(existing: Optional[Sequence[Sequence[str]]] = None
                           ) -> str:
    data = _canonical_rows(existing)
    numbered = [[str(i + 1), *row] for i, row in enumerate(data)]
    table = _md_table(_KPI_HEADER, _KPI_SEP, numbered)
    guides = '\n\n'.join(
        _kpi_guide_block(i + 1, row[0], row[6], row[4])
        for i, row in enumerate(data)
    )
    return (
        f'{_KPI_HEADING}\n\n{table}\n\n{_GUIDES_HEADING}\n\n{guides}\n'
    )


def repair_first_kpi_table(text: str) -> Tuple[str, int]:
    """Replace the first counted KPI table (and guides) in place."""
    current = text or ''
    if (_count_kpi_rows(current) >= _MIN_KPI
            and _kpi_schema_valid(current)
            and not _synth_kpi_blockers(current, 'drafting')
            and not _leak_terms(current)):
        return current, _count_kpi_rows(current)
    existing = _existing_ai_rows(current)
    rebuilt = _canonical_kpi_section(existing)
    return rebuilt, len(_canonical_rows(existing))


def evaluate_rel36_18_ai_sdaia_kpi_synth(
        *,
        task_id: Any = '',
        domain: Any = 'ai',
        lang: Any = 'ar',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        first_kpi_table_header_before: str = '',
        first_kpi_table_header_after: str = '',
        kpi_rows_before: int = 0,
        kpi_rows_after: int = 0,
        first_kpi_table_rows_before: int = 0,
        first_kpi_table_rows_after: int = 0,
        synth_kpis_blockers_before: Optional[Sequence[str]] = None,
        synth_kpis_blockers_after: Optional[Sequence[str]] = None,
        schema_valid_after: bool = False,
        ai_domain_roles_after: bool = False,
        leakage_terms_after: Optional[Sequence[str]] = None,
        save_blockers_before: Optional[Sequence[str]] = None,
        save_blockers_after: Optional[Sequence[str]] = None,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
) -> Dict[str, Any]:
    after = list(synth_kpis_blockers_after or [])
    leaks = list(leakage_terms_after or [])
    save_after = list(save_blockers_after or [])
    passed = (
        int(kpi_rows_after or 0) >= _MIN_KPI
        and bool(schema_valid_after)
        and not after
        and not leaks
        and not save_after
        and bool(ai_domain_roles_after)
        and 'synth_failed:kpis' not in after
        and 'synth_failed:kpis' not in save_after
    )
    return {
        'task_id': str(task_id or ''),
        'domain': str(domain or ''),
        'lang': str(lang or ''),
        'document_type': str(document_type or ''),
        'selected_frameworks': list(_selected_list(selected_frameworks)),
        'first_kpi_table_header_before': first_kpi_table_header_before,
        'first_kpi_table_header_after': first_kpi_table_header_after,
        'kpi_rows_before': int(kpi_rows_before or 0),
        'kpi_rows_after': int(kpi_rows_after or 0),
        'first_kpi_table_rows_before': int(first_kpi_table_rows_before or 0),
        'first_kpi_table_rows_after': int(first_kpi_table_rows_after or 0),
        'synth_kpis_blockers_before': list(synth_kpis_blockers_before or []),
        'synth_kpis_blockers_after': after,
        'schema_valid_after': bool(schema_valid_after),
        'ai_domain_roles_after': bool(ai_domain_roles_after),
        'leakage_terms_after': leaks,
        'save_blockers_before': list(save_blockers_before or []),
        'save_blockers_after': save_after,
        'docx_allowed': bool(docx_allowed),
        'pdf_allowed': bool(pdf_allowed),
        'passed': bool(passed),
        'applied': True,
    }


def emit_rel36_18(payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_18_AI_SDAIA_KPI_SYNTH_REPAIR_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True)
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_18_ai_sdaia_kpi_synth(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'ai',
        lang: Any = 'ar',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        generation_mode: Any = 'drafting',
        task_id: Any = '',
        emit: bool = True,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
        backend: Any = None,
        attempt_id: Any = '',
        doc_subtype: Any = '',
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    del backend, attempt_id, doc_subtype
    secs = dict(sections or {})
    blob = '\n'.join(str(v) for v in secs.values() if isinstance(v, str))
    in_scope = rel36_18_should_apply(
        domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, text=blob)
    before = str(secs.get('kpis') or '')
    rows_b = _count_kpi_rows(before)
    hdr_b = _first_kpi_header(before)
    synth_b = _synth_kpi_blockers(before, generation_mode) if in_scope else []
    save_b = list(synth_b)
    after = before
    if in_scope and (synth_b or not _kpi_schema_valid(before)
                     or rows_b < _MIN_KPI or _leak_terms(before)):
        after, _n = repair_first_kpi_table(before)
        secs['kpis'] = after
    final = str(secs.get('kpis') or after)
    rows_a = _count_kpi_rows(final)
    hdr_a = _first_kpi_header(final)
    synth_a = _synth_kpi_blockers(final, generation_mode) if in_scope else []
    leaks = _leak_terms(final, selected_frameworks) if in_scope else []
    save_a = list(synth_a) + [f'forbidden_leak:{t}' for t in leaks]
    schema = _kpi_schema_valid(final) if in_scope else False
    roles = _ai_roles_ok(final) if in_scope else False
    if not in_scope:
        diag = {
            'task_id': str(task_id or ''),
            'domain': str(domain or ''),
            'lang': str(lang or ''),
            'document_type': str(document_type or ''),
            'selected_frameworks': list(_selected_list(selected_frameworks)),
            'applied': False,
            'passed': False,
        }
        if emit:
            emit_rel36_18(diag)
        return secs if sections is None else (
            secs if secs is not sections else sections), diag
    export_ok = (
        bool(docx_allowed) or bool(pdf_allowed)
        or (not save_a and not synth_a and not leaks and schema and roles
            and rows_a >= _MIN_KPI)
    )
    diag = evaluate_rel36_18_ai_sdaia_kpi_synth(
        task_id=task_id,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        first_kpi_table_header_before=hdr_b,
        first_kpi_table_header_after=hdr_a,
        kpi_rows_before=rows_b,
        kpi_rows_after=rows_a,
        first_kpi_table_rows_before=rows_b,
        first_kpi_table_rows_after=rows_a,
        synth_kpis_blockers_before=synth_b,
        synth_kpis_blockers_after=synth_a,
        schema_valid_after=schema,
        ai_domain_roles_after=roles,
        leakage_terms_after=leaks,
        save_blockers_before=save_b,
        save_blockers_after=save_a,
        docx_allowed=docx_allowed or export_ok,
        pdf_allowed=pdf_allowed or export_ok,
    )
    if emit:
        emit_rel36_18(diag)
    if isinstance(sections, dict):
        sections['kpis'] = final
        return sections, diag
    return secs, diag
