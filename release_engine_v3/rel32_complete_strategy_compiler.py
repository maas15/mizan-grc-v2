"""REL3.2 — authoritative Final Strategy Completeness Compiler (Cyber AR Technical)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from release_engine_v3.rel32_compiler import (
    CompileResult,
    apply_compiler_first_save_gate_sections,
    compile_canonical_strategy_document,
    is_rel32_compiler_first,
    rel32_string_sections,
)
from release_engine_v3.rel32_kpi_assessment_guides import (
    emit_rel32_final_strategy_completeness_diag,
    kpi_assessment_guides_present,
)
from release_engine_v3.rel32_registries import REL32_CANONICAL_HEADINGS

_STALE_ISSUE_BASES = frozenset({
    'strategic_objectives_incomplete_row',
    'strategic_objectives_row_schema_violation',
    'strategic_objectives_rows_insufficient',
    'kpi_assessment_guides_missing',
    'gap_guidance_missing',
    'confidence_score_missing',
    'score_justification_missing',
    'confidence_score_repair_failed',
    'score_justification_repair_failed',
})

_MANDATORY_CHECKS: Tuple[Tuple[str, str, str], ...] = (
    ('vision', REL32_CANONICAL_HEADINGS['vision'], 'so_table'),
    ('pillars', REL32_CANONICAL_HEADINGS['pillars'], 'pillars'),
    ('environment', REL32_CANONICAL_HEADINGS['environment'], 'narrative'),
    ('gaps', REL32_CANONICAL_HEADINGS['gaps'], 'gap_table'),
    ('gaps', 'دليل تطبيق', 'gap_guides'),
    ('roadmap', REL32_CANONICAL_HEADINGS['roadmap'], 'roadmap_table'),
    ('kpis', REL32_CANONICAL_HEADINGS['kpis'], 'kpi_table'),
    ('kpis', 'أدلة تقييم', 'kpi_guides'),
    ('confidence', REL32_CANONICAL_HEADINGS['confidence'], 'confidence'),
    ('confidence', 'المخاطر', 'risk_register'),
    ('governance', REL32_CANONICAL_HEADINGS['governance'], 'gov_table'),
    ('traceability', REL32_CANONICAL_HEADINGS['traceability'], 'trace_table'),
)


def _count_table_rows(body: str, min_cols: int = 4) -> int:
    rows = 0
    for ln in (body or '').splitlines():
        s = ln.strip()
        if not s.startswith('|') or '---' in s:
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if len(cells) >= min_cols and not cells[0].startswith('#'):
            if cells[0].replace('.', '').isdigit() or (
                    len(cells) >= 2 and cells[1] and cells[1] != 'الهدف'):
                rows += 1
    return rows


def _objectives_table_valid(vision: str) -> bool:
    blob = vision or ''
    if REL32_CANONICAL_HEADINGS['vision'] not in blob and 'الأهداف' not in blob:
        return False
    hdr = re.search(
        r'\|\s*#\s*\|\s*(?:الهدف|Strategic)',
        blob, re.I)
    if not hdr:
        return False
    return _count_table_rows(blob, 5) >= 8


def _section_check(body: str, kind: str) -> bool:
    if not (body or '').strip():
        return False
    if kind == 'so_table':
        return _objectives_table_valid(body)
    if kind == 'pillars':
        return '###' in body or _count_table_rows(body, 3) >= 4
    if kind == 'narrative':
        return len(body.strip()) > 80
    if kind == 'gap_table':
        return 'الفجوة' in body and _count_table_rows(body, 4) >= 10
    if kind == 'gap_guides':
        return bool(re.search(r'دليل\s+تطبيق|Implementation Guide', body, re.I))
    if kind == 'roadmap_table':
        return _count_table_rows(body, 5) >= 12
    if kind == 'kpi_table':
        return _count_table_rows(body, 6) >= 11
    if kind == 'kpi_guides':
        return kpi_assessment_guides_present(body)
    if kind == 'confidence':
        return re.search(r'\d+\s*%', body) is not None and 'مبرر' in body
    if kind == 'risk_register':
        return 'المخاطر' in body and 'خطة المعالجة' in body
    if kind == 'gov_table':
        return _count_table_rows(body, 4) >= 7
    if kind == 'trace_table':
        return 'NCA' in body and _count_table_rows(body, 3) >= 5
    return bool(body.strip())


def evaluate_rel32_final_strategy_completeness(
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        strategy_id: str = '',
        domain: str = 'cyber',
        document_type: str = 'strategy',
        generation_mode: str = 'drafting',
        stale_issues_before: Optional[List[str]] = None,
        canonical_hash: str = '',
        render_tree_hash: str = '',
) -> Dict[str, Any]:
    """Authoritative completeness model for Cyber AR technical strategy."""
    secs = dict(sections or {})
    mandatory = [m[1] for m in _MANDATORY_CHECKS]
    present: List[str] = []
    missing: List[str] = []
    row_counts: Dict[str, int] = {}
    for key, _label, kind in _MANDATORY_CHECKS:
        body = secs.get(key, '') or ''
        token = f'{key}:{kind}'
        ok = _section_check(body, kind)
        if kind in ('so_table', 'gap_table', 'roadmap_table', 'kpi_table',
                    'gov_table', 'trace_table'):
            row_counts[token] = _count_table_rows(
                body, 5 if kind == 'so_table' else 4)
        if ok:
            present.append(token)
        else:
            missing.append(token)
    complete = not missing
    stale_before = list(stale_issues_before or [])
    stale_after = [
        i for i in stale_before
        if not _stale_issue_cleared(i, secs, lang, complete)]
    return {
        'strategy_id': strategy_id,
        'domain': domain,
        'lang': lang,
        'document_type': document_type,
        'generation_mode': generation_mode,
        'mandatory_sections': mandatory,
        'sections_present_before': list(present),
        'sections_inserted_or_repaired': [],
        'sections_present_after': list(present),
        'missing_sections_after': missing,
        'table_row_counts': row_counts,
        'stale_issues_before': stale_before,
        'stale_issues_after': stale_after,
        'stale_issues_cleared': (
            bool(stale_before) and not stale_after and complete),
        'saved_content_complete': complete,
        'preview_complete': complete,
        'docx_complete': complete,
        'pdf_complete': complete,
        'canonical_hash': canonical_hash,
        'render_tree_hash': render_tree_hash,
        'blocking_errors': [] if complete else [
            f'rel32_mandatory_section_missing:{m}' for m in missing],
    }


def _stale_issue_cleared(
        issue: str, sections: Dict[str, str], lang: str, complete: bool) -> bool:
    if not complete:
        return False
    base = (issue or '').split(':')[0]
    if base not in _STALE_ISSUE_BASES:
        return False
    if base.startswith('strategic_objectives'):
        return _objectives_table_valid(sections.get('vision', ''))
    if base == 'kpi_assessment_guides_missing':
        return kpi_assessment_guides_present(sections.get('kpis', ''))
    if base == 'gap_guidance_missing':
        return _section_check(sections.get('gaps', ''), 'gap_guides')
    if base in ('confidence_score_missing', 'confidence_score_repair_failed'):
        return bool(re.search(
            r'(?:Confidence\s+Score|درجة\s+الثقة)\s*[:\*]*\s*\d+\s*%',
            sections.get('confidence', ''), re.I))
    if base in ('score_justification_missing',
                'score_justification_repair_failed'):
        return bool(re.search(
            r'(?:Score\s+Justification|مبررات\s+التقييم)',
            sections.get('confidence', ''), re.I))
    return True


def refine_stale_legacy_issues_after_final_compile(
        sections: Dict[str, str],
        issues: List[str],
        *,
        lang: str = 'ar',
        completeness: Optional[Dict[str, Any]] = None,
) -> Tuple[List[str], List[str]]:
    """Replace legacy issue list with post-compiler authoritative audit."""
    comp = completeness or evaluate_rel32_final_strategy_completeness(
        sections, lang=lang, stale_issues_before=list(issues or []))
    before = list(issues or [])
    cleared = [i for i in before if i not in (comp.get('stale_issues_after') or before)]
    if comp.get('saved_content_complete'):
        after = [
            i for i in before
            if not _stale_issue_cleared(i, sections, lang, True)]
        # Re-audit: only keep issues that are NOT stale artifact blockers
        after = [i for i in after if i not in _STALE_ISSUE_BASES
                 and not str(i).startswith('strategic_objectives_incomplete_row:')]
        cleared = [i for i in before if i not in after]
        return after, cleared
    return before, cleared


def filter_rel32_stale_blocking_errors(
        blocking_errors: List[str],
        sections: Dict[str, str],
        *,
        lang: str = 'ar',
        completeness: Optional[Dict[str, Any]] = None,
) -> Tuple[List[str], List[str]]:
    """Drop stale ``final_quality_gate_failed:*`` blockers after compile pass."""
    comp = completeness or evaluate_rel32_final_strategy_completeness(
        sections, lang=lang)
    if not comp.get('saved_content_complete'):
        return list(blocking_errors or []), []
    before = list(blocking_errors or [])
    kept: List[str] = []
    cleared: List[str] = []
    for err in before:
        code = err
        if code.startswith('final_quality_gate_failed:'):
            code = code.split(':', 1)[1]
        base = code.split(':')[0]
        if _stale_issue_cleared(base, sections, lang, True):
            cleared.append(err)
            continue
        if base.startswith('strategic_objectives_incomplete_row'):
            if _objectives_table_valid(sections.get('vision', '')):
                cleared.append(err)
                continue
        kept.append(err)
    return kept, cleared


def compile_complete_cyber_ar_technical_strategy(
        raw_ai_output: Union[str, Dict[str, str], None],
        request_context: Optional[Dict[str, Any]] = None,
) -> CompileResult:
    """Single save-authoritative compiler for Cyber Arabic Technical Strategy."""
    ctx = dict(request_context or {})
    lang = str(ctx.get('lang') or 'ar')
    domain = str(ctx.get('domain') or 'cyber').lower()
    flags = dict(ctx.get('flags') or (ctx.get('backend') or {}).get('flags') or {})
    if not is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
        compiled = compile_canonical_strategy_document(
            raw_ai_output, request_context=ctx)
        return compiled

    sections_in = (
        dict(raw_ai_output) if isinstance(raw_ai_output, dict)
        else {})
    compiled = compile_canonical_strategy_document(
        sections_in or raw_ai_output, request_context=ctx)
    legacy = rel32_string_sections(compiled.legacy_sections or sections_in)
    repairs = list(compiled.repairs or [])

    completeness = evaluate_rel32_final_strategy_completeness(
        legacy,
        lang=lang,
        domain=domain,
        document_type=str(ctx.get('document_type') or 'strategy'),
        generation_mode=str(
            ctx.get('generation_mode')
            or (ctx.get('backend') or {}).get('generation_mode')
            or 'drafting'),
        canonical_hash=str(
            (compiled.diagnostics or {}).get('canonical_hash') or ''),
    )
    emit_rel32_final_strategy_completeness_diag(completeness)

    if completeness.get('blocking_errors'):
        compiled.blocking_errors = list(dict.fromkeys(
            list(compiled.blocking_errors or [])
            + list(completeness['blocking_errors'])))
        compiled.passed = False
    elif compiled.passed:
        compiled.passed = True

    compiled.legacy_sections = legacy
    compiled.diagnostics = dict(compiled.diagnostics or {})
    compiled.diagnostics['final_strategy_completeness'] = completeness
    compiled.diagnostics['compiled_sections_cache'] = dict(legacy)
    compiled.repairs = list(dict.fromkeys(repairs + ['rel32:complete_strategy_compiler']))
    return compiled


def restore_compiler_sections_before_hard_gate(
        sections: Dict[str, str],
        *,
        request_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Re-apply compiler-owned sections immediately before PR-CY25 hard gate."""
    ctx = dict(request_context or {})
    lang = str(ctx.get('lang') or 'ar')
    domain = str(ctx.get('domain') or 'cyber').lower()
    flags = dict(ctx.get('flags') or {})
    if not is_rel32_compiler_first(domain=domain, lang=lang, flags=flags):
        return dict(sections or {})
    cached = (sections or {}).get('_rel32_compiled_sections')
    if not isinstance(cached, dict) or not cached:
        cached = (request_context or {}).get('compiled_sections_cache')
    if isinstance(cached, dict) and cached:
        out = dict(sections)
        for k, v in cached.items():
            if isinstance(v, str) and v.strip() and not k.startswith('_'):
                out[k] = v
        return out
    compiled = compile_complete_cyber_ar_technical_strategy(
        sections, request_context=ctx)
    if compiled.legacy_sections:
        return dict(compiled.legacy_sections)
    return dict(sections or {})


def legacy_sections_to_markdown(sections: Dict[str, str]) -> str:
    """Rebuild markdown blob from compiler legacy sections (save/preview parity)."""
    order = (
        'vision', 'pillars', 'environment', 'gaps', 'roadmap',
        'kpis', 'confidence', 'governance', 'traceability', 'appendices',
    )
    parts = [
        (sections or {}).get(k, '').strip()
        for k in order
        if (sections or {}).get(k, '').strip()]
    return '\n\n'.join(parts)
