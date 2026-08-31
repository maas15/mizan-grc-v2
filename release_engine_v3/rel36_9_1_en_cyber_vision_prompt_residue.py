"""REL36.9.1 — English Cyber ECC+DCC vision prompt-residue repair.

Staging Attempt 3 on PR #123 (task ``bac5632f-bc5a-42e4-84d4-956ea01bea3b``)
failed before save with:

    vision_contains_prompt_residue

That tag is emitted only by ``detect_arabic_prompt_residue`` after
``_apply_final_synthesis_pass`` / ``synthesize_objectives_depth`` can
rewrite the vision section. ``sanitize_arabic_prompt_residue`` uses the
same patterns but runs *before* those writers, so English Cyber has no
post-synthesis cleanup. This module removes prompt/meta residue from the
vision/objectives section and rebuilds a weak vision paragraph when
needed. It does not mark the gate passed and does not change the
detector.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _selected_list,
    rel36_8_should_apply,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_9_1_EN_CYBER_VISION_PROMPT_RESIDUE_TAG = (
    '[REL36.9.1-EN-CYBER-VISION-PROMPT-RESIDUE-REPAIR]')

CANONICAL_EN_CYBER_VISION = (
    'Establish a resilient, risk-based cybersecurity capability aligned '
    'with NCA ECC and NCA DCC, enabling secure digital services, protected '
    'sensitive data, effective detection and response, and sustainable '
    'compliance.'
)

MIN_OBJECTIVE_ROWS = 4
WEAK_VISION_CHARS = 80

# Fallback copy of app._PROMPT_RESIDUE_PATTERNS so this module can run
# without importing app. apply() prefers the live compiled list.
_FALLBACK_PROMPT_RESIDUE_PATTERNS = [
    r'(?i)^.*\b(?:write|draft|compose|produce|generate)\s+(?:the\s+following|two|three|\d+)\s+(?:paragraphs?|sentences?|sections?|lines?)\b[^\n]*\n?',
    r'(?i)^.*\b(?:please\s+)?(?:include|ensure|make\s+sure)\s+(?:at\s+least|that\s+the\s+following|each|every)\b[^\n]*\n?',
    r'(?i)^\[\s*(?:insert|add|provide|include|write|note|fill|describe|specify|detail)[^\]]*\]\s*\n?',
    r'(?i)^<[^<>\n]*(?:insert|placeholder|instruction|example|template)[^<>\n]*>\s*\n?',
    r'(?i)^\(\s*(?:insert|add|describe|note|placeholder|to be)\s+[^)]*\)\s*\n?',
    r'(?i)^.*\b(?:as\s+an?\s+(?:AI|assistant|model)|do\s+not\s+include|avoid\s+mentioning)\b[^\n]*\n?',
    r'(?i)^.*\b(?:note\s+(?:to|for)\s+(?:the\s+)?(?:model|editor|reviewer|draft(?:er)?|writer)|reminder\s+(?:to|for)\s+(?:the\s+)?(?:model|editor))\s*:[^\n]*\n?',
    r'(?i)^.*\b(?:here\s+is|below\s+is|following\s+is)\s+(?:a|the)\s+(?:draft|template|example|placeholder)\b[^\n]*\n?',
    r'^.*\b(?:اكتب|حرّر|حرر|قدّم|قدم|استخرج)\s+(?:فقرتين|ثلاث\s+فقرات|فقرة|\d+\s+فقرات?)\b[^\n]*\n?',
    r'^\[[^\]]{0,50}(?:أدخل|ضع|اكتب|أضف|مثال|قالب)[^\]]*\]\s*\n?',
    r'^\(\s*(?:أدخل|ضع|اكتب|أضف|ملاحظة|قالب|توضيح)\s+[^)]*\)\s*\n?',
    r'^.*\bملاحظة\s+(?:للنموذج|للمحرر|داخلية)\b[^\n]*\n?',
    r'^.*\b(?:تأكد\s+من\s+تضمين|يرجى\s+تضمين|يجب\s+أن\s+تحتوي)\b[^\n]*\n?',
    r'^\s*(?:TBD|TODO|FIXME|XXX|\[TBD\]|\[TODO\])[:\s]?[^\n]*\n?',
    r'^\s*\[PLACEHOLDER(?:[^\]]*)\]\s*\n?',
    r'^\s*\[\[.*?\]\]\s*\n?',
    r'(?i)^\s*(?:System|Tool|User|Assistant|Human|Model)\s*(?:/\s*(?:System|Tool|User|Assistant|Human|Model))?\s*:[^\n]*\n?',
    r'(?i)^\s*<\|?\s*(?:system|tool|user|assistant|endoftext|im_start|im_end)\s*\|?>\s*\n?',
    r'(?i)^\s*```(?:system|tool|prompt|instruction)\s*\n(?:.|\n)*?^```\s*\n?',
    r'(?i)^\s*(?:Output|Response|Answer|Prompt|Instruction)\s*:\s*$',
]

# Conversational / scaffolding lines that leaked into Attempt-class English
# Cyber visions even when the gate's "Here is a draft" pattern is narrower.
_EXTRA_LINE_PATTERNS = [
    r'(?i)^\s*(?:here|below|following)\s+is\b[^\n]*\n?',
    r'(?i)^\s*as\s+requested\b[^\n]*\n?',
    r'(?i)^\s*i\s+will\s+(?:now\s+)?(?:generate|draft|write|create|prepare|produce|compose|output)\b[^\n]*\n?',
    r'(?i)^\s*(?:sure|certainly|of\s+course|absolutely)[,!]?\s+[^\n]*\n?',
    r'(?i)^\s*(?:i\s+have\s+(?:created|prepared|drafted|generated|written)|this\s+is\s+(?:a|the)\s+(?:draft|placeholder|template|example))\b[^\n]*\n?',
    r'(?i)^\s*the\s+following\s+strategy\b[^\n]*\n?',
    r'(?i)^\s*(?:draft|placeholder|template)\s+(?:strategy|vision|output|section)\b[^\n]*\n?',
]

_PHRASE_REWRITES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'(?i)\bplease\s+include\b'), 'include'),
    (re.compile(r'(?i)\bensure\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\bmake\s+sure\s+that\s+the\s+following\b'), 'establish'),
    (re.compile(r'(?i)\binclude\s+at\s+least\b'), 'include'),
    (re.compile(r'(?i)\bmake\s+sure\s+each\b'), 'cover each'),
    (re.compile(r'(?i)\bmake\s+sure\s+every\b'), 'cover every'),
    (re.compile(r'(?i)\bhere\s+is\s+(?:a|the)\s+(?:draft|template|example|placeholder)\b[^.|\n]*[.:]?'), ''),
    (re.compile(r'(?i)\bbelow\s+is\s+(?:a|the)\s+(?:draft|template|example|placeholder)\b[^.|\n]*[.:]?'), ''),
    (re.compile(r'(?i)\bas\s+requested[,:]?\s*'), ''),
    (re.compile(r'(?i)\bas\s+an?\s+(?:AI|assistant|model)\b[^.|\n]*[.:]?'), ''),
    (re.compile(r'(?i)\bdo\s+not\s+include\b'), 'exclude'),
    (re.compile(r'(?i)\bavoid\s+mentioning\b'), ''),
    (re.compile(r'(?i)\bnote\s+(?:to|for)\s+(?:the\s+)?(?:model|editor|reviewer|draft(?:er)?|writer)\s*:[^.|\n]*[.:]?'), ''),
    (re.compile(r'(?i)\b(?:write|draft|compose|produce|generate)\s+(?:the\s+following|two|three|\d+)\s+(?:paragraphs?|sentences?|sections?|lines?)\b[^.|\n]*[.:]?'), ''),
    (re.compile(r'(?i)^\s*(?:here|below|following)\s+is(?:\s+(?:a|the))?(?:\s+\w+){0,10}\s*[:.\-–—]\s*'), ''),
    (re.compile(r'(?i)\bthe\s+following\s+strategy\b'), 'this strategy'),
)

_COMMENT_RE = re.compile(r'<!--.*?-->', re.DOTALL)
_MD_COMMENT_RE = re.compile(r'^\[//\]:[^\n]*\n?', re.MULTILINE)
_FENCE_RE = re.compile(
    r'```(?:system|tool|prompt|instruction|json|xml)[\s\S]*?```',
    re.IGNORECASE,
)
_CHAT_TOKEN_RE = re.compile(
    r'<\|?\s*(?:system|tool|user|assistant|endoftext|im_start|im_end)\s*\|?>',
    re.IGNORECASE,
)
_JSON_SCAFFOLD_RE = re.compile(
    r'^\s*[\{\[]\s*"(?:role|system|user|content|instruction|prompt)"'
    r'[\s\S]{0,800}?[\]\}]\s*$',
    re.MULTILINE,
)
_SEP_ROW_RE = re.compile(r'^\|[\s:\-|]+\|\s*$')
_HEADER_CELL_RE = re.compile(
    r'(?i)^(?:#|no\.?|id|strategic objective|objective|rationale|'
    r'target(?:\s+metric)?|justification|timeframe|indicator|'
    r'الهدف(?:\s+الاستراتيجي)?|المبرر|الإطار الزمني)$'
)
_SUBSTANCE_RE = re.compile(
    r'(?i)\b(?:cyber|security|resilien|nca|ecc|dcc|protect|detect|'
    r'complian|risk-based|digital service|sensitive data)\b'
)
_OBJECTIVES_HEADING_RE = re.compile(
    r'(?i)^#{1,4}\s*(?:\d+\.\s*)?(?:strategic\s+objectives?|objectives?|الأهداف)'
)
_VISION_HEADING_RE = re.compile(
    r'(?i)^#{1,4}\s*(?:\d+\.\s*)?(?:vision(?:\s+and\s+strategic\s+objectives?)?|'
    r'الرؤية)'
)


def rel36_9_1_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        text: str = '',
) -> bool:
    return rel36_8_should_apply(
        domain=domain, lang=lang, document_type=document_type,
        selected_frameworks=selected_frameworks, pillars_text=text)


def _prompt_residue_compiled() -> List[re.Pattern[str]]:
    try:
        import app as _app
        compiled = getattr(_app, '_PROMPT_RESIDUE_COMPILED', None)
        if compiled:
            return list(compiled)
    except Exception:  # noqa: BLE001
        pass
    return [re.compile(p, re.MULTILINE) for p in _FALLBACK_PROMPT_RESIDUE_PATTERNS]


def _extra_line_compiled() -> List[re.Pattern[str]]:
    return [re.compile(p, re.MULTILINE) for p in _EXTRA_LINE_PATTERNS]


def collect_residue_tokens(text: str) -> List[str]:
    """Return unique excerpts matching the live prompt-residue gate."""
    hits: List[str] = []
    seen = set()
    for rx in _prompt_residue_compiled():
        for m in rx.finditer(text or ''):
            excerpt = (m.group(0) or '').strip()
            excerpt = re.sub(r'\s+', ' ', excerpt)[:80]
            if excerpt and excerpt not in seen:
                seen.add(excerpt)
                hits.append(excerpt)
    return hits


def _vision_gate_tags(sections: Dict[str, Any]) -> List[str]:
    staged = {'vision': str((sections or {}).get('vision') or '')}
    try:
        import app as _app
        defects = _app.detect_arabic_prompt_residue(staged, 'en')
        return [str(t) for t, _ in (defects or []) if str(t).startswith('vision_')]
    except Exception:  # noqa: BLE001
        return (
            ['vision_contains_prompt_residue']
            if collect_residue_tokens(staged['vision']) else []
        )


def count_objective_table_rows(text: str) -> int:
    count = 0
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped.startswith('|') or _SEP_ROW_RE.match(stripped):
            continue
        cells = [c.strip() for c in stripped.strip('|').split('|')]
        if not cells:
            continue
        first = cells[0].strip().rstrip('.')
        if _HEADER_CELL_RE.match(first) or first == '':
            continue
        if any(_HEADER_CELL_RE.match(c) for c in cells[1:3]) and not first.isdigit():
            joined = ' '.join(cells).lower()
            if 'objective' in joined or 'الهدف' in joined:
                continue
        count += 1
    return count


def _strip_scaffolding(text: str) -> Tuple[str, bool]:
    orig = text or ''
    out = _COMMENT_RE.sub('', orig)
    out = _MD_COMMENT_RE.sub('', out)
    out = _FENCE_RE.sub('', out)
    out = _CHAT_TOKEN_RE.sub('', out)
    out = _JSON_SCAFFOLD_RE.sub('', out)
    return out, out != orig


def _is_table_line(line: str) -> bool:
    return line.strip().startswith('|')


def _rewrite_phrases(line: str) -> str:
    out = line
    for rx, repl in _PHRASE_REWRITES:
        out = rx.sub(repl, out)
    out = re.sub(r'[ \t]{2,}', ' ', out)
    out = re.sub(r'\s+([,.;:])', r'\1', out)
    return out.strip() if not _is_table_line(line) else out.rstrip()


def _line_matches(line: str, compiled: Sequence[re.Pattern[str]]) -> bool:
    blob = line if line.endswith('\n') else line + '\n'
    return any(rx.search(blob) for rx in compiled)


def _clean_non_table_line(
        line: str,
        gate_rx: Sequence[re.Pattern[str]],
        extra_rx: Sequence[re.Pattern[str]],
) -> Optional[str]:
    stripped = line.strip()
    if not stripped:
        return ''
    if _line_matches(line, extra_rx) or _line_matches(line, gate_rx):
        rewritten = _rewrite_phrases(stripped)
        if not rewritten or _line_matches(rewritten, gate_rx) or _line_matches(
                rewritten, extra_rx):
            return None
        return rewritten
    rewritten = _rewrite_phrases(stripped)
    if rewritten and not _line_matches(rewritten, gate_rx):
        return rewritten
    if _line_matches(rewritten or stripped, gate_rx):
        return None
    return rewritten


def _clean_table_line(
        line: str,
        gate_rx: Sequence[re.Pattern[str]],
) -> Optional[str]:
    if _SEP_ROW_RE.match(line.strip()):
        return line.rstrip()
    rewritten = _rewrite_phrases(line)
    if not _line_matches(rewritten, gate_rx):
        return rewritten.rstrip()
    # Last resort: drop only the matched span, keep the row structure.
    blob = rewritten if rewritten.endswith('\n') else rewritten + '\n'
    for rx in gate_rx:
        blob, n = rx.subn('', blob)
        if n:
            rewritten = blob.rstrip('\n')
    rewritten = _rewrite_phrases(rewritten)
    if not rewritten.strip().startswith('|'):
        return line.rstrip()
    if _line_matches(rewritten, gate_rx):
        return line.rstrip()
    return rewritten.rstrip()


def _prose_is_weak(prose_lines: Sequence[str]) -> bool:
    blob = '\n'.join(
        ln for ln in prose_lines
        if ln.strip() and not ln.strip().startswith('#')
    ).strip()
    if len(blob) < WEAK_VISION_CHARS:
        return True
    return not bool(_SUBSTANCE_RE.search(blob))


def repair_english_cyber_vision_prompt_residue(
        text: str,
) -> Tuple[str, Dict[str, Any]]:
    """Clean prompt/meta residue from an English Cyber vision section."""
    original = text or ''
    gate_rx = _prompt_residue_compiled()
    extra_rx = _extra_line_compiled()
    tokens_before = collect_residue_tokens(original)
    rows_before = count_objective_table_rows(original)

    cleaned, scaffold_removed = _strip_scaffolding(original)
    heading_lines: List[str] = []
    prose_lines: List[str] = []
    table_lines: List[str] = []
    in_table = False
    cleanup_applied = scaffold_removed or bool(tokens_before)

    for line in cleaned.splitlines():
        stripped = line.strip()
        if _is_table_line(line):
            in_table = True
            kept = _clean_table_line(line, gate_rx)
            if kept is not None:
                table_lines.append(kept)
                if kept != line.rstrip():
                    cleanup_applied = True
            else:
                cleanup_applied = True
            continue
        if in_table and stripped == '':
            table_lines.append('')
            continue
        if in_table and stripped:
            in_table = False
        if _VISION_HEADING_RE.match(stripped):
            heading_lines.append(stripped)
            continue
        if _OBJECTIVES_HEADING_RE.match(stripped):
            table_lines.append(stripped)
            continue
        kept = _clean_non_table_line(line, gate_rx, extra_rx)
        if kept is None:
            cleanup_applied = True
            continue
        if kept != stripped:
            cleanup_applied = True
        if kept == '' and not prose_lines:
            continue
        prose_lines.append(kept)

    while prose_lines and prose_lines[-1] == '':
        prose_lines.pop()
    while table_lines and table_lines[-1] == '':
        table_lines.pop()

    vision_rebuilt = False
    if _prose_is_weak(prose_lines):
        prose_lines = [CANONICAL_EN_CYBER_VISION]
        vision_rebuilt = True
        cleanup_applied = True

    parts: List[str] = []
    if heading_lines:
        parts.append('\n'.join(heading_lines))
    if prose_lines:
        parts.append('\n\n'.join(ln for ln in prose_lines if ln.strip()))
    if table_lines:
        # Keep a Strategic Objectives heading when a table survived
        # without one.
        table_blob = '\n'.join(table_lines).strip()
        if table_blob.startswith('|') and not any(
                _OBJECTIVES_HEADING_RE.match(ln.strip())
                for ln in heading_lines + table_lines):
            table_blob = '### Strategic Objectives\n\n' + table_blob
        parts.append(table_blob)

    repaired = '\n\n'.join(p for p in parts if p).strip() + '\n'
    # Collapse leftover blank runs.
    repaired = re.sub(r'\n{3,}', '\n\n', repaired)
    tokens_after = collect_residue_tokens(repaired)
    if tokens_after:
        # Final fail-closed rebuild of prose only; keep the table.
        table_only = '\n'.join(table_lines).strip()
        rebuilt_parts = [CANONICAL_EN_CYBER_VISION]
        if table_only:
            rebuilt_parts.append(table_only)
        repaired = '\n\n'.join(rebuilt_parts).strip() + '\n'
        vision_rebuilt = True
        cleanup_applied = True
        tokens_after = collect_residue_tokens(repaired)

    rows_after = count_objective_table_rows(repaired)
    return repaired, {
        'residue_tokens_before': tokens_before,
        'residue_tokens_after': tokens_after,
        'vision_chars_before': len(original),
        'vision_chars_after': len(repaired),
        'objectives_rows_before': rows_before,
        'objectives_rows_after': rows_after,
        'vision_rebuilt': vision_rebuilt,
        'cleanup_applied': cleanup_applied,
    }


def evaluate_rel36_9_1_en_cyber_vision_prompt_residue(
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Any = '',
        residue_tokens_before: Optional[List[str]] = None,
        residue_tokens_after: Optional[List[str]] = None,
        vision_chars_before: int = 0,
        vision_chars_after: int = 0,
        objectives_rows_before: int = 0,
        objectives_rows_after: int = 0,
        vision_rebuilt: bool = False,
        cleanup_applied: bool = False,
        vision_gate_before: Optional[List[str]] = None,
        vision_gate_after: Optional[List[str]] = None,
        blocking_errors_before: Optional[List[str]] = None,
        blocking_errors_after: Optional[List[str]] = None,
) -> Dict[str, Any]:
    tokens_after = list(residue_tokens_after or [])
    gate_after = list(vision_gate_after or [])
    blockers_after = list(blocking_errors_after or [])
    rows_after = int(objectives_rows_after or 0)
    rows_before = int(objectives_rows_before or 0)
    rows_ok = rows_after >= rows_before or rows_after >= MIN_OBJECTIVE_ROWS
    passed = (
        tokens_after == []
        and gate_after == []
        and blockers_after == []
        and rows_ok
    )
    return {
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'task_id': str(task_id or ''),
        'residue_tokens_before': list(residue_tokens_before or []),
        'residue_tokens_after': tokens_after,
        'vision_chars_before': int(vision_chars_before or 0),
        'vision_chars_after': int(vision_chars_after or 0),
        'objectives_rows_before': rows_before,
        'objectives_rows_after': rows_after,
        'vision_rebuilt': bool(vision_rebuilt),
        'cleanup_applied': bool(cleanup_applied),
        'vision_gate_before': list(vision_gate_before or []),
        'vision_gate_after': gate_after,
        'blocking_errors_before': list(blocking_errors_before or []),
        'blocking_errors_after': blockers_after,
        'passed': passed,
        'applied': True,
    }


def emit_rel36_9_1_en_cyber_vision_prompt_residue(
        payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_9_1_EN_CYBER_VISION_PROMPT_RESIDUE_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_9_1_en_cyber_vision_prompt_residue(
        sections: Dict[str, Any],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        task_id: Any = None,
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    out = dict(sections or {})
    blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
    if not rel36_9_1_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks, text=blob):
        return sections, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'blocking_errors_after': [],
            'residue_tokens_after': [],
            'vision_gate_after': [],
        }

    vision_before = str(out.get('vision') or '')
    gate_before = _vision_gate_tags({'vision': vision_before})
    blockers_before = list(gate_before)
    repaired, stats = repair_english_cyber_vision_prompt_residue(vision_before)
    out['vision'] = repaired
    gate_after = _vision_gate_tags(out)
    tokens_after = list(stats.get('residue_tokens_after') or [])
    if gate_after:
        tokens_after = tokens_after or collect_residue_tokens(repaired)
    blockers_after = list(gate_after)
    diag = evaluate_rel36_9_1_en_cyber_vision_prompt_residue(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        task_id=task_id,
        residue_tokens_before=stats.get('residue_tokens_before') or [],
        residue_tokens_after=tokens_after,
        vision_chars_before=stats.get('vision_chars_before') or 0,
        vision_chars_after=stats.get('vision_chars_after') or 0,
        objectives_rows_before=stats.get('objectives_rows_before') or 0,
        objectives_rows_after=stats.get('objectives_rows_after') or 0,
        vision_rebuilt=bool(stats.get('vision_rebuilt')),
        cleanup_applied=bool(stats.get('cleanup_applied')),
        vision_gate_before=gate_before,
        vision_gate_after=gate_after,
        blocking_errors_before=blockers_before,
        blocking_errors_after=blockers_after,
    )
    if emit:
        emit_rel36_9_1_en_cyber_vision_prompt_residue(diag)
    return out, diag
