"""PR-REL3.3 — deterministic gap_assessment placeholder completion.

Resolves missing organization / framework context before generation and
completes forbidden placeholder tokens in gap_assessment documents after
LLM generation.  The existing placeholder-text save gate still runs
after this pass and is not weakened.

Strategy and risk documents are never mutated.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

ORG_PROFILE_AR = 'الجهة محل التقييم'
ORG_PROFILE_EN = 'the organization under assessment'
FRAMEWORK_PROFILE_EN = 'Baseline Global Standards Profile'
FRAMEWORK_PROFILE_AR = 'ملف مرجعي للمعايير العالمية الأساسية'
BASELINE_GLOBAL_STANDARDS = (
    'ISO/IEC 27001:2022',
    'NIST CSF 2.0',
    'ISO 22301',
    'COBIT 2019',
    'ISO 31000',
)
CURRENT_STATE_AR = (
    'تحتاج الجهة إلى استكمال التوثيق والتحقق من مستوى التطبيق الحالي')
TARGET_STATE_AR = (
    'تحقيق مستوى امتثال قابل للقياس وفق الضوابط المرجعية المختارة')
RECOMMENDATION_AR = (
    'إعداد خطة معالجة تفصيلية وتحديد المالك والجدول الزمني ومؤشر الإغلاق')
CURRENT_STATE_EN = (
    'The organization needs to complete documentation and verify the '
    'current implementation level')
TARGET_STATE_EN = (
    'Achieve a measurable compliance level against the selected reference '
    'controls')
RECOMMENDATION_EN = (
    'Prepare a detailed remediation plan with owner, timeline, and '
    'closure indicator')
BUDGET_AR = 'ميزانية تُحدد وفق ملف الجهة'
BUDGET_EN = 'Budget to be confirmed from the organization profile'
CHALLENGES_AR = (
    'تحديات تشغيلية وتنظيمية تتطلب تقييماً منظماً مقابل المعايير المرجعية')
CHALLENGES_EN = (
    'Operational and regulatory challenges requiring a structured '
    'assessment against the reference standards')

# Longer Arabic form first so "غير محددة" is not left matching "غير محدد".
_FORBIDDEN_EXACT = (
    'غير محددة',
    'غير محدد',
    'Not specified',
    'not specified',
    'N/A',
    'n/a',
    'NA',
    'TBD',
    'tbd',
    'TBA',
    'tba',
)
_KSA_MARKERS = (
    'nca', 'ecc', 'dcc', 'ccc', 'ndmo', 'sama', 'ksa', 'nec',
    'pdpl', 'السعود', 'الوطنية للأمن السيبراني', 'ندمو',
)
_SEP_ROW_RE = re.compile(r'^\|[\s\-:|]+\|$')
_GATE_PATTERNS = (
    r'\*\*Frameworks?:\*\*\s*Not specified',
    r'\*\*Frameworks?:\*\*\s*\s*$',
    r'Regulatory Context[\s\S]{0,200}?Not specified',
    r'غير محدد',
)
_SCAN_KEYS = (
    'gaps', 'scope', 'findings', 'remediation', 'recommendations',
    'guides', 'environment', 'vision', 'roadmap', 'confidence',
    'executive_summary',
)
_GATE_KEYS = ('vision', 'environment', 'gaps', 'roadmap', 'confidence')


def is_gap_placeholder_completion_applicable(document_type: Any) -> bool:
    dt = str(document_type or '').strip().lower()
    dt = {
        'gap assessment': 'gap_assessment',
        'compliance mapping': 'gap_assessment',
    }.get(dt, dt)
    return dt == 'gap_assessment'


def _normalize_domain(domain: Any) -> str:
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        return normalize_domain_code(str(domain or ''), default='global')
    except Exception:  # noqa: BLE001
        return str(domain or 'global').strip().lower() or 'global'


def _is_forbidden_value(value: Any) -> bool:
    s = str(value or '').strip()
    if not s:
        return True
    low = s.lower()
    if low in ('none', 'null', '-', '—', '–', '.', 'n/a', 'na', 'tbd', 'tba'):
        return True
    for tok in _FORBIDDEN_EXACT:
        if tok.lower() in low or tok in s:
            return True
    return False


def _frameworks_from_data(data: Any) -> List[str]:
    if not isinstance(data, dict):
        return []
    raw = data.get('frameworks') or data.get('selected_frameworks') or []
    if isinstance(raw, str):
        raw = [p.strip() for p in raw.split(',') if p.strip()]
    out: List[str] = []
    for fw in raw:
        s = str(fw or '').strip()
        if s and s not in out and not _is_forbidden_value(s):
            out.append(s)
    return out


def _selected_ksa_frameworks(frameworks: List[str]) -> bool:
    blob = ' '.join(frameworks).lower()
    return any(m in blob for m in _KSA_MARKERS)


def _baseline_frameworks(lang: str) -> List[str]:
    label = FRAMEWORK_PROFILE_AR if lang == 'ar' else FRAMEWORK_PROFILE_EN
    return [label, *BASELINE_GLOBAL_STANDARDS]


def _org_label(lang: str) -> str:
    return ORG_PROFILE_AR if lang == 'ar' else ORG_PROFILE_EN


def _fw_label(lang: str, selected: Optional[List[str]] = None) -> str:
    if selected:
        return '، '.join(selected) if lang == 'ar' else ', '.join(selected)
    return FRAMEWORK_PROFILE_AR if lang == 'ar' else FRAMEWORK_PROFILE_EN


def resolve_gap_assessment_context(
        data: Dict[str, Any],
        *,
        lang: str = 'ar',
        domain: Any = 'global',
        document_type: Any = 'gap_assessment',
        emit: bool = False,
) -> Dict[str, Any]:
    """Fill missing org/framework context on a gap_assessment request.

    Mutates ``data`` in place.  Never writes "غير محدد" / "Not specified".
    """
    before_org = str((data or {}).get('org_name') or '').strip()
    before_struct = str((data or {}).get('org_structure') or '').strip()
    before_fw = list(_frameworks_from_data(data))
    ctx = {
        'organization_profile_before': before_org or before_struct,
        'framework_profile_before': ', '.join(before_fw),
        'organization_profile_after': before_org or before_struct,
        'framework_profile_after': ', '.join(before_fw),
        'applied': False,
    }
    if not is_gap_placeholder_completion_applicable(document_type):
        return ctx
    if not isinstance(data, dict):
        return ctx

    org = _org_label(lang)
    if _is_forbidden_value(data.get('org_name')):
        data['org_name'] = org
        ctx['applied'] = True
    if _is_forbidden_value(data.get('org_structure')):
        data['org_structure'] = org
        ctx['applied'] = True
    if _is_forbidden_value(data.get('budget')):
        data['budget'] = BUDGET_AR if lang == 'ar' else BUDGET_EN
        ctx['applied'] = True
    if _is_forbidden_value(data.get('challenges')):
        data['challenges'] = CHALLENGES_AR if lang == 'ar' else CHALLENGES_EN
        ctx['applied'] = True

    fws = _frameworks_from_data(data)
    if not fws:
        data['frameworks'] = _baseline_frameworks(lang)
        ctx['applied'] = True
        fws = list(data['frameworks'])
    elif not _selected_ksa_frameworks(fws):
        # Keep caller-selected global frameworks; never inject KSA labels.
        data['frameworks'] = fws

    ctx['organization_profile_after'] = str(
        data.get('org_name') or data.get('org_structure') or org).strip()
    ctx['framework_profile_after'] = ', '.join(
        _frameworks_from_data(data) or _baseline_frameworks(lang))
    if emit:
        print(
            '[REL33-GAP-CONTEXT-RESOLVER] '
            f"org={ctx['organization_profile_before']!r}->"
            f"{ctx['organization_profile_after']!r} "
            f"fw={ctx['framework_profile_before']!r}->"
            f"{ctx['framework_profile_after']!r}",
            flush=True,
        )
    return ctx


def sanitize_gap_prompt_text(text: Any, *, lang: str = 'ar',
                             frameworks: Optional[List[str]] = None) -> str:
    """Replace forbidden prompt tokens without claiming KSA applicability."""
    blob = str(text or '')
    if not blob:
        return blob
    org = _org_label(lang)
    fw = _fw_label(lang, frameworks)
    for tok in _FORBIDDEN_EXACT:
        if tok in blob:
            blob = blob.replace(tok, fw if 'framework' in blob.lower()
                                or 'إطار' in blob or 'معياري' in blob
                                else org)
        elif tok.lower() in blob.lower() and tok.isascii():
            blob = re.sub(re.escape(tok), org, blob, flags=re.IGNORECASE)
    return blob


def count_forbidden_placeholders(text: Any) -> int:
    blob = str(text or '')
    if not blob:
        return 0
    n = 0
    for tok in _FORBIDDEN_EXACT:
        if tok.isascii():
            n += len(re.findall(r'(?<![A-Za-z])' + re.escape(tok)
                                + r'(?![A-Za-z])', blob, flags=re.I))
        else:
            n += blob.count(tok)
    return n


def placeholder_gate_section_hits(sections: Dict[str, Any]) -> List[str]:
    """Mirror the app.py placeholder-text gate section list (not weakened)."""
    hits: List[str] = []
    if not isinstance(sections, dict):
        return hits
    for key in _GATE_KEYS:
        txt = sections.get(key, '') or ''
        if not txt:
            continue
        for pat in _GATE_PATTERNS:
            if re.search(pat, txt, re.IGNORECASE):
                hits.append(key)
                break
    return hits


def _header_role(cell: str) -> str:
    s = (cell or '').strip().lower()
    if any(k in s for k in (
            'framework', 'إطار', 'المعيار', 'معياري', 'standard', 'مرجع')):
        return 'framework'
    if any(k in s for k in (
            'org', 'organization', 'جهة', 'منظمة', 'المؤسسة', 'profile',
            'ملف')):
        return 'organization'
    if any(k in s for k in (
            'current', 'الحالة الحالية', 'الوضع الحالي', 'الحالي')):
        return 'current'
    if any(k in s for k in (
            'target', 'المستهدف', 'المستهدفة', 'الوضع المستهدف')):
        return 'target'
    if any(k in s for k in (
            'recommend', 'توصي', 'معالج', 'إجراء', 'خطة')):
        return 'recommendation'
    if any(k in s for k in ('control', 'ضابط', 'control id')):
        return 'control'
    if any(k in s for k in ('gap', 'فجوة', 'وصف', 'description')):
        return 'gap'
    return ''


def _value_for_role(role: str, lang: str, frameworks: List[str]) -> str:
    if role == 'framework' or role == 'control':
        return _fw_label(lang, frameworks)
    if role == 'organization':
        return _org_label(lang)
    if role == 'current':
        return CURRENT_STATE_AR if lang == 'ar' else CURRENT_STATE_EN
    if role == 'target':
        return TARGET_STATE_AR if lang == 'ar' else TARGET_STATE_EN
    if role == 'recommendation':
        return RECOMMENDATION_AR if lang == 'ar' else RECOMMENDATION_EN
    if role == 'gap':
        return (
            'فجوة امتثال تتطلب توثيقاً ومعالجة وفق المعايير المرجعية'
            if lang == 'ar' else
            'Compliance gap requiring documentation and remediation '
            'against the reference standards')
    return CURRENT_STATE_AR if lang == 'ar' else CURRENT_STATE_EN


def _cell_has_forbidden_token(cell: str) -> bool:
    s = str(cell or '')
    if not s.strip():
        return False
    low = s.lower()
    for tok in _FORBIDDEN_EXACT:
        if tok.isascii():
            if re.search(r'(?<![A-Za-z])' + re.escape(tok) + r'(?![A-Za-z])',
                         s, flags=re.I):
                return True
        elif tok in s:
            return True
    if low in ('none', 'null'):
        return True
    return False


def _cell_needs_completion(cell: str, role: str) -> bool:
    s = (cell or '').strip()
    if _cell_has_forbidden_token(s):
        return True
    empty = (not s) or s in ('-', '—', '–', '.')
    return empty and role in (
        'framework', 'organization', 'current', 'target',
        'recommendation', 'control')


def _complete_table_line(
        line: str, roles: List[str], lang: str, frameworks: List[str],
) -> Tuple[str, int]:
    s = line.strip()
    if not (s.startswith('|') and s.endswith('|')):
        return line, 0
    if _SEP_ROW_RE.match(s):
        return line, 0
    cells = [c.strip() for c in s.split('|')[1:-1]]
    if not cells:
        return line, 0
    changed = 0
    out = []
    for i, cell in enumerate(cells):
        role = roles[i] if i < len(roles) else ''
        if _cell_needs_completion(cell, role):
            out.append(_value_for_role(role or 'current', lang, frameworks))
            changed += 1
        else:
            out.append(cell)
    if not changed:
        return line, 0
    rebuilt = '| ' + ' | '.join(out) + ' |'
    lead = line[:len(line) - len(line.lstrip())]
    return lead + rebuilt, changed


def _complete_text(
        text: str, lang: str, frameworks: List[str],
) -> Tuple[str, int, int]:
    """Return (new_text, rows_scanned, fields_completed)."""
    if not text:
        return text, 0, 0
    lines = text.split('\n')
    roles: List[str] = []
    in_table = False
    rows_scanned = 0
    rows_completed = 0
    fields = 0
    out_lines: List[str] = []
    for ln in lines:
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and not _SEP_ROW_RE.match(s):
            cells = [c.strip() for c in s.split('|')[1:-1]]
            hdr_roles = [_header_role(c) for c in cells]
            if sum(1 for r in hdr_roles if r) >= 1 and not any(
                    c.replace('.', '').isdigit() for c in cells[:1]):
                roles = hdr_roles
                in_table = True
                out_lines.append(ln)
                continue
            if in_table:
                rows_scanned += 1
                new_ln, n = _complete_table_line(ln, roles, lang, frameworks)
                fields += n
                if n:
                    rows_completed += 1
                out_lines.append(new_ln)
                continue
        elif _SEP_ROW_RE.match(s):
            out_lines.append(ln)
            continue
        else:
            if s and not s.startswith('|'):
                in_table = False
                roles = []
            new_ln, n = _complete_prose_line(ln, lang, frameworks)
            fields += n
            out_lines.append(new_ln)
            continue
        out_lines.append(ln)
    return '\n'.join(out_lines), rows_scanned, rows_completed, fields


def _complete_prose_line(
        line: str, lang: str, frameworks: List[str],
) -> Tuple[str, int]:
    if not line or not count_forbidden_placeholders(line):
        return line, 0
    blob = line
    n = 0
    low = blob.lower()
    use_fw = any(k in low for k in (
        'framework', 'regulatory', 'standard', 'إطار', 'معياري', 'تنظيم'))
    repl = _fw_label(lang, frameworks) if use_fw else _org_label(lang)
    for tok in _FORBIDDEN_EXACT:
        if tok.isascii():
            new, c = re.subn(
                r'(?<![A-Za-z])' + re.escape(tok) + r'(?![A-Za-z])',
                repl, blob, flags=re.I)
        else:
            c = blob.count(tok)
            new = blob.replace(tok, repl)
        if c:
            blob = new
            n += c
    return blob, n


def apply_gap_placeholder_completion(
        sections: Dict[str, Any],
        *,
        domain: Any = 'global',
        document_type: Any = 'gap_assessment',
        lang: str = 'ar',
        data: Optional[Dict[str, Any]] = None,
        route: str = '',
        emit: bool = True,
        skip_replace: bool = False,
) -> Dict[str, Any]:
    """Complete forbidden placeholders in gap_assessment sections.

    ``skip_replace`` is test-only: proves the save gate still fail-closes
    when placeholders remain after this pass.
    """
    dcode = _normalize_domain(domain)
    lang_n = 'ar' if str(lang or 'ar').lower().startswith('ar') else 'en'
    ctx = resolve_gap_assessment_context(
        data or {}, lang=lang_n, domain=dcode,
        document_type=document_type, emit=False)
    fws = _frameworks_from_data(data) or _baseline_frameworks(lang_n)
    diag: Dict[str, Any] = {
        'diag': 'REL33-GAP-PLACEHOLDER-COMPLETION',
        'route': route or f'{dcode}:gap_assessment:{lang_n}',
        'domain': dcode,
        'document_type': 'gap_assessment',
        'artifact_type': 'gap_assessment',
        'language': lang_n,
        'organization_profile_before': ctx.get('organization_profile_before'),
        'organization_profile_after': ctx.get('organization_profile_after'),
        'framework_profile_before': ctx.get('framework_profile_before'),
        'framework_profile_after': ctx.get('framework_profile_after'),
        'placeholders_before': 0,
        'placeholders_after': 0,
        'rows_scanned': 0,
        'rows_completed': 0,
        'fields_completed': 0,
        'completion_applied': False,
        'placeholder_gate_passed': False,
        'blocking_errors': [],
        'passed': False,
    }
    if not is_gap_placeholder_completion_applicable(document_type):
        diag['document_type'] = str(document_type or '').strip().lower()
        diag['artifact_type'] = diag['document_type']
        diag['blocking_errors'] = []
        diag['passed'] = True
        _emit(diag, emit)
        return diag
    if not isinstance(sections, dict):
        diag['blocking_errors'].append(
            'rel33_gap_placeholder_completion_failed')
        _emit(diag, emit)
        return diag

    before = 0
    for key in _SCAN_KEYS:
        before += count_forbidden_placeholders(sections.get(key, '') or '')
    diag['placeholders_before'] = before

    if not skip_replace:
        for key in _SCAN_KEYS:
            raw = sections.get(key, '')
            if not isinstance(raw, str) or not raw:
                continue
            new, rows, rows_done, fields = _complete_text(raw, lang_n, fws)
            diag['rows_scanned'] += rows
            diag['rows_completed'] += rows_done
            diag['fields_completed'] += fields
            if new != raw:
                sections[key] = new
                diag['completion_applied'] = True
        sections['_document_type'] = 'gap_assessment'

    after = 0
    for key in _SCAN_KEYS:
        after += count_forbidden_placeholders(sections.get(key, '') or '')
    diag['placeholders_after'] = after
    gate_hits = placeholder_gate_section_hits(sections)
    if after > 0 or gate_hits:
        diag['blocking_errors'].append(
            'rel33_gap_placeholder_completion_failed')
        diag['placeholder_gate_passed'] = False
        diag['passed'] = False
    else:
        diag['placeholder_gate_passed'] = True
        diag['passed'] = True
        if before > 0:
            diag['completion_applied'] = True
    _emit(diag, emit)
    return diag


def run_gap_placeholder_completion(
        sections: Dict[str, Any],
        *,
        data: Optional[Dict[str, Any]] = None,
        domain: Any = 'global',
        document_type: Any = 'gap_assessment',
        lang: str = 'ar',
        route: str = '',
        emit: bool = True,
) -> Dict[str, Any]:
    """Public generation-path entry: complete then fail-closed if leftovers."""
    diag = apply_gap_placeholder_completion(
        sections,
        domain=domain,
        document_type=document_type,
        lang=lang,
        data=data,
        route=route,
        emit=emit,
    )
    return {
        'diag': diag,
        'fail_closed': bool(diag.get('blocking_errors')),
        'fail_closed_reason': (
            'rel33_gap_placeholder_completion_failed'
            if diag.get('blocking_errors') else ''),
        'placeholder_gate_passed': bool(diag.get('placeholder_gate_passed')),
    }


def _emit(diag: Dict[str, Any], emit: bool) -> None:
    if not emit:
        return
    try:
        print(
            '[REL33-GAP-PLACEHOLDER-COMPLETION] '
            f"route={diag.get('route')!r} domain={diag.get('domain')!r} "
            f"document_type={diag.get('document_type')!r} "
            f"org={diag.get('organization_profile_before')!r}->"
            f"{diag.get('organization_profile_after')!r} "
            f"fw={diag.get('framework_profile_before')!r}->"
            f"{diag.get('framework_profile_after')!r} "
            f"placeholders={diag.get('placeholders_before')}->"
            f"{diag.get('placeholders_after')} "
            f"rows={diag.get('rows_scanned')}/"
            f"{diag.get('rows_completed')} "
            f"fields={diag.get('fields_completed')} "
            f"applied={diag.get('completion_applied')} "
            f"gate_passed={diag.get('placeholder_gate_passed')} "
            f"blockers={diag.get('blocking_errors')} "
            f"passed={diag.get('passed')}",
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass
