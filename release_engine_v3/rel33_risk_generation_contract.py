"""REL3.3 — ERM risk generation contract.

An ERM risk artifact (``document_type=risk``) must be risk-native: it may only
contain risk sections (scenario, risk context/register, controls, treatment
strategy/plan, KRI monitoring, risk owners, risk summary, impact). It must
never be saved as an accepted risk artifact while carrying strategy-shaped
sections (vision/strategic objectives/strategic pillars/roadmap/strategy KPI
table/governance model/traceability matrix/strategic alignment/strategic
initiatives).

This module provides:
  * ``detect_forbidden_strategy_sections`` — heading-level detection of
    strategy-shaped sections in risk markdown;
  * ``risk_native_repair`` — a single deterministic pass that removes the
    forbidden strategy section blocks while preserving risk-native content;
  * ``evaluate_risk_generation_contract`` — the fail-closed contract used at
    the risk save gate; emits ``[REL33-RISK-GENERATION-CONTRACT]``.

It NEVER weakens the risk-domain guard, suppresses ``rel33_domain_contamination``,
or bypasses export evidence. Cyber-primary substance is still evaluated by the
risk-native domain isolation guard; this contract only enforces risk-native
*structure* and delegates cyber-primary detection to the shared guard.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

# Forbidden strategy section heading markers (normalized, lowercase). Matched
# against ## / ### / #### heading text only — never against body prose — so a
# risk section that *mentions* a word incidentally is never flagged. Phrases are
# specific enough that risk-native headings (e.g. "استراتيجية المعالجة" /
# "treatment strategy", "مصفوفة تحديد مستوى الخطورة") never match.
FORBIDDEN_STRATEGY_SECTION_MARKERS: Tuple[str, ...] = (
    # Arabic strategy sections
    'الرؤية والاهداف',
    'الرؤية والأهداف',
    'الرؤية',
    'الاهداف الاستراتيجية',
    'الأهداف الاستراتيجية',
    'الركائز الاستراتيجية',
    'خارطة الطريق',
    'خريطة الطريق',
    'مصفوفة التتبع',
    'مصفوفة تتبع',
    'المواءمة الاستراتيجية',
    'المبادرات الاستراتيجية',
    'نموذج الحوكمة',
    'مؤشرات الأداء الرئيسية',
    'مؤشرات الاداء الرئيسية',
    'الأهداف والمبادرات الاستراتيجية',
    # English strategy sections
    'strategic objectives',
    'strategic pillars',
    'roadmap',
    'traceability matrix',
    'strategic alignment',
    'strategic initiatives',
    'governance model',
    'key performance indicators',
    'vision and objectives',
    'vision & objectives',
    'strategic vision',
    'implementation roadmap',
    'strategy roadmap',
    'kpi dashboard',
)

# Bare English 'vision' is only treated as a strategy heading when it is the
# whole heading (or "vision and ...") — avoids matching an unrelated word.
_STRATEGY_HEADING_EXACT_EN = ('vision', 'kpis')

# Risk-native section heading markers (informational — reported in the diag).
RISK_NATIVE_SECTION_MARKERS: Tuple[str, ...] = (
    'وصف السيناريو', 'السيناريو', 'سياق المخاطر', 'تقييم المخاطر',
    'سجل المخاطر', 'الضوابط', 'استراتيجية المعالجة', 'خطة المعالجة',
    'اجراءات المعالجة', 'إجراءات المعالجة', 'مقاييس kri', 'مؤشرات المخاطر',
    'المالكون', 'المسؤوليات', 'ملخص المخاطر', 'التأثير', 'المخاطر المتاصلة',
    'المخاطر المتبقية', 'مصفوفة تحديد مستوى الخطورة', 'الاجراءات',
    'scenario', 'risk context', 'risk register', 'risk assessment',
    'controls', 'treatment', 'kri', 'risk owner', 'risk summary', 'impact',
    'inherent risk', 'residual risk',
)


def emit_rel33_risk_generation_contract(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-RISK-GENERATION-CONTRACT] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _normalize_heading(text: str) -> str:
    """Lowercase + normalize Arabic/markdown variants for robust marker match.

    Tolerant to: markdown bold/italic markers, tatweel (ـ), Arabic diacritics,
    hamza/alef/ya/ta-marbuta variants, punctuation and separators, and leading
    section numbering. This makes heading detection resilient to LLM styling
    variants (e.g. ``**الرؤية والأهداف الاستراتيجية**`` or ``الــرؤية``).
    """
    s = str(text or '').strip().lower()
    s = s.replace('*', ' ').replace('_', ' ').replace('#', ' ')
    s = s.replace('\u0640', '')  # strip tatweel/kashida
    for a, b in (
            ('أ', 'ا'), ('إ', 'ا'), ('آ', 'ا'), ('ى', 'ي'),
            ('ة', 'ه'), ('ؤ', 'و'), ('ئ', 'ي'), ('ﻻ', 'لا')):
        s = s.replace(a, b)
    s = re.sub(r'[\u064b-\u0652]', '', s)  # strip Arabic diacritics
    # unify punctuation/separators to single spaces
    s = re.sub(r'[\u060c\u061b\.:،؛\-–—/\\|()\[\]"\'`]+', ' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def _heading_is_forbidden(heading_text: str) -> str:
    """Return the matched forbidden marker for a heading, or '' if risk-native.

    Only the heading text (already stripped of leading '#') is inspected. A
    numeric prefix like "5. " is tolerated. Both raw and Arabic-normalized
    forms are checked so slugified/diacritic variants still match.
    """
    raw = str(heading_text or '').strip()
    raw = re.sub(r'^\s*#+\s*', '', raw)
    raw = re.sub(r'^\s*\d+[\.\)\-]?\s*', '', raw)  # drop leading numbering
    norm = _normalize_heading(raw)
    low = raw.lower()
    for marker in FORBIDDEN_STRATEGY_SECTION_MARKERS:
        m = _normalize_heading(marker)
        if m and (m in norm or m in low):
            return marker
    # exact English heading tokens (avoid substring false positives)
    tokens = re.split(r'[\s:،—\-]+', low)
    for tok in _STRATEGY_HEADING_EXACT_EN:
        if tok in tokens:
            return tok
    return ''


def _is_risk_heading_line(line: str) -> bool:
    """Heading test aligned EXACTLY with ``_split_risk_markdown``.

    The risk splitter delimits sections on any line whose stripped form starts
    with ``##`` (``line.strip().startswith('##')`` — any leading whitespace, any
    hash count >= 2, with or without a following space). The contract's
    detection/repair MUST use the identical rule, otherwise a heading the
    splitter turns into a section (e.g. one with >3 leading spaces, 5+ hashes,
    or no space after the hashes) could escape the contract while still reaching
    the domain guard as a ``vision``-style section key.
    """
    return str(line or '').strip().startswith('##')


def _risk_heading_text(line: str) -> str:
    """Heading text with the same normalization the splitter would see."""
    return str(line or '').strip().lstrip('#').strip()


def detect_forbidden_strategy_sections(content: str) -> List[str]:
    """Return the list of forbidden strategy heading texts found in ``content``.

    Detection is heading-scoped and aligned with ``_split_risk_markdown`` (any
    ``##``+ heading after stripping). Risk-native headings and body prose are
    never flagged.
    """
    hits: List[str] = []
    for line in str(content or '').splitlines():
        if _is_risk_heading_line(line):
            heading = _risk_heading_text(line)
            if heading and _heading_is_forbidden(heading):
                hits.append(heading)
    # de-dupe, preserve order
    seen = set()
    out: List[str] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def detect_risk_native_sections(content: str) -> List[str]:
    """Return risk-native heading texts found (informational for the diag)."""
    out: List[str] = []
    for line in str(content or '').splitlines():
        if _is_risk_heading_line(line):
            heading = _risk_heading_text(line)
            if not heading or _heading_is_forbidden(heading):
                continue
            norm = _normalize_heading(heading)
            if any(_normalize_heading(m) in norm for m in RISK_NATIVE_SECTION_MARKERS):
                out.append(heading)
    return out


def risk_native_repair(content: str) -> str:
    """Remove forbidden strategy section blocks; preserve risk-native content.

    Deterministic single pass aligned with ``_split_risk_markdown``: a heading
    line (``line.strip().startswith('##')``) whose text matches a forbidden
    strategy marker is dropped together with its body, up to (but not including)
    the next ``##``+ heading line. Risk-native sections and all non-heading
    prose outside forbidden blocks are preserved verbatim. Using the flat
    splitter rule (rather than markdown depth) guarantees the contract removes
    exactly the sections the splitter — and therefore the domain guard — would
    otherwise see.
    """
    lines = str(content or '').splitlines()
    out: List[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if _is_risk_heading_line(line) and _heading_is_forbidden(
                _risk_heading_text(line)):
            # Skip this section block until the next ``##``+ heading line.
            i += 1
            while i < n and not _is_risk_heading_line(lines[i]):
                i += 1
            continue
        out.append(line)
        i += 1
    # collapse excessive blank lines introduced by removals
    repaired = '\n'.join(out)
    repaired = re.sub(r'\n{3,}', '\n\n', repaired).strip()
    return repaired


def evaluate_risk_generation_contract(
        content: str,
        *,
        domain: str = '',
        route: str = '',
        generation_stage: str = 'pre_save',
        prompt_profile: str = 'risk_native',
        selected_frameworks: Optional[List[str]] = None,
        allow_cyber_context: bool = False,
        emit: bool = True,
) -> Dict[str, Any]:
    """Fail-closed risk-native structure contract for ERM risk generation.

    Flow:
      1. Detect forbidden strategy sections in the generated risk content.
      2. If none: contract passes (no repair).
      3. If found: run ONE deterministic ``risk_native_repair`` pass.
      4. Re-detect on the repaired content; also re-run the risk-native domain
         isolation guard for cyber-primary substance.
      5. If the repaired content is still strategy-shaped OR still carries
         cyber-primary substance → fail closed:
            * ``rel33_risk_generation_strategy_shape_detected`` (structure), or
            * ``rel33_risk_generation_not_risk_native`` (cyber-primary remains).

    Returns a diagnostic dict (also the repaired content under ``content``).
    Never suppresses the domain guard; cyber-primary detection is delegated to
    ``evaluate_rel33_risk_domain_isolation``.
    """
    from release_engine_v3.domain_codes import normalize_domain_code

    dcode = ''
    try:
        dcode = normalize_domain_code(str(domain or ''), default='')
    except Exception:  # noqa: BLE001
        dcode = str(domain or '').strip().lower()
    is_cyber = dcode == 'cyber' or bool(allow_cyber_context)

    original = str(content or '')
    forbidden_before = detect_forbidden_strategy_sections(original)
    repaired = original
    repair_attempted = False
    repair_passed = False

    if forbidden_before:
        repair_attempted = True
        repaired = risk_native_repair(original)
        forbidden_after = detect_forbidden_strategy_sections(repaired)
        repair_passed = not forbidden_after
    else:
        forbidden_after = []
        repair_passed = True

    # Cyber-primary evaluation on the (repaired) content via the shared guard.
    cyber_terms: List[str] = []
    cyber_detected = False
    iso_blockers: List[str] = []
    try:
        from release_engine_v3.rel33_risk_artifact import (
            _split_risk_markdown as _split_risk_md,
            normalize_risk_export_sections as _norm_risk_secs,
        )
        from release_engine_v3.rel33_domain_guard import (
            evaluate_rel33_risk_domain_isolation,
        )
        _secs = _norm_risk_secs(_split_risk_md(repaired))
        _iso = evaluate_rel33_risk_domain_isolation(
            _secs,
            domain=dcode,
            document_type='risk',
            route=route or 'generate-risk',
            phase='pre_save:generation_contract',
            artifact_type='risk',
            section_classifier='risk_generation_contract',
            selected_registry=dcode,
            strategy_repairer_invoked=False,
            emit=False,
        )
        cyber_terms = list(_iso.get('cyber_primary_terms') or [])
        cyber_detected = bool(_iso.get('cyber_substance_detected'))
        # Only treat as blocking when a real domain is known and not cyber.
        if dcode and not is_cyber and not _iso.get('contract_passed'):
            iso_blockers = list(_iso.get('blocking_errors') or [])
    except Exception:  # noqa: BLE001
        pass

    blocking_errors: List[str] = []
    if forbidden_before and not repair_passed:
        blocking_errors.append('rel33_risk_generation_strategy_shape_detected')
    if iso_blockers:
        # Repaired content still carries cyber-primary substance.
        blocking_errors.append('rel33_risk_generation_not_risk_native')

    contract_passed = not blocking_errors
    risk_native_after = detect_risk_native_sections(repaired)

    diag: Dict[str, Any] = {
        'tag': '[REL33-RISK-GENERATION-CONTRACT]',
        'route': str(route or ''),
        'domain': dcode or str(domain or ''),
        'document_type': 'risk',
        'artifact_type': 'risk',
        'generation_stage': str(generation_stage or ''),
        'prompt_profile': str(prompt_profile or ''),
        'compiler_selected': 'risk_native',
        'strategy_compiler_attempted': False,
        'risk_compiler_attempted': True,
        'forbidden_strategy_sections_detected': bool(forbidden_before),
        'forbidden_strategy_section_keys': list(forbidden_before),
        'forbidden_strategy_sections_after_repair': list(forbidden_after),
        'cyber_primary_terms_detected': sorted(set(cyber_terms)),
        'cyber_substance_detected': bool(cyber_detected),
        'risk_native_sections_detected': list(risk_native_after),
        'risk_repair_attempted': bool(repair_attempted),
        'risk_repair_passed': bool(repair_attempted and repair_passed
                                   and not iso_blockers),
        'generation_saved_real': bool(contract_passed),
        'blocking_errors': list(dict.fromkeys(blocking_errors)),
        'contract_passed': bool(contract_passed),
        'content': repaired if contract_passed else original,
    }
    if emit:
        _emit = {k: v for k, v in diag.items() if k != 'content'}
        emit_rel33_risk_generation_contract(_emit)
    return diag


def emit_rel33_risk_export_prep_contract(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-RISK-EXPORT-PREP-CONTRACT] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _sha256_short(text: str) -> str:
    import hashlib
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()[:16]


def evaluate_risk_export_prep_contract(
        content: str,
        *,
        domain: str = '',
        route: str = '',
        risk_id: Any = '',
        source_stage: str = 'export_prep',
        allow_cyber_context: bool = False,
        emit: bool = True,
) -> Dict[str, Any]:
    """Second hard boundary — risk-native structure contract at export-prep.

    Runs the same detection + one deterministic repair as the generation
    contract, but from the export-prep boundary so a strategy-shaped SAVED
    artifact can never reach the exporters. Emits
    ``[REL33-RISK-EXPORT-PREP-CONTRACT]``.

    On failure returns fail-closed blockers using export-prep-specific codes
    (never strategy vision/roadmap blockers):
      * ``rel33_risk_export_prep_strategy_shape_detected`` — repaired content is
        still strategy-shaped;
      * ``rel33_risk_export_prep_not_risk_native`` — cyber-primary substance
        remains in kept risk-native sections after repair.

    Returns a dict with ``content`` (repaired content to use for export when the
    contract passes; original when it fails), ``contract_passed``, and
    ``blocking_errors``.
    """
    saved = str(content or '')
    inner = evaluate_risk_generation_contract(
        saved,
        domain=domain,
        route=route or 'export-prep',
        generation_stage=source_stage,
        allow_cyber_context=allow_cyber_context,
        emit=False,
    )
    export_content = inner.get('content') if inner.get('contract_passed') else saved
    # Map generation-contract blockers to export-prep-specific codes.
    prep_blockers: List[str] = []
    for b in (inner.get('blocking_errors') or []):
        if b == 'rel33_risk_generation_strategy_shape_detected':
            prep_blockers.append('rel33_risk_export_prep_strategy_shape_detected')
        elif b == 'rel33_risk_generation_not_risk_native':
            prep_blockers.append('rel33_risk_export_prep_not_risk_native')
        else:
            prep_blockers.append(b)
    contract_passed = not prep_blockers

    saved_hash = _sha256_short(saved)
    export_hash = _sha256_short(export_content)
    diag: Dict[str, Any] = {
        'tag': '[REL33-RISK-EXPORT-PREP-CONTRACT]',
        'route': str(route or ''),
        'domain': inner.get('domain'),
        'document_type': 'risk',
        'artifact_type': 'risk',
        'risk_id': str(risk_id or ''),
        'source_stage': str(source_stage or ''),
        'forbidden_strategy_sections_detected': bool(
            inner.get('forbidden_strategy_sections_detected')),
        'forbidden_strategy_section_keys': list(
            inner.get('forbidden_strategy_section_keys') or []),
        'risk_export_prep_repair_attempted': bool(
            inner.get('risk_repair_attempted')),
        'risk_export_prep_repair_passed': bool(
            inner.get('risk_repair_attempted')
            and inner.get('risk_repair_passed')
            and contract_passed),
        'cyber_primary_terms_detected_after_repair': list(
            inner.get('cyber_primary_terms_detected') or []),
        'risk_native_sections_detected': list(
            inner.get('risk_native_sections_detected') or []),
        'content_used_for_export_hash': export_hash,
        'saved_content_hash': saved_hash,
        'export_content_differs_from_saved': bool(export_hash != saved_hash),
        'strategy_compiler_attempted': False,
        'risk_compiler_attempted': True,
        'blocking_errors': list(dict.fromkeys(prep_blockers)),
        'contract_passed': bool(contract_passed),
    }
    if emit:
        emit_rel33_risk_export_prep_contract(diag)
    out = dict(diag)
    out['content'] = export_content
    return out
