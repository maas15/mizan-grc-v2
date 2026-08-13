"""REL3.3 — export domain guard with compiler-first reference context."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Set

COMPILER_FIRST_DOMAIN_CODES = frozenset({'data', 'ai', 'dt', 'erm', 'global'})

REFERENCE_CONTEXT_SECTIONS = frozenset({
    'environment', 'gaps', 'roadmap', 'kpis', 'confidence',
    'traceability', 'governance', 'flattened',
})

NON_STRATEGY_DOMAIN_GUARD_TYPES = frozenset({
    'gap_assessment', 'risk', 'risk_assessment', 'policy', 'procedure',
    'audit', 'roadmap', 'executive_summary',
})

COMPILER_FIRST_ALLOWED_REFERENCE_TERMS = frozenset({
    'nca ecc', 'nca dcc', 'essential cybersecurity controls',
    'ciso', 'csirt', 'soc', 'iso 27001', 'nist csf', 'ecc', 'dcc',
    'الأمن السيبراني', 'ضوابط الأمن السيبراني',
})

PRIMARY_IDENTITY_SECTIONS = frozenset({'vision', 'pillars'})

CYBER_PRIMARY_IDENTITY_MARKERS = (
    'nca ecc', 'nca dcc', 'essential cybersecurity controls',
    'csirt', 'security operations center', 'soc manager',
    'الأمن السيبراني', 'ضوابط الأمن السيبراني',
    'ecc-1', 'ecc 1:', 'tcc-', 'ضابط ecc',
)

CYBER_CANONICAL_HEADING_MARKERS = (
    'strategic vision', 'vision statement', 'الرؤية الاستراتيجية',
    'strategic pillars', 'الركائز الاستراتيجية',
)


def emit_rel33_domain_guard_decision(diag: Dict[str, Any]) -> None:
    try:
        print(
            '[REL33-DOMAIN-GUARD-DECISION] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def _norm_domain_code(domain: str, normalize_fn: Callable[[str], str]) -> str:
    try:
        return normalize_fn(domain or '')
    except Exception:  # noqa: BLE001
        return str(domain or '').strip().lower()


def _section_text(sections: Dict[str, Any], key: str) -> str:
    return str((sections or {}).get(key) or '')


def _has_cyber_primary_identity(text: str) -> bool:
    blob = (text or '').lower()
    if not blob.strip():
        return False
    hits = sum(1 for m in CYBER_PRIMARY_IDENTITY_MARKERS if m in blob)
    return hits >= 2 or (
        hits >= 1 and any(h in blob for h in CYBER_CANONICAL_HEADING_MARKERS))


def _is_cyber_canonical_strategy_sections(sections: Dict[str, Any]) -> bool:
    """True when sections look like a full Cyber strategy artifact."""
    if not isinstance(sections, dict):
        return False
    keys = {
        k for k, v in sections.items()
        if not str(k).startswith('_') and str(v or '').strip()}
    core = {'vision', 'pillars', 'gaps', 'roadmap', 'kpis'}
    if len(keys & core) < 4:
        return False
    vision = _section_text(sections, 'vision')
    pillars = _section_text(sections, 'pillars')
    return _has_cyber_primary_identity(vision) or _has_cyber_primary_identity(pillars)


def filter_compiler_first_contamination(
        contamination: List[Dict[str, Any]],
        *,
        domain_code: str,
        sections: Dict[str, Any],
        row_domain_code: str = '',
) -> List[Dict[str, Any]]:
    """Allow control/reference mentions in non-primary sections for data/ai/dt."""
    if domain_code not in COMPILER_FIRST_DOMAIN_CODES:
        return list(contamination or [])
    if row_domain_code and row_domain_code != domain_code:
        return list(contamination or [])
    filtered: List[Dict[str, Any]] = []
    for rec in contamination or []:
        sec = str(rec.get('section') or '')
        if sec in PRIMARY_IDENTITY_SECTIONS:
            # Partial template bleed (ECC/CISO mentions) in vision/pillars is
            # expected on live data/ai/dt generation. Full cyber-canonical
            # artifacts are blocked earlier in evaluate_export_domain_guard.
            continue
        if sec in REFERENCE_CONTEXT_SECTIONS:
            continue
        if sec == 'flattened':
            continue
        filtered.append(rec)
    return filtered


def _data_roadmap_has_cyber_primary_initiatives(sections: Dict[str, Any]) -> List[str]:
    """Block data strategy when roadmap uses cyber canonical initiatives as primary."""
    from release_engine_v3.rel32_registries import CYBER_ROADMAP_PRIMARY_MARKERS
    roadmap = _section_text(sections, 'roadmap')
    if not roadmap.strip():
        return []
    blob = roadmap.lower()
    hits = [
        m for m in CYBER_ROADMAP_PRIMARY_MARKERS
        if m.lower() in blob or m in roadmap]
    # Require at least two cyber-primary signals to avoid false positives on
    # allowed cross-domain reference mentions in environment/traceability.
    if len(hits) >= 2:
        return hits
    strong = (
        'تأسيس حوكمة الأمن السيبراني',
        'تمكين SOC/SIEM',
        'تشغيل SOC وSIEM',
    )
    if any(s in roadmap for s in strong):
        return [h for h in hits if h] or list(strong[:1])
    return []


# ── REL3.3 Domain Isolation Contract ─────────────────────────────────────────
# Cyber-primary substance markers. A non-cyber strategy document must never
# contain these as rows/owners/frameworks/initiatives. Neutral single passing
# references in narrative sections are tolerated (2-hit rule below).
CYBER_PRIMARY_SUBSTANCE_MARKERS_ASCII = (
    'nca ecc', 'nca dcc', 'ciso', 'csirt', 'siem', 'soc',
    'iam/pam', 'mfa', 'dlp',
)

CYBER_PRIMARY_SUBSTANCE_MARKERS_AR = (
    'مركز العمليات الأمنية',
    'فريق الاستجابة للحوادث',
    'حوكمة الأمن السيبراني',
    'إدارة الثغرات',
    'الحماية والكشف والاستجابة',
    'التوعية الأمنية',
    'الهوية وحماية البيانات',
    'المرونة واستمرارية الأعمال',
)

# Narrative sections tolerate one passing reference; table/substance
# sections block on the first cyber-primary marker.
ISOLATION_NARRATIVE_SECTIONS = frozenset({'vision', 'environment', 'appendices'})

ISOLATION_GUARDED_SECTIONS = (
    'vision', 'pillars', 'environment', 'gaps', 'roadmap',
    'kpis', 'confidence', 'governance', 'traceability', 'appendices',
)


def find_cyber_primary_markers(text: str) -> List[str]:
    """Distinct cyber-primary substance markers found in a text blob."""
    blob = str(text or '')
    if not blob.strip():
        return []
    low = blob.lower()
    hits: List[str] = []
    for m in CYBER_PRIMARY_SUBSTANCE_MARKERS_ASCII:
        if re.search(r'(?<![a-z0-9])' + re.escape(m) + r'(?![a-z0-9])', low):
            hits.append(m)
    for m in CYBER_PRIMARY_SUBSTANCE_MARKERS_AR:
        if m in blob:
            hits.append(m)
    return hits


def emit_rel33_domain_isolation_contract(diag: Dict[str, Any]) -> None:
    """[REL33-DOMAIN-ISOLATION-CONTRACT] — substance/domain isolation trace."""
    try:
        print(
            '[REL33-DOMAIN-ISOLATION-CONTRACT] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def resolve_rel33_domain_or_fail(context: Dict[str, Any]) -> str:
    """Central REL3.3 domain resolver — never defaults blank to cyber.

    Resolution order: explicit ``domain`` → ``request_domain`` →
    ``db_domain`` → ``contract_meta_domain`` → ``sections_json_domain`` →
    ``content_json_domain`` → ``backend['domain']`` → route ``slug`` prefix.
    Raises ``ValueError('rel33_export_domain_missing:<where>')`` when the
    domain cannot be resolved.
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    ctx = dict(context or {})
    backend = ctx.get('backend') if isinstance(ctx.get('backend'), dict) else {}
    slug = str(ctx.get('slug') or ctx.get('route') or '')
    slug_domain = slug.split(':', 1)[0] if ':' in slug else ''
    candidates = (
        ('explicit', ctx.get('domain')),
        ('request', ctx.get('request_domain')),
        ('db', ctx.get('db_domain')),
        ('contract_meta', ctx.get('contract_meta_domain')),
        ('sections_json', ctx.get('sections_json_domain')),
        ('content_json', ctx.get('content_json_domain')),
        ('backend', (backend or {}).get('domain')),
        ('slug', slug_domain),
    )
    for _source, raw in candidates:
        code = normalize_domain_code(str(raw or ''), default='')
        if code:
            return code
    where = str(ctx.get('where') or ctx.get('phase') or 'resolver')
    raise ValueError(f'rel33_export_domain_missing:{where}')


def evaluate_domain_isolation_contract(
        sections: Dict[str, Any],
        *,
        domain: str,
        route: str = '',
        document_type: str = 'strategy',
        phase: str = 'pre_save',
        repairer_name: str = '',
        selected_registry: str = '',
        emit: bool = True,
) -> Dict[str, Any]:
    """REL3.3 Domain Isolation Contract — section-wide cyber-primary scan.

    For non-cyber domains, blocks cyber-primary substance (rows, owners,
    frameworks, initiatives) in every guarded section with
    ``rel33_domain_contamination:<section>:cyber_primary``. Blank domains
    fail closed with ``rel33_substance_domain_missing``. Cyber documents
    always pass this contract (cyber substance is expected there).
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    dcode = normalize_domain_code(str(domain or ''), default='')
    blockers: List[str] = []
    contaminated: List[str] = []
    blocked_terms: List[str] = []
    if not dcode:
        blockers.append('rel33_substance_domain_missing')
    elif dcode != 'cyber':
        for sec in ISOLATION_GUARDED_SECTIONS:
            body = str((sections or {}).get(sec) or '')
            if not body.strip():
                continue
            hits = find_cyber_primary_markers(body)
            min_hits = 2 if sec in ISOLATION_NARRATIVE_SECTIONS else 1
            if len(hits) >= min_hits:
                contaminated.append(sec)
                blocked_terms.extend(hits)
                blockers.append(
                    f'rel33_domain_contamination:{sec}:cyber_primary')
    diag = {
        'route': str(route or ''),
        'domain': dcode,
        'document_type': str(document_type or 'strategy'),
        'phase': str(phase or ''),
        'section': ','.join(contaminated) if contaminated else '',
        'repairer_name': str(repairer_name or ''),
        'resolved_domain': dcode,
        'domain_source': 'caller',
        'selected_registry': str(selected_registry or dcode),
        'cyber_registry_attempted': bool(contaminated),
        'cyber_registry_blocked': bool(contaminated),
        'injected_families': [],
        'blocked_terms': sorted(set(blocked_terms)),
        'contaminated_sections': contaminated,
        'pre_save_guard_passed': (phase != 'pre_save') or not blockers,
        'pre_export_guard_passed': (
            not phase.startswith('pre_export')) or not blockers,
        'contract_passed': not blockers,
        'blocking_errors': list(dict.fromkeys(blockers)),
    }
    if emit:
        emit_rel33_domain_isolation_contract(diag)
    return diag


# ── REL3.3 ERM Risk Domain Isolation ─────────────────────────────────────────
# A risk (document_type=risk/risk_assessment) document must never carry
# Cyber-*primary* substance (the cyber document's identity: its owner role,
# primary framework, or primary governance/ops initiatives). Generic security
# terms that are legitimate risk *controls* (MFA, IAM/PAM, DLP inside a
# treatment/register table) are allowed per the ERM substance contract, and a
# single incidental prose mention of SOC/CISO is tolerated. Only cyber-primary
# substance in an identity position (heading / table row / list item / labeled
# owner-role-framework) is blocked. NON_STRATEGY_DOMAIN_GUARD_TYPES risk types
# route here instead of through the strategy isolation contract, which is tuned
# for strategy section shapes and over-blocks incidental terms in a risk intro
# that the shared strategy splitter mislabels as ``vision``.

RISK_DOCUMENT_TYPES = frozenset({'risk', 'risk_assessment'})

# ERM-allowed risk substance (informational — never blocked).
ERM_ALLOWED_SUBSTANCE_MARKERS = (
    'risk appetite', 'risk register', 'inherent risk', 'residual risk',
    'controls', 'kri', 'treatment plan', 'risk owner', 'risk committee',
    'likelihood', 'impact', 'risk response',
    'شهية المخاطر', 'سجل المخاطر', 'المخاطر المتأصلة', 'المخاطر المتبقية',
    'الضوابط', 'مؤشرات المخاطر', 'خطة المعالجة', 'مالك المخاطر',
    'لجنة المخاطر', 'الاحتمالية', 'التأثير', 'الاستجابة للمخاطر',
)

# Cyber-primary substance that is *never* legitimate in an ERM risk document —
# blocked wherever it appears (these are cyber-strategy identity/ops concepts,
# not generic risk controls).
CYBER_RISK_STRONG_MARKERS_AR = (
    'حوكمة الأمن السيبراني',
    'مركز العمليات الأمنية',
    'الاستجابة للحوادث السيبرانية',
    'إدارة الثغرات السيبرانية',
)
CYBER_RISK_STRONG_MARKERS_ASCII = (
    'csirt', 'nca ecc', 'nca dcc', 'security operations center',
)

# Cyber-primary substance blocked only in an *identity* position (heading,
# table row, list item, or labeled owner/role/framework). In plain prose a
# single mention is treated as an incidental reference and tolerated (#6).
CYBER_RISK_CONTEXTUAL_MARKERS_ASCII = (
    'ciso', 'soc', 'siem', 'iam/pam', 'mfa',
)

# Risk sections whose whole purpose is to enumerate controls/treatments; the
# contextual markers above are legitimate *controls* here (ERM substance #4)
# and must not be flagged. Strong markers are still blocked everywhere.
RISK_CONTROL_SECTIONS = frozenset({
    'register', 'risk_register', 'treatments', 'treatment', 'risk_treatment',
    'heatmap', 'appetite', 'controls', 'kri', 'kris',
})

_PRIMARY_LINE_LABELS_ASCII = ('owner:', 'role:', 'framework:', 'primary')
_PRIMARY_LINE_LABELS_AR = ('المالك', 'الدور', 'الإطار', 'الجهة المالكة',
                           'الإطار الأساسي')


def _risk_line_is_identity_position(line: str) -> bool:
    """True when a line is an identity/substance position (not plain prose)."""
    s = str(line or '').strip()
    if not s:
        return False
    if s.startswith('#'):
        return True
    if s.startswith('|'):
        return True
    if re.match(r'^([-*•]|\d+[.)])\s', s):
        return True
    low = s.lower()
    if any(lbl in low for lbl in _PRIMARY_LINE_LABELS_ASCII):
        return True
    if any(lbl in s for lbl in _PRIMARY_LINE_LABELS_AR):
        return True
    return False


def _ascii_word_hit(marker: str, low_text: str) -> bool:
    return bool(re.search(
        r'(?<![a-z0-9])' + re.escape(marker) + r'(?![a-z0-9])', low_text))


def find_cyber_primary_risk_markers(
        text: str, *, section_key: str = '') -> List[str]:
    """Cyber-*primary* substance markers illegitimate in an ERM risk section.

    Strong markers block anywhere. Contextual markers block only in identity
    positions (heading/table/list/labeled) and never inside control/treatment
    sections (where they are legitimate risk controls).
    """
    blob = str(text or '')
    if not blob.strip():
        return []
    low = blob.lower()
    hits: List[str] = []
    for m in CYBER_RISK_STRONG_MARKERS_AR:
        if m in blob:
            hits.append(m)
    for m in CYBER_RISK_STRONG_MARKERS_ASCII:
        if _ascii_word_hit(m, low):
            hits.append(m)
    sec = str(section_key or '').strip().lower()
    if sec not in RISK_CONTROL_SECTIONS:
        for line in blob.splitlines():
            if not _risk_line_is_identity_position(line):
                continue
            ll = line.lower()
            for m in CYBER_RISK_CONTEXTUAL_MARKERS_ASCII:
                if _ascii_word_hit(m, ll):
                    hits.append(m)
    return sorted(set(hits))


def emit_rel33_risk_domain_isolation(diag: Dict[str, Any]) -> None:
    """[REL33-RISK-DOMAIN-ISOLATION] — ERM risk domain/document_type trace."""
    try:
        print(
            '[REL33-RISK-DOMAIN-ISOLATION] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def evaluate_rel33_risk_domain_isolation(
        sections: Dict[str, Any],
        *,
        domain: str,
        document_type: str,
        route: str = '',
        phase: str = 'pre_export',
        artifact_type: str = 'risk',
        section_classifier: str = '',
        selected_registry: str = '',
        strategy_repairer_invoked: bool = False,
        emit: bool = True,
) -> Dict[str, Any]:
    """REL3.3 ERM risk domain isolation — document_type-aware, fail-closed.

    Applies to non-cyber risk documents. Blocks cyber-*primary* substance in
    any section (treating a strategy-splitter-mislabeled ``vision`` intro as a
    risk section, domain=erm/document_type=risk — requirement #3). Blank
    domain or document_type fails closed. Cyber risk documents pass (cyber
    substance is expected there).
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    dcode = normalize_domain_code(str(domain or ''), default='')
    dtype = str(document_type or '').strip().lower()
    blockers: List[str] = []
    contaminated: List[str] = []
    blocked_terms: List[str] = []
    cyber_terms: List[str] = []

    if not dtype:
        blockers.append('rel33_risk_document_type_missing')
    if not dcode:
        blockers.append('rel33_risk_domain_missing')

    if dcode and dtype and dcode != 'cyber':
        for sec, body in (sections or {}).items():
            if str(sec).startswith('_'):
                continue
            text = str(body or '')
            if not text.strip():
                continue
            hits = find_cyber_primary_risk_markers(text, section_key=str(sec))
            if hits:
                contaminated.append(str(sec))
                cyber_terms.extend(hits)
                blocked_terms.extend(hits)
                blockers.append(
                    f'rel33_domain_contamination:{sec}:cyber_primary')

    resolved_registry = str(selected_registry or dcode or '')
    passed = not blockers
    diag = {
        'route': str(route or ''),
        'domain': dcode or str(domain or ''),
        'document_type': dtype,
        'artifact_type': str(artifact_type or 'risk'),
        'phase': str(phase or ''),
        'section': ','.join(sorted(set(contaminated))) if contaminated else '',
        'section_classifier': str(section_classifier or ''),
        'resolved_domain': dcode,
        'resolved_document_type': dtype,
        'selected_registry': resolved_registry,
        'strategy_repairer_invoked': bool(strategy_repairer_invoked),
        'cyber_substance_detected': bool(cyber_terms),
        'cyber_primary_terms': sorted(set(cyber_terms)),
        'blocked_terms': sorted(set(blocked_terms)),
        'pre_save_guard_passed': (phase != 'pre_save') or passed,
        'pre_export_guard_passed': (
            not str(phase or '').startswith('pre_export')) or passed,
        'contract_passed': passed,
        'blocking_errors': list(dict.fromkeys(blockers)),
    }
    if emit:
        emit_rel33_risk_domain_isolation(diag)
    return diag


def emit_rel33_export_domain_propagation(diag: Dict[str, Any]) -> None:
    """[REL33-EXPORT-DOMAIN-PROPAGATION] — export/render domain trace."""
    try:
        print(
            '[REL33-EXPORT-DOMAIN-PROPAGATION] '
            + json.dumps(diag, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def resolve_rel33_export_domain(
        *,
        request_domain: str = '',
        db_domain: str = '',
        content_json_domain: str = '',
        sections_json_domain: str = '',
        contract_meta_domain: str = '',
) -> Dict[str, Any]:
    """Resolve the export domain with DB/artifact metadata fallback.

    Never defaults a blank domain to Cyber. Returns a diag dict with
    ``resolved_domain`` (canonical code, '' when unresolvable),
    ``domain_missing`` and ``domain_source``.
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    candidates = (
        ('request', request_domain),
        ('db', db_domain),
        ('contract_meta', contract_meta_domain),
        ('sections_json', sections_json_domain),
        ('content_json', content_json_domain),
    )
    resolved = ''
    source = ''
    for name, raw in candidates:
        code = normalize_domain_code(str(raw or ''), default='')
        if code:
            resolved = code
            source = name
            break
    return {
        'request_domain': str(request_domain or ''),
        'db_domain': str(db_domain or ''),
        'content_json_domain': str(content_json_domain or ''),
        'sections_json_domain': str(sections_json_domain or ''),
        'contract_meta_domain': str(contract_meta_domain or ''),
        'resolved_domain': resolved,
        'domain_source': source,
        'domain_missing': not resolved,
        'fallback_domain_used': False,
    }


def evaluate_pre_export_bytes_domain_guard(
        sections_dict: Dict[str, Any],
        *,
        domain: str,
        route: str,
        artifact_id='',
        document_type: str = '',
) -> List[str]:
    """Final domain guard on the exact sections used for returned bytes.

    REL3.3 P0 — runs inside the exporters, after all repair/contract
    passes, so late-stage cyber injection cannot ship. Returns blocking
    errors (empty list ⇒ allowed):
      * blank domain → ``rel33_export_domain_missing:<route>``
      * non-cyber cyber-primary substance →
        ``rel33_domain_contamination:<section>:cyber_primary``
      * data + cyber roadmap rows → ``data_roadmap_cyber_contamination``

    ``document_type`` routes risk/risk_assessment artifacts through the ERM
    risk isolation (document_type-aware) instead of the strategy isolation
    contract, so a risk intro the shared strategy splitter mislabels as
    ``vision`` is still evaluated as domain=erm/document_type=risk (#3) and
    incidental generic security terms are not misread as cyber contamination
    (#6). Risk substance (cyber-primary) is still blocked before any bytes.
    """
    from release_engine_v3.domain_codes import normalize_domain_code
    dcode = normalize_domain_code(str(domain or ''), default='')
    route_n = str(route or 'export').lower()
    dtype = str(
        document_type
        or (sections_dict or {}).get('_document_type')
        or '').strip().lower()
    blockers: List[str] = []
    if not dcode:
        blockers.append(f'rel33_export_domain_missing:{route_n}')
        emit_rel33_export_domain_propagation({
            'route': route_n,
            'export_route': route_n,
            'artifact_id': str(artifact_id or ''),
            'domain_guard_domain': '',
            'domain_missing': True,
            'fallback_domain_used': False,
            'blocking_errors': list(blockers),
        })
        return blockers

    if dtype in RISK_DOCUMENT_TYPES:
        risk_iso = evaluate_rel33_risk_domain_isolation(
            sections_dict or {},
            domain=dcode,
            document_type=dtype,
            route=route_n,
            phase=f'pre_export:{route_n}',
            artifact_type='risk',
            section_classifier='pre_export_bytes',
            selected_registry=dcode,
            emit=True,
        )
        blockers.extend(risk_iso.get('blocking_errors') or [])
        return list(dict.fromkeys(blockers))

    isolation = evaluate_domain_isolation_contract(
        sections_dict or {},
        domain=dcode,
        route=route_n,
        phase=f'pre_export:{route_n}',
        repairer_name='evaluate_pre_export_bytes_domain_guard',
        selected_registry=dcode,
        emit=True,
    )
    blockers.extend(isolation.get('blocking_errors') or [])

    if dcode == 'data':
        hits = _data_roadmap_has_cyber_primary_initiatives(sections_dict or {})
        if hits:
            blockers.append('data_roadmap_cyber_contamination')
            emit_rel33_export_domain_propagation({
                'route': route_n,
                'export_route': route_n,
                'artifact_id': str(artifact_id or ''),
                'domain_guard_domain': dcode,
                'domain_missing': False,
                'fallback_domain_used': False,
                'contaminating_terms': hits[:6],
                'blocking_errors': list(dict.fromkeys(blockers)),
            })
    return list(dict.fromkeys(blockers))


def evaluate_export_domain_guard(
        sections_dict: Dict[str, Any],
        *,
        domain: str,
        language: str,
        artifact_type: str,
        artifact_id,
        route: str = '',
        document_type: str = 'strategy',
        row_domain: str = '',
        selected_frameworks: Optional[List[str]] = None,
        validate_fn: Callable[..., List[Dict[str, Any]]],
        domain_context_fn: Callable[..., Dict[str, Any]],
        normalize_domain_fn: Callable[[str], str],
        contamination_error_cls: type = RuntimeError,
        is_compiler_first_fn: Optional[Callable[..., bool]] = None,
        sealed_db_authority: bool = False,
) -> Dict[str, Any]:
    """Run domain isolation and return guard decision (raises on hard block)."""

    dtype = str(document_type or artifact_type or 'strategy').strip().lower()
    domain_code = _norm_domain_code(domain, normalize_domain_fn)
    row_code = _norm_domain_code(row_domain, normalize_domain_fn) if row_domain else domain_code
    compiler_first = False
    if callable(is_compiler_first_fn):
        try:
            compiler_first = bool(is_compiler_first_fn(
                domain=domain, lang=language, document_type=dtype))
        except Exception:  # noqa: BLE001
            compiler_first = domain_code in COMPILER_FIRST_DOMAIN_CODES

    allowed_refs = sorted({
        str(t).strip()
        for t in (selected_frameworks or [])
        if str(t).strip()
    })
    allowed_refs.extend(sorted(COMPILER_FIRST_ALLOWED_REFERENCE_TERMS))

    diag: Dict[str, Any] = {
        'route': route or 'export',
        'domain': domain_code,
        'artifact_id': str(artifact_id or ''),
        'artifact_type': str(artifact_type or 'strategy'),
        'document_type': dtype,
        'guard_phase': route or 'export_domain_isolation',
        'blocked_terms': [],
        'allowed_reference_terms': allowed_refs,
        'contaminating_terms': [],
        'contaminating_sections': [],
        'allowed_framework_terms': list(selected_frameworks or []),
        'compiler_first_artifact': compiler_first,
        'sealed_db_authority': sealed_db_authority,
        'domain_guard_passed': False,
        'blocking_errors': [],
    }

    if dtype in NON_STRATEGY_DOMAIN_GUARD_TYPES:
        diag['domain_guard_passed'] = True
        emit_rel33_domain_guard_decision(diag)
        return diag

    if (artifact_type or 'strategy') != 'strategy':
        diag['domain_guard_passed'] = True
        emit_rel33_domain_guard_decision(diag)
        return diag

    if row_code and row_code != domain_code:
        diag['blocking_errors'] = [
            f'artifact_domain_mismatch:row={row_code}:requested={domain_code}']
        emit_rel33_domain_guard_decision(diag)
        raise contamination_error_cls(
            f'Export blocked — artifact domain {row_code!r} does not match '
            f'requested {domain_code!r}')

    if (_is_cyber_canonical_strategy_sections(sections_dict)
            and domain_code != 'cyber'
            and not (compiler_first and domain_code in COMPILER_FIRST_DOMAIN_CODES)):
        diag['blocking_errors'] = ['cyber_canonical_artifact_in_non_cyber_domain']
        diag['contaminating_sections'] = ['vision', 'pillars']
        emit_rel33_domain_guard_decision(diag)
        raise contamination_error_cls(
            'Export blocked — saved artifact is a Cyber canonical strategy')

    if domain_code == 'data':
        cyber_road_hits = _data_roadmap_has_cyber_primary_initiatives(sections_dict)
        if cyber_road_hits:
            diag['blocking_errors'] = ['data_roadmap_cyber_contamination']
            diag['contaminating_terms'] = cyber_road_hits
            diag['contaminating_sections'] = ['roadmap']
            emit_rel33_domain_guard_decision(diag)
            raise contamination_error_cls(
                'Export blocked — data roadmap contains cyber canonical initiatives: '
                + ', '.join(cyber_road_hits[:6]))

    ctx = domain_context_fn(
        domain, lang=(language or 'en'),
        selected_frameworks=selected_frameworks or None)
    raw_hits = validate_fn(sections_dict, ctx)
    hits = raw_hits
    if compiler_first and domain_code in COMPILER_FIRST_DOMAIN_CODES:
        hits = filter_compiler_first_contamination(
            raw_hits,
            domain_code=domain_code,
            sections=sections_dict,
            row_domain_code=row_code,
        )

    if hits:
        terms: Set[str] = set()
        secs: Set[str] = set()
        for rec in hits:
            secs.add(str(rec.get('section') or ''))
            for t in rec.get('found_terms') or []:
                terms.add(str(t))
        blocked = sorted(terms)
        diag['blocked_terms'] = blocked
        diag['contaminating_terms'] = blocked
        diag['contaminating_sections'] = sorted(secs)
        diag['blocking_errors'] = ['domain_contamination']
        emit_rel33_domain_guard_decision(diag)
        summary = '; '.join(
            f"{rec.get('section', '?')}={list(rec.get('found_terms', []))[:4]}"
            for rec in hits)
        raise contamination_error_cls(
            f'Export blocked — saved strategy contains cross-domain content '
            f'({ctx.get("display_en") or domain_code}): {summary}')

    diag['domain_guard_passed'] = True
    emit_rel33_domain_guard_decision(diag)
    return diag
