"""REL36.6 — ERM risk domain isolation from strategy / cyber artifacts.

Risk export must stay namespaced by domain=erm, document_type=risk, and
risk_id. A colliding numeric strategy_id must never become content
authority. Does not weaken rel33_domain_contamination.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG = '[REL36.6-ERM-RISK-DOMAIN-ISOLATION]'

STRATEGY_SECTION_MARKERS = (
    'الرؤية والأهداف الاستراتيجية',
    '1_vision_strategic_objectives',
    'vision_strategic_objectives',
    'خارطة الطريق التنفيذية',
    'الركائز الاستراتيجية',
    'مصفوفة تتبع الأطر المرجعية',
    'نموذج الحوكمة والمسؤوليات',
    'مؤشرات الأداء الرئيسية',
)

CYBER_PRIMARY_MARKERS = (
    'cyber_primary',
    'NCA ECC',
    'NCA DCC',
    'CISO',
    'SIEM',
    'CSIRT',
    'SOC/SIEM',
    'فريق الأمن السيبراني',
)


def risk_cache_key(risk_id: Any, *, domain: str = 'erm',
                   document_type: str = 'risk') -> str:
    """Namespaced cache key — never a bare numeric strategy_id."""
    rid = str(risk_id or '').strip() or 'none'
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        dcode = normalize_domain_code(str(domain or 'erm'), default='erm') or 'erm'
    except Exception:  # noqa: BLE001
        dcode = str(domain or 'erm').strip().lower() or 'erm'
    dtype = str(document_type or 'risk').strip().lower() or 'risk'
    return f'risk:{dcode}:{dtype}:{rid}'


def contains_strategy_sections(text: str, sections: Optional[Dict[str, Any]] = None) -> bool:
    blob = str(text or '')
    keys = ' '.join(str(k) for k in (sections or {}) if not str(k).startswith('_'))
    hay = f'{blob}\n{keys}'
    if any(tok in hay for tok in STRATEGY_SECTION_MARKERS):
        return True
    try:
        from release_engine_v3.rel33_risk_generation_contract import (
            detect_forbidden_strategy_sections,
        )
        return bool(detect_forbidden_strategy_sections(blob))
    except Exception:  # noqa: BLE001
        return False


def contains_cyber_primary(text: str, sections: Optional[Dict[str, Any]] = None) -> bool:
    blob = str(text or '')
    try:
        from release_engine_v3.rel33_domain_guard import (
            evaluate_rel33_risk_domain_isolation,
        )
        from release_engine_v3.rel33_risk_artifact import (
            _split_risk_markdown,
            normalize_risk_export_sections,
        )
        secs = dict(sections or {})
        if not secs and blob.strip():
            secs = normalize_risk_export_sections(_split_risk_markdown(blob))
        iso = evaluate_rel33_risk_domain_isolation(
            secs or {'register': blob},
            domain='erm',
            document_type='risk',
            route='rel36.6',
            phase='rel36_6_probe',
            emit=False,
        )
        return any(
            'rel33_domain_contamination' in str(b)
            for b in (iso.get('blocking_errors') or [])
        )
    except Exception:  # noqa: BLE001
        return 'rel33_domain_contamination' in blob


def evaluate_rel36_6_erm_risk_domain_isolation(
        *,
        route: str = '',
        domain: str = '',
        document_type: str = 'risk',
        lang: str = 'ar',
        risk_id: Any = '',
        strategy_id: Any = '',
        cache_key: str = '',
        source_artifact_type: str = '',
        loaded_artifact_type: str = '',
        loaded_domain: str = '',
        loaded_document_type: str = '',
        content: str = '',
        sections: Optional[Dict[str, Any]] = None,
        contamination_before: Optional[Iterable[str]] = None,
        contamination_after: Optional[Iterable[str]] = None,
        repair_applied: bool = False,
        blocking_errors: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Build the REL36.6 isolation diagnostic. Fail closed on contamination."""
    dtype = str(document_type or 'risk').strip().lower() or 'risk'
    dcode = str(domain or '').strip()
    content_s = str(content or '')
    secs = dict(sections or {})
    has_strategy = contains_strategy_sections(content_s, secs)
    has_cyber = contains_cyber_primary(content_s, secs)
    before = [str(x) for x in (contamination_before or []) if str(x).strip()]
    after = [str(x) for x in (contamination_after or []) if str(x).strip()]
    blockers = [str(x) for x in (blocking_errors or []) if str(x).strip()]

    if has_strategy and 'strategy_section_contamination' not in blockers:
        blockers.append('strategy_section_contamination')
        if 'الرؤية_والأهداف_الاستراتيجية' not in after:
            after.append('الرؤية_والأهداف_الاستراتيجية')
    if has_cyber and 'rel33_domain_contamination' not in ''.join(blockers):
        blockers.append('rel33_domain_contamination:erm_risk:cyber_primary')
        if 'cyber_primary' not in after:
            after.append('cyber_primary')

    loaded_type = str(loaded_artifact_type or '').strip().lower()
    loaded_dtype = str(loaded_document_type or '').strip().lower()
    loaded_dom = str(loaded_domain or '').strip().lower()
    if loaded_type in ('strategy', 'strategy_document') or loaded_dtype in (
            'strategy', 'strategy_document'):
        blockers.append('strategy_id_fallback_blocked')
    if loaded_dom in ('cyber', 'cyber security', 'cybersecurity') and dtype in (
            'risk', 'risk_assessment'):
        blockers.append('artifact_id_collision:cyber_strategy_on_erm_risk_export')

    if str(strategy_id or '').strip() and not str(risk_id or '').strip():
        blockers.append('strategy_id_used_as_risk_authority')

    passed = (
        dtype in ('risk', 'risk_assessment')
        and not has_strategy
        and not has_cyber
        and not blockers
    )
    return {
        'tag': REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG,
        'route': str(route or ''),
        'domain': dcode,
        'document_type': dtype,
        'lang': str(lang or 'ar'),
        'risk_id': str(risk_id or ''),
        'strategy_id': str(strategy_id or ''),
        'cache_key': cache_key or risk_cache_key(
            risk_id, domain=dcode or 'erm', document_type=dtype),
        'source_artifact_type': str(source_artifact_type or ''),
        'loaded_artifact_type': str(loaded_artifact_type or ''),
        'loaded_domain': str(loaded_domain or ''),
        'loaded_document_type': str(loaded_document_type or ''),
        'contains_strategy_sections': has_strategy,
        'contains_cyber_primary': has_cyber,
        'contamination_before': before,
        'contamination_after': after,
        'repair_applied': bool(repair_applied),
        'blocking_errors': list(dict.fromkeys(blockers)),
        'passed': bool(passed),
    }


def emit_rel36_6_erm_risk_domain_isolation(diag: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        'route': diag.get('route'),
        'domain': diag.get('domain'),
        'document_type': diag.get('document_type'),
        'lang': diag.get('lang'),
        'risk_id': diag.get('risk_id'),
        'strategy_id': diag.get('strategy_id'),
        'cache_key': diag.get('cache_key'),
        'source_artifact_type': diag.get('source_artifact_type'),
        'loaded_artifact_type': diag.get('loaded_artifact_type'),
        'loaded_domain': diag.get('loaded_domain'),
        'loaded_document_type': diag.get('loaded_document_type'),
        'contains_strategy_sections': bool(diag.get('contains_strategy_sections')),
        'contains_cyber_primary': bool(diag.get('contains_cyber_primary')),
        'contamination_before': list(diag.get('contamination_before') or []),
        'contamination_after': list(diag.get('contamination_after') or []),
        'repair_applied': bool(diag.get('repair_applied')),
        'blocking_errors': list(diag.get('blocking_errors') or []),
        'passed': bool(diag.get('passed')),
    }
    print(
        REL36_6_ERM_RISK_DOMAIN_ISOLATION_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, default=str),
        flush=True,
    )
    return payload
