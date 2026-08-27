"""REL36.7 — deterministic Data PDPL roadmap balance top-up.

When domain=data, document_type=strategy, and PDPL is selected, the
roadmap must include consent_management, data_subject_rights, and
breach_notification rows on the first official pass.

The prior path asked the AI to splice top-up rows inside one
convergence cycle. Official main staging failed after that single
cycle with:

    data_roadmap_balance_missing:consent_management,data_subject_rights,breach_notification

This module inserts Arabic (or English) detector-visible rows before
the roadmap balance gate. It does not weaken the gate, skip evidence,
or add cyber owners / NCA / NIST terms.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG = (
    '[REL36.7-DATA-PDPL-ROADMAP-BALANCE-REPAIR]')

REQUIRED_PDPL_ROADMAP_FAMILIES = (
    'consent_management',
    'data_subject_rights',
    'breach_notification',
)

# Must stay aligned with app._DATA_ROADMAP_BALANCE_TOPICS so inserted
# rows are detected by the unchanged balance checker.
FAMILY_DETECT_TOKENS = {
    'consent_management': (
        'إدارة الموافقات', 'الموافقة', 'موافقة صاحب البيانات',
        'consent management', 'consent', 'subject consent',
        'سجل الموافقات', 'الموافقة الصريحة',
    ),
    'data_subject_rights': (
        'حقوق صاحب البيانات', 'حقوق أصحاب البيانات', 'حقوق الأفراد',
        'حق الوصول', 'حق التصحيح', 'حق الحذف',
        'طلبات أصحاب البيانات',
        'data subject rights', 'dsr', 'subject access request',
        'sar', 'access request', 'rectification', 'erasure',
    ),
    'breach_notification': (
        'الإبلاغ عن الانتهاكات', 'إخطار الخروقات',
        'الإخطار بالخروقات', 'الإبلاغ عن خروقات البيانات',
        'الإبلاغ عن خرق البيانات', 'إشعار خرق البيانات',
        'آلية إخطار الخروقات',
        'breach notification', 'breach reporting',
        'data breach notification', 'incident notification',
    ),
}

_AR_ROWS = {
    'consent_management': (
        '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
        'أتمتة إدارة الموافقات | مسؤول حماية البيانات الشخصية | '
        'منصة موافقات وسجل موافقات موثق | PDPL |'
    ),
    'data_subject_rights': (
        '| المرحلة 2: تمكين وتشغيل (7-18 شهر) | 7-18 شهر | '
        'تفعيل إدارة طلبات أصحاب البيانات | مسؤول حماية البيانات الشخصية | '
        'إجراءات وقنوات DSR مفعلة ومؤشرات زمن استجابة | PDPL |'
    ),
    'breach_notification': (
        '| المرحلة 1: تأسيس (1-6 أشهر) | 1-6 أشهر | '
        'اعتماد إجراءات الإبلاغ عن الانتهاكات | مسؤول حماية البيانات الشخصية | '
        'خطة الإبلاغ عن الانتهاكات واختبار جاهزية خلال المهل النظامية | PDPL |'
    ),
}

_EN_ROWS = {
    'consent_management': (
        '| Phase 2: Enable and operate (7-18 months) | 7-18 months | '
        'Automate consent management | Personal Data Protection Officer | '
        'Consent platform and documented consent register | PDPL |'
    ),
    'data_subject_rights': (
        '| Phase 2: Enable and operate (7-18 months) | 7-18 months | '
        'Operationalize data subject rights requests | '
        'Personal Data Protection Officer | '
        'Active DSR channels and response-time indicators | PDPL |'
    ),
    'breach_notification': (
        '| Phase 1: Foundation (1-6 months) | 1-6 months | '
        'Adopt data breach notification procedures | '
        'Personal Data Protection Officer | '
        'Breach notification plan and readiness test within statutory deadlines | PDPL |'
    ),
}

_TABLE_HEADER_AR = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |'
)
_TABLE_HEADER_EN = (
    '| Phase | Period | Initiative | Owner | Expected deliverable | Framework |'
)
_TABLE_SEP = '|---|---|---|---|---|---|'

_FORBIDDEN_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)


def _norm_domain(domain: Any) -> str:
    raw = str(domain or '').strip()
    try:
        from release_engine_v3.domain_codes import normalize_domain_code
        return (normalize_domain_code(raw, default='') or raw).strip().lower()
    except Exception:  # noqa: BLE001
        low = raw.lower()
        if 'data' in low and 'cyber' not in low:
            return 'data'
        return low


def _norm_doctype(document_type: Any) -> str:
    return str(document_type or 'strategy').strip().lower() or 'strategy'


def pdpl_is_selected(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = ' '.join(str(x) for x in (selected_frameworks or [])).lower()
    return 'pdpl' in blob or 'حماية البيانات الشخصية' in blob


def detect_families(text: str) -> List[str]:
    hay = str(text or '')
    hay_lc = hay.lower()
    found: List[str] = []
    for fam in REQUIRED_PDPL_ROADMAP_FAMILIES:
        tokens = FAMILY_DETECT_TOKENS.get(fam, ())
        if any((t.lower() in hay_lc) or (t in hay) for t in tokens):
            found.append(fam)
    return found


def missing_families(text: str) -> List[str]:
    have = set(detect_families(text))
    return [fam for fam in REQUIRED_PDPL_ROADMAP_FAMILIES if fam not in have]


def _row_for(fam: str, lang: str) -> str:
    bank = _EN_ROWS if str(lang or '').lower().startswith('en') else _AR_ROWS
    return bank[fam]


def _splice_rows(original_text: str, new_rows: Sequence[str], *, lang: str) -> str:
    if not new_rows:
        return original_text or ''
    text = original_text or ''
    lines = text.split('\n')
    sep_re = re.compile(r'^\|[\s\-:|]+\|$')
    last_tbl_idx = -1
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('|') and s.endswith('|') and not sep_re.match(s):
            last_tbl_idx = idx
    if last_tbl_idx < 0:
        header = _TABLE_HEADER_EN if str(lang or '').lower().startswith('en') else _TABLE_HEADER_AR
        block = '\n'.join([header, _TABLE_SEP, *new_rows])
        return (text.rstrip() + ('\n\n' if text.strip() else '') + block + '\n')
    return '\n'.join(lines[:last_tbl_idx + 1] + list(new_rows) + lines[last_tbl_idx + 1:])


def _leak_errors(text: str) -> List[str]:
    hay = str(text or '')
    return [tok for tok in _FORBIDDEN_LEAKS if tok in hay]


def evaluate_rel36_7_data_pdpl_roadmap_balance(
        *,
        domain: Any,
        document_type: Any,
        lang: Any,
        selected_frameworks: Optional[Iterable[Any]],
        roadmap_text: str,
        repair_applied: bool = False,
        inserted_rows: Optional[Sequence[str]] = None,
        missing_before: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    dcode = _norm_domain(domain)
    dtype = _norm_doctype(document_type)
    fws = [str(x) for x in (selected_frameworks or [])]
    required = list(REQUIRED_PDPL_ROADMAP_FAMILIES)
    before = list(missing_before) if missing_before is not None else missing_families(roadmap_text)
    detected_before = [fam for fam in required if fam not in before]
    detected_after = detect_families(roadmap_text)
    missing_after = missing_families(roadmap_text)
    blocking = []
    in_scope = (
        dcode == 'data'
        and dtype == 'strategy'
        and pdpl_is_selected(fws)
    )
    if in_scope and missing_after:
        blocking.append(
            'data_roadmap_balance_missing:' + ','.join(missing_after))
    blocking.extend(f'forbidden_leak:{tok}' for tok in _leak_errors(roadmap_text))
    passed = (not in_scope) or (not missing_after and not blocking)
    return {
        'domain': dcode or str(domain or ''),
        'document_type': dtype,
        'lang': str(lang or ''),
        'selected_frameworks': fws,
        'required_families': required,
        'detected_families_before': detected_before,
        'missing_families_before': list(before),
        'inserted_rows': list(inserted_rows or []),
        'detected_families_after': detected_after,
        'missing_families_after': missing_after,
        'repair_applied': bool(repair_applied),
        'roadmap_balance_passed': not missing_after if in_scope else True,
        'blocking_errors': blocking,
        'passed': passed,
        'in_scope': in_scope,
    }


def emit_rel36_7_data_pdpl_roadmap_balance(diag: Dict[str, Any]) -> Dict[str, Any]:
    payload = {k: v for k, v in (diag or {}).items() if k != 'in_scope'}
    print(
        REL36_7_DATA_PDPL_ROADMAP_BALANCE_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, default=str),
        flush=True,
    )
    return diag


def apply_rel36_7_data_pdpl_roadmap_balance(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'data',
        document_type: Any = 'strategy',
        lang: Any = 'ar',
        selected_frameworks: Optional[Iterable[Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Insert missing PDPL roadmap rows in-place. Idempotent."""
    secs = sections if isinstance(sections, dict) else {}
    roadmap = str(secs.get('roadmap') or '')
    missing_before = missing_families(roadmap)
    in_scope = (
        _norm_domain(domain) == 'data'
        and _norm_doctype(document_type) == 'strategy'
        and pdpl_is_selected(selected_frameworks)
    )
    inserted: List[str] = []
    if in_scope and missing_before:
        lang_key = 'en' if str(lang or '').lower().startswith('en') else 'ar'
        rows = [_row_for(fam, lang_key) for fam in missing_before]
        roadmap = _splice_rows(roadmap, rows, lang=lang_key)
        secs['roadmap'] = roadmap
        inserted = list(missing_before)
    diag = evaluate_rel36_7_data_pdpl_roadmap_balance(
        domain=domain,
        document_type=document_type,
        lang=lang,
        selected_frameworks=selected_frameworks,
        roadmap_text=str(secs.get('roadmap') or roadmap),
        repair_applied=bool(inserted),
        inserted_rows=inserted,
        missing_before=missing_before,
    )
    if emit:
        emit_rel36_7_data_pdpl_roadmap_balance(diag)
    return secs, diag
