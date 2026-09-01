"""REL36.10 — deterministic Data Arabic data_catalog roadmap top-up.

After PR #123 merged to main, official main-staging acceptance stopped:

    data_roadmap_balance_missing:data_catalog (roadmap) 0/1

REL36.7 / REL36.8.2 insert PDPL families only. ``data_catalog`` is an
NDMO balance family and still relied on a one-cycle AI top-up. The
unchanged official detector also does not map common Arabic catalog
wording (جرد أصول البيانات / سجل البيانات / ملكية البيانات /
قاموس البيانات) to ``data_catalog`` unless a detector token such as
``كتالوج البيانات`` is present.

This module inserts one detector-visible Arabic catalog row. It does
not weaken ``data_roadmap_balance_missing``, skip the save gate, or
remove existing PDPL family rows.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG = (
    '[REL36.10-DATA-CATALOG-ROADMAP-BALANCE]')

# Must stay aligned with app._DATA_ROADMAP_BALANCE_TOPICS['data_catalog'].
# Do not add extra tokens here — that would weaken the official gate.
DATA_CATALOG_DETECT_TOKENS = (
    'كتالوج البيانات', 'فهرس البيانات',
    'البيانات الوصفية', 'بيانات وصفية', 'ميتاداتا',
    'data catalog', 'data catalogue', 'metadata',
    'metadata management',
)

# Official PDPL tokens — aligned with REL36.7 / app balance topics.
PDPL_FAMILY_TOKENS = {
    'personal_data_classification': (
        'تصنيف البيانات الشخصية', 'تصنيف بيانات شخصية',
        'تصنيف البيانات', 'تصنيف الأصول البياناتية',
        'personal data classification', 'personal-data classification',
        'pii classification', 'data classification',
    ),
    'consent_management': (
        'إدارة الموافقات', 'الموافقة', 'موافقة صاحب البيانات',
        'consent management', 'consent', 'subject consent',
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

REQUIRED_PDPL_FAMILIES = (
    'personal_data_classification',
    'consent_management',
    'data_subject_rights',
    'breach_notification',
)

# Full official topic map for save-blocker computation. Tokens copied
# from app._DATA_ROADMAP_BALANCE_TOPICS — do not add extras.
_OFFICIAL_BALANCE_TOKENS = {
    'data_quality': (
        'جودة البيانات', 'إدارة جودة البيانات', 'مقاييس جودة البيانات',
        'data quality', 'data quality management', 'dq',
    ),
    'data_catalog': DATA_CATALOG_DETECT_TOKENS,
    'data_lifecycle': (
        'دورة حياة البيانات', 'الاحتفاظ بالبيانات', 'إتلاف البيانات',
        'أرشفة البيانات',
        'data lifecycle', 'data retention', 'data disposal',
        'data archiving', 'records lifecycle',
    ),
    'privacy_governance': (
        'حوكمة الخصوصية', 'خصوصية البيانات', 'حماية البيانات الشخصية',
        'ضوابط الخصوصية',
        'privacy governance', 'data privacy', 'privacy controls',
        'privacy program',
    ),
    **PDPL_FAMILY_TOKENS,
}

_BALANCE_BY_FRAMEWORK = {
    'NDMO': ('data_quality', 'data_catalog', 'data_lifecycle'),
    'PDPL': (
        'privacy_governance', 'consent_management',
        'data_subject_rights', 'personal_data_classification',
        'breach_notification',
    ),
}

_AR_CATALOG_ROW = (
    '| الربع 1 | إنشاء وتحديث كتالوج البيانات المؤسسي وجرد أصول '
    'البيانات وسجل البيانات وربطها بملكية البيانات ومصادرها مع قاموس '
    'البيانات | مكتب إدارة البيانات | كتالوج بيانات مؤسسي وسجل البيانات '
    'وجرد أصول البيانات محدث | NDMO | مكتمل جزئياً |'
)

_TABLE_HEADER_AR = (
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |'
)
_TABLE_SEP = '|---|---|---|---|---|---|'

_FORBIDDEN_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)

_NEAR_MISS_ARABIC = (
    'جرد أصول البيانات',
    'سجل البيانات',
    'ملكية البيانات',
    'قاموس البيانات',
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


def _norm_lang(lang: Any) -> str:
    return str(lang or '').strip().lower()


def ndmo_or_pdpl_selected(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = ' '.join(str(x) for x in (selected_frameworks or [])).lower()
    return (
        'ndmo' in blob
        or 'pdpl' in blob
        or 'حماية البيانات الشخصية' in blob
        or 'مكتب إدارة البيانات الوطنية' in blob
    )


def ndmo_selected(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = ' '.join(str(x) for x in (selected_frameworks or [])).lower()
    return 'ndmo' in blob


def pdpl_selected(selected_frameworks: Optional[Iterable[Any]]) -> bool:
    blob = ' '.join(str(x) for x in (selected_frameworks or [])).lower()
    return 'pdpl' in blob or 'حماية البيانات الشخصية' in blob


def rel36_10_should_apply(
        *,
        domain: Any,
        document_type: Any,
        lang: Any,
        selected_frameworks: Optional[Iterable[Any]],
) -> bool:
    return (
        _norm_domain(domain) == 'data'
        and _norm_doctype(document_type) == 'strategy'
        and _norm_lang(lang).startswith('ar')
        and ndmo_or_pdpl_selected(selected_frameworks)
    )


def data_catalog_present(text: str) -> bool:
    hay = str(text or '')
    hay_lc = hay.lower()
    return any((t.lower() in hay_lc) or (t in hay)
               for t in DATA_CATALOG_DETECT_TOKENS)


def detect_pdpl_families(text: str) -> List[str]:
    hay = str(text or '')
    hay_lc = hay.lower()
    found: List[str] = []
    for fam in REQUIRED_PDPL_FAMILIES:
        tokens = PDPL_FAMILY_TOKENS.get(fam, ())
        if any((t.lower() in hay_lc) or (t in hay) for t in tokens):
            found.append(fam)
    return found


def detect_balance_families(text: str) -> List[str]:
    hay = str(text or '')
    hay_lc = hay.lower()
    found: List[str] = []
    for fam, tokens in _OFFICIAL_BALANCE_TOKENS.items():
        if any((t.lower() in hay_lc) or (t in hay) for t in tokens):
            found.append(fam)
    return found


def required_balance_families(
        selected_frameworks: Optional[Iterable[Any]]) -> List[str]:
    required: List[str] = []
    seen = set()
    if ndmo_selected(selected_frameworks):
        for fam in _BALANCE_BY_FRAMEWORK['NDMO']:
            if fam not in seen:
                seen.add(fam)
                required.append(fam)
    if pdpl_selected(selected_frameworks):
        for fam in _BALANCE_BY_FRAMEWORK['PDPL']:
            if fam not in seen:
                seen.add(fam)
                required.append(fam)
    return required


def missing_balance_families(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    have = set(detect_balance_families(text))
    return [fam for fam in required_balance_families(selected_frameworks)
            if fam not in have]


def save_blockers_for(
        text: str,
        selected_frameworks: Optional[Iterable[Any]],
) -> List[str]:
    missing = missing_balance_families(text, selected_frameworks)
    if not missing:
        return []
    return [f'data_roadmap_balance_missing:{fam}' for fam in missing]


def count_roadmap_rows(text: str) -> int:
    n = 0
    sep_re = re.compile(r'^\|[\s\-:|]+\|$')
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if not (s.startswith('|') and s.endswith('|')):
            continue
        if sep_re.match(s):
            continue
        cells = [c.strip() for c in s.strip('|').split('|')]
        if cells[:3] in (
                ['المرحلة', 'الفترة', 'المبادرة'],
                ['Phase', 'Period', 'Initiative'],
                ['الربع', 'المبادرة', 'المسؤول'],
        ):
            continue
        n += 1
    return n


def _leak_terms(text: str) -> List[str]:
    hay = str(text or '')
    return [tok for tok in _FORBIDDEN_LEAKS if tok in hay]


def _splice_rows(original_text: str, new_rows: Sequence[str]) -> str:
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
        block = '\n'.join([_TABLE_HEADER_AR, _TABLE_SEP, *new_rows])
        return (text.rstrip() + ('\n\n' if text.strip() else '') + block + '\n')
    return '\n'.join(
        lines[:last_tbl_idx + 1] + list(new_rows) + lines[last_tbl_idx + 1:])


def evaluate_rel36_10_data_catalog_roadmap_balance(
        *,
        domain: Any,
        document_type: Any,
        lang: Any,
        selected_frameworks: Optional[Iterable[Any]],
        roadmap_text: str,
        roadmap_text_before: Optional[str] = None,
        repair_applied: bool = False,
        inserted_rows: Optional[Sequence[str]] = None,
        docx_allowed: Optional[bool] = None,
        pdf_allowed: Optional[bool] = None,
) -> Dict[str, Any]:
    before_text = (
        roadmap_text_before if roadmap_text_before is not None
        else roadmap_text)
    after_text = str(roadmap_text or '')
    fws = [str(x) for x in (selected_frameworks or [])]
    in_scope = rel36_10_should_apply(
        domain=domain, document_type=document_type, lang=lang,
        selected_frameworks=fws)
    families_before = detect_balance_families(before_text)
    families_after = detect_balance_families(after_text)
    missing_before = missing_balance_families(before_text, fws)
    missing_after = missing_balance_families(after_text, fws)
    catalog_before = data_catalog_present(before_text)
    catalog_after = data_catalog_present(after_text)
    pdpl_after = detect_pdpl_families(after_text)
    leaks = _leak_terms(after_text)
    blockers_before = save_blockers_for(before_text, fws) if in_scope else []
    blockers_after = save_blockers_for(after_text, fws) if in_scope else []
    if in_scope and leaks:
        blockers_after = list(blockers_after) + [
            f'forbidden_leak:{tok}' for tok in leaks]
    passed = (not in_scope) or (
        catalog_after
        and not missing_after
        and not leaks
        and not [b for b in blockers_after if b.startswith(
            'data_roadmap_balance_missing:')]
        and (docx_allowed is not False)
        and (pdf_allowed is not False)
    )
    if in_scope and not catalog_after:
        passed = False
    return {
        'domain': _norm_domain(domain) or str(domain or ''),
        'lang': str(lang or ''),
        'document_type': _norm_doctype(document_type),
        'selected_frameworks': fws,
        'roadmap_rows_before': count_roadmap_rows(before_text),
        'roadmap_rows_after': count_roadmap_rows(after_text),
        'families_before': families_before,
        'families_after': families_after,
        'missing_families_before': missing_before,
        'missing_families_after': missing_after,
        'data_catalog_present_before': catalog_before,
        'data_catalog_present_after': catalog_after,
        'pdpl_families_present_after': pdpl_after,
        'leakage_terms_after': leaks,
        'save_blockers_before': blockers_before,
        'save_blockers_after': [
            b for b in blockers_after
            if b.startswith('data_roadmap_balance_missing:')
        ],
        'docx_allowed': bool(docx_allowed) if docx_allowed is not None else None,
        'pdf_allowed': bool(pdf_allowed) if pdf_allowed is not None else None,
        'passed': passed,
        'repair_applied': bool(repair_applied),
        'inserted_rows': list(inserted_rows or []),
        'near_miss_arabic_without_detector': [
            tok for tok in _NEAR_MISS_ARABIC if tok in str(before_text or '')
        ] if not catalog_before else [],
        'in_scope': in_scope,
    }


def emit_rel36_10_data_catalog_roadmap_balance(
        diag: Dict[str, Any]) -> Dict[str, Any]:
    payload = {k: v for k, v in (diag or {}).items() if k != 'in_scope'}
    print(
        REL36_10_DATA_CATALOG_ROADMAP_BALANCE_TAG + ' '
        + json.dumps(payload, ensure_ascii=False, default=str),
        flush=True,
    )
    return diag


def apply_rel36_10_data_catalog_roadmap_balance(
        sections: Optional[Dict[str, Any]],
        *,
        domain: Any = 'data',
        document_type: Any = 'strategy',
        lang: Any = 'ar',
        selected_frameworks: Optional[Iterable[Any]] = None,
        emit: bool = True,
        docx_allowed: Optional[bool] = None,
        pdf_allowed: Optional[bool] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Insert a detector-visible data_catalog row. Idempotent."""
    secs = sections if isinstance(sections, dict) else {}
    before = str(secs.get('roadmap') or '')
    in_scope = rel36_10_should_apply(
        domain=domain, document_type=document_type, lang=lang,
        selected_frameworks=selected_frameworks)
    inserted: List[str] = []
    after = before
    if in_scope and not data_catalog_present(before):
        after = _splice_rows(before, [_AR_CATALOG_ROW])
        secs['roadmap'] = after
        inserted = ['data_catalog']
    diag = evaluate_rel36_10_data_catalog_roadmap_balance(
        domain=domain,
        document_type=document_type,
        lang=lang,
        selected_frameworks=selected_frameworks,
        roadmap_text=str(secs.get('roadmap') or after),
        roadmap_text_before=before,
        repair_applied=bool(inserted),
        inserted_rows=inserted,
        docx_allowed=docx_allowed,
        pdf_allowed=pdf_allowed,
    )
    if emit:
        emit_rel36_10_data_catalog_roadmap_balance(diag)
    return secs, diag
