"""User-provided sector operating context for REL37 strategies.

The selected sector is request context, not a framework selection and not
proof of regulatory applicability or compliance. Labels are limited to the
documented Data Management UI options.
"""
from __future__ import annotations

from typing import Dict, Iterable, Optional, Set, Tuple

# Exact option values from app.py TEXT['en'|'ar']['sectors'].
UI_SECTOR_PAIRS: Tuple[Tuple[str, str], ...] = (
    ('Government', 'حكومي'),
    ('Banking/Finance', 'بنوك/مالي'),
    ('Healthcare', 'رعاية صحية'),
    ('Energy', 'طاقة'),
    ('Telecom', 'اتصالات'),
    ('Retail', 'تجزئة'),
    ('Manufacturing', 'تصنيع'),
)

# Same skip set as validate_strategy_fail_closed check F.
GENERIC_SECTORS = frozenset({
    'General', 'general', 'حكومي', 'Government',
    'Not specified', 'غير محدد',
})


def request_sector(payload: Optional[Dict] = None) -> str:
    return str((payload or {}).get('sector') or '').strip()


def present_sector_label(sector: str, lang: str) -> str:
    """Language-correct UI label. Unknown values stay exact."""
    raw = str(sector or '').strip()
    if not raw:
        return ''
    lang_n = 'ar' if str(lang or '').lower().startswith('ar') else 'en'
    for english, arabic in UI_SECTOR_PAIRS:
        if raw in (english, arabic):
            return arabic if lang_n == 'ar' else english
    return raw


def sector_reference_aliases(sector: str) -> Set[str]:
    raw = str(sector or '').strip()
    aliases = {raw} if raw else set()
    for english, arabic in UI_SECTOR_PAIRS:
        if raw in (english, arabic):
            aliases.update({english, arabic})
            break
    return {item for item in aliases if item}


def is_generic_sector(sector: str) -> bool:
    raw = str(sector or '').strip()
    if not raw:
        return True
    if raw in GENERIC_SECTORS:
        return True
    return raw.lower() in {item.lower() for item in GENERIC_SECTORS}


def _haystack_without_org(env_txt: str, org_name: str = '') -> str:
    haystack = str(env_txt or '')
    org = str(org_name or '').strip()
    if org:
        haystack = haystack.replace(org, ' ')
    return haystack


def environment_mentions_requested_sector(
        env_txt: str,
        sector: str,
        org_name: str = '',
) -> bool:
    """True when required sector context is present, or the check is skipped.

    Generic / empty sectors keep the existing omission contract. A match
    that exists only inside org_name does not count.
    """
    raw = str(sector or '').strip()
    if is_generic_sector(raw):
        return True
    haystack = _haystack_without_org(env_txt, org_name)
    hay_l = haystack.lower()
    for alias in sector_reference_aliases(raw):
        if any(ord(ch) > 127 for ch in alias):
            if alias in haystack:
                return True
            continue
        if alias.lower() in hay_l:
            return True
    return False


def operating_context_clause(sector: str, lang: str) -> str:
    presented = present_sector_label(sector, lang)
    if not presented:
        return ''
    if str(lang or '').lower().startswith('ar'):
        return f'في سياق تشغيلي لقطاع {presented}'
    return f'in the {presented} sector operating context'


def environment_narrative_paragraphs(narrative: str) -> list:
    """Keep the persisted narrative intact; do not invent extra clauses."""
    import re
    return [
        part.strip()
        for part in re.split(r'\n\s*\n', str(narrative or '').strip())
        if part.strip()
    ]


def cover_sector_from_hashed_narrative(narrative: str, lang: str) -> str:
    """Cover sector from the hashed environment narrative only.

    ``model.sector`` is HASH_EXCLUDED provenance and is not consulted.
    A post-save raw provenance change therefore cannot silently change
    the cover while the hashed body stays unchanged. Documents with no
    UI-pair mention return '' so the existing legacy/neutral cover (—)
    is used. Client Healthcare is never inferred.
    """
    hay = str(narrative or '')
    if not hay.strip():
        return ''
    lang_n = 'ar' if str(lang or '').lower().startswith('ar') else 'en'
    earliest = None
    chosen = ''
    for english, arabic in UI_SECTOR_PAIRS:
        for alias in (english, arabic):
            idx = hay.find(alias)
            if idx < 0:
                continue
            if earliest is None or idx < earliest:
                earliest = idx
                chosen = arabic if lang_n == 'ar' else english
    return chosen


def sector_runtime_diagnostics(sector: str, lang: str) -> Dict[str, str]:
    raw = str(sector or '').strip()
    return {
        'request_sector': raw,
        'presented_sector': present_sector_label(raw, lang),
    }


def supported_ui_sectors(lang: str) -> Iterable[str]:
    lang_n = 'ar' if str(lang or '').lower().startswith('ar') else 'en'
    for english, arabic in UI_SECTOR_PAIRS:
        yield arabic if lang_n == 'ar' else english
