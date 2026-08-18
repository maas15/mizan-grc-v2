"""Canonical domain code normalization (shared by REL3.1/REL3.3 authority)."""

from __future__ import annotations

_DOMAIN_CODE_MAP = {
    'cyber security': 'cyber',
    'cybersecurity': 'cyber',
    'cyber_security': 'cyber',
    'cyber': 'cyber',
    'الأمن السيبراني': 'cyber',
    'data management': 'data',
    'data_management': 'data',
    'data': 'data',
    'إدارة البيانات': 'data',
    'artificial intelligence': 'ai',
    'artificial_intelligence': 'ai',
    'ai': 'ai',
    'الذكاء الاصطناعي': 'ai',
    'digital transformation': 'dt',
    'digital_transformation': 'dt',
    'dt': 'dt',
    'التحول الرقمي': 'dt',
    'global standards': 'global',
    'global_standards': 'global',
    'global': 'global',
    'المعايير العالمية': 'global',
    'enterprise risk management': 'erm',
    'enterprise_risk_management': 'erm',
    'erm': 'erm',
    'إدارة المخاطر المؤسسية': 'erm',
}


def normalize_domain_code(raw: str, *, default: str = '') -> str:
    """Map display/slug/Arabic domain labels to canonical REL3.3 codes."""
    if not raw or not str(raw).strip():
        return default
    key = str(raw).strip().lower().replace('-', '_')
    key_sp = key.replace('_', ' ')
    if key in _DOMAIN_CODE_MAP:
        return _DOMAIN_CODE_MAP[key]
    if key_sp in _DOMAIN_CODE_MAP:
        return _DOMAIN_CODE_MAP[key_sp]
    compact = str(raw).strip().lower().replace('-', ' ').replace('_', ' ')
    if compact in _DOMAIN_CODE_MAP:
        return _DOMAIN_CODE_MAP[compact]
    if 'cyber' in compact or 'سيبر' in str(raw):
        return 'cyber'
    return default or key.replace(' ', '_')
