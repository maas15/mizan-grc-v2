"""Domain pack registry."""

from domains.ai import pack as ai_pack
from domains.cyber import pack as cyber_pack
from domains.data import pack as data_pack
from domains.digital_transformation import pack as dt_pack
from domains.enterprise_risk import pack as erm_pack
from domains.global_standards import pack as global_pack

DOMAIN_PACKS = {
    'cyber': cyber_pack,
    'data': data_pack,
    'ai': ai_pack,
    'dt': dt_pack,
    'erm': erm_pack,
    'global': global_pack,
}


def get_domain_pack(code: str):
    c = (code or '').strip().lower()
    aliases = {
        'cyber_security': 'cyber',
        'data_management': 'data',
        'artificial_intelligence': 'ai',
        'digital_transformation': 'dt',
        'enterprise_risk_management': 'erm',
        'global_standards': 'global',
    }
    c = aliases.get(c, c)
    return DOMAIN_PACKS.get(c)
