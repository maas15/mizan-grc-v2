"""Domain pack registry — maps codes to REL2 packs."""

from domain_packs.artificial_intelligence import pack as ai_pack
from domain_packs.cyber import pack as cyber_pack
from domain_packs.data_management import pack as data_pack
from domain_packs.digital_transformation import pack as dt_pack
from domain_packs.enterprise_risk import pack as erm_pack
from domain_packs.global_standards import pack as global_pack

DOMAIN_PACKS = {
    'cyber': cyber_pack,
    'cyber_security': cyber_pack,
    'data': data_pack,
    'data_management': data_pack,
    'ai': ai_pack,
    'artificial_intelligence': ai_pack,
    'dt': dt_pack,
    'digital_transformation': dt_pack,
    'erm': erm_pack,
    'enterprise_risk_management': erm_pack,
    'global': global_pack,
    'global_standards': global_pack,
}


def get_domain_pack(code: str):
    c = (code or '').strip().lower()
    return DOMAIN_PACKS.get(c) or DOMAIN_PACKS.get(
        {
            'cyber_security': 'cyber',
            'data_management': 'data',
            'artificial_intelligence': 'ai',
            'digital_transformation': 'dt',
            'enterprise_risk_management': 'erm',
            'global_standards': 'global',
        }.get(c, c))
