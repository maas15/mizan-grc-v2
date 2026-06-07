from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.data import pack as legacy

pack = build_pack(
    'data_management',
    'Data Management',
    'إدارة البيانات',
    legacy_pack=legacy,
    terminology_en={'cdo': 'CDO', 'dg': 'Data Governance'},
    terminology_ar={'cdo': 'مدير البيانات', 'dg': 'حوكمة البيانات'},
    objective_families=['governance', 'quality', 'stewardship'],
    pillar_families=['governance', 'architecture', 'quality'],
    roadmap_families=['foundation', 'operational'],
    kpi_kri_families=['quality', 'coverage'],
    risk_categories=['quality', 'privacy', 'access'],
    governance_roles=['CDO', 'Data Steward', 'DPO'],
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
