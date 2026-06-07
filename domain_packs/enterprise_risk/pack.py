from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.enterprise_risk import pack as legacy

pack = build_pack(
    'enterprise_risk_management',
    'Enterprise Risk Management',
    'إدارة المخاطر المؤسسية',
    legacy_pack=legacy,
    terminology_en={'erm': 'ERM', 'cro': 'CRO'},
    terminology_ar={'erm': 'مخاطر مؤسسية', 'cro': 'مدير المخاطر'},
    objective_families=['framework', 'appetite', 'culture'],
    pillar_families=['governance', 'assessment', 'reporting'],
    roadmap_families=['setup', 'embed'],
    kpi_kri_families=['coverage', 'maturity'],
    risk_categories=['strategic', 'operational', 'compliance'],
    governance_roles=['CRO', 'Board', 'Risk Committee'],
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
