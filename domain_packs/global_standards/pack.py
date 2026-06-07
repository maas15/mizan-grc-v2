from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.global_standards import pack as legacy

pack = build_pack(
    'global_standards',
    'Global / International Standards',
    'المعايير الدولية',
    legacy_pack=legacy,
    terminology_en={'iso': 'ISO', 'nist': 'NIST'},
    terminology_ar={'iso': 'آيزو', 'nist': 'نست'},
    objective_families=['alignment', 'controls'],
    pillar_families=['governance', 'operations'],
    roadmap_families=['baseline', 'maturity'],
    kpi_kri_families=['coverage', 'assessment'],
    risk_categories=['compliance', 'operational'],
    governance_roles=['CISO', 'Compliance Officer'],
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
