from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.ai import pack as legacy

pack = build_pack(
    'artificial_intelligence',
    'Artificial Intelligence',
    'الذكاء الاصطناعي',
    legacy_pack=legacy,
    terminology_en={'ai': 'AI', 'model': 'Model'},
    terminology_ar={'ai': 'ذكاء اصطناعي', 'model': 'نموذج'},
    objective_families=['governance', 'inventory', 'risk'],
    pillar_families=['governance', 'lifecycle', 'monitoring'],
    roadmap_families=['inventory', 'controls'],
    kpi_kri_families=['inventory', 'bias'],
    risk_categories=['model', 'bias', 'privacy'],
    governance_roles=['AI Officer', 'CRO', 'Legal'],
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
