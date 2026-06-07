from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.digital_transformation import pack as legacy

pack = build_pack(
    'digital_transformation',
    'Digital Transformation',
    'التحول الرقمي',
    legacy_pack=legacy,
    terminology_en={'dga': 'DGA', 'api': 'API'},
    terminology_ar={'dga': 'الحكومة الرقمية', 'api': 'واجهة برمجية'},
    objective_families=['digitisation', 'integration'],
    pillar_families=['channels', 'platform', 'data'],
    roadmap_families=['short', 'medium'],
    kpi_kri_families=['services', 'adoption'],
    risk_categories=['delivery', 'adoption'],
    governance_roles=['CDO', 'Program Director'],
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
