from domain_packs import _noisy_shared
from domain_packs._base import build_pack
from domains.cyber import pack as legacy

pack = build_pack(
    'cyber',
    'Cyber Security',
    'الأمن السيبراني',
    legacy_pack=legacy,
    terminology_en={'ciso': 'CISO', 'soc': 'SOC', 'dcc': 'DCC'},
    terminology_ar={'ciso': 'مدير أمن المعلومات', 'soc': 'مركز العمليات', 'dcc': 'حماية البيانات'},
    objective_families=['governance', 'operations', 'data_protection', 'compliance'],
    pillar_families=['governance', 'protection', 'detection', 'response'],
    roadmap_families=['foundation', 'enablement', 'sustainment', 'dcc'],
    kpi_kri_families=['detection', 'response', 'compliance', 'data'],
    risk_categories=['operational', 'regulatory', 'third_party'],
    governance_roles=['CISO', 'DPO', 'SOC Manager', 'Board'],
    traceability_requirements={'required': True, 'min_trace_markers': 0},
)

pack['noisy_sections'] = lambda clean: _noisy_shared.apply_noisy_mutations(clean)
