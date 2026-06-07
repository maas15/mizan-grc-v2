"""PR-REL2 domain pack base — extends legacy domains/ packs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from framework_catalogs.catalog import catalog_for_domain

MANDATORY_CANONICAL_SECTIONS = [
    'vision_objectives',
    'pillars',
    'environment',
    'gap_analysis',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
]

DOCUMENT_TYPES = [
    'strategy', 'policy', 'procedure', 'risk_register',
    'audit', 'roadmap', 'executive_summary', 'kpi_kri',
    'gap_assessment', 'traceability_matrix',
]


def build_pack(
        code: str,
        display_en: str,
        display_ar: str,
        *,
        legacy_pack: Dict[str, Any],
        terminology_en: Dict[str, str],
        terminology_ar: Dict[str, str],
        objective_families: List[str],
        pillar_families: List[str],
        roadmap_families: List[str],
        kpi_kri_families: List[str],
        risk_categories: List[str],
        governance_roles: List[str],
        traceability_requirements: Optional[Dict[str, Any]] = None,
        scoring_weights: Optional[Dict[str, float]] = None,
        board_rules: Optional[Dict[str, Any]] = None,
        technical_rules: Optional[Dict[str, Any]] = None,
        noisy_fixtures_module=None,
) -> Dict[str, Any]:
    fw_ids = legacy_pack.get('frameworks_default') or []
    catalog = catalog_for_domain(code)
    return {
        **legacy_pack,
        'pack_version': 'rel2',
        'code': code,
        'display_en': display_en,
        'display_ar': display_ar,
        'mandatory_canonical_sections': list(MANDATORY_CANONICAL_SECTIONS),
        'document_types': list(DOCUMENT_TYPES),
        'framework_catalog_ids': [e['framework_id'] for e in catalog] or fw_ids,
        'framework_catalog': catalog,
        'terminology_en': terminology_en,
        'terminology_ar': terminology_ar,
        'mandatory_objective_families': objective_families,
        'mandatory_pillar_families': pillar_families,
        'mandatory_roadmap_families': roadmap_families,
        'kpi_kri_families': kpi_kri_families,
        'risk_categories': risk_categories,
        'governance_raci_roles': governance_roles,
        'traceability_requirements': traceability_requirements or {'required': False},
        'scoring_weights': scoring_weights or {},
        'board_output_rules': board_rules or {'min_objectives': 3},
        'technical_output_rules': technical_rules or {'min_objectives': 3},
        'policy_procedure_templates': {'policy': 'rel2_policy_v1', 'procedure': 'rel2_procedure_v1'},
        'audit_risk_roadmap_requirements': {
            'audit': ['scope', 'criteria', 'findings'],
            'risk_register': ['risk_id', 'owner', 'treatment'],
            'roadmap': ['phase', 'owner', 'timeline'],
        },
        'noisy_fixtures': noisy_fixtures_module,
    }
