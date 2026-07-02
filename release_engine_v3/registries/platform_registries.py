"""PR-REL3.3 — unified platform registries (domain + document-type aware)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from release_engine.traceability_substance_model import TRACE_CANONICAL_REGISTRY
from release_engine_v3.rel32_registries import (
    ARABIC_CANONICAL_REPAIR_REGISTRY,
    GAP_FAMILY_REGISTRY,
    GOVERNANCE_ROLE_REGISTRY,
    KPI_CANONICAL_REGISTRY_FULL,
    PILLAR_INITIATIVE_REGISTRY,
    RISK_TREATMENT_REGISTRY,
    ROADMAP_FAMILY_REGISTRY,
    STRATEGIC_OBJECTIVE_REGISTRY,
    TRACEABILITY_CANONICAL_REGISTRY,
)

# Unify family IDs used across trace / roadmap / DQS layers.
CANONICAL_FAMILY_ALIASES: Dict[str, str] = {
    'sensitive_data_handling': 'sensitive_handling',
    'sensitive_data': 'sensitive_handling',
    'ecc_soc_monitoring': 'ecc_soc',
    'soc_monitoring': 'ecc_soc',
    'soc_siem': 'ecc_soc',
}

DOMAIN_CAPABILITY_REGISTRY: Dict[str, Tuple[str, ...]] = {
    'cyber': (
        'governance', 'soc', 'iam', 'incident_response', 'vulnerability',
        'data_protection', 'awareness', 'backup_dr',
    ),
    'data': (
        'data_governance', 'data_quality', 'metadata', 'privacy',
        'data_security', 'data_sharing', 'lifecycle',
    ),
    'ai': (
        'ai_governance', 'model_risk', 'bias_fairness', 'explainability',
        'data_lineage', 'human_oversight',
    ),
    'dt': (
        'digital_strategy', 'platform_modernization', 'cloud', 'api',
        'customer_experience', 'agile_delivery',
    ),
    'erm': (
        'risk_governance', 'risk_appetite', 'risk_register', 'controls',
        'reporting', 'culture',
    ),
    'global': (
        'compliance_mapping', 'gap_assessment', 'audit_evidence',
        'control_library', 'certification',
    ),
}

DOCUMENT_TYPE_SCHEMA_REGISTRY: Dict[str, Dict[str, Any]] = {
    'strategy': {
        'sections': (
            'vision', 'pillars', 'environment', 'gaps', 'roadmap',
            'kpis', 'confidence', 'governance', 'traceability',
        ),
        'min_consulting_grade': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'policy': {
        'sections': ('purpose', 'scope', 'roles', 'controls', 'exceptions'),
        'min_compliance_structure': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'procedure': {
        'sections': ('purpose', 'steps', 'roles', 'inputs', 'outputs'),
        'min_operational_actionability': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'risk': {
        'sections': ('register', 'heatmap', 'appetite', 'treatments'),
        'min_risk_completeness': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'audit': {
        'sections': ('scope', 'findings', 'evidence', 'recommendations'),
        'min_evidence_traceability': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'roadmap': {
        'sections': ('phases', 'initiatives', 'owners', 'deliverables'),
        'min_initiative_coverage': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'executive_summary': {
        'sections': ('decision', 'priorities', 'risks', 'ask'),
        'min_executive_readiness': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'gap_assessment': {
        'sections': ('scope', 'gaps', 'guides', 'remediation'),
        'min_consulting_grade': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'kpi_framework': {
        'sections': ('kpi_main', 'kpi_formula', 'assessment_guides'),
        'min_consulting_grade': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
    'governance_model': {
        'sections': ('roles', 'committees', 'escalation', 'raci'),
        'min_compliance_structure': 90,
        'routes': ('preview', 'docx', 'pdf'),
    },
}

FRAMEWORK_TRACEABILITY_REGISTRY = TRACEABILITY_CANONICAL_REGISTRY
GAP_REGISTRY = GAP_FAMILY_REGISTRY
KPI_KRI_REGISTRY = KPI_CANONICAL_REGISTRY_FULL
ROADMAP_REGISTRY = ROADMAP_FAMILY_REGISTRY
RISK_TREATMENT_REGISTRY_OUT = RISK_TREATMENT_REGISTRY
POLICY_CONTROL_REGISTRY: Dict[str, Any] = {}
PROCEDURE_STEP_REGISTRY: Dict[str, Any] = {}
AUDIT_EVIDENCE_REGISTRY: Dict[str, Any] = {}
ARABIC_POLISH_REGISTRY: Tuple[Tuple[str, str], ...] = ARABIC_CANONICAL_REPAIR_REGISTRY
ENGLISH_POLISH_REGISTRY: Tuple[Tuple[str, str], ...] = ()
EXECUTIVE_RENDERING_REGISTRY: Dict[str, Any] = {
    'gap_action_min_rows': 3,
    'framework_labels_concise': True,
    'hide_diagnostics_in_user_output': True,
}


def normalize_canonical_family(family_id: str) -> str:
    """Map legacy/alternate family IDs to one canonical registry key."""
    fid = (family_id or '').strip()
    if not fid:
        return fid
    if fid in TRACE_CANONICAL_REGISTRY:
        return fid
    alias = CANONICAL_FAMILY_ALIASES.get(fid)
    if alias and alias in TRACE_CANONICAL_REGISTRY:
        return alias
    if alias:
        for k in TRACE_CANONICAL_REGISTRY:
            if normalize_canonical_family(k) == alias:
                return k
    return fid


def immutable_traceability_row(family_id: str) -> Optional[Dict[str, str]]:
    """Return frozen traceability row from canonical registry (no inference)."""
    fam = normalize_canonical_family(family_id)
    if fam not in TRACE_CANONICAL_REGISTRY:
        return None
    spec = TRACE_CANONICAL_REGISTRY[fam]
    return {
        'family': fam,
        'framework': spec['framework'],
        'capability': spec['capability'],
        'gap': spec['expected_gap'],
        'initiative': spec['initiative'],
        'metric': spec['metric'],
        'risk': spec['risk'],
    }


def resolve_registries(
        *,
        domain: str,
        document_type: str,
        lang: str = 'ar',
) -> Dict[str, Any]:
    """Return registry bundle for domain × document_type × lang."""
    d = (domain or 'cyber').strip().lower()
    dt = (document_type or 'strategy').strip().lower()
    schema = DOCUMENT_TYPE_SCHEMA_REGISTRY.get(dt, {})
    return {
        'domain': d,
        'document_type': dt,
        'lang': lang,
        'schema': schema,
        'capabilities': DOMAIN_CAPABILITY_REGISTRY.get(d, ()),
        'gap': GAP_REGISTRY,
        'roadmap': ROADMAP_REGISTRY,
        'kpi': KPI_KRI_REGISTRY,
        'traceability': TRACEABILITY_CANONICAL_REGISTRY,
        'risk': RISK_TREATMENT_REGISTRY_OUT,
        'governance': GOVERNANCE_ROLE_REGISTRY,
        'pillars': PILLAR_INITIATIVE_REGISTRY,
        'objectives': STRATEGIC_OBJECTIVE_REGISTRY,
        'arabic_polish': ARABIC_POLISH_REGISTRY,
        'executive_rendering': EXECUTIVE_RENDERING_REGISTRY,
    }
