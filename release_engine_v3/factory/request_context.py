"""Factory request context for Final Document Factory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DocumentRequestContext:
    """Typed compile/export context — AI output is never authoritative."""

    domain: str
    document_type: str
    lang: str = 'ar'
    org_name: str = ''
    sector: str = ''
    frameworks: List[str] = field(default_factory=list)
    flags: Dict[str, Any] = field(default_factory=dict)
    backend: Dict[str, Any] = field(default_factory=dict)
    strategy_id: str = ''
    artifact_id: str = ''

    def normalized_domain(self) -> str:
        from release_engine_v3.domain_codes import normalize_domain_code
        return normalize_domain_code(self.domain or 'cyber', default='cyber')

    def normalized_document_type(self) -> str:
        dt = (self.document_type or 'strategy').strip().lower()
        aliases = {
            'strategy document': 'strategy',
            'policy document': 'policy',
            'procedure document': 'procedure',
            'risk register': 'risk',
            'risk assessment': 'risk',
            'audit report': 'audit',
            'audit / assessment': 'audit',
            'executive summary': 'executive_summary',
            'gap assessment': 'gap_assessment',
            'kpi/kri framework': 'kpi_framework',
            'governance model': 'governance_model',
            'erm framework': 'strategy',
            'risk appetite': 'risk',
            'risk report': 'risk',
            'compliance mapping': 'gap_assessment',
            'audit checklist': 'audit',
        }
        return aliases.get(dt, dt.replace(' ', '_'))
