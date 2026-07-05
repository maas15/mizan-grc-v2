"""PR-REL3.2 — deterministic registries for compiler-first strategy documents."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from cyber_board_ready_prcy88 import (
    PRCY88_ARABIC_FIXES,
    PRCY88_KPI_CATALOG_AR,
    PRCY88_KPI_FAMILIES,
    PRCY88_ROADMAP_CATALOG_AR,
    PRCY88_ROADMAP_FAMILIES,
    PRCY88_SO_CATALOG_AR,
    PRCY88_SO_FAMILIES,
)
from release_engine.kpi_model import KPI_CANONICAL_REGISTRY
from release_engine.pillar_model import CYBER_PILLAR_FAMILIES, _PILLAR_CATALOG_AR
from release_engine.roadmap_model import ROADMAP_FAMILIES, _ROADMAP_CATALOG_AR
from release_engine.risk_treatment_model import _RISK_TREATMENTS_AR
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    _DCC_REGISTRY_ORDER,
    _ECC_REGISTRY_ORDER,
)

# ── Hardcoded REL3.2 canonical section headings (never from AI) ─────────────
REL32_CANONICAL_HEADINGS: Dict[str, str] = {
    'vision': 'الرؤية والأهداف الاستراتيجية',
    'pillars': 'الركائز الاستراتيجية',
    'environment': 'البيئة التنظيمية والتهديدات',
    'gaps': 'تحليل الفجوات',
    'roadmap': 'خارطة الطريق التنفيذية',
    'kpis': 'مؤشرات الأداء الرئيسية',
    'confidence': 'تقييم الثقة والمخاطر',
    'governance': 'نموذج الحوكمة والمسؤوليات',
    'traceability': 'مصفوفة تتبع الأطر المرجعية',
}

REL32_SECTION_ORDER: Tuple[str, ...] = (
    'vision', 'pillars', 'environment', 'gaps', 'roadmap',
    'kpis', 'confidence', 'governance', 'traceability', 'appendices',
)

# ── Gap families derived from traceability canonical registry ───────────────
GAP_FAMILY_REGISTRY: Dict[str, Dict[str, str]] = {}
for _fam, _spec in TRACE_CANONICAL_REGISTRY.items():
    _gap = _spec['expected_gap']
    GAP_FAMILY_REGISTRY[_fam] = {
        'gap_label': _gap,
        'description': _spec['initiative'],
        'priority': 'عالية' if 'غياب' in _gap else 'متوسطة',
        'status': 'مفتوحة',
        'framework': _spec['framework'],
        'treatment': _spec['initiative'],
        'owner': (
            'مدير حماية البيانات' if _spec['framework'] == 'NCA DCC'
            else 'CISO'),
    }

GAP_FAMILY_ORDER: Tuple[str, ...] = _DCC_REGISTRY_ORDER + _ECC_REGISTRY_ORDER

# ── Roadmap family registry ─────────────────────────────────────────────────
ROADMAP_FAMILY_REGISTRY: Dict[str, Tuple[str, ...]] = {
    fam: tuple(PRCY88_ROADMAP_CATALOG_AR.get(fam) or _ROADMAP_CATALOG_AR.get(fam) or ())
    for fam in ROADMAP_FAMILIES
}

# ── KPI canonical registry (REL3 + PRCY88 merged) ───────────────────────────
KPI_CANONICAL_REGISTRY_FULL: Dict[str, Dict[str, str]] = dict(
    KPI_CANONICAL_REGISTRY)
for _kf in PRCY88_KPI_FAMILIES:
    if _kf in PRCY88_KPI_CATALOG_AR:
        _cells = PRCY88_KPI_CATALOG_AR[_kf]
        # PRCY88 catalog order: … | source | owner | frequency |
        KPI_CANONICAL_REGISTRY_FULL[_kf] = {
            'label_ar': _cells[1],
            'kpi_type': _cells[2],
            'target': _cells[3],
            'formula': _cells[4],
            'source': _cells[5],
            'owner': _cells[6] if len(_cells) > 6 else 'CISO',
            'frequency': _cells[7] if len(_cells) > 7 else 'شهري',
        }

# ── Traceability canonical registry ─────────────────────────────────────────
TRACEABILITY_CANONICAL_REGISTRY = TRACE_CANONICAL_REGISTRY
TRACEABILITY_FAMILY_ORDER: Tuple[str, ...] = GAP_FAMILY_ORDER

# ── Pillar initiative registry ──────────────────────────────────────────────
PILLAR_INITIATIVE_REGISTRY: Dict[str, Tuple[Tuple[str, str, str], ...]] = {}
for _pi, _fam in enumerate(CYBER_PILLAR_FAMILIES):
    if _pi < len(_PILLAR_CATALOG_AR):
        PILLAR_INITIATIVE_REGISTRY[_fam] = _PILLAR_CATALOG_AR[_pi][1]

# ── Strategic objective registry ────────────────────────────────────────────
STRATEGIC_OBJECTIVE_REGISTRY: Dict[str, Tuple[str, ...]] = {
    fam: PRCY88_SO_CATALOG_AR[fam]
    for fam in PRCY88_SO_FAMILIES
    if fam in PRCY88_SO_CATALOG_AR
}

# ── Governance role registry (cyber) ────────────────────────────────────────
GOVERNANCE_ROLE_REGISTRY: Dict[str, Dict[str, str]] = {
    'ciso': {
        'role': 'CISO / رئيس الأمن السيبراني',
        'scope': 'قيادة برنامج الأمن السيبراني والحوكمة والامتثال',
        'accountability': 'الإدارة العليا ومجلس الإدارة',
        'escalation': 'تقرير ربع سنوي للجنة الحوكمة',
        'framework': 'NCA ECC',
    },
    'soc_manager': {
        'role': 'مدير SOC',
        'scope': 'تشغيل مركز العمليات الأمنية وSIEM والكشف',
        'accountability': 'CISO',
        'escalation': 'تصعيد الحوادث الحرجة لقائد CSIRT',
        'framework': 'NCA ECC',
    },
    'csirt_lead': {
        'role': 'قائد CSIRT',
        'scope': 'الاستجابة للحوادث وخطط الاحتواء والتعافي',
        'accountability': 'CISO',
        'escalation': 'تصعيد للإدارة العليا خلال SLA',
        'framework': 'NCA ECC',
    },
    'iam_manager': {
        'role': 'مدير IAM/PAM',
        'scope': 'إدارة الهوية والوصول والصلاحيات المميزة وMFA',
        'accountability': 'CISO',
        'escalation': 'تقرير شهري لجنة الحوكمة',
        'framework': 'NCA ECC',
    },
    'dpo': {
        'role': 'مدير حماية البيانات',
        'scope': 'تصنيف البيانات والتشفير وDLP وحماية البيانات الحساسة',
        'accountability': 'CISO',
        'escalation': 'تقرير ربع سنوي لجنة الحوكمة',
        'framework': 'NCA DCC',
    },
    'compliance_manager': {
        'role': 'مدير الامتثال',
        'scope': 'متابعة امتثال NCA ECC وNCA DCC والمراجعات',
        'accountability': 'CISO',
        'escalation': 'تقرير امتثال ربع سنوي',
        'framework': 'NCA ECC / DCC',
    },
    'bcp_manager': {
        'role': 'مدير استمرارية الأعمال',
        'scope': 'النسخ الاحتياطي والتعافي من الكوارث وخطط BCP',
        'accountability': 'CISO',
        'escalation': 'تقرير اختبارات DR سنوياً',
        'framework': 'NCA ECC',
    },
}

# ── Risk treatment registry ─────────────────────────────────────────────────
RISK_TREATMENT_REGISTRY: Dict[str, str] = dict(_RISK_TREATMENTS_AR)

# ── Arabic canonical repair registry ──────────────────────────────────────────
ARABIC_CANONICAL_REPAIR_REGISTRY: Tuple[Tuple[str, str], ...] = tuple(
    PRCY88_ARABIC_FIXES)

# ── Confidence factors (weights must sum to 100%) ───────────────────────────
CONFIDENCE_FACTOR_REGISTRY: Tuple[Tuple[str, str], ...] = (
    ('اكتمال المدخلات', '20%'),
    ('تغطية الأطر المرجعية', '20%'),
    ('جدوى خارطة الطريق', '20%'),
    ('جاهزية الموارد', '15%'),
    ('نضج الحوكمة', '15%'),
    ('جاهزية حماية البيانات', '10%'),
)

DEFAULT_CONFIDENCE_SCORE = '76%'
DEFAULT_CONFIDENCE_RATIONALE = (
    'تقييم مبني على اكتمال المدخلات وتغطية الأطر المرجعية '
    'وجدوى خارطة الطريق وجاهزية الموارد ونضج الحوكمة '
    'وجاهزية حماية البيانات.')


def registry_schema_version() -> str:
    return 'rel32.0'


def emit_rel32_registry_diag() -> Dict[str, Any]:
    return {
        'schema': registry_schema_version(),
        'gap_families': len(GAP_FAMILY_REGISTRY),
        'roadmap_families': len(ROADMAP_FAMILY_REGISTRY),
        'kpi_families': len(KPI_CANONICAL_REGISTRY_FULL),
        'trace_families': len(TRACEABILITY_CANONICAL_REGISTRY),
        'pillar_families': len(PILLAR_INITIATIVE_REGISTRY),
        'governance_roles': len(GOVERNANCE_ROLE_REGISTRY),
        'risk_themes': len(RISK_TREATMENT_REGISTRY),
    }
