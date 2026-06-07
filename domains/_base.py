"""Shared domain pack fields."""

MANDATORY_CANONICAL_SECTIONS = [
    'vision_objectives',
    'pillars',
    'environment',
    'gap_analysis',
    'roadmap',
    'kpi_kri',
    'confidence_risk',
]

MANDATORY_LEGACY_SECTIONS = [
    'vision', 'pillars', 'environment', 'gaps',
    'roadmap', 'kpis', 'confidence',
]


def pack(
        code: str,
        display_en: str,
        display_ar: str,
        *,
        fixtures_ar,
        fixtures_en,
        frameworks=None,
        doc_subtypes=None,
):
    return {
        'code': code,
        'display_en': display_en,
        'display_ar': display_ar,
        'mandatory_canonical_sections': list(MANDATORY_CANONICAL_SECTIONS),
        'mandatory_legacy_sections': list(MANDATORY_LEGACY_SECTIONS),
        'document_types': ['strategy'],
        'doc_subtypes': doc_subtypes or ['technical', 'board'],
        'frameworks_default': frameworks or [],
        'fixtures_ar': fixtures_ar,
        'fixtures_en': fixtures_en,
    }
