"""Shared minimal strategy section fixtures (EN) per non-cyber domain."""

DATA_SECTIONS = {
    'vision': (
        '## 1. Vision and Strategic Objectives\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Data governance | Framework approved | Foundation | 6 months |\n'
        '| 2 | Data stewardship | 100% domains owned | Accountability | 12 months |\n'
    ),
    'pillars': '## 2. Pillars\n\n| # | Pillar | Initiative | Owner |\n|---|---|---|\n| 1 | DG | Committee | CDO |\n',
    'environment': '## 3. Environment\n\nNDMO data governance requirements.\n',
    'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | No DG committee | High |\n',
    'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | DG foundations | 0-6 months |\n',
    'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Data quality | > 90% |\n',
    'confidence': '## 7. Confidence\n\n**Confidence score:** 80%\n**Justification:** DG programme.\n',
}

AI_SECTIONS = {
    'vision': (
        '## 1. Vision\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | AI governance | Policy approved | Foundation | 6 months |\n'
        '| 2 | Model risk | 100% inventoried | Risk | 12 months |\n'
    ),
    'pillars': '## 2. Pillars\n\nAI governance framework.\n',
    'environment': '## 3. Environment\n\nNIST AI RMF.\n',
    'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | No AI governance | High |\n',
    'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | AI inventory | 0-6 months |\n',
    'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Model inventory | 100% |\n',
    'confidence': '## 7. Confidence\n\n**Confidence score:** 78%\n**Justification:** Model risk.\n',
}

DT_SECTIONS = {
    'vision': (
        '## 1. Vision\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | Digitise services | 80% online | UX | 12 months |\n'
        '| 2 | Integration APIs | 100% integrated | Interop | 18 months |\n'
    ),
    'pillars': '## 2. Pillars\n\nDGA-aligned transformation.\n',
    'environment': '## 3. Environment\n\nDGA digital requirements.\n',
    'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | Low digitisation | High |\n',
    'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | Service digitisation | 0-6 months |\n',
    'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Online services | 80% |\n',
    'confidence': '## 7. Confidence\n\n**Confidence score:** 75%\n**Justification:** Adoption risk.\n',
}

ERM_SECTIONS = {
    'vision': (
        '## 1. Vision\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | ERM framework | Approved | Foundation | 6 months |\n'
        '| 2 | Risk appetite | Documented | Governance | 12 months |\n'
    ),
    'pillars': '## 2. Pillars\n\nEnterprise risk pillars.\n',
    'environment': '## 3. Environment\n\nISO 31000 alignment.\n',
    'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | No ERM framework | High |\n',
    'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | ERM setup | 0-6 months |\n',
    'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Risk register coverage | 100% |\n',
    'confidence': '## 7. Confidence\n\n**Confidence score:** 77%\n**Justification:** Risk culture.\n',
}

GLOBAL_SECTIONS = {
    'vision': (
        '## 1. Vision\n\n'
        '| # | Objective | Metric | Rationale | Timeframe |\n'
        '|---|-----------|--------|-----------|----------|\n'
        '| 1 | ISO alignment | Mapped | Foundation | 6 months |\n'
        '| 2 | Control baseline | Implemented | Compliance | 12 months |\n'
    ),
    'pillars': '## 2. Pillars\n\nGlobal standards pillars.\n',
    'environment': '## 3. Environment\n\nISO 27001 and NIST CSF.\n',
    'gaps': '## 4. Gaps\n\n| # | Gap | Severity |\n|---|---|\n| 1 | Control gaps | Medium |\n',
    'roadmap': '## 5. Roadmap\n\n| Phase | Initiative | Months |\n|---|---|\n| Short | Baseline controls | 0-6 months |\n',
    'kpis': '## 6. KPIs\n\n| # | Metric | Target |\n|---|---|\n| 1 | Control coverage | 95% |\n',
    'confidence': '## 7. Confidence\n\n**Confidence score:** 79%\n**Justification:** Standards gap.\n',
}


def ar_mirror(sections_en):
    """Lightweight AR headers; body structure preserved for REL1 structural gate."""
    out = {}
    headers = {
        'vision': '## 1. الرؤية والأهداف الاستراتيجية\n\n',
        'pillars': '## 2. الركائز\n\n',
        'environment': '## 3. البيئة\n\n',
        'gaps': '## 4. الفجوات\n\n',
        'roadmap': '## 5. خارطة الطريق\n\n',
        'kpis': '## 6. مؤشرات الأداء\n\n',
        'confidence': '## 7. تقييم الثقة\n\n**درجة الثقة:** 80%\n**مبررات التقييم:** نص.\n',
    }
    for k, v in sections_en.items():
        body = v.split('\n\n', 1)
        rest = body[1] if len(body) > 1 else v
        if k == 'confidence' and '##' in v:
            out[k] = headers.get(k, '') + (
                rest if 'درجة' not in v else v.replace(
                    '## 7. Confidence', '## 7. تقييم الثقة'))
            continue
        out[k] = headers.get(k, '') + rest
    if 'confidence' in sections_en:
        out['confidence'] = (
            '## 7. تقييم الثقة\n\n'
            '**درجة الثقة:** 80%\n'
            '**مبررات التقييم:** نص.\n'
            + sections_en['confidence'].split('\n\n', 1)[-1]
            if '|' in sections_en['confidence']
            else '## 7. تقييم الثقة\n\n**درجة الثقة:** 80%\n**مبررات التقييم:** نص.\n'
        )
    return out
