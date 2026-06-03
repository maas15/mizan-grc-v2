"""English Cyber strategy fixtures."""

_EN_SO = (
    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
)

_ROADMAP = (
    '## 5. Roadmap\n\n'
    '| Phase | Period | Initiative | Owner | Output | Framework |\n'
    '|---|---|---|---|---|---|\n'
    '| Phase 1: Foundation | 1-6 months | CISO governance | CISO | Structure | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | SOC operations | SOC Mgr | Center | NCA ECC |\n'
    '| Phase 3: Improve | 19-24 months | CSIRT maturity | CISO | Program | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | Data classification | DPO | Inventory | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | Encryption | DPO | Controls | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | DLP monitoring | DPO | Monitor | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | Sensitive data | DPO | Procedures | NCA DCC |\n'
    '\n'
    '| # | Item | Description | Timing | Cost |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Hardware | Security equipment | As needed | '
    '1.2M SAR <!-- trace:section=roadmap;key=row_1 --> |\n'
)


def technical_sections():
    return {
        'vision': (
            '## 1. Vision and Strategic Objectives\n\n'
            '### Strategic Objectives\n\n'
            + _EN_SO
            + '| 1 | Establish cybersecurity function and CISO | 100% | Governance | 6 months |\n'
            + '| 2 | SOC/CSIRT operations | 100% | Operations | 12 months |\n'
            + '| 3 | IAM/PAM/MFA | 95% | Identity | 12 months |\n'
            + '| 4 | DCC data protection | 90% | Compliance | 18 months |\n'
            + '| 5 | ECC/DCC framework | 90% | Regulatory | 18 months |\n'
        ),
        'pillars': '## 2. Pillars\n\nText.\n',
        'environment': '## 3. Environment\n\nClassification and DLP.\n',
        'gaps': '## 4. Gaps\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP,
        'kpis': (
            '## 6. KPIs\n\n'
            '| # | Metric | Target | Formula | Source | Frequency |\n'
            '|---|---|---|---|---|\n'
            '| 1 | MTTD | ≤ 60 min | detect/SIEM | SIEM/SOC | monthly |\n'
            '| 2 | MTTR | ≤ 4 hr | response | ITSM/SOAR | monthly |\n'
            '| 3 | DCC compliance | ≥ 90% | f | DCC | quarterly |\n'
        ),
        'confidence': (
            '## 7. Confidence\n\n'
            '**Confidence score:** 82%\n'
            '**Justification:** Operational rationale.\n'
            '| # | Risk factor | Likelihood | Impact | Plan |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Operational risk | medium | high | plan |\n'
        ),
    }


def board_sections():
    return technical_sections()
