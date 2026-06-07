"""English Cyber strategy fixtures — CY88/CY89 canonical KPI/SO shape."""

from domains.cyber.fixtures_ar import _KPI_SEALABLE

_EN_SO = (    '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |\n'
    '|---|---|---|---|---|\n'
)

_ROADMAP = (
    '## 5. Roadmap\n\n'
    '| Phase | Period | Initiative | Owner | Output | Framework |\n'
    '|---|---|---|---|---|---|\n'
    '| Phase 1: Foundation | 1-6 months | CISO governance | CISO | Structure | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | SOC operations | SOC Mgr | Center | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | IAM/PAM/MFA | IAM Mgr | Controls | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | CSIRT program | CSIRT Lead | Team | NCA ECC |\n'
    '| Phase 3: Improve | 19-24 months | CSIRT maturity | CISO | Program | NCA ECC |\n'
    '| Phase 2: Enable | 7-18 months | Data classification | DPO | Inventory | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | Encryption controls | DPO | Keys | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | DLP monitoring | DPO | Monitor | NCA DCC |\n'
    '| Phase 2: Enable | 7-18 months | Sensitive data protection | DPO | Procedures | NCA DCC |\n'
    '\n'
    '| # | Item | Description | Timing | Cost |\n'
    '|---|---|---|---|---|\n'
    '| 1 | Hardware | Security equipment | As needed | '
    '1.2M SAR <!-- trace:section=roadmap;key=row_1 --> |\n'
)

_CONF = (    '## 7. Confidence\n\n'
    '**Confidence score:** 82%\n'
    '**Justification:** Operational rationale.\n'
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
            + '| 5 | ECC/DCC framework alignment | 90% | Regulatory | 18 months |\n'
            + '| 6 | Third-party cyber risk program | 90% | Supply chain | 18 months |\n'
        ),
        'pillars': '## 2. Pillars\n\nGovernance, protection, detection, response.\n',
        'environment': '## 3. Environment\n\nClassification, encryption, and DLP.\n',
        'gaps': '## 4. Gaps\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP,
        'kpis': _KPI_SEALABLE,
        'confidence': _CONF,
    }


def board_sections():
    secs = technical_sections()
    secs['vision'] = (
        '## 1. Executive Vision\n\n'
        '### Strategic Objectives\n\n'
        + _EN_SO
        + '| 1 | Board cyber governance oversight | 100% | Board | 6 months |\n'
        + '| 2 | SOC/CSIRT operations | 100% | Operations | 12 months |\n'
        + '| 3 | IAM/PAM/MFA | 95% | Identity | 12 months |\n'
        + '| 4 | DCC data protection | 90% | Compliance | 18 months |\n'
        + '| 5 | ECC/DCC framework | 90% | Regulatory | 18 months |\n'
        + '| 6 | Third-party risk | 90% | Supply chain | 18 months |\n'
    )
    return secs
