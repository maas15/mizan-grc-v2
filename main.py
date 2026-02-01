"""Main entry point for Mizan GRC Test Version"""

import sys
from datetime import datetime
from mizan_grc.models import Risk, Control, ComplianceRequirement, RiskLevel, ControlStatus
from mizan_grc.grc_manager import GRCManager
from version import __version__, __application__, __description__


def main():
    """Main application entry point"""
    print(f"=" * 60)
    print(f"{__application__} v{__version__}")
    print(f"{__description__}")
    print(f"=" * 60)
    print()
    
    # Initialize GRC Manager
    grc = GRCManager()
    
    # Add sample risks
    risk1 = Risk(
        id="R001",
        title="Data Breach Risk",
        description="Risk of unauthorized access to sensitive data",
        level=RiskLevel.HIGH,
        identified_date=datetime.now(),
        owner="Security Team"
    )
    
    risk2 = Risk(
        id="R002",
        title="Compliance Violation Risk",
        description="Risk of non-compliance with GDPR requirements",
        level=RiskLevel.MEDIUM,
        identified_date=datetime.now(),
        owner="Compliance Team"
    )
    
    grc.add_risk(risk1)
    grc.add_risk(risk2)
    
    # Add sample control
    control1 = Control(
        id="C001",
        title="Multi-Factor Authentication",
        description="Implement MFA for all user accounts",
        status=ControlStatus.ACTIVE,
        associated_risks=["R001"]
    )
    
    grc.add_control(control1)
    
    # Add sample compliance requirements
    req1 = ComplianceRequirement(
        id="CR001",
        title="Data Encryption at Rest",
        description="All sensitive data must be encrypted",
        framework="ISO27001",
        compliant=True
    )
    
    req2 = ComplianceRequirement(
        id="CR002",
        title="Access Control Policy",
        description="Documented access control procedures",
        framework="SOC2",
        compliant=False
    )
    
    grc.add_compliance_requirement(req1)
    grc.add_compliance_requirement(req2)
    
    # Display summary
    print("📊 GRC Dashboard")
    print("-" * 60)
    
    print(f"\n🔴 Risks ({len(grc.get_all_risks())} total):")
    for risk in grc.get_all_risks():
        status = "✓ Mitigated" if risk.mitigated else "⚠ Active"
        print(f"  - [{risk.id}] {risk.title} - {risk.level.value.upper()} ({status})")
    
    print(f"\n🛡️ Controls ({len(grc.controls)} total):")
    for control in grc.controls:
        print(f"  - [{control.id}] {control.title} - {control.status.value.upper()}")
    
    compliance_status = grc.get_compliance_status()
    print(f"\n✅ Compliance Status:")
    print(f"  - Total Requirements: {compliance_status['total']}")
    print(f"  - Compliant: {compliance_status['compliant']}")
    print(f"  - Non-Compliant: {compliance_status['non_compliant']}")
    print(f"  - Compliance Rate: {compliance_status['compliance_rate']:.1f}%")
    
    print("\n" + "=" * 60)
    print("Test version loaded successfully! ✨")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
