"""GRC Manager - Core business logic"""

from typing import List, Optional
from .models import Risk, Control, ComplianceRequirement, RiskLevel


class GRCManager:
    """Manages GRC operations"""
    
    def __init__(self):
        self.risks: List[Risk] = []
        self.controls: List[Control] = []
        self.compliance_requirements: List[ComplianceRequirement] = []
    
    def add_risk(self, risk: Risk) -> Risk:
        """Add a new risk"""
        self.risks.append(risk)
        return risk
    
    def get_risk(self, risk_id: str) -> Optional[Risk]:
        """Get a risk by ID"""
        for risk in self.risks:
            if risk.id == risk_id:
                return risk
        return None
    
    def get_all_risks(self) -> List[Risk]:
        """Get all risks"""
        return self.risks
    
    def get_risks_by_level(self, level: RiskLevel) -> List[Risk]:
        """Get risks by severity level"""
        return [risk for risk in self.risks if risk.level == level]
    
    def add_control(self, control: Control) -> Control:
        """Add a new control"""
        self.controls.append(control)
        return control
    
    def get_control(self, control_id: str) -> Optional[Control]:
        """Get a control by ID"""
        for control in self.controls:
            if control.id == control_id:
                return control
        return None
    
    def add_compliance_requirement(self, requirement: ComplianceRequirement) -> ComplianceRequirement:
        """Add a compliance requirement"""
        self.compliance_requirements.append(requirement)
        return requirement
    
    def get_compliance_status(self) -> dict:
        """Get overall compliance status"""
        total = len(self.compliance_requirements)
        compliant = sum(1 for req in self.compliance_requirements if req.compliant)
        return {
            "total": total,
            "compliant": compliant,
            "non_compliant": total - compliant,
            "compliance_rate": (compliant / total * 100) if total > 0 else 0
        }
