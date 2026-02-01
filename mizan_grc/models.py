"""Core domain models for Mizan GRC"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from datetime import datetime


class RiskLevel(Enum):
    """Risk severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlStatus(Enum):
    """Control implementation status"""
    PLANNED = "planned"
    IMPLEMENTED = "implemented"
    ACTIVE = "active"
    INACTIVE = "inactive"


@dataclass
class Risk:
    """Represents a risk in the GRC system"""
    id: str
    title: str
    description: str
    level: RiskLevel
    identified_date: datetime
    owner: str
    mitigated: bool = False
    
    def assess(self) -> dict:
        """Assess the risk"""
        return {
            "id": self.id,
            "title": self.title,
            "level": self.level.value,
            "mitigated": self.mitigated
        }


@dataclass
class Control:
    """Represents a control measure"""
    id: str
    title: str
    description: str
    status: ControlStatus
    associated_risks: List[str]
    
    def activate(self):
        """Activate the control"""
        self.status = ControlStatus.ACTIVE
    
    def deactivate(self):
        """Deactivate the control"""
        self.status = ControlStatus.INACTIVE


@dataclass
class ComplianceRequirement:
    """Represents a compliance requirement"""
    id: str
    title: str
    description: str
    framework: str  # e.g., ISO27001, SOC2, GDPR
    compliant: bool = False
    
    def mark_compliant(self):
        """Mark requirement as compliant"""
        self.compliant = True
    
    def mark_non_compliant(self):
        """Mark requirement as non-compliant"""
        self.compliant = False
