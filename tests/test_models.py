"""Test suite for Mizan GRC models"""

import pytest
from datetime import datetime
from mizan_grc.models import (
    Risk, Control, ComplianceRequirement,
    RiskLevel, ControlStatus
)


def test_risk_creation():
    """Test creating a risk"""
    risk = Risk(
        id="R001",
        title="Test Risk",
        description="This is a test risk",
        level=RiskLevel.HIGH,
        identified_date=datetime.now(),
        owner="Test Owner"
    )
    
    assert risk.id == "R001"
    assert risk.title == "Test Risk"
    assert risk.level == RiskLevel.HIGH
    assert risk.mitigated is False


def test_risk_assessment():
    """Test risk assessment"""
    risk = Risk(
        id="R001",
        title="Test Risk",
        description="This is a test risk",
        level=RiskLevel.MEDIUM,
        identified_date=datetime.now(),
        owner="Test Owner"
    )
    
    assessment = risk.assess()
    assert assessment["id"] == "R001"
    assert assessment["title"] == "Test Risk"
    assert assessment["level"] == "medium"
    assert assessment["mitigated"] is False


def test_control_activation():
    """Test control activation"""
    control = Control(
        id="C001",
        title="Test Control",
        description="This is a test control",
        status=ControlStatus.PLANNED,
        associated_risks=["R001"]
    )
    
    assert control.status == ControlStatus.PLANNED
    
    control.activate()
    assert control.status == ControlStatus.ACTIVE
    
    control.deactivate()
    assert control.status == ControlStatus.INACTIVE


def test_compliance_requirement():
    """Test compliance requirement"""
    req = ComplianceRequirement(
        id="CR001",
        title="Test Requirement",
        description="This is a test requirement",
        framework="ISO27001"
    )
    
    assert req.compliant is False
    
    req.mark_compliant()
    assert req.compliant is True
    
    req.mark_non_compliant()
    assert req.compliant is False
