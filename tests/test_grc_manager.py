"""Test suite for GRC Manager"""

import pytest
from datetime import datetime
from mizan_grc.grc_manager import GRCManager
from mizan_grc.models import (
    Risk, Control, ComplianceRequirement,
    RiskLevel, ControlStatus
)


def test_grc_manager_initialization():
    """Test GRC Manager initialization"""
    grc = GRCManager()
    assert len(grc.risks) == 0
    assert len(grc.controls) == 0
    assert len(grc.compliance_requirements) == 0


def test_add_and_get_risk():
    """Test adding and retrieving a risk"""
    grc = GRCManager()
    
    risk = Risk(
        id="R001",
        title="Test Risk",
        description="Test description",
        level=RiskLevel.HIGH,
        identified_date=datetime.now(),
        owner="Test Owner"
    )
    
    added_risk = grc.add_risk(risk)
    assert added_risk.id == "R001"
    
    retrieved_risk = grc.get_risk("R001")
    assert retrieved_risk is not None
    assert retrieved_risk.id == "R001"
    assert retrieved_risk.title == "Test Risk"


def test_get_risks_by_level():
    """Test filtering risks by level"""
    grc = GRCManager()
    
    high_risk = Risk(
        id="R001",
        title="High Risk",
        description="Test",
        level=RiskLevel.HIGH,
        identified_date=datetime.now(),
        owner="Owner"
    )
    
    low_risk = Risk(
        id="R002",
        title="Low Risk",
        description="Test",
        level=RiskLevel.LOW,
        identified_date=datetime.now(),
        owner="Owner"
    )
    
    grc.add_risk(high_risk)
    grc.add_risk(low_risk)
    
    high_risks = grc.get_risks_by_level(RiskLevel.HIGH)
    assert len(high_risks) == 1
    assert high_risks[0].id == "R001"


def test_add_control():
    """Test adding a control"""
    grc = GRCManager()
    
    control = Control(
        id="C001",
        title="Test Control",
        description="Test description",
        status=ControlStatus.ACTIVE,
        associated_risks=["R001"]
    )
    
    added_control = grc.add_control(control)
    assert added_control.id == "C001"
    
    retrieved_control = grc.get_control("C001")
    assert retrieved_control is not None
    assert retrieved_control.id == "C001"


def test_compliance_status():
    """Test compliance status calculation"""
    grc = GRCManager()
    
    req1 = ComplianceRequirement(
        id="CR001",
        title="Requirement 1",
        description="Test",
        framework="ISO27001",
        compliant=True
    )
    
    req2 = ComplianceRequirement(
        id="CR002",
        title="Requirement 2",
        description="Test",
        framework="SOC2",
        compliant=False
    )
    
    req3 = ComplianceRequirement(
        id="CR003",
        title="Requirement 3",
        description="Test",
        framework="GDPR",
        compliant=True
    )
    
    grc.add_compliance_requirement(req1)
    grc.add_compliance_requirement(req2)
    grc.add_compliance_requirement(req3)
    
    status = grc.get_compliance_status()
    assert status["total"] == 3
    assert status["compliant"] == 2
    assert status["non_compliant"] == 1
    assert status["compliance_rate"] == pytest.approx(66.67, rel=0.1)


def test_compliance_status_empty():
    """Test compliance status with no requirements"""
    grc = GRCManager()
    
    status = grc.get_compliance_status()
    assert status["total"] == 0
    assert status["compliant"] == 0
    assert status["non_compliant"] == 0
    assert status["compliance_rate"] == 0
