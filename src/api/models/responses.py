"""
Response models for FedRAMP Gap Analysis API.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class AnalysisJobResponse(BaseModel):
    """Response for analysis job creation."""
    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Job status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="Job creation timestamp")
    estimated_completion_time: Optional[datetime] = Field(
        default=None,
        description="Estimated completion time"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "job_id": "job_abc123def456",
                "status": "pending",
                "message": "Analysis job started successfully",
                "created_at": "2026-02-06T09:00:00Z",
                "estimated_completion_time": "2026-02-06T09:15:00Z"
            }
        }


class JobStatusResponse(BaseModel):
    """Response for job status query."""
    job_id: str = Field(..., description="Job identifier")
    status: str = Field(..., description="Current status")
    progress: float = Field(..., ge=0.0, le=100.0, description="Progress percentage")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    result_available: bool = Field(..., description="Whether results are available")
    
    class Config:
        schema_extra = {
            "example": {
                "job_id": "job_abc123def456",
                "status": "detecting_gaps",
                "progress": 65.0,
                "created_at": "2026-02-06T09:00:00Z",
                "updated_at": "2026-02-06T09:10:00Z",
                "error_message": None,
                "result_available": False
            }
        }


class GapResponse(BaseModel):
    """Response model for a compliance gap."""
    gap_id: str
    control_id: str
    control_name: str
    gap_type: str
    severity: str
    description: str
    policy_requirement: str
    design_specification: Optional[str]
    code_implementation: Optional[str]
    evidence: List[Dict[str, Any]]
    risk_score: float
    impact: str
    likelihood: str
    
    class Config:
        schema_extra = {
            "example": {
                "gap_id": "gap_ia_2_1_001",
                "control_id": "IA-2(1)",
                "control_name": "Multi-Factor Authentication",
                "gap_type": "missing_implementation",
                "severity": "critical",
                "description": "MFA not implemented for privileged accounts",
                "policy_requirement": "Implement MFA using TOTP",
                "design_specification": "TOTP-based MFA with Google Authenticator",
                "code_implementation": None,
                "evidence": [
                    {"type": "missing", "details": "No MFA service found"}
                ],
                "risk_score": 9.5,
                "impact": "critical",
                "likelihood": "high"
            }
        }


class RiskAssessmentResponse(BaseModel):
    """Response model for risk assessment."""
    gap_id: str
    control_id: str
    risk_score: float
    impact: str
    likelihood: str
    risk_level: str
    business_impact: str
    technical_impact: str
    compliance_impact: str
    exploitability: float
    remediation_priority: int


class RemediationStepResponse(BaseModel):
    """Response model for a remediation step."""
    step_number: int
    description: str
    technical_details: str
    code_example: Optional[str]
    verification: str


class RemediationResponse(BaseModel):
    """Response model for remediation recommendation."""
    gap_id: str
    control_id: str
    summary: str
    description: str
    steps: List[RemediationStepResponse]
    effort_estimate: str
    estimated_hours: int
    required_skills: List[str]
    dependencies: List[str]
    references: List[Dict[str, str]]
    testing_guidance: str
    validation_criteria: List[str]


class AnalysisSummaryResponse(BaseModel):
    """Response model for analysis summary."""
    total_controls_evaluated: int
    controls_with_gaps: int
    controls_compliant: int
    total_gaps: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    average_risk_score: float
    compliance_score: float
    
    class Config:
        schema_extra = {
            "example": {
                "total_controls_evaluated": 35,
                "controls_with_gaps": 12,
                "controls_compliant": 23,
                "total_gaps": 15,
                "critical_gaps": 2,
                "high_gaps": 5,
                "medium_gaps": 6,
                "low_gaps": 2,
                "average_risk_score": 6.45,
                "compliance_score": 65.7
            }
        }


class ControlCoverageResponse(BaseModel):
    """Response model for control coverage."""
    total_required: int
    total_implemented: int
    coverage_percentage: float
    by_family: Dict[str, Dict[str, int]]


class AnalysisResultResponse(BaseModel):
    """Complete analysis result response."""
    job_id: str
    analysis_date: datetime
    gaps: List[GapResponse]
    risk_assessments: List[RiskAssessmentResponse]
    remediations: List[RemediationResponse]
    summary: AnalysisSummaryResponse
    control_coverage: ControlCoverageResponse
    
    class Config:
        schema_extra = {
            "example": {
                "job_id": "job_abc123def456",
                "analysis_date": "2026-02-06T09:15:00Z",
                "gaps": [],
                "risk_assessments": [],
                "remediations": [],
                "summary": {
                    "total_controls_evaluated": 35,
                    "controls_with_gaps": 12,
                    "total_gaps": 15,
                    "compliance_score": 65.7
                },
                "control_coverage": {
                    "total_required": 35,
                    "total_implemented": 23,
                    "coverage_percentage": 65.7
                }
            }
        }


class ControlResponse(BaseModel):
    """Response model for a FedRAMP control."""
    control_id: str
    control_name: str
    control_family: str
    baseline: str
    description: str
    implementation_guidance: str
    patterns: List[str]
    keywords: List[str]
    verification_methods: List[str]
    
    class Config:
        schema_extra = {
            "example": {
                "control_id": "AC-2",
                "control_name": "Account Management",
                "control_family": "AC",
                "baseline": "High",
                "description": "Manage information system accounts",
                "implementation_guidance": "Implement automated account management",
                "patterns": ["UserDetailsService", "UserRepository"],
                "keywords": ["user", "account", "registration"],
                "verification_methods": ["code_review", "authentication_test"]
            }
        }


class ControlListResponse(BaseModel):
    """Response model for control list."""
    total: int
    controls: List[ControlResponse]


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(..., description="Current timestamp")
    components: Dict[str, str] = Field(..., description="Component health status")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": "2026-02-06T09:00:00Z",
                "components": {
                    "database": "healthy",
                    "cache": "healthy",
                    "orchestrator": "healthy"
                }
            }
        }


class ErrorResponse(BaseModel):
    """Response model for errors."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Any] = Field(default=None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid request parameters",
                "details": {"field": "repository.url", "issue": "Invalid URL format"},
                "timestamp": "2026-02-06T09:00:00Z"
            }
        }

# Made with Bob
