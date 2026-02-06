"""
Request models for FedRAMP Gap Analysis API.
"""

from pydantic import BaseModel, Field, HttpUrl, validator
from typing import List, Optional, Dict, Any
from enum import Enum


class DocumentType(str, Enum):
    """Supported document types."""
    PDF = "pdf"
    DOCX = "docx"
    CONFLUENCE = "confluence"
    HTML = "html"


class DocumentInput(BaseModel):
    """Input document specification."""
    url: str = Field(..., description="URL or path to the document")
    type: DocumentType = Field(..., description="Document type")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")
    
    class Config:
        schema_extra = {
            "example": {
                "url": "s3://bucket/fedramp-policy.pdf",
                "type": "pdf",
                "metadata": {"version": "1.0"}
            }
        }


class RepositoryCredentials(BaseModel):
    """Git repository credentials."""
    type: str = Field(..., description="Credential type: token, ssh, basic")
    token: Optional[str] = Field(default=None, description="Access token")
    username: Optional[str] = Field(default=None, description="Username for basic auth")
    password: Optional[str] = Field(default=None, description="Password for basic auth")
    ssh_key: Optional[str] = Field(default=None, description="SSH private key")


class RepositoryInput(BaseModel):
    """Git repository specification."""
    url: str = Field(..., description="Git repository URL")
    branch: str = Field(default="main", description="Branch to analyze")
    local_path: Optional[str] = Field(default=None, description="Local repository path (if already cloned)")
    credentials: Optional[RepositoryCredentials] = Field(default=None, description="Repository credentials")
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://github.com/example/secure-app.git",
                "branch": "main",
                "credentials": {
                    "type": "token",
                    "token": "ghp_xxxxxxxxxxxx"
                }
            }
        }


class AnalysisOptions(BaseModel):
    """Analysis configuration options."""
    control_families: Optional[List[str]] = Field(
        default=None,
        description="Specific control families to analyze (e.g., ['AC', 'AU', 'IA'])"
    )
    include_remediation: bool = Field(
        default=True,
        description="Include remediation recommendations"
    )
    include_code_examples: bool = Field(
        default=True,
        description="Include code examples in remediation"
    )
    risk_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Only report gaps with risk score above threshold"
    )
    severity_filter: Optional[List[str]] = Field(
        default=None,
        description="Filter gaps by severity (critical, high, medium, low)"
    )


class ComprehensiveAnalysisRequest(BaseModel):
    """Request for comprehensive gap analysis."""
    policy_documents: List[DocumentInput] = Field(
        ...,
        description="Policy documents containing FedRAMP requirements"
    )
    design_documents: Optional[List[DocumentInput]] = Field(
        default=None,
        description="Design documents with system specifications"
    )
    repository: Optional[RepositoryInput] = Field(
        default=None,
        description="Source code repository to analyze"
    )
    analysis_options: Optional[AnalysisOptions] = Field(
        default=None,
        description="Analysis configuration options"
    )
    webhook_url: Optional[str] = Field(
        default=None,
        description="Webhook URL for completion notification"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "policy_documents": [
                    {
                        "url": "s3://bucket/fedramp-policy.pdf",
                        "type": "pdf"
                    }
                ],
                "design_documents": [
                    {
                        "url": "https://confluence.example.com/page/123",
                        "type": "confluence"
                    }
                ],
                "repository": {
                    "url": "https://github.com/example/app.git",
                    "branch": "main"
                },
                "analysis_options": {
                    "control_families": ["AC", "AU", "IA", "SC"],
                    "include_remediation": True
                }
            }
        }


class PolicyAnalysisRequest(BaseModel):
    """Request for policy document analysis only."""
    policy_documents: List[DocumentInput] = Field(
        ...,
        description="Policy documents to analyze"
    )
    analysis_options: Optional[AnalysisOptions] = Field(
        default=None,
        description="Analysis options"
    )


class CodeAnalysisRequest(BaseModel):
    """Request for code repository analysis only."""
    repository: RepositoryInput = Field(
        ...,
        description="Repository to analyze"
    )
    analysis_options: Optional[AnalysisOptions] = Field(
        default=None,
        description="Analysis options"
    )


class ReportGenerationRequest(BaseModel):
    """Request for report generation."""
    job_id: str = Field(..., description="Analysis job ID")
    format: str = Field(
        default="json",
        description="Report format: json, pdf, html, excel"
    )
    include_sections: Optional[List[str]] = Field(
        default=None,
        description="Sections to include: summary, gaps, remediation, coverage"
    )
    template: Optional[str] = Field(
        default=None,
        description="Custom report template"
    )
    
    @validator('format')
    def validate_format(cls, v):
        """Validate report format."""
        allowed = ['json', 'pdf', 'html', 'excel']
        if v not in allowed:
            raise ValueError(f"Format must be one of {allowed}")
        return v

# Made with Bob
