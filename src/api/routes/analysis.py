"""
Analysis API endpoints for FedRAMP Gap Analysis Agent.

Provides endpoints for starting and managing gap analysis jobs.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, status
from typing import Dict, Any
import uuid
from datetime import datetime

from src.core.orchestrator import GapAnalysisOrchestrator, AnalysisStatus
from src.api.models.requests import (
    ComprehensiveAnalysisRequest,
    PolicyAnalysisRequest,
    CodeAnalysisRequest
)
from src.api.models.responses import (
    AnalysisJobResponse,
    JobStatusResponse,
    AnalysisResultResponse
)
from src.utils.logger import get_main_logger

logger = get_main_logger()
router = APIRouter()

# Global orchestrator instance (in production, use dependency injection)
orchestrator = GapAnalysisOrchestrator(
    controls_data_path="data/controls/fedramp_high_baseline.json",
    patterns_data_path="data/patterns/java_security_patterns.json"
)


@router.post(
    "/analyze/comprehensive",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start comprehensive gap analysis",
    description="Analyze policy documents, design documents, and code repository for FedRAMP compliance gaps"
)
async def start_comprehensive_analysis(
    request: ComprehensiveAnalysisRequest,
    background_tasks: BackgroundTasks
) -> AnalysisJobResponse:
    """
    Start a comprehensive FedRAMP gap analysis.
    
    This endpoint initiates an asynchronous analysis job that:
    1. Parses policy documents to extract requirements
    2. Parses design documents to extract specifications
    3. Analyzes code repository for security implementations
    4. Detects compliance gaps
    5. Assesses risk for each gap
    6. Generates remediation recommendations
    
    Returns a job ID that can be used to check status and retrieve results.
    """
    try:
        # Generate unique job ID
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        
        logger.info(f"Starting comprehensive analysis: {job_id}")
        
        # Extract document URLs
        policy_docs = [doc.url for doc in request.policy_documents]
        design_docs = [doc.url for doc in request.design_documents] if request.design_documents else []
        
        # Start analysis
        job = await orchestrator.start_analysis(
            job_id=job_id,
            policy_documents=policy_docs,
            design_documents=design_docs,
            repository_url=request.repository.url if request.repository else None,
            repository_path=request.repository.local_path if request.repository else None
        )
        
        return AnalysisJobResponse(
            job_id=job.job_id,
            status=job.status.value,
            message="Analysis job started successfully",
            created_at=job.created_at,
            estimated_completion_time=None  # TODO: Calculate based on input size
        )
        
    except Exception as e:
        logger.error(f"Failed to start analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start analysis: {str(e)}"
        )


@router.post(
    "/analyze/policy",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Analyze policy documents only",
    description="Extract and analyze FedRAMP requirements from policy documents"
)
async def analyze_policy_documents(
    request: PolicyAnalysisRequest
) -> AnalysisJobResponse:
    """
    Analyze policy documents to extract FedRAMP requirements.
    
    This endpoint focuses on parsing policy documents (PDFs, DOCX)
    to extract control requirements and compliance criteria.
    """
    try:
        job_id = f"job_policy_{uuid.uuid4().hex[:12]}"
        
        logger.info(f"Starting policy analysis: {job_id}")
        
        policy_docs = [doc.url for doc in request.policy_documents]
        
        # Start policy-only analysis
        job = await orchestrator.start_analysis(
            job_id=job_id,
            policy_documents=policy_docs,
            design_documents=[],
            repository_url=None
        )
        
        return AnalysisJobResponse(
            job_id=job.job_id,
            status=job.status.value,
            message="Policy analysis started",
            created_at=job.created_at
        )
        
    except Exception as e:
        logger.error(f"Failed to start policy analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start policy analysis: {str(e)}"
        )


@router.post(
    "/analyze/code",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Analyze code repository",
    description="Analyze source code for security patterns and compliance implementations"
)
async def analyze_code_repository(
    request: CodeAnalysisRequest
) -> AnalysisJobResponse:
    """
    Analyze code repository for security implementations.
    
    This endpoint scans a Git repository to identify:
    - Security patterns (authentication, authorization, encryption)
    - Anti-patterns (hardcoded credentials, weak crypto)
    - Configuration issues
    - Missing security controls
    """
    try:
        job_id = f"job_code_{uuid.uuid4().hex[:12]}"
        
        logger.info(f"Starting code analysis: {job_id}")
        
        # Start code-only analysis
        job = await orchestrator.start_analysis(
            job_id=job_id,
            policy_documents=[],
            design_documents=[],
            repository_url=request.repository.url,
            repository_path=request.repository.local_path
        )
        
        return AnalysisJobResponse(
            job_id=job.job_id,
            status=job.status.value,
            message="Code analysis started",
            created_at=job.created_at
        )
        
    except Exception as e:
        logger.error(f"Failed to start code analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start code analysis: {str(e)}"
        )


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get job status",
    description="Retrieve the current status and progress of an analysis job"
)
async def get_job_status(job_id: str) -> JobStatusResponse:
    """
    Get the status of an analysis job.
    
    Returns current status, progress percentage, and any error messages.
    Poll this endpoint to track job progress.
    """
    try:
        job = orchestrator.get_job_status(job_id)
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job not found: {job_id}"
            )
        
        return JobStatusResponse(
            job_id=job.job_id,
            status=job.status.value,
            progress=job.progress,
            created_at=job.created_at,
            updated_at=job.updated_at,
            error_message=job.error_message,
            result_available=job.status == AnalysisStatus.COMPLETED
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get job status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get job status: {str(e)}"
        )


@router.get(
    "/jobs/{job_id}/result",
    response_model=AnalysisResultResponse,
    summary="Get analysis results",
    description="Retrieve the complete analysis results for a completed job"
)
async def get_analysis_result(job_id: str) -> AnalysisResultResponse:
    """
    Get the complete analysis results.
    
    Returns:
    - List of identified gaps
    - Risk assessments
    - Remediation recommendations
    - Summary statistics
    - Control coverage analysis
    
    Only available for completed jobs.
    """
    try:
        job = orchestrator.get_job_status(job_id)
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job not found: {job_id}"
            )
        
        if job.status != AnalysisStatus.COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Job not completed yet. Current status: {job.status.value}"
            )
        
        result = orchestrator.get_job_result(job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Results not found for job: {job_id}"
            )
        
        return AnalysisResultResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get analysis result: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get analysis result: {str(e)}"
        )


@router.delete(
    "/jobs/{job_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel analysis job",
    description="Cancel a running analysis job"
)
async def cancel_job(job_id: str):
    """
    Cancel a running analysis job.
    
    This will stop the analysis and clean up resources.
    Completed jobs cannot be cancelled.
    """
    try:
        job = orchestrator.get_job_status(job_id)
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job not found: {job_id}"
            )
        
        if job.status in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel job in status: {job.status.value}"
            )
        
        # TODO: Implement job cancellation
        logger.info(f"Cancelling job: {job_id}")
        
        return None
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel job: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel job: {str(e)}"
        )


@router.get(
    "/jobs",
    response_model=Dict[str, Any],
    summary="List all jobs",
    description="List all analysis jobs with optional filtering"
)
async def list_jobs(
    status: str = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """
    List all analysis jobs.
    
    Supports filtering by status and pagination.
    """
    try:
        all_jobs = list(orchestrator.jobs.values())
        
        # Filter by status if provided
        if status:
            all_jobs = [j for j in all_jobs if j.status.value == status]
        
        # Sort by created_at descending
        all_jobs.sort(key=lambda j: j.created_at, reverse=True)
        
        # Paginate
        total = len(all_jobs)
        jobs = all_jobs[offset:offset + limit]
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "jobs": [j.to_dict() for j in jobs]
        }
        
    except Exception as e:
        logger.error(f"Failed to list jobs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list jobs: {str(e)}"
        )

# Made with Bob
