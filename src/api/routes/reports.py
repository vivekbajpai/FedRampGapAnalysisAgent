"""
Report API endpoints for FedRAMP Gap Analysis Agent.
"""

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional
import json
import io

from src.api.models.requests import ReportGenerationRequest
from src.api.models.responses import AnalysisResultResponse
from src.core.orchestrator import GapAnalysisOrchestrator, AnalysisStatus
from src.utils.logger import get_main_logger

logger = get_main_logger()
router = APIRouter()

# Global orchestrator instance
orchestrator = GapAnalysisOrchestrator(
    controls_data_path="data/controls/fedramp_high_baseline.json",
    patterns_data_path="data/patterns/java_security_patterns.json"
)


@router.get(
    "/reports/{job_id}",
    summary="Get analysis report",
    description="Retrieve analysis report in specified format"
)
async def get_report(
    job_id: str,
    format: str = "json"
):
    """
    Get analysis report in the specified format.
    
    Supported formats:
    - json: JSON format (default)
    - pdf: PDF report
    - html: HTML report
    - excel: Excel spreadsheet
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
                detail=f"Job not completed. Current status: {job.status.value}"
            )
        
        result = orchestrator.get_job_result(job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for job: {job_id}"
            )
        
        # Return based on format
        if format == "json":
            return result
        
        elif format == "pdf":
            # TODO: Implement PDF generation
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="PDF format not yet implemented"
            )
        
        elif format == "html":
            # TODO: Implement HTML generation
            html_content = generate_html_report(result)
            return Response(content=html_content, media_type="text/html")
        
        elif format == "excel":
            # TODO: Implement Excel generation
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Excel format not yet implemented"
            )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported format: {format}. Use json, pdf, html, or excel"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get report: {str(e)}"
        )


@router.get(
    "/reports/{job_id}/summary",
    summary="Get report summary",
    description="Get executive summary of analysis results"
)
async def get_report_summary(job_id: str):
    """
    Get executive summary of the analysis.
    
    Returns high-level statistics and key findings without detailed gap information.
    """
    try:
        result = orchestrator.get_job_result(job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for job: {job_id}"
            )
        
        return {
            "job_id": job_id,
            "summary": result.get("summary"),
            "control_coverage": result.get("control_coverage"),
            "top_risks": sorted(
                result.get("gaps", []),
                key=lambda g: g.get("risk_score", 0),
                reverse=True
            )[:5]  # Top 5 highest risk gaps
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get summary: {str(e)}"
        )


@router.get(
    "/reports/{job_id}/gaps",
    summary="Get detailed gaps",
    description="Get detailed list of all identified gaps"
)
async def get_report_gaps(
    job_id: str,
    severity: Optional[str] = None,
    control_family: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get detailed list of gaps with optional filtering.
    
    Filters:
    - severity: Filter by severity (critical, high, medium, low)
    - control_family: Filter by control family (AC, AU, IA, etc.)
    - limit/offset: Pagination
    """
    try:
        result = orchestrator.get_job_result(job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for job: {job_id}"
            )
        
        gaps = result.get("gaps", [])
        
        # Apply filters
        if severity:
            gaps = [g for g in gaps if g.get("severity") == severity]
        
        if control_family:
            gaps = [g for g in gaps if g.get("control_id", "").startswith(control_family)]
        
        # Paginate
        total = len(gaps)
        gaps = gaps[offset:offset + limit]
        
        return {
            "job_id": job_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "gaps": gaps
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get gaps: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get gaps: {str(e)}"
        )


@router.get(
    "/reports/{job_id}/remediations",
    summary="Get remediation recommendations",
    description="Get remediation recommendations for identified gaps"
)
async def get_report_remediations(
    job_id: str,
    control_id: Optional[str] = None
):
    """
    Get remediation recommendations.
    
    Optionally filter by specific control ID.
    """
    try:
        result = orchestrator.get_job_result(job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for job: {job_id}"
            )
        
        remediations = result.get("remediations", [])
        
        # Filter by control if specified
        if control_id:
            remediations = [r for r in remediations if r.get("control_id") == control_id]
        
        return {
            "job_id": job_id,
            "total": len(remediations),
            "remediations": remediations
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get remediations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get remediations: {str(e)}"
        )


@router.post(
    "/reports/generate",
    summary="Generate custom report",
    description="Generate a custom report with specific sections and format"
)
async def generate_custom_report(request: ReportGenerationRequest):
    """
    Generate a custom report with specified sections and format.
    
    Allows customization of:
    - Report format (json, pdf, html, excel)
    - Included sections (summary, gaps, remediation, coverage)
    - Custom templates
    """
    try:
        result = orchestrator.get_job_result(request.job_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report not found for job: {request.job_id}"
            )
        
        # Filter sections if specified
        if request.include_sections:
            filtered_result = {
                "job_id": result.get("job_id"),
                "analysis_date": result.get("analysis_date")
            }
            
            for section in request.include_sections:
                if section in result:
                    filtered_result[section] = result[section]
            
            result = filtered_result
        
        # Generate in requested format
        if request.format == "json":
            return result
        
        elif request.format == "pdf":
            # TODO: Implement PDF generation with custom template
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="PDF format not yet implemented"
            )
        
        elif request.format == "html":
            html_content = generate_html_report(result, request.template)
            return Response(content=html_content, media_type="text/html")
        
        elif request.format == "excel":
            # TODO: Implement Excel generation
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Excel format not yet implemented"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


def generate_html_report(result: dict, template: Optional[str] = None) -> str:
    """Generate HTML report from analysis results."""
    summary = result.get("summary", {})
    gaps = result.get("gaps", [])
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>FedRAMP Gap Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; }}
            .stat {{ display: inline-block; margin: 10px 20px; }}
            .stat-label {{ font-weight: bold; }}
            .gap {{ border: 1px solid #bdc3c7; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            .critical {{ border-left: 5px solid #e74c3c; }}
            .high {{ border-left: 5px solid #e67e22; }}
            .medium {{ border-left: 5px solid #f39c12; }}
            .low {{ border-left: 5px solid #3498db; }}
        </style>
    </head>
    <body>
        <h1>FedRAMP Gap Analysis Report</h1>
        <p>Job ID: {result.get('job_id')}</p>
        <p>Analysis Date: {result.get('analysis_date')}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stat">
                <span class="stat-label">Compliance Score:</span>
                <span>{summary.get('compliance_score', 0):.1f}%</span>
            </div>
            <div class="stat">
                <span class="stat-label">Total Gaps:</span>
                <span>{summary.get('total_gaps', 0)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Critical:</span>
                <span>{summary.get('critical_gaps', 0)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">High:</span>
                <span>{summary.get('high_gaps', 0)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Average Risk:</span>
                <span>{summary.get('average_risk_score', 0):.2f}/10</span>
            </div>
        </div>
        
        <h2>Identified Gaps</h2>
    """
    
    for gap in gaps[:20]:  # Show first 20 gaps
        severity = gap.get('severity', 'low')
        html += f"""
        <div class="gap {severity}">
            <h3>{gap.get('control_id')} - {gap.get('control_name')}</h3>
            <p><strong>Severity:</strong> {severity.upper()}</p>
            <p><strong>Risk Score:</strong> {gap.get('risk_score', 0):.2f}/10</p>
            <p><strong>Description:</strong> {gap.get('description')}</p>
        </div>
        """
    
    html += """
    </body>
    </html>
    """
    
    return html

# Made with Bob
