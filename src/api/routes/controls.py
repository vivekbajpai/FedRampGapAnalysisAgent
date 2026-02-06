"""
Controls API endpoints for FedRAMP Gap Analysis Agent.
"""

from fastapi import APIRouter, HTTPException, status
from typing import List, Optional

from src.gap_detection.control_mapper import ControlMapper
from src.api.models.responses import ControlResponse, ControlListResponse
from src.utils.logger import get_main_logger

logger = get_main_logger()
router = APIRouter()

# Initialize control mapper
control_mapper = ControlMapper(controls_data_path="data/controls/fedramp_high_baseline.json")


@router.get(
    "/controls",
    response_model=ControlListResponse,
    summary="List FedRAMP controls",
    description="Get list of all FedRAMP High baseline controls"
)
async def list_controls(
    family: Optional[str] = None,
    baseline: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> ControlListResponse:
    """
    List FedRAMP controls with optional filtering.
    
    Filters:
    - family: Filter by control family (AC, AU, IA, etc.)
    - baseline: Filter by baseline (Low, Moderate, High)
    - search: Search in control name, description, or keywords
    - limit/offset: Pagination
    """
    try:
        # Get all controls
        if family:
            controls = control_mapper.get_controls_by_family(family)
        else:
            control_ids = control_mapper.get_all_control_ids()
            controls = [control_mapper.get_control_info(cid) for cid in control_ids]
            controls = [c for c in controls if c is not None]
        
        # Apply baseline filter
        if baseline:
            controls = [c for c in controls if c.baseline == baseline]
        
        # Apply search filter
        if search:
            search_lower = search.lower()
            controls = [
                c for c in controls
                if (search_lower in c.control_id.lower() or
                    search_lower in c.control_name.lower() or
                    any(search_lower in kw.lower() for kw in c.keywords))
            ]
        
        # Paginate
        total = len(controls)
        controls = controls[offset:offset + limit]
        
        # Convert to response model
        control_responses = [
            ControlResponse(
                control_id=c.control_id,
                control_name=c.control_name,
                control_family=c.control_family,
                baseline=c.baseline,
                description=c.implementation_guidance,
                implementation_guidance=c.implementation_guidance,
                patterns=c.patterns,
                keywords=c.keywords,
                verification_methods=c.verification_methods
            )
            for c in controls
        ]
        
        return ControlListResponse(
            total=total,
            controls=control_responses
        )
        
    except Exception as e:
        logger.error(f"Failed to list controls: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list controls: {str(e)}"
        )


@router.get(
    "/controls/{control_id}",
    response_model=ControlResponse,
    summary="Get control details",
    description="Get detailed information about a specific control"
)
async def get_control(control_id: str) -> ControlResponse:
    """
    Get detailed information about a specific FedRAMP control.
    
    Returns control metadata, implementation guidance, patterns, and verification methods.
    """
    try:
        control = control_mapper.get_control_info(control_id)
        
        if not control:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Control not found: {control_id}"
            )
        
        return ControlResponse(
            control_id=control.control_id,
            control_name=control.control_name,
            control_family=control.control_family,
            baseline=control.baseline,
            description=control.implementation_guidance,
            implementation_guidance=control.implementation_guidance,
            patterns=control.patterns,
            keywords=control.keywords,
            verification_methods=control.verification_methods
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get control: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get control: {str(e)}"
        )


@router.get(
    "/controls/families",
    summary="List control families",
    description="Get list of all control families"
)
async def list_control_families():
    """
    Get list of all FedRAMP control families.
    
    Returns family codes and names.
    """
    try:
        families = control_mapper.get_control_families()
        
        family_info = {
            "AC": "Access Control",
            "AT": "Awareness and Training",
            "AU": "Audit and Accountability",
            "CA": "Security Assessment and Authorization",
            "CM": "Configuration Management",
            "CP": "Contingency Planning",
            "IA": "Identification and Authentication",
            "IR": "Incident Response",
            "MA": "Maintenance",
            "MP": "Media Protection",
            "PE": "Physical and Environmental Protection",
            "PL": "Planning",
            "PS": "Personnel Security",
            "RA": "Risk Assessment",
            "SA": "System and Services Acquisition",
            "SC": "System and Communications Protection",
            "SI": "System and Information Integrity"
        }
        
        return {
            "total": len(families),
            "families": [
                {
                    "code": family,
                    "name": family_info.get(family, family),
                    "control_count": len(control_mapper.get_controls_by_family(family))
                }
                for family in sorted(families)
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to list families: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list families: {str(e)}"
        )


@router.get(
    "/controls/search",
    response_model=ControlListResponse,
    summary="Search controls",
    description="Search controls by keyword or pattern"
)
async def search_controls(
    query: str,
    limit: int = 50
) -> ControlListResponse:
    """
    Search controls by keyword, pattern, or description.
    
    Searches across:
    - Control ID
    - Control name
    - Keywords
    - Patterns
    """
    try:
        controls = control_mapper.search_controls(query)
        
        # Limit results
        total = len(controls)
        controls = controls[:limit]
        
        control_responses = [
            ControlResponse(
                control_id=c.control_id,
                control_name=c.control_name,
                control_family=c.control_family,
                baseline=c.baseline,
                description=c.implementation_guidance,
                implementation_guidance=c.implementation_guidance,
                patterns=c.patterns,
                keywords=c.keywords,
                verification_methods=c.verification_methods
            )
            for c in controls
        ]
        
        return ControlListResponse(
            total=total,
            controls=control_responses
        )
        
    except Exception as e:
        logger.error(f"Failed to search controls: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search controls: {str(e)}"
        )


@router.get(
    "/controls/{control_id}/patterns",
    summary="Get control patterns",
    description="Get code patterns associated with a control"
)
async def get_control_patterns(control_id: str):
    """
    Get code patterns associated with a specific control.
    
    Returns patterns that should be present in code to satisfy the control.
    """
    try:
        control = control_mapper.get_control_info(control_id)
        
        if not control:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Control not found: {control_id}"
            )
        
        return {
            "control_id": control.control_id,
            "control_name": control.control_name,
            "patterns": control.patterns,
            "keywords": control.keywords,
            "implementation_guidance": control.implementation_guidance
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get patterns: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get patterns: {str(e)}"
        )


@router.get(
    "/controls/{control_id}/guidance",
    summary="Get implementation guidance",
    description="Get implementation guidance for a control"
)
async def get_implementation_guidance(control_id: str):
    """
    Get detailed implementation guidance for a control.
    
    Returns guidance on how to implement the control in code.
    """
    try:
        guidance = control_mapper.get_implementation_guidance(control_id)
        
        if not guidance:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Guidance not found for control: {control_id}"
            )
        
        verification_methods = control_mapper.get_verification_methods(control_id)
        
        return {
            "control_id": control_id,
            "implementation_guidance": guidance,
            "verification_methods": verification_methods
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get guidance: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get guidance: {str(e)}"
        )

# Made with Bob
