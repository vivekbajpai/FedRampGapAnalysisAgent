"""
FedRAMP Gap Detection Engine

This module implements the core gap detection logic that compares policy requirements,
design specifications, and code implementations to identify compliance gaps.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class GapType(Enum):
    """Types of compliance gaps that can be detected."""
    MISSING_IN_DESIGN = "missing_in_design"
    MISSING_IN_CODE = "missing_in_code"
    MISSING_IMPLEMENTATION = "missing_implementation"
    PARTIAL_IMPLEMENTATION = "partial_implementation"
    INCORRECT_IMPLEMENTATION = "incorrect_implementation"
    OUTDATED_IMPLEMENTATION = "outdated_implementation"
    CONFIGURATION_GAP = "configuration_gap"


class GapSeverity(Enum):
    """Severity levels for identified gaps."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Gap:
    """Represents a compliance gap identified during analysis."""
    gap_id: str
    control_id: str
    control_name: str
    gap_type: GapType
    severity: GapSeverity
    description: str
    policy_requirement: str
    design_specification: Optional[str] = None
    code_implementation: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    impact: str = ""
    likelihood: str = ""
    remediation: Optional[Dict[str, Any]] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert gap to dictionary representation."""
        return {
            "gap_id": self.gap_id,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "gap_type": self.gap_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "policy_requirement": self.policy_requirement,
            "design_specification": self.design_specification,
            "code_implementation": self.code_implementation,
            "evidence": self.evidence,
            "risk_score": self.risk_score,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "remediation": self.remediation,
            "detected_at": self.detected_at.isoformat()
        }


@dataclass
class AnalysisContext:
    """Context for gap analysis containing all input sources."""
    policy_requirements: Dict[str, Dict[str, Any]]
    design_specifications: Dict[str, Dict[str, Any]]
    code_patterns: Dict[str, Dict[str, Any]]
    control_metadata: Dict[str, Dict[str, Any]]


class GapDetector:
    """
    Main gap detection engine that identifies compliance gaps by comparing
    policy requirements, design specifications, and code implementations.
    """
    
    def __init__(self, control_mapper=None, risk_assessor=None):
        """
        Initialize the gap detector.
        
        Args:
            control_mapper: Control mapping component
            risk_assessor: Risk assessment component
        """
        self.control_mapper = control_mapper
        self.risk_assessor = risk_assessor
        self.gaps: List[Gap] = []
        
    def detect_gaps(self, context: AnalysisContext) -> List[Gap]:
        """
        Detect compliance gaps across all control families.
        
        Args:
            context: Analysis context with policy, design, and code data
            
        Returns:
            List of identified gaps
        """
        logger.info("Starting gap detection analysis")
        self.gaps = []
        
        # Get all control IDs from policy requirements
        all_controls = set(context.policy_requirements.keys())
        
        # Also check for controls mentioned in design but not in policy
        all_controls.update(context.design_specifications.keys())
        
        for control_id in all_controls:
            logger.debug(f"Analyzing control: {control_id}")
            
            policy = context.policy_requirements.get(control_id)
            design = context.design_specifications.get(control_id)
            code = context.code_patterns.get(control_id)
            metadata = context.control_metadata.get(control_id, {})
            
            # Detect different types of gaps
            gaps = self._analyze_control(control_id, policy, design, code, metadata)
            self.gaps.extend(gaps)
        
        # Calculate risk scores for all gaps
        if self.risk_assessor:
            for gap in self.gaps:
                gap.risk_score = self.risk_assessor.calculate_risk_score(gap)
        
        logger.info(f"Gap detection complete. Found {len(self.gaps)} gaps")
        return self.gaps
    
    def _analyze_control(
        self,
        control_id: str,
        policy: Optional[Dict[str, Any]],
        design: Optional[Dict[str, Any]],
        code: Optional[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> List[Gap]:
        """
        Analyze a single control for gaps.
        
        Args:
            control_id: Control identifier (e.g., "AC-2")
            policy: Policy requirements for this control
            design: Design specifications for this control
            code: Code implementation patterns for this control
            metadata: Control metadata (name, family, etc.)
            
        Returns:
            List of gaps found for this control
        """
        gaps = []
        
        # If no policy requirement, skip (not in scope)
        if not policy:
            return gaps
        
        control_name = metadata.get("name", control_id)
        
        # Gap Type 1: Missing in design documentation
        if not design or not design.get("specified"):
            gap = self._create_gap(
                control_id=control_id,
                control_name=control_name,
                gap_type=GapType.MISSING_IN_DESIGN,
                severity=GapSeverity.HIGH,
                description=f"Control {control_id} is required by policy but not documented in design specifications",
                policy_requirement=policy.get("requirement", ""),
                design_specification=None,
                code_implementation=None
            )
            gaps.append(gap)
            return gaps  # If not in design, likely not in code either
        
        # Gap Type 2: Missing in code implementation
        if not code or not code.get("found"):
            gap = self._create_gap(
                control_id=control_id,
                control_name=control_name,
                gap_type=GapType.MISSING_IN_CODE,
                severity=GapSeverity.CRITICAL,
                description=f"Control {control_id} is specified in design but not implemented in code",
                policy_requirement=policy.get("requirement", ""),
                design_specification=design.get("specification", ""),
                code_implementation=None,
                evidence=[{"type": "missing", "details": "No matching code patterns found"}]
            )
            gaps.append(gap)
            return gaps
        
        # Gap Type 3: Partial or incorrect implementation
        implementation_gaps = self._check_implementation_quality(
            control_id, control_name, policy, design, code
        )
        gaps.extend(implementation_gaps)
        
        return gaps
    
    def _check_implementation_quality(
        self,
        control_id: str,
        control_name: str,
        policy: Dict[str, Any],
        design: Dict[str, Any],
        code: Dict[str, Any]
    ) -> List[Gap]:
        """
        Check if implementation meets requirements (partial, incorrect, etc.).
        
        Args:
            control_id: Control identifier
            control_name: Control name
            policy: Policy requirements
            design: Design specifications
            code: Code implementation
            
        Returns:
            List of implementation quality gaps
        """
        gaps = []
        
        # Check if all required features are implemented
        required_features = policy.get("required_features", [])
        implemented_features = code.get("implemented_features", [])
        
        missing_features = set(required_features) - set(implemented_features)
        
        if missing_features:
            gap = self._create_gap(
                control_id=control_id,
                control_name=control_name,
                gap_type=GapType.PARTIAL_IMPLEMENTATION,
                severity=GapSeverity.HIGH,
                description=f"Control {control_id} is partially implemented. Missing features: {', '.join(missing_features)}",
                policy_requirement=policy.get("requirement", ""),
                design_specification=design.get("specification", ""),
                code_implementation=code.get("implementation", ""),
                evidence=[{
                    "type": "missing_features",
                    "required": list(required_features),
                    "implemented": list(implemented_features),
                    "missing": list(missing_features)
                }]
            )
            gaps.append(gap)
        
        # Check configuration issues
        if code.get("configuration_issues"):
            for issue in code["configuration_issues"]:
                gap = self._create_gap(
                    control_id=control_id,
                    control_name=control_name,
                    gap_type=GapType.CONFIGURATION_GAP,
                    severity=self._determine_severity(issue.get("severity", "medium")),
                    description=f"Configuration issue in {control_id}: {issue.get('description', '')}",
                    policy_requirement=policy.get("requirement", ""),
                    design_specification=design.get("specification", ""),
                    code_implementation=code.get("implementation", ""),
                    evidence=[issue]
                )
                gaps.append(gap)
        
        # Check for incorrect implementation patterns
        if code.get("anti_patterns"):
            for anti_pattern in code["anti_patterns"]:
                gap = self._create_gap(
                    control_id=control_id,
                    control_name=control_name,
                    gap_type=GapType.INCORRECT_IMPLEMENTATION,
                    severity=GapSeverity.HIGH,
                    description=f"Incorrect implementation pattern detected in {control_id}: {anti_pattern.get('description', '')}",
                    policy_requirement=policy.get("requirement", ""),
                    design_specification=design.get("specification", ""),
                    code_implementation=code.get("implementation", ""),
                    evidence=[anti_pattern]
                )
                gaps.append(gap)
        
        return gaps
    
    def _create_gap(
        self,
        control_id: str,
        control_name: str,
        gap_type: GapType,
        severity: GapSeverity,
        description: str,
        policy_requirement: str,
        design_specification: Optional[str],
        code_implementation: Optional[str],
        evidence: Optional[List[Dict[str, Any]]] = None
    ) -> Gap:
        """Create a gap instance with unique ID."""
        gap_id = f"gap_{control_id.lower().replace('-', '_')}_{len(self.gaps) + 1}"
        
        return Gap(
            gap_id=gap_id,
            control_id=control_id,
            control_name=control_name,
            gap_type=gap_type,
            severity=severity,
            description=description,
            policy_requirement=policy_requirement,
            design_specification=design_specification,
            code_implementation=code_implementation,
            evidence=evidence or []
        )
    
    def _determine_severity(self, severity_str: str) -> GapSeverity:
        """Convert severity string to enum."""
        severity_map = {
            "critical": GapSeverity.CRITICAL,
            "high": GapSeverity.HIGH,
            "medium": GapSeverity.MEDIUM,
            "low": GapSeverity.LOW,
            "info": GapSeverity.INFO
        }
        return severity_map.get(severity_str.lower(), GapSeverity.MEDIUM)
    
    def get_gaps_by_severity(self, severity: GapSeverity) -> List[Gap]:
        """Get all gaps of a specific severity."""
        return [gap for gap in self.gaps if gap.severity == severity]
    
    def get_gaps_by_control_family(self, family: str) -> List[Gap]:
        """Get all gaps for a specific control family (e.g., 'AC', 'AU')."""
        return [gap for gap in self.gaps if gap.control_id.startswith(family)]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of detected gaps."""
        return {
            "total_gaps": len(self.gaps),
            "by_severity": {
                "critical": len(self.get_gaps_by_severity(GapSeverity.CRITICAL)),
                "high": len(self.get_gaps_by_severity(GapSeverity.HIGH)),
                "medium": len(self.get_gaps_by_severity(GapSeverity.MEDIUM)),
                "low": len(self.get_gaps_by_severity(GapSeverity.LOW)),
                "info": len(self.get_gaps_by_severity(GapSeverity.INFO))
            },
            "by_type": {
                gap_type.value: len([g for g in self.gaps if g.gap_type == gap_type])
                for gap_type in GapType
            },
            "average_risk_score": sum(g.risk_score for g in self.gaps) / len(self.gaps) if self.gaps else 0.0
        }

# Made with Bob
