"""
Risk Assessor for FedRAMP Gap Analysis

Calculates risk scores and severity levels for identified compliance gaps
based on control criticality, gap type, and potential impact.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

from .detector import Gap, GapType, GapSeverity

logger = logging.getLogger(__name__)


class ImpactLevel(Enum):
    """Impact levels for security gaps."""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class LikelihoodLevel(Enum):
    """Likelihood levels for gap exploitation."""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class RiskAssessment:
    """Detailed risk assessment for a gap."""
    gap_id: str
    control_id: str
    risk_score: float  # 0-10 scale
    impact: ImpactLevel
    likelihood: LikelihoodLevel
    risk_level: str  # "Critical", "High", "Medium", "Low"
    business_impact: str
    technical_impact: str
    compliance_impact: str
    exploitability: float  # 0-1 scale
    remediation_priority: int  # 1-5, 1 being highest
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "gap_id": self.gap_id,
            "control_id": self.control_id,
            "risk_score": round(self.risk_score, 2),
            "impact": self.impact.value,
            "likelihood": self.likelihood.value,
            "risk_level": self.risk_level,
            "business_impact": self.business_impact,
            "technical_impact": self.technical_impact,
            "compliance_impact": self.compliance_impact,
            "exploitability": round(self.exploitability, 2),
            "remediation_priority": self.remediation_priority
        }


class RiskAssessor:
    """
    Assesses risk levels for compliance gaps using multiple factors:
    - Control criticality (from FedRAMP baseline)
    - Gap type (missing vs partial implementation)
    - Impact on confidentiality, integrity, availability
    - Likelihood of exploitation
    - Business and compliance impact
    """
    
    def __init__(self):
        """Initialize the risk assessor with control criticality data."""
        self.control_criticality = self._initialize_control_criticality()
        self.control_family_weights = self._initialize_family_weights()
    
    def _initialize_control_criticality(self) -> Dict[str, float]:
        """
        Initialize control criticality scores (0-10 scale).
        Based on FedRAMP High baseline and NIST 800-53 priority.
        """
        return {
            # Access Control (AC) - Critical controls
            "AC-2": 9.0,   # Account Management
            "AC-3": 9.5,   # Access Enforcement
            "AC-6": 8.5,   # Least Privilege
            "AC-7": 8.0,   # Unsuccessful Logon Attempts
            "AC-17": 8.5,  # Remote Access
            
            # Audit and Accountability (AU) - High priority
            "AU-2": 8.5,   # Audit Events
            "AU-3": 8.0,   # Content of Audit Records
            "AU-6": 7.5,   # Audit Review
            "AU-9": 8.0,   # Protection of Audit Information
            "AU-12": 8.5,  # Audit Generation
            
            # Identification and Authentication (IA) - Critical
            "IA-2": 9.5,   # Identification and Authentication
            "IA-2(1)": 10.0,  # Multi-Factor Authentication
            "IA-2(2)": 9.0,   # Network Access to Privileged Accounts
            "IA-5": 9.0,   # Authenticator Management
            "IA-5(1)": 8.5,   # Password-Based Authentication
            
            # System and Communications Protection (SC) - Critical
            "SC-7": 9.0,   # Boundary Protection
            "SC-8": 9.5,   # Transmission Confidentiality and Integrity
            "SC-8(1)": 9.5,   # Cryptographic Protection
            "SC-13": 9.5,  # Cryptographic Protection
            "SC-28": 9.0,  # Protection of Information at Rest
            
            # Configuration Management (CM) - High
            "CM-2": 7.5,   # Baseline Configuration
            "CM-6": 8.0,   # Configuration Settings
            "CM-7": 8.5,   # Least Functionality
            
            # Contingency Planning (CP) - High
            "CP-9": 8.0,   # Information System Backup
            "CP-10": 7.5,  # Information System Recovery
            
            # Incident Response (IR) - High
            "IR-4": 8.0,   # Incident Handling
            "IR-5": 7.5,   # Incident Monitoring
            "IR-6": 8.0,   # Incident Reporting
            
            # System and Information Integrity (SI) - Critical
            "SI-2": 9.0,   # Flaw Remediation
            "SI-3": 8.5,   # Malicious Code Protection
            "SI-4": 8.5,   # Information System Monitoring
            "SI-10": 8.0,  # Information Input Validation
            "SI-11": 7.5,  # Error Handling
        }
    
    def _initialize_family_weights(self) -> Dict[str, float]:
        """Initialize control family importance weights."""
        return {
            "AC": 0.95,  # Access Control - Critical
            "AU": 0.85,  # Audit and Accountability - High
            "IA": 0.95,  # Identification and Authentication - Critical
            "SC": 0.95,  # System and Communications Protection - Critical
            "SI": 0.90,  # System and Information Integrity - Critical
            "CM": 0.80,  # Configuration Management - High
            "CP": 0.75,  # Contingency Planning - High
            "IR": 0.80,  # Incident Response - High
            "CA": 0.70,  # Security Assessment - Medium
            "AT": 0.60,  # Awareness and Training - Medium
            "MA": 0.65,  # Maintenance - Medium
            "MP": 0.70,  # Media Protection - Medium
            "PE": 0.75,  # Physical Protection - High
            "PL": 0.65,  # Planning - Medium
            "PS": 0.70,  # Personnel Security - Medium
            "RA": 0.75,  # Risk Assessment - High
            "SA": 0.70,  # System Acquisition - Medium
        }
    
    def calculate_risk_score(self, gap: Gap) -> float:
        """
        Calculate overall risk score for a gap (0-10 scale).
        
        Args:
            gap: Gap to assess
            
        Returns:
            Risk score from 0 (lowest) to 10 (highest)
        """
        # Get control criticality
        control_criticality = self.get_control_criticality(gap.control_id)
        
        # Get gap type severity multiplier
        gap_type_multiplier = self._get_gap_type_multiplier(gap.gap_type)
        
        # Get control family weight
        family = gap.control_id.split('-')[0]
        family_weight = self.control_family_weights.get(family, 0.7)
        
        # Calculate base risk score
        base_score = control_criticality * gap_type_multiplier * family_weight
        
        # Adjust for evidence and confidence
        evidence_factor = self._calculate_evidence_factor(gap)
        
        # Final risk score (0-10 scale)
        risk_score = min(10.0, base_score * evidence_factor)
        
        return risk_score
    
    def assess_gap(self, gap: Gap, control_metadata: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """
        Perform comprehensive risk assessment for a gap.
        
        Args:
            gap: Gap to assess
            control_metadata: Additional control metadata
            
        Returns:
            Detailed risk assessment
        """
        # Calculate risk score
        risk_score = self.calculate_risk_score(gap)
        
        # Determine impact level
        impact = self._determine_impact_level(gap, risk_score)
        
        # Determine likelihood
        likelihood = self._determine_likelihood(gap, control_metadata)
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(impact, likelihood)
        
        # Assess business impact
        business_impact = self._assess_business_impact(gap, control_metadata)
        
        # Assess technical impact
        technical_impact = self._assess_technical_impact(gap)
        
        # Assess compliance impact
        compliance_impact = self._assess_compliance_impact(gap)
        
        # Calculate exploitability
        exploitability = self._calculate_exploitability(gap, likelihood)
        
        # Determine remediation priority
        priority = self._determine_remediation_priority(risk_score, impact, likelihood)
        
        assessment = RiskAssessment(
            gap_id=gap.gap_id,
            control_id=gap.control_id,
            risk_score=risk_score,
            impact=impact,
            likelihood=likelihood,
            risk_level=risk_level,
            business_impact=business_impact,
            technical_impact=technical_impact,
            compliance_impact=compliance_impact,
            exploitability=exploitability,
            remediation_priority=priority
        )
        
        # Update gap with risk information
        gap.risk_score = risk_score
        gap.impact = impact.value
        gap.likelihood = likelihood.value
        
        return assessment
    
    def get_control_criticality(self, control_id: str) -> float:
        """
        Get criticality score for a control.
        
        Args:
            control_id: Control identifier
            
        Returns:
            Criticality score (0-10)
        """
        # Direct lookup
        if control_id in self.control_criticality:
            return self.control_criticality[control_id]
        
        # Family-based default
        family = control_id.split('-')[0]
        family_weight = self.control_family_weights.get(family, 0.7)
        return 7.0 * family_weight  # Default moderate criticality
    
    def _get_gap_type_multiplier(self, gap_type: GapType) -> float:
        """Get severity multiplier based on gap type."""
        multipliers = {
            GapType.MISSING_IMPLEMENTATION: 1.0,      # Most severe
            GapType.MISSING_IN_CODE: 0.95,
            GapType.MISSING_IN_DESIGN: 0.85,
            GapType.INCORRECT_IMPLEMENTATION: 0.90,
            GapType.PARTIAL_IMPLEMENTATION: 0.75,
            GapType.OUTDATED_IMPLEMENTATION: 0.70,
            GapType.CONFIGURATION_GAP: 0.65,
        }
        return multipliers.get(gap_type, 0.8)
    
    def _calculate_evidence_factor(self, gap: Gap) -> float:
        """Calculate evidence confidence factor."""
        if not gap.evidence:
            return 0.9  # Slight reduction for no evidence
        
        # More evidence increases confidence
        evidence_count = len(gap.evidence)
        if evidence_count >= 3:
            return 1.1  # High confidence
        elif evidence_count >= 2:
            return 1.0
        else:
            return 0.95
    
    def _determine_impact_level(self, gap: Gap, risk_score: float) -> ImpactLevel:
        """Determine impact level based on risk score and gap characteristics."""
        if risk_score >= 9.0:
            return ImpactLevel.CRITICAL
        elif risk_score >= 7.5:
            return ImpactLevel.HIGH
        elif risk_score >= 5.0:
            return ImpactLevel.MODERATE
        elif risk_score >= 2.5:
            return ImpactLevel.LOW
        else:
            return ImpactLevel.NEGLIGIBLE
    
    def _determine_likelihood(self, gap: Gap, control_metadata: Optional[Dict[str, Any]]) -> LikelihoodLevel:
        """Determine likelihood of gap exploitation."""
        # Missing implementations are more likely to be exploited
        if gap.gap_type in [GapType.MISSING_IMPLEMENTATION, GapType.MISSING_IN_CODE]:
            return LikelihoodLevel.HIGH
        
        # Incorrect implementations are also high risk
        if gap.gap_type == GapType.INCORRECT_IMPLEMENTATION:
            return LikelihoodLevel.HIGH
        
        # Partial implementations depend on what's missing
        if gap.gap_type == GapType.PARTIAL_IMPLEMENTATION:
            return LikelihoodLevel.MODERATE
        
        # Configuration gaps vary
        if gap.gap_type == GapType.CONFIGURATION_GAP:
            return LikelihoodLevel.MODERATE
        
        # Design gaps are lower likelihood (may not be exposed)
        if gap.gap_type == GapType.MISSING_IN_DESIGN:
            return LikelihoodLevel.LOW
        
        return LikelihoodLevel.MODERATE
    
    def _calculate_risk_level(self, impact: ImpactLevel, likelihood: LikelihoodLevel) -> str:
        """Calculate overall risk level from impact and likelihood."""
        # Risk matrix
        risk_matrix = {
            (ImpactLevel.CRITICAL, LikelihoodLevel.VERY_HIGH): "Critical",
            (ImpactLevel.CRITICAL, LikelihoodLevel.HIGH): "Critical",
            (ImpactLevel.CRITICAL, LikelihoodLevel.MODERATE): "High",
            (ImpactLevel.HIGH, LikelihoodLevel.VERY_HIGH): "Critical",
            (ImpactLevel.HIGH, LikelihoodLevel.HIGH): "High",
            (ImpactLevel.HIGH, LikelihoodLevel.MODERATE): "High",
            (ImpactLevel.MODERATE, LikelihoodLevel.HIGH): "High",
            (ImpactLevel.MODERATE, LikelihoodLevel.MODERATE): "Medium",
            (ImpactLevel.LOW, LikelihoodLevel.HIGH): "Medium",
            (ImpactLevel.LOW, LikelihoodLevel.MODERATE): "Low",
        }
        
        return risk_matrix.get((impact, likelihood), "Medium")
    
    def _assess_business_impact(self, gap: Gap, control_metadata: Optional[Dict[str, Any]]) -> str:
        """Assess business impact of the gap."""
        control_family = gap.control_id.split('-')[0]
        
        impact_descriptions = {
            "AC": "Unauthorized access could lead to data breaches and compliance violations",
            "AU": "Lack of audit trails impairs incident detection and forensic analysis",
            "IA": "Weak authentication increases risk of account compromise and data theft",
            "SC": "Inadequate protection exposes sensitive data to interception and tampering",
            "SI": "System vulnerabilities could be exploited leading to service disruption",
            "CM": "Poor configuration management increases security risks and operational issues",
            "CP": "Inadequate contingency planning risks extended downtime and data loss",
            "IR": "Weak incident response delays threat mitigation and increases damage",
        }
        
        return impact_descriptions.get(control_family, "Compliance gap may impact security posture")
    
    def _assess_technical_impact(self, gap: Gap) -> str:
        """Assess technical impact of the gap."""
        if gap.gap_type == GapType.MISSING_IMPLEMENTATION:
            return "Critical security control not implemented, system is vulnerable"
        elif gap.gap_type == GapType.INCORRECT_IMPLEMENTATION:
            return "Incorrect implementation may provide false sense of security"
        elif gap.gap_type == GapType.PARTIAL_IMPLEMENTATION:
            return "Incomplete implementation leaves security gaps"
        elif gap.gap_type == GapType.CONFIGURATION_GAP:
            return "Misconfiguration weakens security controls"
        else:
            return "Technical implementation does not meet requirements"
    
    def _assess_compliance_impact(self, gap: Gap) -> str:
        """Assess compliance impact of the gap."""
        if gap.severity == GapSeverity.CRITICAL:
            return "Critical FedRAMP requirement not met - blocks authorization"
        elif gap.severity == GapSeverity.HIGH:
            return "High-priority FedRAMP requirement not met - requires immediate remediation"
        elif gap.severity == GapSeverity.MEDIUM:
            return "Medium-priority FedRAMP requirement not met - plan remediation"
        else:
            return "Low-priority FedRAMP requirement not met - address in next cycle"
    
    def _calculate_exploitability(self, gap: Gap, likelihood: LikelihoodLevel) -> float:
        """Calculate exploitability score (0-1)."""
        likelihood_scores = {
            LikelihoodLevel.VERY_HIGH: 0.95,
            LikelihoodLevel.HIGH: 0.80,
            LikelihoodLevel.MODERATE: 0.60,
            LikelihoodLevel.LOW: 0.35,
            LikelihoodLevel.VERY_LOW: 0.15,
        }
        
        base_score = likelihood_scores.get(likelihood, 0.5)
        
        # Adjust based on gap type
        if gap.gap_type in [GapType.MISSING_IMPLEMENTATION, GapType.MISSING_IN_CODE]:
            base_score *= 1.1
        
        return min(1.0, base_score)
    
    def _determine_remediation_priority(
        self,
        risk_score: float,
        impact: ImpactLevel,
        likelihood: LikelihoodLevel
    ) -> int:
        """
        Determine remediation priority (1-5, 1 being highest).
        
        Args:
            risk_score: Calculated risk score
            impact: Impact level
            likelihood: Likelihood level
            
        Returns:
            Priority level (1-5)
        """
        if risk_score >= 9.0 or impact == ImpactLevel.CRITICAL:
            return 1  # Immediate
        elif risk_score >= 7.5 or impact == ImpactLevel.HIGH:
            return 2  # Urgent
        elif risk_score >= 5.0:
            return 3  # High
        elif risk_score >= 3.0:
            return 4  # Medium
        else:
            return 5  # Low

# Made with Bob
