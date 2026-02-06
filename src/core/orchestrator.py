"""
FedRAMP Gap Analysis Orchestrator

Coordinates the entire gap analysis workflow including document parsing,
code analysis, gap detection, risk assessment, and report generation.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging
import asyncio
from pathlib import Path

from ..gap_detection.detector import GapDetector, AnalysisContext, Gap
from ..gap_detection.control_mapper import ControlMapper
from ..gap_detection.pattern_matcher import PatternMatcher
from ..gap_detection.risk_assessor import RiskAssessor, RiskAssessment
from ..gap_detection.remediation import RemediationEngine, RemediationRecommendation

logger = logging.getLogger(__name__)


class AnalysisStatus(Enum):
    """Status of analysis job."""
    PENDING = "pending"
    PARSING_DOCUMENTS = "parsing_documents"
    ANALYZING_CODE = "analyzing_code"
    DETECTING_GAPS = "detecting_gaps"
    ASSESSING_RISK = "assessing_risk"
    GENERATING_REMEDIATION = "generating_remediation"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AnalysisJob:
    """Represents an analysis job."""
    job_id: str
    status: AnalysisStatus
    created_at: datetime
    updated_at: datetime
    policy_documents: List[str] = field(default_factory=list)
    design_documents: List[str] = field(default_factory=list)
    repository_url: Optional[str] = None
    progress: float = 0.0
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "policy_documents": self.policy_documents,
            "design_documents": self.design_documents,
            "repository_url": self.repository_url,
            "progress": self.progress,
            "error_message": self.error_message,
            "result": self.result
        }


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    job_id: str
    analysis_date: datetime
    gaps: List[Gap]
    risk_assessments: List[RiskAssessment]
    remediations: List[RemediationRecommendation]
    summary: Dict[str, Any]
    control_coverage: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "analysis_date": self.analysis_date.isoformat(),
            "gaps": [gap.to_dict() for gap in self.gaps],
            "risk_assessments": [ra.to_dict() for ra in self.risk_assessments],
            "remediations": [rem.to_dict() for rem in self.remediations],
            "summary": self.summary,
            "control_coverage": self.control_coverage
        }


class GapAnalysisOrchestrator:
    """
    Orchestrates the complete FedRAMP gap analysis workflow.
    
    Workflow:
    1. Parse policy documents to extract requirements
    2. Parse design documents to extract specifications
    3. Analyze code repository for implementations
    4. Map code patterns to FedRAMP controls
    5. Detect gaps between requirements and implementations
    6. Assess risk for each gap
    7. Generate remediation recommendations
    8. Create comprehensive report
    """
    
    def __init__(
        self,
        controls_data_path: Optional[str] = None,
        patterns_data_path: Optional[str] = None
    ):
        """
        Initialize the orchestrator.
        
        Args:
            controls_data_path: Path to FedRAMP controls data
            patterns_data_path: Path to security patterns data
        """
        self.control_mapper = ControlMapper(controls_data_path)
        self.pattern_matcher = PatternMatcher()
        self.risk_assessor = RiskAssessor()
        self.remediation_engine = RemediationEngine()
        self.gap_detector = GapDetector(
            control_mapper=self.control_mapper,
            risk_assessor=self.risk_assessor
        )
        
        self.jobs: Dict[str, AnalysisJob] = {}
        
        logger.info("Gap Analysis Orchestrator initialized")
    
    async def start_analysis(
        self,
        job_id: str,
        policy_documents: List[str],
        design_documents: List[str],
        repository_url: Optional[str] = None,
        repository_path: Optional[str] = None
    ) -> AnalysisJob:
        """
        Start a new gap analysis job.
        
        Args:
            job_id: Unique job identifier
            policy_documents: List of policy document paths/URLs
            design_documents: List of design document paths/URLs
            repository_url: Git repository URL (optional)
            repository_path: Local repository path (optional)
            
        Returns:
            Analysis job
        """
        job = AnalysisJob(
            job_id=job_id,
            status=AnalysisStatus.PENDING,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            policy_documents=policy_documents,
            design_documents=design_documents,
            repository_url=repository_url
        )
        
        self.jobs[job_id] = job
        
        # Start analysis in background
        asyncio.create_task(self._run_analysis(job, repository_path))
        
        logger.info(f"Started analysis job: {job_id}")
        return job
    
    async def _run_analysis(
        self,
        job: AnalysisJob,
        repository_path: Optional[str] = None
    ) -> None:
        """
        Run the complete analysis workflow.
        
        Args:
            job: Analysis job
            repository_path: Local repository path
        """
        try:
            # Step 1: Parse policy documents
            job.status = AnalysisStatus.PARSING_DOCUMENTS
            job.progress = 10.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Parsing policy documents")
            
            policy_requirements = await self._parse_policy_documents(
                job.policy_documents
            )
            
            # Step 2: Parse design documents
            job.progress = 25.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Parsing design documents")
            
            design_specifications = await self._parse_design_documents(
                job.design_documents
            )
            
            # Step 3: Analyze code repository
            job.status = AnalysisStatus.ANALYZING_CODE
            job.progress = 40.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Analyzing code repository")
            
            code_patterns = await self._analyze_code_repository(repository_path)
            
            # Step 4: Detect gaps
            job.status = AnalysisStatus.DETECTING_GAPS
            job.progress = 60.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Detecting compliance gaps")
            
            context = AnalysisContext(
                policy_requirements=policy_requirements,
                design_specifications=design_specifications,
                code_patterns=code_patterns,
                control_metadata=self._get_control_metadata()
            )
            
            gaps = self.gap_detector.detect_gaps(context)
            
            # Step 5: Assess risk
            job.status = AnalysisStatus.ASSESSING_RISK
            job.progress = 75.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Assessing risk")
            
            risk_assessments = [
                self.risk_assessor.assess_gap(gap, context.control_metadata.get(gap.control_id))
                for gap in gaps
            ]
            
            # Step 6: Generate remediation recommendations
            job.status = AnalysisStatus.GENERATING_REMEDIATION
            job.progress = 85.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Generating remediation recommendations")
            
            remediations = [
                self.remediation_engine.generate_remediation(
                    gap,
                    context.control_metadata.get(gap.control_id)
                )
                for gap in gaps
            ]
            
            # Step 7: Generate report
            job.status = AnalysisStatus.GENERATING_REPORT
            job.progress = 95.0
            job.updated_at = datetime.utcnow()
            logger.info(f"Job {job.job_id}: Generating report")
            
            result = AnalysisResult(
                job_id=job.job_id,
                analysis_date=datetime.utcnow(),
                gaps=gaps,
                risk_assessments=risk_assessments,
                remediations=remediations,
                summary=self._generate_summary(gaps, risk_assessments),
                control_coverage=self._calculate_control_coverage(
                    policy_requirements,
                    code_patterns
                )
            )
            
            # Complete job
            job.status = AnalysisStatus.COMPLETED
            job.progress = 100.0
            job.updated_at = datetime.utcnow()
            job.result = result.to_dict()
            
            logger.info(f"Job {job.job_id}: Analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Job {job.job_id}: Analysis failed: {e}", exc_info=True)
            job.status = AnalysisStatus.FAILED
            job.error_message = str(e)
            job.updated_at = datetime.utcnow()
    
    async def _parse_policy_documents(
        self,
        document_paths: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parse policy documents to extract FedRAMP requirements.
        
        Args:
            document_paths: List of document paths
            
        Returns:
            Dictionary mapping control IDs to requirements
        """
        # TODO: Implement actual document parsing
        # For now, return sample data based on loaded controls
        
        requirements = {}
        for control_id in self.control_mapper.get_all_control_ids():
            control_info = self.control_mapper.get_control_info(control_id)
            if control_info:
                requirements[control_id] = {
                    "requirement": control_info.implementation_guidance,
                    "required_features": getattr(control_info, 'required_features', []),
                    "specified": True
                }
        
        logger.info(f"Parsed {len(requirements)} policy requirements")
        return requirements
    
    async def _parse_design_documents(
        self,
        document_paths: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parse design documents to extract specifications.
        
        Args:
            document_paths: List of document paths
            
        Returns:
            Dictionary mapping control IDs to design specifications
        """
        # TODO: Implement actual document parsing
        # For now, return sample data
        
        specifications = {}
        for control_id in ["AC-2", "AC-3", "IA-2", "IA-2(1)", "AU-2", "SC-8", "SC-13"]:
            specifications[control_id] = {
                "specification": f"Design specification for {control_id}",
                "specified": True
            }
        
        logger.info(f"Parsed {len(specifications)} design specifications")
        return specifications
    
    async def _analyze_code_repository(
        self,
        repository_path: Optional[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Analyze code repository for security implementations.
        
        Args:
            repository_path: Path to repository
            
        Returns:
            Dictionary mapping control IDs to code patterns
        """
        if not repository_path:
            logger.warning("No repository path provided, skipping code analysis")
            return {}
        
        # Scan repository for Java files
        repo_path = Path(repository_path)
        if not repo_path.exists():
            logger.warning(f"Repository path does not exist: {repository_path}")
            return {}
        
        code_patterns = {}
        java_files = list(repo_path.rglob("*.java"))
        
        logger.info(f"Found {len(java_files)} Java files to analyze")
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Match patterns in file
                matches = self.pattern_matcher.match_patterns(
                    content,
                    str(java_file.relative_to(repo_path))
                )
                
                # Group matches by control
                for match in matches:
                    for control_id in match.related_controls:
                        if control_id not in code_patterns:
                            code_patterns[control_id] = {
                                "found": True,
                                "implementation": f"Found in {java_file.name}",
                                "implemented_features": [],
                                "configuration_issues": [],
                                "anti_patterns": []
                            }
                        
                        # Categorize match
                        if match.category.value == "good_pattern":
                            code_patterns[control_id]["implemented_features"].append(
                                match.pattern_name
                            )
                        elif match.category.value == "anti_pattern":
                            code_patterns[control_id]["anti_patterns"].append({
                                "description": match.description,
                                "file": match.file_path,
                                "line": match.line_number,
                                "severity": "high"
                            })
                        elif match.category.value == "configuration":
                            code_patterns[control_id]["configuration_issues"].append({
                                "description": match.description,
                                "file": match.file_path,
                                "line": match.line_number,
                                "severity": "medium"
                            })
                            
            except Exception as e:
                logger.warning(f"Failed to analyze {java_file}: {e}")
        
        logger.info(f"Analyzed code, found patterns for {len(code_patterns)} controls")
        return code_patterns
    
    def _get_control_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Get metadata for all controls."""
        metadata = {}
        for control_id in self.control_mapper.get_all_control_ids():
            control_info = self.control_mapper.get_control_info(control_id)
            if control_info:
                metadata[control_id] = {
                    "name": control_info.control_name,
                    "family": control_info.control_family,
                    "baseline": control_info.baseline,
                    "guidance": control_info.implementation_guidance
                }
        return metadata
    
    def _generate_summary(
        self,
        gaps: List[Gap],
        risk_assessments: List[RiskAssessment]
    ) -> Dict[str, Any]:
        """Generate analysis summary."""
        total_controls = len(self.control_mapper.get_all_control_ids())
        controls_with_gaps = len(set(gap.control_id for gap in gaps))
        
        return {
            "total_controls_evaluated": total_controls,
            "controls_with_gaps": controls_with_gaps,
            "controls_compliant": total_controls - controls_with_gaps,
            "total_gaps": len(gaps),
            "critical_gaps": len([g for g in gaps if g.severity.value == "critical"]),
            "high_gaps": len([g for g in gaps if g.severity.value == "high"]),
            "medium_gaps": len([g for g in gaps if g.severity.value == "medium"]),
            "low_gaps": len([g for g in gaps if g.severity.value == "low"]),
            "average_risk_score": sum(ra.risk_score for ra in risk_assessments) / len(risk_assessments) if risk_assessments else 0.0,
            "compliance_score": ((total_controls - controls_with_gaps) / total_controls * 100) if total_controls > 0 else 0.0
        }
    
    def _calculate_control_coverage(
        self,
        policy_requirements: Dict[str, Dict[str, Any]],
        code_patterns: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate control coverage statistics."""
        total_required = len(policy_requirements)
        implemented = len([c for c in code_patterns.values() if c.get("found")])
        
        coverage_by_family = {}
        for control_id in policy_requirements.keys():
            family = control_id.split('-')[0]
            if family not in coverage_by_family:
                coverage_by_family[family] = {"required": 0, "implemented": 0}
            
            coverage_by_family[family]["required"] += 1
            if control_id in code_patterns and code_patterns[control_id].get("found"):
                coverage_by_family[family]["implemented"] += 1
        
        return {
            "total_required": total_required,
            "total_implemented": implemented,
            "coverage_percentage": (implemented / total_required * 100) if total_required > 0 else 0.0,
            "by_family": coverage_by_family
        }
    
    def get_job_status(self, job_id: str) -> Optional[AnalysisJob]:
        """Get status of an analysis job."""
        return self.jobs.get(job_id)
    
    def get_job_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get result of a completed analysis job."""
        job = self.jobs.get(job_id)
        if job and job.status == AnalysisStatus.COMPLETED:
            return job.result
        return None

# Made with Bob
