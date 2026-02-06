"""
Test suite for FedRAMP Gap Detection Engine
"""

import pytest
from datetime import datetime
from src.gap_detection.detector import (
    GapDetector, Gap, GapType, GapSeverity, AnalysisContext
)
from src.gap_detection.control_mapper import ControlMapper
from src.gap_detection.pattern_matcher import PatternMatcher, PatternType, PatternCategory
from src.gap_detection.risk_assessor import RiskAssessor, ImpactLevel, LikelihoodLevel
from src.gap_detection.remediation import RemediationEngine, EffortLevel


class TestGapDetector:
    """Test cases for GapDetector."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.control_mapper = ControlMapper()
        self.risk_assessor = RiskAssessor()
        self.detector = GapDetector(
            control_mapper=self.control_mapper,
            risk_assessor=self.risk_assessor
        )
    
    def test_detect_missing_in_design(self):
        """Test detection of controls missing in design."""
        context = AnalysisContext(
            policy_requirements={
                "AC-2": {
                    "requirement": "Implement account management",
                    "required_features": ["account_creation", "account_disabling"],
                    "specified": True
                }
            },
            design_specifications={},  # Missing in design
            code_patterns={},
            control_metadata={
                "AC-2": {
                    "name": "Account Management",
                    "family": "AC"
                }
            }
        )
        
        gaps = self.detector.detect_gaps(context)
        
        assert len(gaps) == 1
        assert gaps[0].control_id == "AC-2"
        assert gaps[0].gap_type == GapType.MISSING_IN_DESIGN
        assert gaps[0].severity == GapSeverity.HIGH
    
    def test_detect_missing_in_code(self):
        """Test detection of controls missing in code."""
        context = AnalysisContext(
            policy_requirements={
                "IA-2": {
                    "requirement": "Implement authentication",
                    "required_features": ["user_authentication"],
                    "specified": True
                }
            },
            design_specifications={
                "IA-2": {
                    "specification": "Use Spring Security for authentication",
                    "specified": True
                }
            },
            code_patterns={},  # Missing in code
            control_metadata={
                "IA-2": {
                    "name": "Identification and Authentication",
                    "family": "IA"
                }
            }
        )
        
        gaps = self.detector.detect_gaps(context)
        
        assert len(gaps) == 1
        assert gaps[0].control_id == "IA-2"
        assert gaps[0].gap_type == GapType.MISSING_IN_CODE
        assert gaps[0].severity == GapSeverity.CRITICAL
    
    def test_detect_partial_implementation(self):
        """Test detection of partial implementations."""
        context = AnalysisContext(
            policy_requirements={
                "IA-2(1)": {
                    "requirement": "Implement MFA",
                    "required_features": ["mfa_enrollment", "totp_generation", "mfa_verification"],
                    "specified": True
                }
            },
            design_specifications={
                "IA-2(1)": {
                    "specification": "Implement TOTP-based MFA",
                    "specified": True
                }
            },
            code_patterns={
                "IA-2(1)": {
                    "found": True,
                    "implementation": "Partial MFA implementation",
                    "implemented_features": ["mfa_enrollment"],  # Missing other features
                    "configuration_issues": [],
                    "anti_patterns": []
                }
            },
            control_metadata={
                "IA-2(1)": {
                    "name": "Multi-Factor Authentication",
                    "family": "IA"
                }
            }
        )
        
        gaps = self.detector.detect_gaps(context)
        
        assert len(gaps) == 1
        assert gaps[0].control_id == "IA-2(1)"
        assert gaps[0].gap_type == GapType.PARTIAL_IMPLEMENTATION
        assert "totp_generation" in gaps[0].description
        assert "mfa_verification" in gaps[0].description
    
    def test_detect_configuration_issues(self):
        """Test detection of configuration issues."""
        context = AnalysisContext(
            policy_requirements={
                "SC-8": {
                    "requirement": "Enforce TLS",
                    "required_features": ["tls_enforcement"],
                    "specified": True
                }
            },
            design_specifications={
                "SC-8": {
                    "specification": "Use TLS 1.2+",
                    "specified": True
                }
            },
            code_patterns={
                "SC-8": {
                    "found": True,
                    "implementation": "TLS configured",
                    "implemented_features": ["tls_enforcement"],
                    "configuration_issues": [
                        {
                            "description": "TLS 1.0 enabled (should be disabled)",
                            "severity": "high"
                        }
                    ],
                    "anti_patterns": []
                }
            },
            control_metadata={
                "SC-8": {
                    "name": "Transmission Confidentiality",
                    "family": "SC"
                }
            }
        )
        
        gaps = self.detector.detect_gaps(context)
        
        assert len(gaps) == 1
        assert gaps[0].gap_type == GapType.CONFIGURATION_GAP
        assert "TLS 1.0" in gaps[0].description
    
    def test_get_summary(self):
        """Test gap summary generation."""
        context = AnalysisContext(
            policy_requirements={
                "AC-2": {"requirement": "Account management", "specified": True},
                "IA-2": {"requirement": "Authentication", "specified": True},
                "AU-2": {"requirement": "Audit logging", "specified": True}
            },
            design_specifications={
                "IA-2": {"specification": "Spring Security", "specified": True}
            },
            code_patterns={},
            control_metadata={
                "AC-2": {"name": "Account Management", "family": "AC"},
                "IA-2": {"name": "Authentication", "family": "IA"},
                "AU-2": {"name": "Audit Events", "family": "AU"}
            }
        )
        
        gaps = self.detector.detect_gaps(context)
        summary = self.detector.get_summary()
        
        assert summary["total_gaps"] == len(gaps)
        assert "by_severity" in summary
        assert "by_type" in summary


class TestControlMapper:
    """Test cases for ControlMapper."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = ControlMapper()
    
    def test_map_code_pattern_to_controls(self):
        """Test mapping code patterns to controls."""
        patterns = self.mapper.map_code_pattern_to_controls("@PreAuthorize")
        
        assert "AC-3" in patterns
        assert "AC-6" in patterns
    
    def test_map_multiple_patterns(self):
        """Test mapping multiple patterns."""
        patterns = ["@PreAuthorize", "BCryptPasswordEncoder", "AuditLogger"]
        control_patterns = self.mapper.map_code_patterns_to_controls(patterns)
        
        assert "AC-3" in control_patterns
        assert "IA-5" in control_patterns
        assert "AU-2" in control_patterns
    
    def test_get_control_info(self):
        """Test retrieving control information."""
        control = self.mapper.get_control_info("AC-2")
        
        assert control is not None
        assert control.control_id == "AC-2"
        assert control.control_name == "Account Management"
        assert control.control_family == "AC"
    
    def test_get_controls_by_family(self):
        """Test retrieving controls by family."""
        ac_controls = self.mapper.get_controls_by_family("AC")
        
        assert len(ac_controls) > 0
        assert all(c.control_family == "AC" for c in ac_controls)
    
    def test_search_controls(self):
        """Test control search functionality."""
        results = self.mapper.search_controls("authentication")
        
        assert len(results) > 0
        assert any("authentication" in c.control_name.lower() for c in results)


class TestPatternMatcher:
    """Test cases for PatternMatcher."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.matcher = PatternMatcher()
    
    def test_match_authentication_pattern(self):
        """Test matching authentication patterns."""
        code = """
        @Configuration
        @EnableWebSecurity
        public class SecurityConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http.authorizeRequests().anyRequest().authenticated();
            }
        }
        """
        
        matches = self.matcher.match_patterns(code, "SecurityConfig.java")
        
        assert len(matches) > 0
        auth_matches = [m for m in matches if m.pattern_type == PatternType.AUTHENTICATION]
        assert len(auth_matches) > 0
    
    def test_match_hardcoded_credentials(self):
        """Test detection of hardcoded credentials."""
        code = """
        public class Config {
            private String password = "MySecretPassword123";
            private String apiKey = "sk_live_abc123xyz";
        }
        """
        
        matches = self.matcher.match_patterns(code, "Config.java")
        
        anti_patterns = self.matcher.get_anti_patterns()
        assert len(anti_patterns) > 0
        assert any("hardcoded" in m.description.lower() for m in anti_patterns)
    
    def test_match_authorization_pattern(self):
        """Test matching authorization patterns."""
        code = """
        @RestController
        public class AdminController {
            @PreAuthorize("hasRole('ADMIN')")
            @GetMapping("/admin")
            public String adminPage() {
                return "admin";
            }
        }
        """
        
        matches = self.matcher.match_patterns(code, "AdminController.java")
        
        authz_matches = [m for m in matches if m.pattern_type == PatternType.AUTHORIZATION]
        assert len(authz_matches) > 0
    
    def test_get_summary(self):
        """Test pattern matching summary."""
        code = """
        @EnableWebSecurity
        public class SecurityConfig {
            @Bean
            public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
            }
        }
        """
        
        self.matcher.match_patterns(code, "SecurityConfig.java")
        summary = self.matcher.get_summary()
        
        assert "total_matches" in summary
        assert "by_type" in summary
        assert "by_category" in summary


class TestRiskAssessor:
    """Test cases for RiskAssessor."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.assessor = RiskAssessor()
    
    def test_calculate_risk_score_critical(self):
        """Test risk score calculation for critical gaps."""
        gap = Gap(
            gap_id="gap_001",
            control_id="IA-2(1)",
            control_name="Multi-Factor Authentication",
            gap_type=GapType.MISSING_IMPLEMENTATION,
            severity=GapSeverity.CRITICAL,
            description="MFA not implemented",
            policy_requirement="Implement MFA for privileged accounts",
            design_specification="TOTP-based MFA",
            code_implementation=None
        )
        
        risk_score = self.assessor.calculate_risk_score(gap)
        
        assert risk_score >= 8.0  # High risk for missing MFA
    
    def test_assess_gap(self):
        """Test comprehensive gap assessment."""
        gap = Gap(
            gap_id="gap_002",
            control_id="SC-13",
            control_name="Cryptographic Protection",
            gap_type=GapType.INCORRECT_IMPLEMENTATION,
            severity=GapSeverity.HIGH,
            description="Weak encryption algorithm used",
            policy_requirement="Use FIPS-validated cryptography",
            design_specification="AES-256 encryption",
            code_implementation="DES encryption found"
        )
        
        assessment = self.assessor.assess_gap(gap)
        
        assert assessment.risk_score > 0
        assert assessment.impact in [ImpactLevel.CRITICAL, ImpactLevel.HIGH]
        assert assessment.likelihood in [LikelihoodLevel.HIGH, LikelihoodLevel.MODERATE]
        assert assessment.remediation_priority <= 2  # High priority
    
    def test_get_control_criticality(self):
        """Test control criticality retrieval."""
        # Critical controls
        assert self.assessor.get_control_criticality("IA-2(1)") >= 9.0
        assert self.assessor.get_control_criticality("SC-13") >= 9.0
        
        # High priority controls
        assert self.assessor.get_control_criticality("AC-2") >= 8.0
        assert self.assessor.get_control_criticality("AU-2") >= 8.0


class TestRemediationEngine:
    """Test cases for RemediationEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = RemediationEngine()
    
    def test_generate_remediation_with_template(self):
        """Test remediation generation for controls with templates."""
        gap = Gap(
            gap_id="gap_003",
            control_id="AC-2",
            control_name="Account Management",
            gap_type=GapType.MISSING_IN_CODE,
            severity=GapSeverity.HIGH,
            description="Account management not implemented",
            policy_requirement="Implement user account lifecycle management",
            design_specification="Spring Security user management",
            code_implementation=None
        )
        
        remediation = self.engine.generate_remediation(gap)
        
        assert remediation.control_id == "AC-2"
        assert len(remediation.steps) > 0
        assert remediation.effort_estimate in [EffortLevel.LOW, EffortLevel.MEDIUM, EffortLevel.HIGH]
        assert remediation.estimated_hours > 0
        assert len(remediation.required_skills) > 0
    
    def test_generate_remediation_generic(self):
        """Test generic remediation generation."""
        gap = Gap(
            gap_id="gap_004",
            control_id="CM-2",
            control_name="Baseline Configuration",
            gap_type=GapType.MISSING_IN_DESIGN,
            severity=GapSeverity.MEDIUM,
            description="Baseline configuration not documented",
            policy_requirement="Maintain baseline configurations",
            design_specification=None,
            code_implementation=None
        )
        
        remediation = self.engine.generate_remediation(gap)
        
        assert remediation.control_id == "CM-2"
        assert len(remediation.steps) > 0
        assert len(remediation.validation_criteria) > 0


@pytest.fixture
def sample_analysis_context():
    """Fixture providing sample analysis context."""
    return AnalysisContext(
        policy_requirements={
            "AC-2": {
                "requirement": "Implement account management",
                "required_features": ["account_creation", "account_disabling"],
                "specified": True
            },
            "IA-2": {
                "requirement": "Implement authentication",
                "required_features": ["user_authentication"],
                "specified": True
            }
        },
        design_specifications={
            "AC-2": {
                "specification": "Spring Security user management",
                "specified": True
            }
        },
        code_patterns={
            "AC-2": {
                "found": True,
                "implementation": "UserDetailsService implemented",
                "implemented_features": ["account_creation"],
                "configuration_issues": [],
                "anti_patterns": []
            }
        },
        control_metadata={
            "AC-2": {"name": "Account Management", "family": "AC"},
            "IA-2": {"name": "Authentication", "family": "IA"}
        }
    )


def test_end_to_end_analysis(sample_analysis_context):
    """Test complete end-to-end gap analysis workflow."""
    # Initialize components
    control_mapper = ControlMapper()
    risk_assessor = RiskAssessor()
    detector = GapDetector(control_mapper=control_mapper, risk_assessor=risk_assessor)
    remediation_engine = RemediationEngine()
    
    # Detect gaps
    gaps = detector.detect_gaps(sample_analysis_context)
    
    assert len(gaps) > 0
    
    # Assess risk for each gap
    assessments = [
        risk_assessor.assess_gap(gap, sample_analysis_context.control_metadata.get(gap.control_id))
        for gap in gaps
    ]
    
    assert len(assessments) == len(gaps)
    
    # Generate remediation for each gap
    remediations = [
        remediation_engine.generate_remediation(gap, sample_analysis_context.control_metadata.get(gap.control_id))
        for gap in gaps
    ]
    
    assert len(remediations) == len(gaps)
    
    # Verify all components work together
    for gap, assessment, remediation in zip(gaps, assessments, remediations):
        assert gap.control_id == assessment.control_id == remediation.control_id
        assert assessment.risk_score > 0
        assert len(remediation.steps) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Made with Bob
