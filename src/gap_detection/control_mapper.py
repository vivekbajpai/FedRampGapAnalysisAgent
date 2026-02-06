"""
FedRAMP Control Mapper

Maps code patterns, design specifications, and policy requirements to FedRAMP controls
based on NIST 800-53 Rev 5 control framework.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class ControlFamily(Enum):
    """FedRAMP control families based on NIST 800-53."""
    AC = "Access Control"
    AT = "Awareness and Training"
    AU = "Audit and Accountability"
    CA = "Security Assessment and Authorization"
    CM = "Configuration Management"
    CP = "Contingency Planning"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    MA = "Maintenance"
    MP = "Media Protection"
    PE = "Physical and Environmental Protection"
    PL = "Planning"
    PS = "Personnel Security"
    RA = "Risk Assessment"
    SA = "System and Services Acquisition"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"


@dataclass
class ControlMapping:
    """Represents a mapping between code patterns and FedRAMP controls."""
    control_id: str
    control_name: str
    control_family: str
    baseline: str  # "Low", "Moderate", "High"
    patterns: List[str]
    keywords: List[str]
    implementation_guidance: str
    verification_methods: List[str]


class ControlMapper:
    """
    Maps code patterns and security implementations to FedRAMP controls.
    Provides bidirectional mapping between controls and code patterns.
    """
    
    def __init__(self, controls_data_path: Optional[str] = None):
        """
        Initialize the control mapper.
        
        Args:
            controls_data_path: Path to FedRAMP controls data file
        """
        self.controls: Dict[str, ControlMapping] = {}
        self.pattern_to_controls: Dict[str, List[str]] = {}
        self.keyword_to_controls: Dict[str, List[str]] = {}
        
        if controls_data_path:
            self.load_controls(controls_data_path)
        else:
            self._initialize_default_mappings()
    
    def load_controls(self, data_path: str) -> None:
        """
        Load FedRAMP controls from JSON file.
        
        Args:
            data_path: Path to controls data file
        """
        try:
            with open(data_path, 'r') as f:
                data = json.load(f)
                
            for control_data in data.get("controls", []):
                mapping = ControlMapping(
                    control_id=control_data["control_id"],
                    control_name=control_data["control_name"],
                    control_family=control_data["control_family"],
                    baseline=control_data.get("baseline", "High"),
                    patterns=control_data.get("patterns", []),
                    keywords=control_data.get("keywords", []),
                    implementation_guidance=control_data.get("implementation_guidance", ""),
                    verification_methods=control_data.get("verification_methods", [])
                )
                self.add_control_mapping(mapping)
                
            logger.info(f"Loaded {len(self.controls)} control mappings from {data_path}")
        except Exception as e:
            logger.error(f"Failed to load controls from {data_path}: {e}")
            self._initialize_default_mappings()
    
    def _initialize_default_mappings(self) -> None:
        """Initialize default control mappings for common security patterns."""
        
        # AC-2: Account Management
        self.add_control_mapping(ControlMapping(
            control_id="AC-2",
            control_name="Account Management",
            control_family="AC",
            baseline="High",
            patterns=[
                "UserDetailsService",
                "UserRepository",
                "AccountService",
                "UserManagement",
                "@PreAuthorize",
                "createUser",
                "deleteUser",
                "disableUser"
            ],
            keywords=["user", "account", "registration", "provisioning", "deprovisioning"],
            implementation_guidance="Implement user account lifecycle management with proper authentication",
            verification_methods=["code_review", "authentication_test", "user_management_test"]
        ))
        
        # AC-3: Access Enforcement
        self.add_control_mapping(ControlMapping(
            control_id="AC-3",
            control_name="Access Enforcement",
            control_family="AC",
            baseline="High",
            patterns=[
                "@PreAuthorize",
                "@Secured",
                "@RolesAllowed",
                "hasRole",
                "hasAuthority",
                "AccessDecisionVoter",
                "SecurityExpressionHandler"
            ],
            keywords=["authorization", "access control", "permission", "role", "privilege"],
            implementation_guidance="Enforce approved authorizations for access to information and system resources",
            verification_methods=["authorization_test", "rbac_test", "access_control_test"]
        ))
        
        # AC-7: Unsuccessful Logon Attempts
        self.add_control_mapping(ControlMapping(
            control_id="AC-7",
            control_name="Unsuccessful Logon Attempts",
            control_family="AC",
            baseline="High",
            patterns=[
                "AuthenticationFailureHandler",
                "BadCredentialsException",
                "LockedException",
                "AccountStatusException",
                "loginAttempts",
                "failedLoginCount"
            ],
            keywords=["failed login", "account lockout", "brute force", "login attempts"],
            implementation_guidance="Enforce a limit on consecutive invalid logon attempts and lock accounts",
            verification_methods=["login_attempt_test", "account_lockout_test"]
        ))
        
        # AU-2: Audit Events
        self.add_control_mapping(ControlMapping(
            control_id="AU-2",
            control_name="Audit Events",
            control_family="AU",
            baseline="High",
            patterns=[
                "@Audit",
                "AuditLogger",
                "EventLogger",
                "SecurityAuditLogger",
                "log.audit",
                "auditEvent",
                "@AfterReturning",
                "@Around"
            ],
            keywords=["audit", "logging", "event", "trail", "record"],
            implementation_guidance="Identify and log security-relevant events",
            verification_methods=["audit_log_review", "event_logging_test"]
        ))
        
        # AU-3: Content of Audit Records
        self.add_control_mapping(ControlMapping(
            control_id="AU-3",
            control_name="Content of Audit Records",
            control_family="AU",
            baseline="High",
            patterns=[
                "AuditEvent",
                "LogEntry",
                "timestamp",
                "userId",
                "eventType",
                "outcome",
                "MDC.put",
                "StructuredLogging"
            ],
            keywords=["audit content", "log format", "event details", "timestamp", "user id"],
            implementation_guidance="Ensure audit records contain sufficient information to establish what, when, where, and who",
            verification_methods=["audit_content_review", "log_format_test"]
        ))
        
        # IA-2: Identification and Authentication
        self.add_control_mapping(ControlMapping(
            control_id="IA-2",
            control_name="Identification and Authentication",
            control_family="IA",
            baseline="High",
            patterns=[
                "AuthenticationManager",
                "AuthenticationProvider",
                "UserDetailsService",
                "authenticate",
                "login",
                "OAuth2",
                "SAML",
                "JWT"
            ],
            keywords=["authentication", "login", "identity", "credentials", "verify"],
            implementation_guidance="Uniquely identify and authenticate organizational users",
            verification_methods=["authentication_test", "identity_verification_test"]
        ))
        
        # IA-2(1): Multi-Factor Authentication
        self.add_control_mapping(ControlMapping(
            control_id="IA-2(1)",
            control_name="Multi-Factor Authentication",
            control_family="IA",
            baseline="High",
            patterns=[
                "MfaProvider",
                "TwoFactorAuthentication",
                "OtpService",
                "TotpGenerator",
                "GoogleAuthenticator",
                "DuoSecurity",
                "mfaEnabled",
                "secondFactor"
            ],
            keywords=["mfa", "2fa", "multi-factor", "two-factor", "otp", "totp"],
            implementation_guidance="Implement multi-factor authentication for network access to privileged accounts",
            verification_methods=["mfa_test", "two_factor_test"]
        ))
        
        # IA-5: Authenticator Management
        self.add_control_mapping(ControlMapping(
            control_id="IA-5",
            control_name="Authenticator Management",
            control_family="IA",
            baseline="High",
            patterns=[
                "PasswordEncoder",
                "BCryptPasswordEncoder",
                "PasswordPolicy",
                "PasswordValidator",
                "passwordStrength",
                "passwordComplexity",
                "passwordExpiration"
            ],
            keywords=["password", "authenticator", "credential", "password policy", "complexity"],
            implementation_guidance="Manage information system authenticators with proper strength and protection",
            verification_methods=["password_policy_test", "credential_management_test"]
        ))
        
        # SC-7: Boundary Protection
        self.add_control_mapping(ControlMapping(
            control_id="SC-7",
            control_name="Boundary Protection",
            control_family="SC",
            baseline="High",
            patterns=[
                "SecurityFilterChain",
                "CorsConfiguration",
                "WebSecurityConfigurerAdapter",
                "HttpSecurity",
                "csrf",
                "cors",
                "firewall"
            ],
            keywords=["boundary", "firewall", "network", "perimeter", "cors", "csrf"],
            implementation_guidance="Monitor and control communications at external boundaries and key internal boundaries",
            verification_methods=["boundary_test", "network_security_test"]
        ))
        
        # SC-8: Transmission Confidentiality and Integrity
        self.add_control_mapping(ControlMapping(
            control_id="SC-8",
            control_name="Transmission Confidentiality and Integrity",
            control_family="SC",
            baseline="High",
            patterns=[
                "requiresSecure",
                "https",
                "TLS",
                "SSL",
                "SSLContext",
                "HttpsURLConnection",
                "secure: true",
                "@RequireHttps"
            ],
            keywords=["tls", "ssl", "https", "encryption", "transmission", "transport security"],
            implementation_guidance="Protect the confidentiality and integrity of transmitted information",
            verification_methods=["tls_test", "encryption_test", "https_enforcement_test"]
        ))
        
        # SC-13: Cryptographic Protection
        self.add_control_mapping(ControlMapping(
            control_id="SC-13",
            control_name="Cryptographic Protection",
            control_family="SC",
            baseline="High",
            patterns=[
                "Cipher",
                "KeyGenerator",
                "SecretKey",
                "AES",
                "RSA",
                "encrypt",
                "decrypt",
                "MessageDigest",
                "SHA-256"
            ],
            keywords=["encryption", "cryptography", "cipher", "key", "crypto"],
            implementation_guidance="Implement cryptographic mechanisms to protect information confidentiality and integrity",
            verification_methods=["encryption_test", "crypto_algorithm_review"]
        ))
        
        # SC-28: Protection of Information at Rest
        self.add_control_mapping(ControlMapping(
            control_id="SC-28",
            control_name="Protection of Information at Rest",
            control_family="SC",
            baseline="High",
            patterns=[
                "DatabaseEncryption",
                "EncryptedColumn",
                "@Encrypted",
                "FileEncryption",
                "StorageEncryption",
                "encryptAtRest"
            ],
            keywords=["data at rest", "storage encryption", "database encryption", "file encryption"],
            implementation_guidance="Protect the confidentiality and integrity of information at rest",
            verification_methods=["storage_encryption_test", "data_at_rest_test"]
        ))
        
        # SI-2: Flaw Remediation
        self.add_control_mapping(ControlMapping(
            control_id="SI-2",
            control_name="Flaw Remediation",
            control_family="SI",
            baseline="High",
            patterns=[
                "dependency-check",
                "OWASP",
                "vulnerability",
                "CVE",
                "security-update",
                "patch"
            ],
            keywords=["vulnerability", "patch", "update", "flaw", "remediation", "cve"],
            implementation_guidance="Identify, report, and correct information system flaws",
            verification_methods=["vulnerability_scan", "dependency_check", "patch_management_review"]
        ))
        
        # SI-4: Information System Monitoring
        self.add_control_mapping(ControlMapping(
            control_id="SI-4",
            control_name="Information System Monitoring",
            control_family="SI",
            baseline="High",
            patterns=[
                "MetricsRegistry",
                "HealthIndicator",
                "MonitoringService",
                "AlertService",
                "Prometheus",
                "Micrometer",
                "@Timed",
                "@Counted"
            ],
            keywords=["monitoring", "metrics", "alerting", "health check", "observability"],
            implementation_guidance="Monitor the information system to detect attacks and indicators of potential attacks",
            verification_methods=["monitoring_test", "alerting_test", "metrics_review"]
        ))
        
        logger.info(f"Initialized {len(self.controls)} default control mappings")
    
    def add_control_mapping(self, mapping: ControlMapping) -> None:
        """
        Add a control mapping to the mapper.
        
        Args:
            mapping: Control mapping to add
        """
        self.controls[mapping.control_id] = mapping
        
        # Build reverse mappings for patterns
        for pattern in mapping.patterns:
            if pattern not in self.pattern_to_controls:
                self.pattern_to_controls[pattern] = []
            self.pattern_to_controls[pattern].append(mapping.control_id)
        
        # Build reverse mappings for keywords
        for keyword in mapping.keywords:
            keyword_lower = keyword.lower()
            if keyword_lower not in self.keyword_to_controls:
                self.keyword_to_controls[keyword_lower] = []
            self.keyword_to_controls[keyword_lower].append(mapping.control_id)
    
    def map_code_pattern_to_controls(self, pattern: str) -> List[str]:
        """
        Map a code pattern to relevant FedRAMP controls.
        
        Args:
            pattern: Code pattern (e.g., class name, annotation, method name)
            
        Returns:
            List of control IDs that match this pattern
        """
        controls = set()
        
        # Direct pattern match
        if pattern in self.pattern_to_controls:
            controls.update(self.pattern_to_controls[pattern])
        
        # Keyword match (case-insensitive)
        pattern_lower = pattern.lower()
        for keyword, control_ids in self.keyword_to_controls.items():
            if keyword in pattern_lower:
                controls.update(control_ids)
        
        return sorted(list(controls))
    
    def map_code_patterns_to_controls(self, patterns: List[str]) -> Dict[str, List[str]]:
        """
        Map multiple code patterns to controls.
        
        Args:
            patterns: List of code patterns
            
        Returns:
            Dictionary mapping control IDs to matched patterns
        """
        control_patterns: Dict[str, List[str]] = {}
        
        for pattern in patterns:
            control_ids = self.map_code_pattern_to_controls(pattern)
            for control_id in control_ids:
                if control_id not in control_patterns:
                    control_patterns[control_id] = []
                control_patterns[control_id].append(pattern)
        
        return control_patterns
    
    def get_control_info(self, control_id: str) -> Optional[ControlMapping]:
        """
        Get detailed information about a control.
        
        Args:
            control_id: Control identifier (e.g., "AC-2")
            
        Returns:
            Control mapping or None if not found
        """
        return self.controls.get(control_id)
    
    def get_controls_by_family(self, family: str) -> List[ControlMapping]:
        """
        Get all controls in a specific family.
        
        Args:
            family: Control family code (e.g., "AC", "AU")
            
        Returns:
            List of control mappings in the family
        """
        return [
            mapping for mapping in self.controls.values()
            if mapping.control_family == family
        ]
    
    def get_all_control_ids(self) -> List[str]:
        """Get list of all control IDs."""
        return sorted(list(self.controls.keys()))
    
    def get_control_families(self) -> Set[str]:
        """Get set of all control families."""
        return {mapping.control_family for mapping in self.controls.values()}
    
    def search_controls(self, query: str) -> List[ControlMapping]:
        """
        Search controls by name, ID, or keywords.
        
        Args:
            query: Search query
            
        Returns:
            List of matching control mappings
        """
        query_lower = query.lower()
        matches = []
        
        for mapping in self.controls.values():
            if (query_lower in mapping.control_id.lower() or
                query_lower in mapping.control_name.lower() or
                any(query_lower in keyword.lower() for keyword in mapping.keywords)):
                matches.append(mapping)
        
        return matches
    
    def get_implementation_guidance(self, control_id: str) -> Optional[str]:
        """
        Get implementation guidance for a control.
        
        Args:
            control_id: Control identifier
            
        Returns:
            Implementation guidance or None
        """
        mapping = self.get_control_info(control_id)
        return mapping.implementation_guidance if mapping else None
    
    def get_verification_methods(self, control_id: str) -> List[str]:
        """
        Get verification methods for a control.
        
        Args:
            control_id: Control identifier
            
        Returns:
            List of verification methods
        """
        mapping = self.get_control_info(control_id)
        return mapping.verification_methods if mapping else []

# Made with Bob
