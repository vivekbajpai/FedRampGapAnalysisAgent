"""
Pattern Matcher for Code Analysis

Identifies security patterns and anti-patterns in source code to support
FedRAMP compliance gap detection.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of security patterns that can be detected."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    AUDIT = "audit"
    SESSION_MANAGEMENT = "session_management"
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"
    SECURE_COMMUNICATION = "secure_communication"
    DATA_PROTECTION = "data_protection"


class PatternCategory(Enum):
    """Category of pattern (positive or negative)."""
    GOOD_PATTERN = "good_pattern"
    ANTI_PATTERN = "anti_pattern"
    CONFIGURATION = "configuration"
    MISSING = "missing"


@dataclass
class PatternMatch:
    """Represents a matched pattern in code."""
    pattern_type: PatternType
    pattern_name: str
    category: PatternCategory
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float  # 0.0 to 1.0
    description: str
    related_controls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pattern_type": self.pattern_type.value,
            "pattern_name": self.pattern_name,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "description": self.description,
            "related_controls": self.related_controls,
            "metadata": self.metadata
        }


@dataclass
class SecurityPattern:
    """Defines a security pattern to search for."""
    name: str
    pattern_type: PatternType
    category: PatternCategory
    regex_patterns: List[str]
    keywords: List[str]
    description: str
    related_controls: List[str]
    confidence_weight: float = 1.0


class PatternMatcher:
    """
    Matches security patterns in source code to identify implementations
    and gaps related to FedRAMP controls.
    """
    
    def __init__(self):
        """Initialize the pattern matcher with predefined patterns."""
        self.patterns: List[SecurityPattern] = []
        self.matches: List[PatternMatch] = []
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize security patterns for detection."""
        
        # Authentication Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Spring Security Authentication",
                pattern_type=PatternType.AUTHENTICATION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"@EnableWebSecurity",
                    r"AuthenticationManager",
                    r"AuthenticationProvider",
                    r"UserDetailsService",
                    r"\.authenticate\(",
                ],
                keywords=["authentication", "login", "credentials"],
                description="Spring Security authentication implementation detected",
                related_controls=["IA-2", "AC-2"],
                confidence_weight=0.9
            ),
            SecurityPattern(
                name="Multi-Factor Authentication",
                pattern_type=PatternType.AUTHENTICATION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"MfaProvider",
                    r"TwoFactorAuth",
                    r"OtpService",
                    r"TotpGenerator",
                    r"mfaEnabled\s*=\s*true",
                ],
                keywords=["mfa", "2fa", "two-factor", "otp", "totp"],
                description="Multi-factor authentication implementation detected",
                related_controls=["IA-2(1)", "IA-2(2)"],
                confidence_weight=1.0
            ),
            SecurityPattern(
                name="Hardcoded Credentials",
                pattern_type=PatternType.AUTHENTICATION,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"password\s*=\s*[\"'][^\"']+[\"']",
                    r"apiKey\s*=\s*[\"'][^\"']+[\"']",
                    r"secret\s*=\s*[\"'][^\"']+[\"']",
                    r"token\s*=\s*[\"'][^\"']+[\"']",
                ],
                keywords=["hardcoded", "password", "secret", "api key"],
                description="Hardcoded credentials detected - security risk",
                related_controls=["IA-5", "SC-12"],
                confidence_weight=0.95
            ),
        ])
        
        # Authorization Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Role-Based Access Control",
                pattern_type=PatternType.AUTHORIZATION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"@PreAuthorize",
                    r"@Secured",
                    r"@RolesAllowed",
                    r"hasRole\(",
                    r"hasAuthority\(",
                ],
                keywords=["authorization", "rbac", "role", "permission"],
                description="Role-based access control implementation detected",
                related_controls=["AC-3", "AC-6"],
                confidence_weight=0.9
            ),
            SecurityPattern(
                name="Missing Authorization",
                pattern_type=PatternType.AUTHORIZATION,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"@RequestMapping.*\n(?!.*@PreAuthorize)(?!.*@Secured)",
                    r"@GetMapping.*\n(?!.*@PreAuthorize)(?!.*@Secured)",
                    r"@PostMapping.*\n(?!.*@PreAuthorize)(?!.*@Secured)",
                ],
                keywords=["unprotected", "no authorization"],
                description="Endpoint without authorization check detected",
                related_controls=["AC-3", "AC-6"],
                confidence_weight=0.8
            ),
        ])
        
        # Encryption Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Strong Encryption",
                pattern_type=PatternType.ENCRYPTION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"AES/GCM",
                    r"AES/CBC",
                    r"RSA/OAEP",
                    r"Cipher\.getInstance\([\"']AES",
                    r"KeyGenerator\.getInstance\([\"']AES",
                ],
                keywords=["aes", "encryption", "cipher", "crypto"],
                description="Strong encryption algorithm detected",
                related_controls=["SC-13", "SC-28"],
                confidence_weight=0.95
            ),
            SecurityPattern(
                name="Weak Encryption",
                pattern_type=PatternType.ENCRYPTION,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"DES",
                    r"MD5",
                    r"SHA1",
                    r"RC4",
                    r"Cipher\.getInstance\([\"']DES",
                ],
                keywords=["des", "md5", "sha1", "weak crypto"],
                description="Weak or deprecated encryption algorithm detected",
                related_controls=["SC-13"],
                confidence_weight=1.0
            ),
            SecurityPattern(
                name="TLS/HTTPS Configuration",
                pattern_type=PatternType.SECURE_COMMUNICATION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"requiresSecure\(\)",
                    r"\.https\(\)",
                    r"SSLContext",
                    r"TLSv1\.2",
                    r"TLSv1\.3",
                ],
                keywords=["tls", "ssl", "https", "secure"],
                description="TLS/HTTPS configuration detected",
                related_controls=["SC-8", "SC-8(1)"],
                confidence_weight=0.9
            ),
        ])
        
        # Logging and Audit Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Security Audit Logging",
                pattern_type=PatternType.AUDIT,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"@Audit",
                    r"auditLogger",
                    r"securityAudit",
                    r"log\.audit\(",
                    r"AuditEvent",
                ],
                keywords=["audit", "security log", "audit trail"],
                description="Security audit logging implementation detected",
                related_controls=["AU-2", "AU-3", "AU-12"],
                confidence_weight=0.9
            ),
            SecurityPattern(
                name="Comprehensive Logging",
                pattern_type=PatternType.LOGGING,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"log\.info\(",
                    r"log\.warn\(",
                    r"log\.error\(",
                    r"Logger\.getLogger",
                    r"@Slf4j",
                ],
                keywords=["logging", "logger", "log"],
                description="Logging implementation detected",
                related_controls=["AU-2", "AU-3"],
                confidence_weight=0.7
            ),
            SecurityPattern(
                name="Sensitive Data in Logs",
                pattern_type=PatternType.LOGGING,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"log.*password",
                    r"log.*secret",
                    r"log.*token",
                    r"log.*apiKey",
                ],
                keywords=["log password", "log secret", "sensitive data"],
                description="Potential sensitive data logging detected",
                related_controls=["AU-9", "SC-28"],
                confidence_weight=0.85
            ),
        ])
        
        # Session Management Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Secure Session Configuration",
                pattern_type=PatternType.SESSION_MANAGEMENT,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"sessionManagement\(\)",
                    r"maximumSessions\(",
                    r"sessionFixation\(\)\.none\(\)",
                    r"invalidateHttpSession\(true\)",
                ],
                keywords=["session", "session management", "session timeout"],
                description="Secure session management configuration detected",
                related_controls=["AC-12", "SC-23"],
                confidence_weight=0.85
            ),
            SecurityPattern(
                name="Session Timeout Configuration",
                pattern_type=PatternType.SESSION_MANAGEMENT,
                category=PatternCategory.CONFIGURATION,
                regex_patterns=[
                    r"session\.timeout",
                    r"maxInactiveInterval",
                    r"sessionTimeout",
                ],
                keywords=["timeout", "session expiration"],
                description="Session timeout configuration detected",
                related_controls=["AC-12"],
                confidence_weight=0.8
            ),
        ])
        
        # Input Validation Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Input Validation",
                pattern_type=PatternType.INPUT_VALIDATION,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"@Valid",
                    r"@Validated",
                    r"@NotNull",
                    r"@Size",
                    r"@Pattern",
                    r"validator\.validate",
                ],
                keywords=["validation", "validate", "sanitize"],
                description="Input validation implementation detected",
                related_controls=["SI-10"],
                confidence_weight=0.85
            ),
            SecurityPattern(
                name="SQL Injection Risk",
                pattern_type=PatternType.INPUT_VALIDATION,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"Statement\.execute\(",
                    r"createQuery\([\"'].*\+",
                    r"executeQuery\([\"'].*\+",
                ],
                keywords=["sql injection", "string concatenation"],
                description="Potential SQL injection vulnerability detected",
                related_controls=["SI-10"],
                confidence_weight=0.9
            ),
        ])
        
        # Error Handling Patterns
        self.patterns.extend([
            SecurityPattern(
                name="Proper Error Handling",
                pattern_type=PatternType.ERROR_HANDLING,
                category=PatternCategory.GOOD_PATTERN,
                regex_patterns=[
                    r"@ExceptionHandler",
                    r"@ControllerAdvice",
                    r"try\s*\{.*\}\s*catch",
                ],
                keywords=["exception", "error handling", "try catch"],
                description="Error handling implementation detected",
                related_controls=["SI-11"],
                confidence_weight=0.7
            ),
            SecurityPattern(
                name="Information Disclosure in Errors",
                pattern_type=PatternType.ERROR_HANDLING,
                category=PatternCategory.ANTI_PATTERN,
                regex_patterns=[
                    r"printStackTrace\(\)",
                    r"e\.getMessage\(\).*response",
                    r"throw.*Exception.*password",
                ],
                keywords=["stack trace", "error disclosure"],
                description="Potential information disclosure in error messages",
                related_controls=["SI-11"],
                confidence_weight=0.8
            ),
        ])
        
        logger.info(f"Initialized {len(self.patterns)} security patterns")
    
    def match_patterns(self, code_content: str, file_path: str) -> List[PatternMatch]:
        """
        Match security patterns in code content.
        
        Args:
            code_content: Source code content to analyze
            file_path: Path to the source file
            
        Returns:
            List of pattern matches found
        """
        matches = []
        lines = code_content.split('\n')
        
        for pattern in self.patterns:
            for regex_pattern in pattern.regex_patterns:
                try:
                    for match in re.finditer(regex_pattern, code_content, re.MULTILINE | re.IGNORECASE):
                        # Find line number
                        line_number = code_content[:match.start()].count('\n') + 1
                        
                        # Extract code snippet (3 lines context)
                        start_line = max(0, line_number - 2)
                        end_line = min(len(lines), line_number + 1)
                        code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        pattern_match = PatternMatch(
                            pattern_type=pattern.pattern_type,
                            pattern_name=pattern.name,
                            category=pattern.category,
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=code_snippet,
                            confidence=pattern.confidence_weight,
                            description=pattern.description,
                            related_controls=pattern.related_controls,
                            metadata={
                                "matched_text": match.group(0),
                                "regex_pattern": regex_pattern
                            }
                        )
                        matches.append(pattern_match)
                        
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{regex_pattern}': {e}")
        
        self.matches.extend(matches)
        return matches
    
    def get_matches_by_type(self, pattern_type: PatternType) -> List[PatternMatch]:
        """Get all matches of a specific pattern type."""
        return [m for m in self.matches if m.pattern_type == pattern_type]
    
    def get_matches_by_category(self, category: PatternCategory) -> List[PatternMatch]:
        """Get all matches of a specific category."""
        return [m for m in self.matches if m.category == category]
    
    def get_anti_patterns(self) -> List[PatternMatch]:
        """Get all anti-pattern matches (security issues)."""
        return self.get_matches_by_category(PatternCategory.ANTI_PATTERN)
    
    def get_good_patterns(self) -> List[PatternMatch]:
        """Get all good pattern matches (security implementations)."""
        return self.get_matches_by_category(PatternCategory.GOOD_PATTERN)
    
    def get_matches_by_control(self, control_id: str) -> List[PatternMatch]:
        """Get all matches related to a specific control."""
        return [m for m in self.matches if control_id in m.related_controls]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of pattern matching results."""
        return {
            "total_matches": len(self.matches),
            "by_type": {
                pattern_type.value: len(self.get_matches_by_type(pattern_type))
                for pattern_type in PatternType
            },
            "by_category": {
                "good_patterns": len(self.get_good_patterns()),
                "anti_patterns": len(self.get_anti_patterns()),
                "configurations": len(self.get_matches_by_category(PatternCategory.CONFIGURATION))
            },
            "high_confidence_issues": len([
                m for m in self.get_anti_patterns() if m.confidence >= 0.9
            ])
        }
    
    def clear_matches(self) -> None:
        """Clear all stored matches."""
        self.matches = []

# Made with Bob
