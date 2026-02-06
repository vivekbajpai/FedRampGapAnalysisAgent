"""
Remediation Suggestion Engine

Provides actionable remediation recommendations for identified compliance gaps
with implementation guidance, code examples, and effort estimates.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from .detector import Gap, GapType

logger = logging.getLogger(__name__)


class EffortLevel(Enum):
    """Effort required for remediation."""
    MINIMAL = "minimal"      # < 1 day
    LOW = "low"              # 1-3 days
    MEDIUM = "medium"        # 1-2 weeks
    HIGH = "high"            # 2-4 weeks
    EXTENSIVE = "extensive"  # > 1 month


@dataclass
class RemediationStep:
    """A single step in the remediation process."""
    step_number: int
    description: str
    technical_details: str
    code_example: Optional[str] = None
    verification: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_number": self.step_number,
            "description": self.description,
            "technical_details": self.technical_details,
            "code_example": self.code_example,
            "verification": self.verification
        }


@dataclass
class RemediationRecommendation:
    """Complete remediation recommendation for a gap."""
    gap_id: str
    control_id: str
    summary: str
    description: str
    steps: List[RemediationStep]
    effort_estimate: EffortLevel
    estimated_hours: int
    required_skills: List[str]
    dependencies: List[str]
    references: List[Dict[str, str]]
    code_examples: List[Dict[str, str]]
    testing_guidance: str
    validation_criteria: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "gap_id": self.gap_id,
            "control_id": self.control_id,
            "summary": self.summary,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "effort_estimate": self.effort_estimate.value,
            "estimated_hours": self.estimated_hours,
            "required_skills": self.required_skills,
            "dependencies": self.dependencies,
            "references": self.references,
            "code_examples": self.code_examples,
            "testing_guidance": self.testing_guidance,
            "validation_criteria": self.validation_criteria
        }


class RemediationEngine:
    """
    Generates remediation recommendations for compliance gaps with
    detailed implementation guidance and code examples.
    """
    
    def __init__(self):
        """Initialize the remediation engine."""
        self.remediation_templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize remediation templates for common controls."""
        return {
            "AC-2": {
                "summary": "Implement comprehensive account management",
                "description": "Establish user account lifecycle management with proper authentication and authorization",
                "effort": EffortLevel.MEDIUM,
                "hours": 40,
                "skills": ["Spring Security", "User Management", "Database Design"],
                "steps": [
                    {
                        "description": "Create user entity and repository",
                        "technical_details": "Define User entity with JPA annotations, create UserRepository interface",
                        "code_example": """
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private boolean enabled = true;
    
    @Column(nullable = false)
    private boolean accountNonLocked = true;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
    
    // Getters and setters
}
""",
                        "verification": "Verify user table created with proper constraints"
                    },
                    {
                        "description": "Implement UserDetailsService",
                        "technical_details": "Create custom UserDetailsService to load user data for authentication",
                        "code_example": """
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) 
            throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + username));
        
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            user.isEnabled(),
            true, // accountNonExpired
            true, // credentialsNonExpired
            user.isAccountNonLocked(),
            getAuthorities(user.getRoles())
        );
    }
    
    private Collection<? extends GrantedAuthority> getAuthorities(
            Set<Role> roles) {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toList());
    }
}
""",
                        "verification": "Test user authentication with valid and invalid credentials"
                    }
                ],
                "testing": "Create integration tests for user registration, authentication, and account lifecycle",
                "validation": [
                    "Users can be created with unique usernames",
                    "Passwords are properly hashed",
                    "Account lockout works after failed attempts",
                    "Disabled accounts cannot authenticate"
                ],
                "references": [
                    {"title": "Spring Security Reference", "url": "https://docs.spring.io/spring-security/reference/"},
                    {"title": "NIST 800-53 AC-2", "url": "https://csrc.nist.gov/Projects/risk-management/sp800-53-controls"}
                ]
            },
            
            "IA-2(1)": {
                "summary": "Implement Multi-Factor Authentication (MFA)",
                "description": "Add TOTP-based MFA to strengthen authentication security",
                "effort": EffortLevel.HIGH,
                "hours": 60,
                "skills": ["Spring Security", "TOTP/OTP", "QR Code Generation"],
                "steps": [
                    {
                        "description": "Add MFA dependencies",
                        "technical_details": "Include Google Authenticator and QR code libraries",
                        "code_example": """
<!-- pom.xml -->
<dependency>
    <groupId>com.warrenstrange</groupId>
    <artifactId>googleauth</artifactId>
    <version>1.5.0</version>
</dependency>
<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>core</artifactId>
    <version>3.5.1</version>
</dependency>
""",
                        "verification": "Dependencies resolve successfully"
                    },
                    {
                        "description": "Create MFA service",
                        "technical_details": "Implement TOTP generation and validation service",
                        "code_example": """
@Service
public class MfaService {
    
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    
    public String generateSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }
    
    public String generateQRUrl(String username, String secret) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(
            "YourApp",
            username,
            new GoogleAuthenticatorKey.Builder(secret).build()
        );
    }
    
    public boolean validateCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}
""",
                        "verification": "Test TOTP code generation and validation"
                    },
                    {
                        "description": "Update User entity for MFA",
                        "technical_details": "Add MFA fields to User entity",
                        "code_example": """
@Entity
public class User {
    // ... existing fields ...
    
    @Column(name = "mfa_enabled")
    private boolean mfaEnabled = false;
    
    @Column(name = "mfa_secret")
    private String mfaSecret;
    
    // Getters and setters
}
""",
                        "verification": "Database schema updated with MFA columns"
                    },
                    {
                        "description": "Implement MFA authentication filter",
                        "technical_details": "Create custom filter to handle MFA verification",
                        "code_example": """
@Component
public class MfaAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private MfaService mfaService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        Authentication auth = SecurityContextHolder.getContext()
            .getAuthentication();
        
        if (auth != null && auth.isAuthenticated()) {
            User user = (User) auth.getPrincipal();
            
            if (user.isMfaEnabled() && !isMfaVerified(request)) {
                // Redirect to MFA verification page
                response.sendRedirect("/mfa/verify");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isMfaVerified(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && 
               Boolean.TRUE.equals(session.getAttribute("mfa_verified"));
    }
}
""",
                        "verification": "MFA verification required for protected resources"
                    }
                ],
                "testing": "Test MFA enrollment, QR code generation, and TOTP validation",
                "validation": [
                    "Users can enable MFA and scan QR code",
                    "TOTP codes are validated correctly",
                    "Invalid codes are rejected",
                    "MFA is enforced for privileged accounts"
                ],
                "references": [
                    {"title": "Google Authenticator", "url": "https://github.com/wstrange/GoogleAuth"},
                    {"title": "NIST 800-63B", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"}
                ]
            },
            
            "SC-8": {
                "summary": "Enforce HTTPS/TLS for all communications",
                "description": "Configure application to use TLS 1.2+ for all data transmission",
                "effort": EffortLevel.LOW,
                "hours": 16,
                "skills": ["Spring Boot", "TLS/SSL Configuration"],
                "steps": [
                    {
                        "description": "Configure HTTPS in application.properties",
                        "technical_details": "Enable HTTPS and configure SSL/TLS settings",
                        "code_example": """
# application.properties
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=${SSL_KEYSTORE_PASSWORD}
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=tomcat

# Enforce TLS 1.2+
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
server.ssl.ciphers=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
""",
                        "verification": "Application starts on HTTPS port"
                    },
                    {
                        "description": "Redirect HTTP to HTTPS",
                        "technical_details": "Configure automatic HTTP to HTTPS redirection",
                        "code_example": """
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requiresChannel()
                .anyRequest()
                .requiresSecure()
            .and()
            .headers()
                .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000);
    }
}
""",
                        "verification": "HTTP requests redirect to HTTPS"
                    }
                ],
                "testing": "Verify all endpoints accessible via HTTPS only",
                "validation": [
                    "All HTTP traffic redirected to HTTPS",
                    "TLS 1.2 or higher enforced",
                    "HSTS header present",
                    "Weak ciphers disabled"
                ],
                "references": [
                    {"title": "Spring Boot SSL", "url": "https://docs.spring.io/spring-boot/docs/current/reference/html/howto.html#howto.webserver.configure-ssl"}
                ]
            },
            
            "AU-2": {
                "summary": "Implement comprehensive audit logging",
                "description": "Configure audit logging for all security-relevant events",
                "effort": EffortLevel.MEDIUM,
                "hours": 32,
                "skills": ["Spring AOP", "Logging Frameworks", "Audit Design"],
                "steps": [
                    {
                        "description": "Create audit event entity",
                        "technical_details": "Define audit log data model",
                        "code_example": """
@Entity
@Table(name = "audit_events")
public class AuditEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private LocalDateTime timestamp;
    
    @Column(nullable = false)
    private String eventType;
    
    @Column(nullable = false)
    private String username;
    
    @Column
    private String ipAddress;
    
    @Column
    private String resource;
    
    @Column
    private String action;
    
    @Column
    private String outcome; // SUCCESS, FAILURE
    
    @Column(length = 2000)
    private String details;
    
    // Getters and setters
}
""",
                        "verification": "Audit events table created"
                    },
                    {
                        "description": "Implement audit logging aspect",
                        "technical_details": "Use AOP to automatically log security events",
                        "code_example": """
@Aspect
@Component
public class AuditLoggingAspect {
    
    @Autowired
    private AuditEventRepository auditRepository;
    
    @AfterReturning(
        pointcut = "@annotation(audited)",
        returning = "result"
    )
    public void logAuditEvent(JoinPoint joinPoint, Audited audited, 
            Object result) {
        Authentication auth = SecurityContextHolder.getContext()
            .getAuthentication();
        
        AuditEvent event = new AuditEvent();
        event.setTimestamp(LocalDateTime.now());
        event.setEventType(audited.eventType());
        event.setUsername(auth != null ? auth.getName() : "anonymous");
        event.setAction(joinPoint.getSignature().getName());
        event.setOutcome("SUCCESS");
        
        auditRepository.save(event);
    }
    
    @AfterThrowing(
        pointcut = "@annotation(audited)",
        throwing = "ex"
    )
    public void logFailedAuditEvent(JoinPoint joinPoint, Audited audited,
            Exception ex) {
        // Log failure event
        AuditEvent event = new AuditEvent();
        event.setTimestamp(LocalDateTime.now());
        event.setEventType(audited.eventType());
        event.setOutcome("FAILURE");
        event.setDetails(ex.getMessage());
        
        auditRepository.save(event);
    }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    String eventType();
}
""",
                        "verification": "Audit events logged for annotated methods"
                    }
                ],
                "testing": "Verify audit logs capture all required events",
                "validation": [
                    "Authentication events logged",
                    "Authorization failures logged",
                    "Data access logged",
                    "Configuration changes logged"
                ],
                "references": [
                    {"title": "Spring AOP", "url": "https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#aop"}
                ]
            }
        }
    
    def generate_remediation(self, gap: Gap, control_metadata: Optional[Dict[str, Any]] = None) -> RemediationRecommendation:
        """
        Generate remediation recommendation for a gap.
        
        Args:
            gap: Gap to remediate
            control_metadata: Additional control metadata
            
        Returns:
            Remediation recommendation
        """
        # Get template for this control
        template = self.remediation_templates.get(gap.control_id)
        
        if template:
            return self._create_from_template(gap, template)
        else:
            return self._create_generic_remediation(gap, control_metadata)
    
    def _create_from_template(self, gap: Gap, template: Dict[str, Any]) -> RemediationRecommendation:
        """Create remediation from template."""
        steps = []
        for i, step_data in enumerate(template["steps"], 1):
            step = RemediationStep(
                step_number=i,
                description=step_data["description"],
                technical_details=step_data["technical_details"],
                code_example=step_data.get("code_example"),
                verification=step_data.get("verification", "")
            )
            steps.append(step)
        
        return RemediationRecommendation(
            gap_id=gap.gap_id,
            control_id=gap.control_id,
            summary=template["summary"],
            description=template["description"],
            steps=steps,
            effort_estimate=template["effort"],
            estimated_hours=template["hours"],
            required_skills=template["skills"],
            dependencies=[],
            references=template.get("references", []),
            code_examples=[],
            testing_guidance=template.get("testing", ""),
            validation_criteria=template.get("validation", [])
        )
    
    def _create_generic_remediation(self, gap: Gap, control_metadata: Optional[Dict[str, Any]]) -> RemediationRecommendation:
        """Create generic remediation for controls without templates."""
        control_family = gap.control_id.split('-')[0]
        
        generic_guidance = {
            "AC": "Review and implement access control mechanisms",
            "AU": "Implement comprehensive audit logging",
            "IA": "Strengthen identification and authentication",
            "SC": "Enhance system and communications protection",
            "SI": "Improve system and information integrity",
            "CM": "Establish configuration management processes",
            "CP": "Develop contingency planning procedures",
            "IR": "Implement incident response capabilities"
        }
        
        summary = generic_guidance.get(control_family, "Address compliance gap")
        
        steps = [
            RemediationStep(
                step_number=1,
                description=f"Review {gap.control_id} requirements",
                technical_details=gap.policy_requirement,
                verification="Understand all control requirements"
            ),
            RemediationStep(
                step_number=2,
                description="Design implementation approach",
                technical_details="Create technical design that meets requirements",
                verification="Design reviewed and approved"
            ),
            RemediationStep(
                step_number=3,
                description="Implement control",
                technical_details="Develop and deploy implementation",
                verification="Implementation complete and tested"
            ),
            RemediationStep(
                step_number=4,
                description="Validate compliance",
                technical_details="Verify implementation meets all requirements",
                verification="Control validated and documented"
            )
        ]
        
        return RemediationRecommendation(
            gap_id=gap.gap_id,
            control_id=gap.control_id,
            summary=summary,
            description=f"Implement {gap.control_name} to address compliance gap",
            steps=steps,
            effort_estimate=EffortLevel.MEDIUM,
            estimated_hours=40,
            required_skills=["Security Engineering", "Compliance"],
            dependencies=[],
            references=[
                {"title": f"NIST 800-53 {gap.control_id}", 
                 "url": f"https://csrc.nist.gov/Projects/risk-management/sp800-53-controls"}
            ],
            code_examples=[],
            testing_guidance="Develop test cases to validate control implementation",
            validation_criteria=["Control implemented", "Requirements met", "Evidence documented"]
        )

# Made with Bob
