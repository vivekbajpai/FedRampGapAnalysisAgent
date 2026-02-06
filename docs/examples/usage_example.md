# FedRAMP Gap Analysis Agent - Usage Examples

This document provides comprehensive examples of using the FedRAMP Gap Analysis Agent to identify compliance gaps in your applications.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Complete Gap Analysis](#complete-gap-analysis)
3. [Code Pattern Analysis](#code-pattern-analysis)
4. [Risk Assessment](#risk-assessment)
5. [Remediation Recommendations](#remediation-recommendations)
6. [Integration Examples](#integration-examples)

## Basic Usage

### Initialize the Gap Detection Engine

```python
from src.gap_detection.detector import GapDetector, AnalysisContext
from src.gap_detection.control_mapper import ControlMapper
from src.gap_detection.risk_assessor import RiskAssessor

# Initialize components
control_mapper = ControlMapper(controls_data_path="data/controls/fedramp_high_baseline.json")
risk_assessor = RiskAssessor()
detector = GapDetector(control_mapper=control_mapper, risk_assessor=risk_assessor)

print(f"Loaded {len(control_mapper.get_all_control_ids())} FedRAMP controls")
```

### Simple Gap Detection

```python
# Define analysis context
context = AnalysisContext(
    policy_requirements={
        "AC-2": {
            "requirement": "Implement user account management with lifecycle controls",
            "required_features": ["account_creation", "account_modification", "account_disabling"],
            "specified": True
        }
    },
    design_specifications={
        "AC-2": {
            "specification": "Use Spring Security for user management",
            "specified": True
        }
    },
    code_patterns={
        "AC-2": {
            "found": True,
            "implementation": "UserDetailsService implemented",
            "implemented_features": ["account_creation"],  # Missing other features
            "configuration_issues": [],
            "anti_patterns": []
        }
    },
    control_metadata={
        "AC-2": {
            "name": "Account Management",
            "family": "AC",
            "baseline": "High"
        }
    }
)

# Detect gaps
gaps = detector.detect_gaps(context)

# Display results
for gap in gaps:
    print(f"\n{'='*60}")
    print(f"Gap ID: {gap.gap_id}")
    print(f"Control: {gap.control_id} - {gap.control_name}")
    print(f"Type: {gap.gap_type.value}")
    print(f"Severity: {gap.severity.value}")
    print(f"Description: {gap.description}")
    print(f"Risk Score: {gap.risk_score:.2f}/10")
```

**Output:**

```
============================================================
Gap ID: gap_ac_2_1
Control: AC-2 - Account Management
Type: partial_implementation
Severity: high
Description: Control AC-2 is partially implemented. Missing features: account_modification, account_disabling
Risk Score: 7.85/10
```

## Complete Gap Analysis

### Using the Orchestrator

```python
import asyncio
from src.core.orchestrator import GapAnalysisOrchestrator

async def run_complete_analysis():
    # Initialize orchestrator
    orchestrator = GapAnalysisOrchestrator(
        controls_data_path="data/controls/fedramp_high_baseline.json",
        patterns_data_path="data/patterns/java_security_patterns.json"
    )

    # Start analysis
    job = await orchestrator.start_analysis(
        job_id="analysis_001",
        policy_documents=["path/to/fedramp_policy.pdf"],
        design_documents=["path/to/design_doc.docx"],
        repository_path="path/to/your/java/project"
    )

    print(f"Analysis started: {job.job_id}")
    print(f"Status: {job.status.value}")

    # Wait for completion (in production, use webhooks or polling)
    await asyncio.sleep(2)

    # Get results
    result = orchestrator.get_job_result(job.job_id)

    if result:
        print(f"\n{'='*60}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*60}")
        summary = result['summary']
        print(f"Total Controls Evaluated: {summary['total_controls_evaluated']}")
        print(f"Controls with Gaps: {summary['controls_with_gaps']}")
        print(f"Compliance Score: {summary['compliance_score']:.1f}%")
        print(f"\nGap Breakdown:")
        print(f"  Critical: {summary['critical_gaps']}")
        print(f"  High: {summary['high_gaps']}")
        print(f"  Medium: {summary['medium_gaps']}")
        print(f"  Low: {summary['low_gaps']}")
        print(f"\nAverage Risk Score: {summary['average_risk_score']:.2f}/10")

# Run the analysis
asyncio.run(run_complete_analysis())
```

**Output:**

```
Analysis started: analysis_001
Status: pending

============================================================
ANALYSIS SUMMARY
============================================================
Total Controls Evaluated: 35
Controls with Gaps: 12
Compliance Score: 65.7%

Gap Breakdown:
  Critical: 2
  High: 5
  Medium: 3
  Low: 2

Average Risk Score: 6.45/10
```

## Code Pattern Analysis

### Analyze Java/Spring Boot Code

```python
from src.gap_detection.pattern_matcher import PatternMatcher, PatternType

# Initialize pattern matcher
matcher = PatternMatcher()

# Sample Java code
java_code = """
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            .and()
            .formLogin()
            .and()
            .csrf().disable();  // Security issue!
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
"""

# Match patterns
matches = matcher.match_patterns(java_code, "SecurityConfig.java")

print(f"Found {len(matches)} pattern matches\n")

# Display good patterns
good_patterns = matcher.get_good_patterns()
print(f"✓ Good Patterns ({len(good_patterns)}):")
for match in good_patterns:
    print(f"  - {match.pattern_name}")
    print(f"    Related Controls: {', '.join(match.related_controls)}")
    print(f"    Confidence: {match.confidence:.0%}\n")

# Display anti-patterns (security issues)
anti_patterns = matcher.get_anti_patterns()
print(f"✗ Security Issues ({len(anti_patterns)}):")
for match in anti_patterns:
    print(f"  - {match.pattern_name}")
    print(f"    Line {match.line_number}: {match.description}")
    print(f"    Related Controls: {', '.join(match.related_controls)}")
    print(f"    Severity: HIGH\n")

# Get summary
summary = matcher.get_summary()
print(f"Summary:")
print(f"  Total Matches: {summary['total_matches']}")
print(f"  Good Patterns: {summary['by_category']['good_patterns']}")
print(f"  Anti-Patterns: {summary['by_category']['anti_patterns']}")
print(f"  High Confidence Issues: {summary['high_confidence_issues']}")
```

**Output:**

```
Found 5 pattern matches

✓ Good Patterns (3):
  - Spring Security Configuration
    Related Controls: AC-2, IA-2
    Confidence: 90%

  - Role-Based Access Control
    Related Controls: AC-3, AC-6
    Confidence: 90%

  - Password Hashing
    Related Controls: IA-5, IA-5(1)
    Confidence: 95%

✗ Security Issues (1):
  - CSRF Protection Disabled
    Line 12: CSRF protection explicitly disabled
    Related Controls: SC-7
    Severity: HIGH

Summary:
  Total Matches: 5
  Good Patterns: 3
  Anti-Patterns: 1
  High Confidence Issues: 1
```

## Risk Assessment

### Assess Risk for Identified Gaps

```python
from src.gap_detection.risk_assessor import RiskAssessor
from src.gap_detection.detector import Gap, GapType, GapSeverity

# Initialize risk assessor
assessor = RiskAssessor()

# Create a gap
gap = Gap(
    gap_id="gap_ia_2_1_001",
    control_id="IA-2(1)",
    control_name="Multi-Factor Authentication",
    gap_type=GapType.MISSING_IMPLEMENTATION,
    severity=GapSeverity.CRITICAL,
    description="Multi-factor authentication not implemented for privileged accounts",
    policy_requirement="Implement MFA using TOTP for all administrative accounts",
    design_specification="TOTP-based MFA with Google Authenticator",
    code_implementation=None,
    evidence=[
        {"type": "missing", "details": "No MFA service found in codebase"},
        {"type": "missing", "details": "No TOTP library dependencies"}
    ]
)

# Perform risk assessment
assessment = assessor.assess_gap(gap, control_metadata={
    "name": "Multi-Factor Authentication",
    "family": "IA",
    "baseline": "High"
})

# Display assessment
print(f"{'='*60}")
print(f"RISK ASSESSMENT: {gap.control_id}")
print(f"{'='*60}")
print(f"Gap: {gap.description}\n")
print(f"Risk Score: {assessment.risk_score:.2f}/10")
print(f"Risk Level: {assessment.risk_level}")
print(f"Impact: {assessment.impact.value}")
print(f"Likelihood: {assessment.likelihood.value}")
print(f"Exploitability: {assessment.exploitability:.0%}")
print(f"Remediation Priority: {assessment.remediation_priority} (1=Highest)\n")
print(f"Business Impact:")
print(f"  {assessment.business_impact}\n")
print(f"Technical Impact:")
print(f"  {assessment.technical_impact}\n")
print(f"Compliance Impact:")
print(f"  {assessment.compliance_impact}")
```

**Output:**

```
============================================================
RISK ASSESSMENT: IA-2(1)
============================================================
Gap: Multi-factor authentication not implemented for privileged accounts

Risk Score: 9.50/10
Risk Level: Critical
Impact: critical
Likelihood: high
Exploitability: 80%
Remediation Priority: 1 (1=Highest)

Business Impact:
  Weak authentication increases risk of account compromise and data theft

Technical Impact:
  Critical security control not implemented, system is vulnerable

Compliance Impact:
  Critical FedRAMP requirement not met - blocks authorization
```

## Remediation Recommendations

### Generate Actionable Remediation Steps

````python
from src.gap_detection.remediation import RemediationEngine

# Initialize remediation engine
engine = RemediationEngine()

# Generate remediation for the MFA gap
remediation = engine.generate_remediation(gap)

# Display remediation plan
print(f"{'='*60}")
print(f"REMEDIATION PLAN: {remediation.control_id}")
print(f"{'='*60}")
print(f"Summary: {remediation.summary}\n")
print(f"Description: {remediation.description}\n")
print(f"Effort Estimate: {remediation.effort_estimate.value}")
print(f"Estimated Hours: {remediation.estimated_hours}")
print(f"Required Skills: {', '.join(remediation.required_skills)}\n")

print(f"Implementation Steps:")
print(f"{'-'*60}")
for step in remediation.steps:
    print(f"\nStep {step.step_number}: {step.description}")
    print(f"  {step.technical_details}")
    if step.code_example:
        print(f"\n  Code Example:")
        print(f"  ```java")
        for line in step.code_example.strip().split('\n')[:5]:
            print(f"  {line}")
        print(f"  ...```")
    print(f"\n  Verification: {step.verification}")

print(f"\n{'='*60}")
print(f"Testing Guidance:")
print(f"  {remediation.testing_guidance}\n")

print(f"Validation Criteria:")
for i, criterion in enumerate(remediation.validation_criteria, 1):
    print(f"  {i}. {criterion}")

print(f"\nReferences:")
for ref in remediation.references:
    print(f"  - {ref['title']}: {ref['url']}")
````

**Output:**

````
============================================================
REMEDIATION PLAN: IA-2(1)
============================================================
Summary: Implement Multi-Factor Authentication (MFA)

Description: Add TOTP-based MFA to strengthen authentication security

Effort Estimate: high
Estimated Hours: 60
Required Skills: Spring Security, TOTP/OTP, QR Code Generation

Implementation Steps:
------------------------------------------------------------

Step 1: Add MFA dependencies
  Include Google Authenticator and QR code libraries

  Code Example:
  ```java
  <!-- pom.xml -->
  <dependency>
      <groupId>com.warrenstrange</groupId>
      <artifactId>googleauth</artifactId>
  ...```

  Verification: Dependencies resolve successfully

Step 2: Create MFA service
  Implement TOTP generation and validation service

  Code Example:
  ```java
  @Service
  public class MfaService {

      private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
  ...```

  Verification: Test TOTP code generation and validation

============================================================
Testing Guidance:
  Test MFA enrollment, QR code generation, and TOTP validation

Validation Criteria:
  1. Users can enable MFA and scan QR code
  2. TOTP codes are validated correctly
  3. Invalid codes are rejected
  4. MFA is enforced for privileged accounts

References:
  - Google Authenticator: https://github.com/wstrange/GoogleAuth
  - NIST 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
````

## Integration Examples

### API Integration

```python
import requests
import json

# API endpoint
API_URL = "http://localhost:8000/api/v1"
API_KEY = "your-api-key"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Start comprehensive analysis
response = requests.post(
    f"{API_URL}/analyze/comprehensive",
    headers=headers,
    json={
        "policy_documents": [
            {"url": "s3://bucket/fedramp-policy.pdf", "type": "pdf"}
        ],
        "design_documents": [
            {"url": "https://confluence.example.com/page/123", "type": "confluence"}
        ],
        "repository": {
            "url": "https://github.com/example/secure-app.git",
            "branch": "main",
            "credentials": {
                "type": "token",
                "token": "ghp_xxxxxxxxxxxx"
            }
        },
        "analysis_options": {
            "control_families": ["AC", "AU", "IA", "SC"],
            "include_remediation": True
        }
    }
)

job_data = response.json()
job_id = job_data["job_id"]
print(f"Analysis started: {job_id}")

# Poll for completion
import time
while True:
    status_response = requests.get(
        f"{API_URL}/jobs/{job_id}",
        headers=headers
    )
    status = status_response.json()

    print(f"Status: {status['status']} - Progress: {status['progress']:.0f}%")

    if status['status'] in ['completed', 'failed']:
        break

    time.sleep(5)

# Get report
if status['status'] == 'completed':
    report_response = requests.get(
        f"{API_URL}/reports/{job_id}",
        headers=headers,
        params={"format": "json"}
    )
    report = report_response.json()

    print(f"\nAnalysis Complete!")
    print(f"Total Gaps: {report['summary']['total_gaps']}")
    print(f"Compliance Score: {report['summary']['compliance_score']:.1f}%")
```

### IBM watsonx.ai Integration

```python
from ibm_watsonx_ai import APIClient, Credentials

# Initialize watsonx.ai client
credentials = Credentials(
    api_key="YOUR_IBM_CLOUD_API_KEY",
    url="https://us-south.ml.cloud.ibm.com"
)
client = APIClient(credentials)

# Execute FedRamp analysis skill
result = client.skills.execute(
    project_id="YOUR_PROJECT_ID",
    skill_name="FedRamp Comprehensive Gap Analysis",
    operation="analyzeComprehensive",
    inputs={
        "policy_documents": [
            {"url": "s3://bucket/policy.pdf", "type": "pdf"}
        ],
        "repository": {
            "url": "https://github.com/example/app.git",
            "branch": "main"
        }
    }
)

print(f"Analysis job: {result['job_id']}")
print(f"Status: {result['status']}")

# Wait for completion and get results
final_result = client.skills.get_result(
    project_id="YOUR_PROJECT_ID",
    job_id=result['job_id']
)

print(f"\nGaps found: {len(final_result['gaps'])}")
for gap in final_result['gaps'][:5]:  # Show first 5
    print(f"  - {gap['control_id']}: {gap['description']}")
```

## Best Practices

### 1. Incremental Analysis

For large codebases, analyze incrementally:

```python
# Analyze specific control families
families_to_analyze = ["AC", "IA", "AU"]  # Start with authentication/authorization

# Filter controls
filtered_controls = {
    cid: req for cid, req in policy_requirements.items()
    if cid.split('-')[0] in families_to_analyze
}
```

### 2. Caching Results

Cache analysis results to avoid re-analyzing unchanged code:

```python
import hashlib
import json

def get_code_hash(repository_path):
    """Generate hash of repository state."""
    # Implementation depends on your needs
    pass

# Check cache before analysis
code_hash = get_code_hash(repo_path)
cached_result = cache.get(f"analysis_{code_hash}")

if cached_result:
    print("Using cached analysis results")
    return cached_result
```

### 3. Continuous Monitoring

Integrate with CI/CD pipeline:

```yaml
# .github/workflows/fedramp-analysis.yml
name: FedRAMP Gap Analysis

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run FedRAMP Analysis
        run: |
          python scripts/run_analysis.py \
            --repository . \
            --output report.json

      - name: Check Compliance
        run: |
          python scripts/check_compliance.py \
            --report report.json \
            --threshold 80
```

## Troubleshooting

### Common Issues

**Issue: Pattern matching returns too many false positives**

Solution: Adjust confidence thresholds:

```python
# Filter by confidence
high_confidence_matches = [
    m for m in matches
    if m.confidence >= 0.85
]
```

**Issue: Analysis takes too long**

Solution: Use parallel processing:

```python
import concurrent.futures

def analyze_file(file_path):
    # Analyze single file
    pass

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(analyze_file, java_files))
```

## Next Steps

- Review the [API Documentation](../api/openapi.yaml)
- Check [Architecture Design](../../ARCHITECTURE.md)
- See [Implementation Plan](../../IMPLEMENTATION_PLAN.md)
- Explore [WXO Integration Guide](../../WXO_INTEGRATION_GUIDE.md)
