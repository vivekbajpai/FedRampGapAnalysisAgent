# FedRAMP Gap Analysis Agent - API Guide

Complete guide for using the FedRAMP Gap Analysis Agent REST API.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Usage Examples](#usage-examples)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Webhooks](#webhooks)

## Getting Started

### Base URL

```
Production: https://api.fedramp-agent.example.com/api/v1
Staging:    https://staging-api.fedramp-agent.example.com/api/v1
Local:      http://localhost:8000/api/v1
```

### Quick Start

```bash
# Start the API server
uvicorn src.api.main:app --reload --port 8000

# Check health
curl http://localhost:8000/api/v1/health

# View API documentation
open http://localhost:8000/docs
```

## Authentication

All API endpoints (except `/health`) require authentication.

### Bearer Token (JWT)

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://api.fedramp-agent.example.com/api/v1/controls
```

### API Key

```bash
curl -H "X-API-Key: YOUR_API_KEY" \
  https://api.fedramp-agent.example.com/api/v1/controls
```

## API Endpoints

### Analysis Endpoints

#### POST /analyze/comprehensive

Start a comprehensive gap analysis.

**Request:**

```json
{
  "policy_documents": [
    {
      "url": "s3://bucket/fedramp-policy.pdf",
      "type": "pdf"
    }
  ],
  "design_documents": [
    {
      "url": "https://confluence.example.com/page/123",
      "type": "confluence"
    }
  ],
  "repository": {
    "url": "https://github.com/example/app.git",
    "branch": "main",
    "credentials": {
      "type": "token",
      "token": "ghp_xxxxxxxxxxxx"
    }
  },
  "analysis_options": {
    "control_families": ["AC", "AU", "IA", "SC"],
    "include_remediation": true,
    "risk_threshold": 5.0
  },
  "webhook_url": "https://your-app.com/webhooks/analysis-complete"
}
```

**Response (202 Accepted):**

```json
{
  "job_id": "job_abc123def456",
  "status": "pending",
  "message": "Analysis job started successfully",
  "created_at": "2026-02-06T09:00:00Z",
  "estimated_completion_time": "2026-02-06T09:15:00Z"
}
```

#### POST /analyze/policy

Analyze policy documents only.

**Request:**

```json
{
  "policy_documents": [
    {
      "url": "s3://bucket/policy.pdf",
      "type": "pdf"
    }
  ]
}
```

#### POST /analyze/code

Analyze code repository only.

**Request:**

```json
{
  "repository": {
    "url": "https://github.com/example/app.git",
    "branch": "main"
  },
  "analysis_options": {
    "control_families": ["AC", "IA", "SC"]
  }
}
```

#### GET /jobs/{jobId}

Get job status and progress.

**Response (200 OK):**

```json
{
  "job_id": "job_abc123def456",
  "status": "detecting_gaps",
  "progress": 65.0,
  "created_at": "2026-02-06T09:00:00Z",
  "updated_at": "2026-02-06T09:10:00Z",
  "error_message": null,
  "result_available": false
}
```

**Status Values:**

- `pending` - Job queued
- `parsing_documents` - Parsing policy/design documents
- `analyzing_code` - Scanning code repository
- `detecting_gaps` - Identifying compliance gaps
- `assessing_risk` - Calculating risk scores
- `generating_remediation` - Creating recommendations
- `generating_report` - Finalizing report
- `completed` - Analysis complete
- `failed` - Analysis failed

#### GET /jobs/{jobId}/result

Get complete analysis results (only available when status is `completed`).

**Response (200 OK):**

```json
{
  "job_id": "job_abc123def456",
  "analysis_date": "2026-02-06T09:15:00Z",
  "gaps": [
    {
      "gap_id": "gap_ia_2_1_001",
      "control_id": "IA-2(1)",
      "control_name": "Multi-Factor Authentication",
      "gap_type": "missing_implementation",
      "severity": "critical",
      "description": "MFA not implemented for privileged accounts",
      "policy_requirement": "Implement MFA using TOTP",
      "design_specification": "TOTP-based MFA with Google Authenticator",
      "code_implementation": null,
      "evidence": [
        {"type": "missing", "details": "No MFA service found"}
      ],
      "risk_score": 9.5,
      "impact": "critical",
      "likelihood": "high"
    }
  ],
  "risk_assessments": [...],
  "remediations": [...],
  "summary": {
    "total_controls_evaluated": 35,
    "controls_with_gaps": 12,
    "controls_compliant": 23,
    "total_gaps": 15,
    "critical_gaps": 2,
    "high_gaps": 5,
    "medium_gaps": 6,
    "low_gaps": 2,
    "average_risk_score": 6.45,
    "compliance_score": 65.7
  },
  "control_coverage": {
    "total_required": 35,
    "total_implemented": 23,
    "coverage_percentage": 65.7,
    "by_family": {
      "AC": {"required": 8, "implemented": 6},
      "AU": {"required": 5, "implemented": 4},
      "IA": {"required": 6, "implemented": 3}
    }
  }
}
```

#### DELETE /jobs/{jobId}

Cancel a running analysis job.

**Response (204 No Content)**

### Report Endpoints

#### GET /reports/{jobId}

Get analysis report in specified format.

**Query Parameters:**

- `format` - Report format: `json`, `pdf`, `html`, `excel` (default: `json`)

**Examples:**

```bash
# JSON format
curl "http://localhost:8000/api/v1/reports/job_abc123?format=json"

# HTML format
curl "http://localhost:8000/api/v1/reports/job_abc123?format=html" > report.html

# PDF format
curl "http://localhost:8000/api/v1/reports/job_abc123?format=pdf" > report.pdf
```

#### GET /reports/{jobId}/summary

Get executive summary only.

**Response:**

```json
{
  "job_id": "job_abc123",
  "summary": {
    "total_controls_evaluated": 35,
    "compliance_score": 65.7,
    "total_gaps": 15,
    "critical_gaps": 2
  },
  "control_coverage": {...},
  "top_risks": [
    {
      "gap_id": "gap_ia_2_1_001",
      "control_id": "IA-2(1)",
      "risk_score": 9.5,
      "severity": "critical"
    }
  ]
}
```

#### GET /reports/{jobId}/gaps

Get detailed list of gaps with filtering.

**Query Parameters:**

- `severity` - Filter by severity: `critical`, `high`, `medium`, `low`
- `control_family` - Filter by family: `AC`, `AU`, `IA`, etc.
- `limit` - Results per page (default: 100)
- `offset` - Pagination offset (default: 0)

**Example:**

```bash
curl "http://localhost:8000/api/v1/reports/job_abc123/gaps?severity=critical&limit=10"
```

#### GET /reports/{jobId}/remediations

Get remediation recommendations.

**Query Parameters:**

- `control_id` - Filter by specific control (optional)

### Control Endpoints

#### GET /controls

List all FedRAMP controls.

**Query Parameters:**

- `family` - Filter by family (AC, AU, IA, etc.)
- `baseline` - Filter by baseline (Low, Moderate, High)
- `search` - Search query
- `limit` - Results per page (default: 100)
- `offset` - Pagination offset (default: 0)

**Example:**

```bash
curl "http://localhost:8000/api/v1/controls?family=AC&limit=10"
```

**Response:**

```json
{
  "total": 25,
  "controls": [
    {
      "control_id": "AC-2",
      "control_name": "Account Management",
      "control_family": "AC",
      "baseline": "High",
      "description": "Manage information system accounts",
      "implementation_guidance": "Implement automated account management",
      "patterns": ["UserDetailsService", "UserRepository"],
      "keywords": ["user", "account", "registration"],
      "verification_methods": ["code_review", "authentication_test"]
    }
  ]
}
```

#### GET /controls/{controlId}

Get details for a specific control.

**Example:**

```bash
curl "http://localhost:8000/api/v1/controls/AC-2"
```

#### GET /controls/families

List all control families.

**Response:**

```json
{
  "total": 17,
  "families": [
    {
      "code": "AC",
      "name": "Access Control",
      "control_count": 25
    },
    {
      "code": "AU",
      "name": "Audit and Accountability",
      "control_count": 12
    }
  ]
}
```

#### GET /controls/search

Search controls by keyword.

**Query Parameters:**

- `query` - Search query (required)
- `limit` - Max results (default: 50)

**Example:**

```bash
curl "http://localhost:8000/api/v1/controls/search?query=authentication"
```

### Health Endpoints

#### GET /health

Health check endpoint.

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-02-06T09:00:00Z",
  "components": {
    "database": "healthy",
    "cache": "healthy",
    "orchestrator": "healthy"
  }
}
```

#### GET /health/live

Kubernetes liveness probe.

#### GET /health/ready

Kubernetes readiness probe.

#### GET /version

Get API version information.

## Usage Examples

### Complete Analysis Workflow

```python
import requests
import time

API_URL = "http://localhost:8000/api/v1"
API_KEY = "your-api-key"

headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

# 1. Start analysis
response = requests.post(
    f"{API_URL}/analyze/comprehensive",
    headers=headers,
    json={
        "policy_documents": [
            {"url": "s3://bucket/policy.pdf", "type": "pdf"}
        ],
        "repository": {
            "url": "https://github.com/example/app.git",
            "branch": "main"
        }
    }
)

job_data = response.json()
job_id = job_data["job_id"]
print(f"Analysis started: {job_id}")

# 2. Poll for completion
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

# 3. Get results
if status['status'] == 'completed':
    result_response = requests.get(
        f"{API_URL}/jobs/{job_id}/result",
        headers=headers
    )
    result = result_response.json()

    print(f"\nAnalysis Complete!")
    print(f"Total Gaps: {result['summary']['total_gaps']}")
    print(f"Compliance Score: {result['summary']['compliance_score']:.1f}%")

    # Get HTML report
    html_response = requests.get(
        f"{API_URL}/reports/{job_id}?format=html",
        headers=headers
    )
    with open("report.html", "w") as f:
        f.write(html_response.text)
    print("Report saved to report.html")
```

### Search for Specific Controls

```python
# Search for authentication-related controls
response = requests.get(
    f"{API_URL}/controls/search",
    headers=headers,
    params={"query": "authentication", "limit": 10}
)

controls = response.json()
for control in controls["controls"]:
    print(f"{control['control_id']}: {control['control_name']}")
```

### Filter Gaps by Severity

```python
# Get only critical gaps
response = requests.get(
    f"{API_URL}/reports/{job_id}/gaps",
    headers=headers,
    params={"severity": "critical"}
)

gaps = response.json()
print(f"Found {gaps['total']} critical gaps")

for gap in gaps['gaps']:
    print(f"\n{gap['control_id']}: {gap['description']}")
    print(f"Risk Score: {gap['risk_score']:.2f}/10")
```

## Error Handling

All errors return a consistent format:

```json
{
  "error": "ValidationError",
  "message": "Invalid request parameters",
  "details": {
    "field": "repository.url",
    "issue": "Invalid URL format"
  },
  "timestamp": "2026-02-06T09:00:00Z"
}
```

### HTTP Status Codes

- `200 OK` - Request successful
- `202 Accepted` - Analysis job started
- `204 No Content` - Successful deletion
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `501 Not Implemented` - Feature not yet implemented

### Error Handling Example

```python
try:
    response = requests.post(
        f"{API_URL}/analyze/comprehensive",
        headers=headers,
        json=request_data
    )
    response.raise_for_status()
    job = response.json()

except requests.exceptions.HTTPError as e:
    error = e.response.json()
    print(f"Error: {error['message']}")
    if 'details' in error:
        print(f"Details: {error['details']}")

except requests.exceptions.ConnectionError:
    print("Failed to connect to API")

except requests.exceptions.Timeout:
    print("Request timed out")
```

## Rate Limiting

Default rate limits:

- 100 requests per minute per API key
- 1000 requests per hour per API key

Rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1612345678
```

When rate limited (429 response):

```json
{
  "error": "RateLimitExceeded",
  "message": "Rate limit exceeded",
  "details": {
    "limit": 100,
    "window": 60,
    "retry_after": 45
  }
}
```

## Webhooks

Configure webhooks to receive notifications when analysis completes.

### Webhook Request

```json
POST https://your-app.com/webhooks/analysis-complete
Content-Type: application/json

{
  "event": "analysis.completed",
  "job_id": "job_abc123def456",
  "status": "completed",
  "timestamp": "2026-02-06T09:15:00Z",
  "summary": {
    "total_gaps": 15,
    "compliance_score": 65.7
  },
  "report_url": "https://api.fedramp-agent.example.com/api/v1/reports/job_abc123def456"
}
```

### Webhook Signature

Webhooks include an HMAC signature for verification:

```
X-Webhook-Signature: sha256=abc123...
```

Verify signature:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Best Practices

1. **Use webhooks** instead of polling for long-running analyses
2. **Cache control data** to reduce API calls
3. **Implement exponential backoff** for retries
4. **Filter results** at the API level rather than client-side
5. **Use pagination** for large result sets
6. **Monitor rate limits** and implement throttling
7. **Validate inputs** before sending requests
8. **Handle errors gracefully** with proper logging

## Support

- **Documentation**: https://docs.fedramp-agent.example.com
- **API Status**: https://status.fedramp-agent.example.com
- **Support Email**: support@example.com
- **GitHub Issues**: https://github.com/example/fedramp-agent/issues
