# FedRamp Gap Analysis Agent

An AI-powered compliance analysis tool that integrates with IBM watsonx.ai to identify gaps between FedRamp policy requirements, design documentation, and source code implementations.

## Overview

The FedRamp Gap Analysis Agent automates the complex process of compliance verification by:

- **Parsing Policy Documents**: Extracts requirements from FedRamp policy PDFs and DOCX files
- **Analyzing Design Documentation**: Reviews system architecture and design documents from Confluence or Word
- **Scanning Source Code**: Analyzes Java/Spring Boot repositories for security and compliance patterns
- **Mapping to Controls**: Maps findings to NIST 800-53 Rev 5 and FedRamp High baseline controls
- **Generating Reports**: Creates comprehensive gap analysis reports with remediation recommendations
- **Integrating with WXO**: Seamlessly integrates with IBM watsonx.ai via OpenAPI

## Key Features

### 🔍 Comprehensive Analysis

- Multi-source analysis (policy, design, code)
- Support for PDF, DOCX, and Confluence documents
- Java/Spring Boot code analysis with security pattern detection
- Dependency vulnerability scanning

### 📊 FedRamp High Baseline Coverage

- Complete NIST 800-53 Rev 5 control mapping
- FedRamp High baseline (325+ controls)
- 17 control families (AC, AU, IA, SC, etc.)
- Risk scoring and severity classification

### 🤖 AI-Powered Intelligence

- Natural language processing for document understanding
- Pattern matching for code analysis
- Semantic similarity detection
- Automated remediation recommendations

### 🔗 IBM watsonx.ai Integration

- OpenAPI 3.1 specification
- OAuth 2.0 / IBM Cloud IAM authentication
- Async job processing with webhooks
- Multi-format report generation (JSON, PDF, HTML, Excel)

### 🚀 Enterprise-Ready

- Horizontal scalability with Kubernetes
- Redis caching for performance
- PostgreSQL for data persistence
- Comprehensive audit logging
- Rate limiting and security controls

## Architecture

```
┌─────────────────────┐
│  IBM watsonx.ai     │
└──────────┬──────────┘
           │ OpenAPI
           ▼
┌─────────────────────┐
│   API Gateway       │
│  (FastAPI/Spring)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│         Orchestration Engine            │
├─────────────┬───────────┬───────────────┤
│   Document  │   Code    │  Gap Detection│
│   Parser    │  Analyzer │    Engine     │
└─────────────┴───────────┴───────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  PostgreSQL  │  Redis Cache  │  Logs    │
└─────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+ or Java 17+
- Docker and Docker Compose
- PostgreSQL 15+
- Redis 7+
- Git
- IBM Cloud account with watsonx.ai access

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/example/fedramp-gap-analysis-agent.git
cd fedramp-gap-analysis-agent
```

2. **Set up environment**

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

3. **Install dependencies**

```bash
# Python
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Or using Docker
docker-compose up -d
```

4. **Initialize database**

```bash
python scripts/setup_db.py
python scripts/load_controls.py
```

5. **Start the service**

```bash
# Development
uvicorn src.api.main:app --reload --port 8000

# Production
docker-compose up -d
```

6. **Verify installation**

```bash
curl http://localhost:8000/api/v1/health
```

## Usage

### Basic Analysis

```python
import requests

# API configuration
API_URL = "https://api.fedramp-agent.example.com/api/v1"
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
            {
                "url": "https://storage.example.com/policy.pdf",
                "type": "pdf"
            }
        ],
        "design_documents": [
            {
                "url": "https://confluence.example.com/pages/123456",
                "type": "confluence"
            }
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

# Check status
status_response = requests.get(
    f"{API_URL}/jobs/{job_id}",
    headers=headers
)
print(status_response.json())

# Get report when complete
report_response = requests.get(
    f"{API_URL}/reports/{report_id}",
    headers=headers,
    params={"format": "json"}
)
report = report_response.json()
```

### Using with IBM watsonx.ai

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
        "policy_documents": [...],
        "repository": {...}
    }
)

print(f"Analysis job: {result['job_id']}")
```

## API Endpoints

### Analysis Endpoints

- `POST /api/v1/analyze/comprehensive` - Full gap analysis
- `POST /api/v1/analyze/policy` - Policy document analysis
- `POST /api/v1/analyze/design` - Design document analysis
- `POST /api/v1/analyze/code` - Source code analysis
- `GET /api/v1/jobs/{job_id}` - Get job status

### Report Endpoints

- `GET /api/v1/reports/{report_id}` - Get analysis report
- `GET /api/v1/reports/{report_id}/summary` - Get executive summary
- `GET /api/v1/reports/{report_id}/gaps` - Get detailed gaps

### Control Endpoints

- `GET /api/v1/controls` - List FedRamp controls
- `GET /api/v1/controls/{control_id}` - Get control details
- `GET /api/v1/controls/families` - List control families

### Health & Status

- `GET /api/v1/health` - Health check
- `GET /api/v1/version` - API version info

## Configuration

### Environment Variables

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
LOG_LEVEL=INFO

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/fedramp_agent
DATABASE_POOL_SIZE=20

# Redis Cache
REDIS_URL=redis://localhost:6379/0
CACHE_TTL=3600

# IBM Cloud
IBM_CLOUD_API_KEY=your-api-key
IBM_CLOUD_IAM_URL=https://iam.cloud.ibm.com
WATSONX_PROJECT_ID=your-project-id

# Security
JWT_SECRET_KEY=your-secret-key
API_KEY_SALT=your-salt
ENCRYPTION_KEY=your-encryption-key

# Analysis Settings
MAX_CONCURRENT_JOBS=10
JOB_TIMEOUT=3600
WEBHOOK_TIMEOUT=30
```

### Control Families

The agent analyzes the following FedRamp High baseline control families:

| Family                               | Code | Controls | Description                 |
| ------------------------------------ | ---- | -------- | --------------------------- |
| Access Control                       | AC   | 25       | User access and permissions |
| Audit and Accountability             | AU   | 12       | Logging and monitoring      |
| Identification and Authentication    | IA   | 11       | User authentication         |
| System and Communications Protection | SC   | 45       | Network and data security   |
| Configuration Management             | CM   | 11       | System configuration        |
| Contingency Planning                 | CP   | 10       | Disaster recovery           |
| Incident Response                    | IR   | 10       | Security incidents          |
| System and Information Integrity     | SI   | 17       | System integrity            |
| ...                                  | ...  | ...      | ...                         |

**Total: 325+ controls across 17 families**

## Report Formats

### JSON Report

```json
{
  "report_id": "report_xyz789",
  "generated_at": "2026-02-06T08:00:00Z",
  "analysis_summary": {
    "total_controls_evaluated": 325,
    "controls_compliant": 250,
    "controls_non_compliant": 50,
    "controls_partial": 25,
    "overall_compliance_score": 76.9,
    "risk_score": 6.2
  },
  "gaps": [
    {
      "gap_id": "gap_001",
      "control_id": "AC-2",
      "severity": "high",
      "description": "Missing multi-factor authentication implementation",
      "remediation": {
        "recommendation": "Implement MFA using Spring Security",
        "implementation_steps": [...],
        "estimated_effort": "medium"
      }
    }
  ]
}
```

### PDF Report

- Executive summary with charts
- Detailed findings by control family
- Risk heat map
- Remediation roadmap

### HTML Report

- Interactive dashboard
- Filterable gap list
- Control coverage matrix
- Trend analysis

### Excel Report

- Multiple worksheets
- Gap details
- Control mapping
- Remediation tracking

## Development

### Project Structure

```
fedramp-gap-analysis-agent/
├── src/                    # Source code
│   ├── api/               # API endpoints
│   ├── core/              # Core business logic
│   ├── parsers/           # Document parsers
│   ├── analyzers/         # Code analyzers
│   ├── gap_detection/     # Gap detection engine
│   └── reports/           # Report generation
├── data/                  # Static data (controls, patterns)
├── tests/                 # Test suite
├── deployment/            # Deployment configs
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

### Running Tests

```bash
# Unit tests
pytest tests/unit -v

# Integration tests
pytest tests/integration -v

# End-to-end tests
pytest tests/e2e -v

# Coverage report
pytest --cov=src --cov-report=html
```

### Code Quality

```bash
# Linting
flake8 src/
pylint src/

# Type checking
mypy src/

# Security scanning
bandit -r src/
safety check
```

## Deployment

### Docker Deployment

```bash
# Build image
docker build -t fedramp-agent:latest .

# Run container
docker run -d \
  -p 8000:8000 \
  --env-file .env \
  fedramp-agent:latest
```

### Kubernetes Deployment

```bash
# Apply configurations
kubectl apply -f deployment/kubernetes/

# Check status
kubectl get pods -n fedramp-agent

# View logs
kubectl logs -f deployment/fedramp-agent -n fedramp-agent
```

### IBM Cloud Deployment

```bash
# Login to IBM Cloud
ibmcloud login --apikey YOUR_API_KEY

# Deploy to Code Engine
ibmcloud ce application create \
  --name fedramp-agent \
  --image fedramp-agent:latest \
  --port 8000 \
  --env-from-configmap fedramp-config \
  --env-from-secret fedramp-secrets
```

## Monitoring

### Metrics

- API request rate and latency
- Analysis job completion rate
- Gap detection accuracy
- Resource utilization (CPU, memory)
- Cache hit rate

### Logging

- Structured JSON logging
- Request/response logging
- Error tracking with stack traces
- Audit trail for compliance

### Alerting

- Failed analysis jobs
- High error rates
- Performance degradation
- Security incidents

## Security

### Authentication

- OAuth 2.0 / IBM Cloud IAM
- API key authentication
- JWT token validation
- Role-based access control (RBAC)

### Data Protection

- Encryption at rest (AES-256)
- Encryption in transit (TLS 1.3)
- Secure credential storage
- PII/PHI data handling

### Compliance

- SOC 2 Type II
- FedRamp Moderate (self-compliance)
- GDPR compliance
- Audit logging

## Troubleshooting

### Common Issues

**Issue: Analysis job stuck in processing**

```bash
# Check job status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/jobs/{job_id}

# Check logs
docker logs fedramp-agent

# Restart worker
docker-compose restart worker
```

**Issue: Document parsing fails**

```bash
# Verify document accessibility
curl -I https://storage.example.com/policy.pdf

# Check parser logs
grep "parser" /var/log/fedramp-agent/app.log

# Test parser directly
python scripts/test_parser.py --file policy.pdf
```

**Issue: High memory usage**

```bash
# Check resource usage
docker stats fedramp-agent

# Adjust worker count
export API_WORKERS=2

# Enable caching
export CACHE_ENABLED=true
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Documentation

- [Architecture Design](ARCHITECTURE.md) - System architecture and design
- [Implementation Plan](IMPLEMENTATION_PLAN.md) - Detailed implementation roadmap
- [WXO Integration Guide](WXO_INTEGRATION_GUIDE.md) - IBM watsonx.ai integration
- [API Documentation](docs/api/openapi.yaml) - OpenAPI specification
- [User Guide](docs/guides/usage.md) - Comprehensive user guide

## Support

- **Documentation**: https://docs.fedramp-agent.example.com
- **Email**: support@example.com
- **GitHub Issues**: https://github.com/example/fedramp-agent/issues
- **Slack**: #fedramp-agent

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details

## Acknowledgments

- NIST for 800-53 control framework
- FedRamp PMO for baseline requirements
- IBM watsonx.ai team for integration support
- Open source community for tools and libraries

## Roadmap

### Version 1.0 (Current)

- ✅ Core analysis engine
- ✅ FedRamp High baseline support
- ✅ Java/Spring Boot analyzer
- ✅ WXO integration

### Version 1.1 (Q2 2026)

- 🔄 Python/Django analyzer
- 🔄 Node.js/Express analyzer
- 🔄 Enhanced ML models
- 🔄 Real-time analysis

### Version 2.0 (Q4 2026)

- 📋 FedRamp Moderate baseline
- 📋 Continuous compliance monitoring
- 📋 Automated remediation
- 📋 Multi-cloud support

---

**Built with ❤️ for FedRamp compliance automation**
