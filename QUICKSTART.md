# FedRamp Gap Analysis Agent - Quick Start Guide (Demo)

This is a simplified demo version without Redis, SMTP, or watsonx.ai dependencies.

## Prerequisites

- Python 3.11 or higher
- Git (optional, for repository analysis)

## 5-Minute Setup

### 1. Install Dependencies

```powershell
# Windows
cd FedRamp
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements-minimal.txt
```

```bash
# Linux/Mac
cd FedRamp
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-minimal.txt
```

### 2. Configure Environment

```powershell
# Windows
copy .env.example .env

# Linux/Mac
cp .env.example .env
```

The default `.env` settings work out of the box for demo:

- Uses SQLite database (no PostgreSQL needed)
- No Redis required (in-memory caching)
- No watsonx.ai needed (disabled by default)

### 3. Run the Application

```bash
# Easiest way - use the run script
python run.py

# Or use Python module syntax
python -m uvicorn src.api.main:app --reload

# Or if uvicorn is in PATH
uvicorn src.api.main:app --reload
```

### 4. Test the API

Open your browser and visit:

- **API Health**: http://localhost:8000/health
- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

## Quick API Test

### Using Browser

Visit: http://localhost:8000/docs

Click on any endpoint to try it out!

### Using curl

```bash
# Health check
curl http://localhost:8000/health

# Get all controls
curl http://localhost:8000/api/v1/controls

# Get control families
curl http://localhost:8000/api/v1/controls/families
```

### Using Python

```python
import requests

# Health check
response = requests.get("http://localhost:8000/health")
print(response.json())

# Get controls
response = requests.get("http://localhost:8000/api/v1/controls")
print(response.json())
```

## What's Included in Demo

✅ **Working Features:**

- FastAPI REST API with auto-generated docs
- Health check endpoints
- SQLite database (no setup needed)
- In-memory caching (no Redis needed)
- JWT authentication (ready to use)
- Rate limiting
- Request/response validation
- Structured logging
- Error handling

🚧 **To Be Implemented:**

- Document parsing (PDF, DOCX)
- Code analysis (Java, Git)
- FedRamp controls database
- Gap detection engine
- Report generation

## Next Steps

1. **Add Document Parsing**: Install optional dependencies

   ```bash
   pip install PyPDF2 python-docx beautifulsoup4
   ```

2. **Add Code Analysis**: Install Git and Java analysis tools

   ```bash
   pip install gitpython javalang
   ```

3. **Load FedRamp Controls**: Import NIST 800-53 controls data

4. **Implement Gap Detection**: Build the analysis engine

5. **Generate Reports**: Add report formatters

## Troubleshooting

### Port Already in Use

```bash
# Use a different port
uvicorn src.api.main:app --reload --port 8001
```

### Import Errors

Make sure you're in the project root and virtual environment is activated:

```bash
cd FedRamp
# Activate venv (see step 1)
python -m uvicorn src.api.main:app --reload
```

### Database Errors

Delete the database file and restart:

```bash
rm fedramp.db
uvicorn src.api.main:app --reload
```

## Development Mode

For development with debug logging:

```bash
# Set DEBUG=true in .env
uvicorn src.api.main:app --reload --log-level debug
```

## API Endpoints

### Health & Status

- `GET /health` - Basic health check
- `GET /health/ready` - Readiness check
- `GET /health/live` - Liveness check
- `GET /health/metrics` - System metrics
- `GET /health/dependencies` - Dependency status

### Analysis (Coming Soon)

- `POST /api/v1/analysis/document` - Analyze document
- `POST /api/v1/analysis/repository` - Analyze Git repository
- `GET /api/v1/analysis/{id}` - Get analysis status

### Reports (Coming Soon)

- `GET /api/v1/reports/{id}` - Get report
- `GET /api/v1/reports/{id}/download` - Download report

### Controls

- `GET /api/v1/controls` - List all controls
- `GET /api/v1/controls/{id}` - Get control details
- `GET /api/v1/controls/families` - List control families
- `GET /api/v1/controls/baselines/{baseline}` - Get baseline controls

## Demo Limitations

This demo version:

- Uses SQLite (not production-ready for scale)
- No Redis caching (uses in-memory)
- No watsonx.ai integration
- No email notifications
- Limited to single-server deployment

For production deployment, see `INSTALLATION.md` for full setup with PostgreSQL, Redis, and watsonx.ai.

## Support

- Check logs in `./logs/` directory
- Visit API docs at `/docs` for interactive testing
- Review `INSTALLATION.md` for full setup
- Check `ARCHITECTURE.md` for system design

## License

See LICENSE file for details.
