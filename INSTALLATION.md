# FedRamp Gap Analysis Agent - Installation Guide

## Prerequisites

- Python 3.11 or higher
- Git
- PostgreSQL 14+ (optional, can use SQLite for development)
- Redis 7+ (optional for caching)

## Windows Installation

### Step 1: Create Virtual Environment

```powershell
# Navigate to project directory
cd FedRamp

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# If you get execution policy error, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 2: Install Dependencies

#### Option A: Minimal Installation (Recommended for initial setup)

```powershell
pip install --upgrade pip
pip install -r requirements-minimal.txt
```

This installs only the core dependencies needed to run the API without heavy ML libraries.

#### Option B: Full Installation (For complete functionality)

```powershell
pip install --upgrade pip

# Install in stages to handle potential issues
pip install -r requirements-minimal.txt

# Then install additional packages
pip install PyPDF2==3.0.1 pdfplumber==0.10.3 python-docx==1.1.0
pip install beautifulsoup4==4.12.3 lxml==5.1.0
pip install javalang==0.13.0 gitpython==3.1.41
pip install reportlab==4.0.9 openpyxl==3.1.2
pip install ibm-cloud-sdk-core==3.19.0 ibm-watsonx-ai==0.2.6
```

**Note:** Skip ML libraries (spacy, transformers, torch) initially as they're large and optional for basic functionality.

### Step 3: Configure Environment

```powershell
# Copy example environment file
copy .env.example .env

# Edit .env file with your settings
notepad .env
```

### Step 4: Initialize Database (Optional)

If using PostgreSQL:

```powershell
# Install PostgreSQL from https://www.postgresql.org/download/windows/
# Then create database
psql -U postgres
CREATE DATABASE fedramp_db;
CREATE USER fedramp WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE fedramp_db TO fedramp;
\q
```

For development, you can use SQLite instead:

```powershell
# Update .env file
# DATABASE_URL=sqlite+aiosqlite:///./fedramp.db
```

### Step 5: Run the Application

```powershell
# Run with uvicorn
python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Or run directly
python -m src.api.main
```

Access the API at: http://localhost:8000

API Documentation: http://localhost:8000/docs

## Linux/Mac Installation

### Step 1: Create Virtual Environment

```bash
cd FedRamp
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements-minimal.txt

# For full installation
pip install -r requirements.txt
```

### Step 3: Configure and Run

```bash
cp .env.example .env
# Edit .env with your settings

# Run application
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

## Docker Installation (Recommended for Production)

```bash
# Build image
docker build -t fedramp-gap-analysis -f deployment/docker/Dockerfile .

# Run container
docker-compose -f deployment/docker/docker-compose.yml up -d
```

## Troubleshooting

### Issue: psycopg2-binary installation fails on Windows

**Solution:** We've removed psycopg2-binary from requirements. Use asyncpg instead, which is already included.

### Issue: Large ML libraries (torch, transformers) taking too long

**Solution:** These are optional. Use requirements-minimal.txt for basic functionality. Install ML libraries only when needed for advanced features.

### Issue: Redis connection errors

**Solution:** Redis is optional for development. Set `ENABLE_CACHING=false` in .env to disable caching.

### Issue: Import errors when running

**Solution:** Make sure you're in the project root directory and virtual environment is activated:

```powershell
# Windows
cd FedRamp
.\venv\Scripts\Activate.ps1

# Linux/Mac
cd FedRamp
source venv/bin/activate
```

## Verification

Test the installation:

```bash
# Check health endpoint
curl http://localhost:8000/health

# Or visit in browser
http://localhost:8000/health
```

Expected response:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "FedRamp Gap Analysis Agent",
  "version": "1.0.0",
  "environment": "development"
}
```

## Next Steps

1. Configure your .env file with proper credentials
2. Set up PostgreSQL database (or use SQLite for development)
3. Load FedRamp controls data (coming in Phase 4)
4. Configure watsonx.ai integration (optional)
5. Start analyzing documents and code!

## Development Setup

For development with hot reload:

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run with auto-reload
uvicorn src.api.main:app --reload --log-level debug
```

## Production Deployment

See `deployment/` directory for:

- Docker configurations
- Kubernetes manifests
- Terraform scripts
- Deployment guides

## Support

For issues and questions:

- Check TROUBLESHOOTING.md
- Review logs in `./logs/` directory
- Check API documentation at `/docs` endpoint
