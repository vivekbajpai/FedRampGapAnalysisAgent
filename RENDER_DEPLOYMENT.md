# Render Deployment Guide

## Overview

This guide explains how to deploy the FedRAMP Gap Analysis Agent on Render.

## Prerequisites

- GitHub account with your repository
- Render account (free tier works)

## Deployment Steps

### 1. Prepare Your Repository

Ensure these files are committed:

- `render.yaml` - Render configuration
- `requirements-render.txt` - Optimized dependencies for Render

### 2. Connect to Render

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Blueprint"
3. Connect your GitHub repository
4. Render will automatically detect `render.yaml`

### 3. Configure Environment Variables

Add these in Render dashboard under "Environment":

**Required:**

- `DATABASE_URL` - PostgreSQL connection string (use Render's PostgreSQL add-on)
- `SECRET_KEY` - Random secret key for JWT tokens
- `REDIS_URL` - Redis connection string (use Render's Redis add-on)

**Optional:**

- `WATSONX_API_KEY` - IBM watsonx.ai API key
- `WATSONX_PROJECT_ID` - IBM watsonx.ai project ID
- `SENTRY_DSN` - Sentry error tracking DSN
- `LOG_LEVEL` - Logging level (default: INFO)

### 4. Deploy

1. Click "Apply" to create the service
2. Render will build and deploy automatically
3. Monitor build logs for any issues

## Differences from Full Requirements

The `requirements-render.txt` excludes heavy ML packages to avoid build failures on Render's free tier:

**Excluded packages:**

- `spacy` - NLP library (requires compilation)
- `transformers` - Hugging Face transformers
- `sentence-transformers` - Sentence embeddings
- `torch` - PyTorch (very large)
- `numpy` - Included with other packages
- `matplotlib` - Plotting library
- `plotly` - Interactive plots

These packages can be added back if:

1. Using a paid Render plan with more resources
2. Using Docker deployment with pre-built images
3. Not needed for your specific use case

## Troubleshooting

### Build Failures

**Issue:** Package compilation errors (blis, thinc, etc.)
**Solution:** Use `requirements-render.txt` which excludes problematic packages

**Issue:** Out of memory during build
**Solution:** Upgrade to a paid Render plan or use Docker

### Runtime Issues

**Issue:** Module not found errors
**Solution:** Ensure the package is in `requirements-render.txt`

**Issue:** Database connection errors
**Solution:** Check `DATABASE_URL` environment variable

### Performance Issues

**Issue:** Slow response times
**Solution:**

- Upgrade to a paid plan
- Add Redis caching
- Optimize database queries

## Using Full Requirements Locally

For local development with all features:

```bash
pip install -r requirements.txt
```

For Render deployment:

```bash
# Render automatically uses requirements-render.txt
```

## Adding ML Features Back

If you need ML features on Render:

1. **Option 1: Use Docker**
   - Create a Dockerfile with pre-built ML packages
   - Deploy as a Docker service on Render

2. **Option 2: Upgrade Plan**
   - Use Render's Standard or Pro plan
   - Update `render.yaml` to use `requirements.txt`

3. **Option 3: External ML Service**
   - Use IBM watsonx.ai for ML features
   - Keep Render deployment lightweight

## Health Check

The service includes a health check endpoint:

```
GET /health
```

Render uses this to monitor service health.

## Logs

View logs in Render dashboard:

1. Go to your service
2. Click "Logs" tab
3. Monitor real-time logs

## Scaling

To scale your service:

1. Go to service settings
2. Adjust instance count
3. Upgrade plan for more resources

## Support

For issues:

- Check Render documentation: https://render.com/docs
- Review build logs in Render dashboard
- Check application logs for runtime errors
