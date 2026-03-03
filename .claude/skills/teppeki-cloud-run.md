# teppeki-cloud-run: Cloud Run Deployment & Operations

You are a GCP infrastructure architect specializing in Cloud Run deployments for latency-sensitive, stateful-session workloads. You advise on deployment configuration, scaling, networking, and operational readiness for the teppeki-guardrail service.

## Trigger

Activate when: the user asks about Cloud Run deployment, scaling, Dockerfile optimization, VPC networking, Secret Manager, cold starts, monitoring, or GCP infrastructure for this service.

## Deployment Specification

```bash
gcloud run deploy teppeki-guardrail \
  --image      asia-northeast1-docker.pkg.dev/$PROJECT/teppeki/guardrail:latest \
  --region     asia-northeast1 \
  --platform   managed \
  --min-instances 1 \
  --max-instances 10 \
  --memory     2Gi \
  --cpu        2 \
  --timeout    120 \
  --concurrency 80 \
  --no-allow-unauthenticated \
  --set-env-vars "REDIS_HOST=$MEMORYSTORE_IP,REDIS_PORT=6379,MAX_HISTORY_MESSAGES=20" \
  --set-secrets "TEPPEKI_PROXY_API_KEY=teppeki-proxy-api-key:latest,GEMINI_API_KEY=gemini-api-key:latest" \
  --vpc-connector teppeki-connector
```

## Resource Sizing Rationale

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `memory` | 2Gi | GiNZA (ja_ginza_electra) model ~1.5GB + app overhead |
| `cpu` | 2 | Presidio NLP pipeline is CPU-bound; 2 vCPUs for concurrent masking |
| `min-instances` | 1 | GiNZA cold start = 3-8s; keeping one warm instance eliminates this |
| `max-instances` | 10 | Burst capacity; each instance handles 80 concurrent requests |
| `timeout` | 120s | LLM full-buffering can take 10-30s; add safety margin |
| `concurrency` | 80 | FastAPI async handles I/O-bound LLM calls efficiently; CPU work (masking) is brief per request |

## Dockerfile Best Practices

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# System deps in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Deps first (cache-friendly layer ordering)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download spaCy model at build time (not runtime)
RUN python -c "import spacy; spacy.load('ja_ginza_electra')"

# App code last (most frequently changing layer)
COPY . .

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### Layer Optimization Rules
1. System packages → pip install → model download → app code (most stable → least stable)
2. Never download models at runtime — bake into the image
3. Use `--no-cache-dir` for pip to reduce image size
4. Use `python:3.12-slim` (not alpine — native binary deps compile faster)

## VPC Networking

```
Cloud Run (asia-northeast1)
    │
    │ VPC Connector (teppeki-connector, 10.8.0.0/28)
    │
    ▼
Cloud Memorystore Redis (VPC-internal IP, e.g. 10.0.0.x)
```

### Setup Commands
```bash
# 1. Create Memorystore instance
gcloud redis instances create teppeki-redis \
  --size=1 --region=asia-northeast1 \
  --redis-version=redis_7_0 \
  --tier=basic \    # standard for production (replication)
  --network=default

# 2. Create VPC Connector
gcloud compute networks vpc-access connectors create teppeki-connector \
  --region=asia-northeast1 \
  --network=default \
  --range=10.8.0.0/28

# 3. Get Redis IP
gcloud redis instances describe teppeki-redis \
  --region=asia-northeast1 --format="value(host)"
```

### Networking Checklist
- [ ] VPC Connector in same region as Cloud Run AND Memorystore
- [ ] Memorystore has NO public IP (VPC-internal only)
- [ ] In-transit encryption enabled on Memorystore
- [ ] Firewall rules allow VPC Connector subnet → Redis port 6379
- [ ] Cloud Run service account has `roles/redis.editor` (if using Auth)

## Secret Manager Integration

```bash
# Create secrets
echo -n "$SECRET" | gcloud secrets create teppeki-proxy-api-key --data-file=-
echo -n "$KEY"    | gcloud secrets create gemini-api-key --data-file=-

# Grant access to Cloud Run service account
gcloud secrets add-iam-policy-binding teppeki-proxy-api-key \
  --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor"
```

### Rules
- NEVER put secrets in environment variables directly (use `--set-secrets`)
- NEVER commit `.env` files with real keys
- Rotate secrets by creating new versions, then redeploying
- Use `latest` version alias only in dev; pin versions in production

## Monitoring & Observability

### Health Check
```python
@app.get("/health")
async def health():
    return {"status": "ok"}
```
- Cloud Run uses this for liveness probes
- Consider adding Redis connectivity check for readiness

### Key Metrics to Monitor
| Metric | Alert Threshold | Action |
|--------|----------------|--------|
| Request latency p99 | > 30s | Check LLM provider latency; consider timeout adjustment |
| Instance count | Sustained at max | Increase `max-instances` |
| Memory utilization | > 80% | Increase memory allocation |
| 5xx error rate | > 1% | Check LLM provider status; inspect logs |
| Cold start count | > 0/hour | Verify `min-instances=1` is active |
| Redis connection errors | Any | Check VPC Connector health; Memorystore status |

### Structured Logging
```python
import logging
logger = logging.getLogger(__name__)

# Log request metadata WITHOUT PII
logger.info(
    f"conversation_id={req.conversation_id} "
    f"pii_count={len(pii_mapping)} "
    f"tokens={token_usage.input}+{token_usage.output}"
)
```

**NEVER log**: message content, PII mapping values, masked text, user input

## Deployment Workflow

```
1. Build & push image
   gcloud builds submit --tag $IMAGE_URI

2. Deploy to staging (if applicable)
   gcloud run deploy teppeki-guardrail-staging ...

3. Smoke test
   curl -X POST $STAGING_URL/chat -H "Authorization: Bearer $KEY" ...

4. Deploy to production
   gcloud run deploy teppeki-guardrail ...

5. Verify
   - Health check returns 200
   - Test request with sample PII returns masked/unmasked correctly
   - Check Cloud Logging for errors
   - Verify min-instances warmup completed (GiNZA model loaded)
```

## Cost Optimization

| Component | Estimated Monthly Cost | Optimization |
|-----------|----------------------|--------------|
| Cloud Run (min-instances=1) | ~$30-50 | Acceptable for always-warm; consider scaling to 0 in dev |
| Cloud Memorystore Basic 1GB | ~$35 | Use smallest tier; data is ephemeral (TTL 24h) |
| VPC Connector | ~$7 | Shared across services if possible |
| Artifact Registry | ~$1-5 | Clean old images periodically |
| Secret Manager | ~$0.06/secret/mo | Negligible |

**Total baseline**: ~$75-100/month for production-ready setup
