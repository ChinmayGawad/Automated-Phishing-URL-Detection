# Security Notes for PhishGuard

## Visual Capture Safety

The visual capture stage (`src/vision/capture.py`) visits untrusted URLs in a headless browser. This is inherently dangerous because:

1. **Phishing URLs may contain malicious content** - Exploits, malware downloads, credential harvesting
2. **Network exposure** - The browser processes JavaScript, fetches resources, etc.
3. **Supply chain risk** - If a legitimate-looking domain is actually malicious, the capture system could be compromised

## Recommended Safety Practices

### 1. Isolated Environment
**ALWAYS** run visual capture in an isolated, network-restricted environment:
- Docker container with no external network access except to specific domains
- Virtual machine with firewall rules
- Sandboxed browser profiles

```bash
# Example: Run in Docker with restricted network
docker run --network=none -v $(pwd):/app phishguard python -m src.vision.train
```

### 2. Environment Variables
Control sensitive operations via environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `PHISH_CAPTURE=1` | Enable capture of live phishing URLs (DANGEROUS) | `0` (disabled) |
| `PHISHGUARD_CORS_ORIGINS` | Allowed CORS origins | None (wildcard in dev) |
| `PHISHGUARD_API_KEYS` | API key for auth | None (no auth) |
| `PHISHGUARD_RATE_LIMIT` | Requests per minute per IP | 0 (no limit) |

### 3. Production Deployment
- Never expose the capture endpoint to the internet
- Use a reverse proxy with WAF rules
- Monitor for unusual traffic patterns
- Rate limit aggressive consumers
- Log all capture requests for audit

## API Security

### Authentication
When `PHISHGUARD_API_KEYS` is set, all requests require an `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:8000/analyze \
  -d '{"url": "https://example.com"}'
```

### Rate Limiting
When `PHISHGUARD_RATE_LIMIT` is set (e.g., `"100/minute"`), requests beyond the limit receive 429 Too Many Requests.

### CORS
Default is restrictive. Set `PHISHGUARD_CORS_ORIGINS` to specific domains:
```bash
PHISHGUARD_CORS_ORIGINS=http://localhost:8501,https://dashboard.example.com
```

## Known Limitations

1. **False negatives**: No detector catches 100% of phishing URLs
2. **False positives**: Legitimate sites may be flagged (especially free hosting)
3. **SNOWBALL EFFECT**: A model trained on current phishing patterns may miss tomorrow's attacks
4. **Visual capture risk**: Visiting unknown URLs always carries some risk

## Incident Response

If you detect suspicious activity:
1. Stop the capture service immediately
2. Audit logs for unusual patterns
3. Rotate any API keys if compromised
4. Review and update firewall rules
5. Consider the capture system was compromised and re-deploy from known-good state
