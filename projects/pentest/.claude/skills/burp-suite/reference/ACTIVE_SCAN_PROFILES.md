# Active Scan Profiles

## Scan Types

### Full Active Scan

Comprehensive vulnerability detection. Use for initial assessment.

**Checks**: SQL injection, XSS, OS command injection, path traversal, file inclusion, SSRF, XXE, SSTI, deserialization, CORS, header injection

**Config**:
- Scan speed: Normal
- Audit items: All
- Follow redirections: In-scope only

### ActiveScan++ Extended Checks

PortSwigger's ActiveScan++ extension adds:

| Check | Description |
|-------|-------------|
| Host header injection | Routing-based SSRF, password reset poisoning |
| DNS rebinding | Bypass same-origin via DNS TTL manipulation |
| Cache poisoning | Web cache poisoning via unkeyed headers |
| Input transformation | Detect server-side input normalization |
| Blind code injection | Time-based detection for SSTI, expression injection |

### Quick Scan

Fast vulnerability sweep. Use for large scope or time-constrained testing.

**Checks**: High-confidence issues only (reflected XSS, obvious SQLi, open redirect)
**Config**:
- Scan speed: Fast
- Skip: Blind/time-based checks
- Follow redirections: Never

### API-Focused Scan

For REST/GraphQL API endpoints.

**Checks**: JSON/XML injection, mass assignment, BOLA/IDOR, authentication bypass
**Config**:
- Content-Type aware payloads
- Scan request body parameters
- Include: Custom headers, auth tokens

## Profile Selection Guide

| Target Type | Recommended Profile | Time Estimate |
|-------------|-------------------|---------------|
| Web app (small, <50 endpoints) | Full Active Scan | 1-2 hours |
| Web app (large, 200+ endpoints) | Quick Scan → targeted Full Scan | 2-4 hours |
| REST API | API-Focused Scan | 30-60 min |
| Single endpoint/parameter | Full Active Scan (targeted) | 10-30 min |
| Bug bounty (time-sensitive) | Quick Scan + ActiveScan++ | 1-2 hours |

## Scan Optimization

**Scope control**: Only scan authorized targets
```
Target → Scope → Include: *.target.com
Target → Scope → Exclude: /logout, /admin/delete
```

**Resource limits**:
- Max concurrent requests: 10 (increase for robust targets)
- Request delay: 100ms minimum (prevent rate limiting)
- Max scan duration: Set per engagement

**False positive reduction**:
- Enable "consolidate passive issues"
- Review confidence levels: Certain > Firm > Tentative
- Validate Tentative findings manually before reporting

## Output Mapping

Burp severity → CVSS mapping:

| Burp Level | CVSS Range | Action |
|------------|------------|--------|
| High | 7.0-10.0 | Report immediately, validate PoC |
| Medium | 4.0-6.9 | Report after validation |
| Low | 0.1-3.9 | Report if demonstrable impact |
| Info | 0.0 | Document for reconnaissance only |
