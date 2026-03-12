# DefectDojo API v2 Reference

## Authentication

**All requests require Token authentication.**

```
Authorization: Token $DEFECTDOJO_TOKEN
Content-Type: application/json
```

### Environment Variables

```bash
export DEFECTDOJO_URL=https://defectdojo.example.com  # No trailing slash
export DEFECTDOJO_TOKEN=<your_api_key>
```

### Token Validation

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  $DEFECTDOJO_URL/api/v2/users/me/
```

### Obtain Token

1. Log in to DefectDojo → Profile → API Key
2. Or: `$DEFECTDOJO_URL/api/key-v2`

## Base URL

```
$DEFECTDOJO_URL/api/v2/
```

## Swagger Documentation

```
$DEFECTDOJO_URL/api/v2/oa3/swagger-ui/
```

## Key Endpoints

### Products

**List Products**
```
GET /api/v2/products/?name={name}&limit=10
```

**Create Product**
```
POST /api/v2/products/
{
  "name": "Example Corp",
  "description": "Security assessment target",
  "prod_type": 1
}
```

**Get Product Types**
```
GET /api/v2/product_types/
```

### Engagements

**List Engagements**
```
GET /api/v2/engagements/?product={product_id}&status=In%20Progress
```

**Create Engagement**
```
POST /api/v2/engagements/
{
  "name": "Q1 2026 Penetration Test",
  "product": 1,
  "target_start": "2026-01-15",
  "target_end": "2026-02-15",
  "engagement_type": "Interactive",
  "status": "In Progress",
  "lead": 1,
  "description": "Quarterly security assessment"
}
```

**Close Engagement**
```
POST /api/v2/engagements/{id}/close/
```

### Tests

**Create Test** (required before findings)
```
POST /api/v2/tests/
{
  "engagement": 5,
  "test_type": 1,
  "target_start": "2026-01-15",
  "target_end": "2026-01-15",
  "title": "Manual Pentest"
}
```

**Get Test Types**
```
GET /api/v2/test_types/?name=Pen%20Test
```

### Findings

**List Findings**
```
GET /api/v2/findings/?test={test_id}&active=true&limit=100
```

**Create Finding**
```
POST /api/v2/findings/
{
  "title": "SQL Injection in Login Form",
  "severity": "Critical",
  "description": "Markdown description...",
  "mitigation": "Use parameterized queries...",
  "impact": "Full database access...",
  "steps_to_reproduce": "1. Navigate to...\n2. Enter payload...",
  "cwe": 89,
  "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvssv3_score": 9.8,
  "test": 1,
  "found_by": [1],
  "active": true,
  "verified": true,
  "numerical_severity": "S0",
  "date": "2026-01-15"
}
```

**Severity → numerical_severity mapping**:
- Critical → S0
- High → S1
- Medium → S2
- Low → S3
- Info → S4

**Upload File to Finding**
```
POST /api/v2/findings/{id}/files/
Content-Type: multipart/form-data

file=@poc.py
title=Proof of Concept Script
```

**Add Note to Finding**
```
POST /api/v2/findings/{id}/notes/
{
  "entry": "Additional context or AI disclosure note",
  "note_type": 1
}
```

### Endpoints

**Create Endpoint**
```
POST /api/v2/endpoints/
{
  "protocol": "https",
  "host": "api.example.com",
  "path": "/login",
  "product": 1
}
```

**Add Endpoint to Finding**
```
POST /api/v2/findings/{id}/endpoint/add/
{
  "endpoint": [endpoint_id]
}
```

### Import/Reimport Scans

**Import Scan** (creates new test)
```
POST /api/v2/import-scan/
Content-Type: multipart/form-data

scan_type=Nuclei Scan
file=@nuclei-results.json
engagement=5
active=true
verified=false
```

**Reimport Scan** (updates existing test)
```
POST /api/v2/reimport-scan/
Content-Type: multipart/form-data

scan_type=Nuclei Scan
file=@nuclei-results.json
test=1
active=true
verified=false
```

**Common scan_type values**:
- `Nuclei Scan`, `Nmap XML Scan`, `ZAP Scan`, `Burp REST API`
- `Trivy Scan`, `Prowler`, `Semgrep JSON Report`
- `Generic Findings Import` (CSV/JSON)

## Pagination

All list endpoints support pagination:
```
GET /api/v2/findings/?limit=100&offset=0
```

Response includes `count`, `next`, `previous`, `results`.

## Error Responses

| Code | Description |
|------|-------------|
| 401 | Invalid or missing token |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 400 | Validation error (check response body for field errors) |
| 429 | Rate limited |

## Common Patterns

### Full Import Workflow

```python
import os, requests

url = os.environ["DEFECTDOJO_URL"]
token = os.environ["DEFECTDOJO_TOKEN"]
headers = {"Authorization": f"Token {token}", "Content-Type": "application/json"}

# 1. Get/create product
r = requests.get(f"{url}/api/v2/products/", params={"name": "Target"}, headers=headers)
product_id = r.json()["results"][0]["id"] if r.json()["count"] > 0 else None

# 2. Create engagement
eng = requests.post(f"{url}/api/v2/engagements/", headers=headers, json={
    "name": "Q1 Pentest", "product": product_id,
    "target_start": "2026-01-15", "target_end": "2026-02-15",
    "engagement_type": "Interactive", "status": "In Progress"
}).json()

# 3. Create test
test = requests.post(f"{url}/api/v2/tests/", headers=headers, json={
    "engagement": eng["id"], "test_type": 1,
    "target_start": "2026-01-15", "target_end": "2026-01-15"
}).json()

# 4. Create finding
finding = requests.post(f"{url}/api/v2/findings/", headers=headers, json={
    "title": "SQL Injection", "severity": "Critical",
    "description": "...", "cwe": 89, "test": test["id"],
    "active": True, "verified": True, "numerical_severity": "S0"
}).json()

# 5. Upload evidence
with open("poc.py", "rb") as f:
    requests.post(f"{url}/api/v2/findings/{finding['id']}/files/",
        headers={"Authorization": f"Token {token}"},
        files={"file": ("poc.py", f)}, data={"title": "PoC Script"})
```
