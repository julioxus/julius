# Intigriti API Reference

## Authentication (MANDATORY)

**All program and scope data MUST be fetched via this API. Never use hardcoded/manual scope.**

**CRITICAL: Both headers are REQUIRED for every request.**

```
Authorization: Bearer $INTIGRITI_TOKEN
Content-Type: application/json
```

### Environment Variable

```bash
export INTIGRITI_TOKEN=<your_bearer_token>
```

### Token Validation

```bash
# Returns 200 if token is valid
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $INTIGRITI_TOKEN" \
  -H "Content-Type: application/json" \
  https://api.intigriti.com/external/researcher/v1/programs
```

### Obtain Token

1. Go to: https://app.intigriti.com/researcher/settings/api
2. Generate a new API token
3. Set as env var: `export INTIGRITI_TOKEN=<token>`

**If INTIGRITI_TOKEN is not set**: Always ask the user to provide it before proceeding.

## Base URL

```
https://api.intigriti.com/external/researcher/v1/
```

## Swagger Documentation

```
https://api.intigriti.com/external/researcher/swagger/index.html
```

## Key Endpoints

### Programs

**List Programs**
```
GET /external/researcher/v1/programs
```

Query params: `statusId`, `typeId`, `following`, `limit` (max 500), `offset`

**Get Program Details (includes domains + rules)**
```
GET /external/researcher/v1/programs/{programId}
```

Response includes: description, rules, bounty table, domains (with tiers), severity ratings.
Note: Program details embed `domains` and `rulesOfEngagement` in a single response.

**Get Program Domains (Scope) - by version**
```
GET /external/researcher/v1/programs/{programId}/domains/{versionId}
```

Response format:
```json
{
  "domains": [
    {
      "id": "uuid",
      "domain": "*.example.com",
      "type": "web_application",
      "tier": 1,
      "description": "Main web application",
      "inScope": true
    },
    {
      "id": "uuid",
      "domain": "api.example.com",
      "type": "api",
      "tier": 2,
      "description": "REST API",
      "inScope": true
    }
  ]
}
```

### Submissions

**Create Submission**
```
POST /external/researcher/v1/programs/{programId}/submission
```

Request body:
```json
{
  "title": "Stored XSS in User Profile Bio",
  "severity": {
    "score": 7.1,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
  },
  "domainId": "uuid-of-in-scope-domain",
  "vulnerabilityTypeId": "uuid-of-vuln-type",
  "description": "Markdown description...",
  "stepsToReproduce": "Numbered steps...",
  "impact": "Impact description..."
}
```

**List My Submissions**
```
GET /external/researcher/v1/submissions
```

**Get Submission Details**
```
GET /external/researcher/v1/submissions/{submissionId}
```

**Add Attachment to Submission**
```
POST /external/researcher/v1/submissions/{submissionId}/attachment
Content-Type: multipart/form-data
```

### Vulnerability Types

**List Vulnerability Types**
```
GET /external/researcher/v1/vulnerability-types
```

Response includes taxonomy IDs needed for submission creation.

## Rate Limits

- API requests: Follow standard rate limiting headers
- `X-RateLimit-Limit`: Max requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `Retry-After`: Wait time when rate limited

## Error Responses

| Code | Description |
|------|-------------|
| 401 | Invalid or expired token |
| 403 | Insufficient permissions |
| 404 | Program/submission not found |
| 422 | Validation error (check field requirements) |
| 429 | Rate limited |

## Common Patterns

### Fetch Scope for Testing (Preferred: use scope_parser.py)

```bash
# Recommended: use the scope_parser tool
python tools/scope_parser.py --api <program_id>
```

```python
# Or programmatically:
import os
import requests

token = os.environ.get("INTIGRITI_TOKEN")
if not token:
    raise RuntimeError("INTIGRITI_TOKEN not set. Ask user for token.")

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
base = "https://api.intigriti.com/external/researcher/v1"

# Get program domains
resp = requests.get(f"{base}/program/{program_id}/domain", headers=headers)
resp.raise_for_status()
domains = resp.json()["domains"]

# Filter in-scope, sort by tier
in_scope = [d for d in domains if d["inScope"]]
in_scope.sort(key=lambda d: d["tier"])
```

### Submit Finding

```python
import os
import requests

token = os.environ.get("INTIGRITI_TOKEN")
if not token:
    raise RuntimeError("INTIGRITI_TOKEN not set. Ask user for token.")

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
base = "https://api.intigriti.com/external/researcher/v1"

submission = {
    "title": "SSRF via Image URL Parameter",
    "severity": {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "domainId": domain_id,
    "vulnerabilityTypeId": vuln_type_id,
    "description": "...",
    "stepsToReproduce": "...",
    "impact": "..."
}
resp = requests.post(f"{base}/program/{program_id}/submission",
                     headers=headers, json=submission)
resp.raise_for_status()
```
