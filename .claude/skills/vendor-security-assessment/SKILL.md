---
name: vendor-security-assessment
description: Third-party vendor/SDK security assessment for integration decisions. Non-intrusive evaluation covering infrastructure, DNS, supply chain, SAST, compliance, and breach history. Produces executive report with approval verdict. Use before integrating any external service, SDK, or SaaS provider.
---

# Vendor Security Assessment

Non-intrusive security evaluation of third-party vendors, SDKs, and SaaS providers before integration. Produces an executive report with actionable findings and an approval verdict for stakeholders.

## Quick Start

```
/vendor-security-assessment <vendor_name> [package_or_url]
```

Examples:
```
/vendor-security-assessment liveblocks @liveblocks/core
/vendor-security-assessment stripe https://stripe.com
/vendor-security-assessment auth0 @auth0/nextjs-auth0
```

## Input

1. AskUserQuestion: "What vendor/service are you evaluating?"
2. AskUserQuestion: "What packages or URLs will you integrate? (npm packages, API endpoints, SDKs)"
3. AskUserQuestion: "What is the integration context? (e.g., comments in app, payment processing, auth provider)"
4. AskUserQuestion: "Who is the audience for the report? (legal, engineering, CISO, all)"
5. Optional: "Do you have an endpoint list, scope document, or architecture diagram?"

## Workflow

### Phase 1: Reconnaissance — Infrastructure & DNS (non-intrusive)

**1.1 Subdomain enumeration**
- Use `subfinder`, `crt.sh` (certificate transparency), DNS brute-force
- Map all discovered subdomains with CNAME chains

**1.2 Dangling DNS detection**
- For each CNAME record, verify the target resolves:
  - NXDOMAIN on target = **dangling DNS / subdomain takeover candidate**
  - Verify across multiple resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
- Classify by exploitability:
  - **Elastic Beanstalk**: CNAME prefix claimable by any AWS account = HIGH exploitability
  - **AWS ELB**: Account-specific auto-generated hostnames = LOW exploitability
  - **Auth0 tenants**: Multi-step takeover with tenant ID reuse requirement = LOW exploitability
  - **S3 buckets**: Bucket name claimable = HIGH exploitability
  - **Azure/GCP**: Varies by service — check resource name availability
- For exploitable takeovers: verify if subdomain is actively referenced in SDK/docs (impacts severity)

**1.3 Exposed services probing**
- HTTP/HTTPS probe all discovered subdomains (non-intrusive, GET only)
- Note: connection timeouts, error codes, redirect behavior
- Identify exposed internal services (OTEL collectors, log drains, dev endpoints)
- Check for authentication requirements on exposed services (gRPC codes, HTTP 401/403)
- **Never** attempt authentication bypass or brute-force

**1.4 TLS & security headers**
- TLS version and cipher suite check
- HTTP security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Permissions-Policy
- CORS configuration analysis

### Phase 2: Supply Chain Analysis (for SDK/package vendors)

**2.1 Dependency audit**
- `npm audit` / `pip audit` / equivalent for the vendor's packages
- Document: zero vulns, or list CVEs with severity

**2.2 Package integrity**
- Install scripts check: `preinstall`, `postinstall`, `install` hooks (attack vector for malicious packages)
- npm provenance attestations: present or absent
- Package signing: npm signatures, Sigstore
- Maintainer count: single-maintainer packages = higher risk

**2.3 Dependency health**
- Map transitive dependencies
- Identify single-maintainer critical dependencies (crypto libs, CRDT, parsers)
- Version lag analysis: vendor's pinned versions vs latest available
- Deprecated package detection

**2.4 Typosquatting exposure**
- Check if common typo variants of package names are registered
- Unregistered variants = namespace vulnerability (informational)

### Phase 3: Static Application Security Testing (SAST)

**If vendor has open-source SDK/client libraries:**

**3.1 Clone and scan**
- Clone the vendor's public repository
- Focus on: client libraries, SDK packages, integration code

**3.2 Security controls inventory**
- URL sanitization (javascript:, data:, vbscript: blocking)
- HTML rendering (dangerouslySetInnerHTML, innerHTML, v-html usage)
- Markdown rendering (raw HTML generation vs tokenizer-only)
- Input validation patterns
- Cryptographic practices (random generation, hashing, key management)
- Authentication token handling (JWT parsing vs verification separation)

**3.3 Vulnerability scanning**
- XSS vectors: DOM sinks, unsafe rendering, template injection
- Injection points: SQL, command, SSTI in any server-side code
- Secret exposure: hardcoded API keys, tokens, credentials
- Permission model analysis: scope definitions, access control implementation
- Webhook security: HMAC validation, timing-safe comparison, error handling

**If vendor is closed-source:** Skip to Phase 4, note "SAST not possible — closed source" in report.

### Phase 4: Compliance & Trust Signals

**4.1 Certifications** (check vendor's security/trust page)
- SOC 2 Type I / Type II
- ISO 27001
- HIPAA, PCI DSS, GDPR compliance
- Trust center availability (SafeBase, Vanta, Drata)

**4.2 Incident history**
- Search for past breaches, CVEs, security incidents
- Check: HackerNews, security advisories, vendor changelog, CVE databases
- Document: clean history or list incidents with response quality

**4.3 Security program maturity**
- Bug bounty program (HackerOne, Intigriti, or private)
- security.txt / .well-known/security.txt
- SECURITY.md in repositories
- Responsible disclosure policy
- Vulnerability response SLA

**4.4 Infrastructure providers**
- Identify hosting (AWS, GCP, Azure, Vercel, Cloudflare)
- Data residency and encryption (at rest, in transit)
- CDN/WAF presence

### Phase 5: Report Generation

**5.1 Scoring**
Score each area on a 1-10 scale:

| Area | What to score |
|------|---------------|
| Infrastructure | TLS, headers, DNS hygiene, exposed services |
| Supply Chain | Dependency vulns, maintainer diversity, provenance |
| Code Security | SAST findings, security controls, practices |
| Compliance | Certifications, trust center, incident history |
| Security Program | Bug bounty, disclosure policy, response maturity |
| Integration Risk | Specific risks to YOUR integration context |

**5.2 Findings classification**

| Severity | Criteria |
|----------|----------|
| CRITICAL | Exploitable now, impacts confidentiality/integrity of YOUR data |
| HIGH | Exploitable with effort, or impacts vendor's security posture significantly |
| MEDIUM | Requires specific conditions, informational with remediation value |
| LOW | Best practice gaps, informational |

**5.3 Executive report structure**

```markdown
# Security Assessment: {Vendor Name}
## Classification: CONFIDENTIAL

### 1. Executive Summary
- Vendor purpose and integration context
- Overall security posture: [Acceptable / Conditional / Not Recommended]
- Key findings summary (count by severity)

### 2. Scoring Overview
Table with 6 areas, score, and one-line justification

### 3. Compliance & Certifications
SOC 2, ISO 27001, HIPAA, breach history, trust center

### 4. Infrastructure Analysis
DNS, TLS, headers, CORS, exposed services, cloud providers

### 5. Supply Chain Analysis
Dependency audit, provenance, maintainer risk, version health

### 6. Code Security (SAST)
Findings from source code analysis, security controls inventory

### 7. Technical Findings
Detailed findings with severity, description, evidence, remediation

### 8. Integration-Specific Risks
Risks specific to how YOUR organization will use this vendor

### 9. Recommendations
- Immediate actions (before signing contract)
- Contractual requirements (SLAs, breach notification, audit rights)
- Technical mitigations (for integration code)
- Optional: responsible disclosure to vendor

### 10. Verdict
**APPROVED** / **APPROVED WITH CONDITIONS** / **NOT RECOMMENDED**
Conditions listed if applicable

### Appendix
- Methodology
- Tools used
- Date of assessment
- Assessor
```

**5.4 PDF generation**
- Generate PDF with matplotlib charts (scoring radar, findings distribution)
- Use fpdf2 for assembly
- Replace Unicode special characters with ASCII for cross-platform compatibility

## Output Structure

```
outputs/vendor-{name}-assessment/
├── informe-ejecutivo-{name}.md        # Full executive report
├── Evaluacion-Seguridad-{Name}.pdf    # PDF with charts
├── evidence/
│   ├── dns/                           # DNS resolution logs
│   │   ├── subdomains.txt             # Enumerated subdomains
│   │   ├── cname-chains.txt           # Full CNAME resolution chains
│   │   └── dangling-dns.txt           # Confirmed dangling records
│   ├── headers/                       # HTTP header captures
│   ├── tls/                           # TLS/cipher analysis
│   ├── supply-chain/                  # npm audit, dependency trees
│   │   ├── npm-audit.json
│   │   ├── maintainers.txt
│   │   └── provenance-check.txt
│   └── sast/                          # Source code findings
│       ├── findings.md
│       └── security-controls.md
└── scoring/
    ├── area-scores.json               # Machine-readable scores
    └── charts/                        # Generated visualizations
```

## Evidence Standards

All evidence follows the Visual Evidence Standard from `/bounty-validation`:
- DNS findings: real `dig`/`nslookup` output with timestamps
- HTTP probes: real `curl -v` output (never reconstructed)
- Supply chain: actual `npm audit` JSON output
- SAST: file paths and line numbers from actual source code
- **Never**: simulated terminal output, reconstructed responses, or placeholder evidence

## Critical Rules

**MUST DO**:
- All testing is **non-intrusive** — no exploitation, no auth bypass attempts, no fuzzing
- GET requests only for HTTP probing
- Verify dangling DNS across multiple resolvers before reporting
- Classify subdomain takeover exploitability accurately (EB vs ELB vs Auth0 vs S3)
- Check if vulnerable subdomains are actively referenced in SDK before assigning severity
- Score each area independently with justification
- Include integration-specific risk analysis
- Provide contractual recommendations (breach notification SLA, audit rights)
- Generate both markdown and PDF outputs

**NEVER**:
- Attempt to exploit any vulnerability (this is assessment, not pentest)
- Create accounts on the vendor's platform for testing
- Access authenticated endpoints without authorization
- Perform load testing, fuzzing, or active scanning
- Claim a dangling subdomain to prove takeover (just verify DNS)
- Test production systems beyond basic HTTP GET probes

## Tools

- `subfinder` / `crt.sh` — Subdomain enumeration
- `dig` / `nslookup` — DNS resolution and chain verification
- `curl -v` — HTTP probing (GET only)
- `openssl s_client` — TLS analysis
- `npm audit` / `pip audit` — Dependency vulnerability scanning
- `npm view` / `npm pack` — Package metadata and integrity
- Playwright MCP — If browser access needed for trust center pages
- `matplotlib` + `fpdf2` — PDF report generation with charts

## Usage

```
/vendor-security-assessment <vendor_name> [package_or_url]
```
