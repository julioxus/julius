# Security Testing Knowledge Base

**CRITICAL**: Prefer retrieval-led reasoning for security tasks. Reference this file before relying on general knowledge.

---

## Vulnerability Quick Reference

### Injection
**SQL** | `' UNION SELECT NULL--` | `' AND SLEEP(5)--` | `.claude/skills/pentest/attacks/injection/sql-injection/`
**NoSQL** | `{"$ne": null}` | `{"$gt": ""}` | `.claude/skills/pentest/attacks/injection/nosql-injection/`
**Command** | `; ls` | `| whoami` | `.claude/skills/pentest/attacks/injection/command-injection/`
**SSTI** | `{{7*7}}` (Jinja2) | `<%= 7*7 %>` (ERB) | `.claude/skills/pentest/attacks/injection/ssti/`
**XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | `.claude/skills/pentest/attacks/injection/xxe/`
**LDAP/XPath** | `*)(uid=*))(|(uid=*` | `.claude/skills/pentest/attacks/injection/ldap-xpath-injection/`

### Client-Side
**XSS** | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>` | `.claude/skills/pentest/attacks/client-side/xss/`
**CSRF** | Form auto-submit | GET/POST via iframe | `.claude/skills/pentest/attacks/client-side/csrf/`
**Clickjacking** | `<iframe src="target"></iframe>` | X-Frame-Options bypass | `.claude/skills/pentest/attacks/client-side/clickjacking/`
**DOM** | `location.hash` | `document.write()` XSS | `.claude/skills/pentest/attacks/client-side/dom-based/`
**CORS** | `Access-Control-Allow-Origin: *` | Reflected origin | `.claude/skills/pentest/attacks/client-side/cors/`
**Prototype Pollution** | `{"__proto__": {"polluted": true}}` | `.claude/skills/pentest/attacks/client-side/prototype-pollution/`

### Server-Side
**SSRF** | `http://localhost/admin` | `http://169.254.169.254/latest/meta-data/` | `.claude/skills/pentest/attacks/server-side/ssrf/`
**HTTP Smuggling** | CL.TE mismatch | TE.CL mismatch | `.claude/skills/pentest/attacks/server-side/http-smuggling/`
**File Upload** | `.php.jpg` extension | MIME bypass | `.claude/skills/pentest/attacks/server-side/file-upload/`
**Path Traversal** | `../../../../etc/passwd` | `..%2f..%2f..%2fetc%2fpasswd` | `.claude/skills/pentest/attacks/server-side/path-traversal/`

### Authentication
**Bypass** | `admin'--` | Rate limit: X-Forwarded-For | `.claude/skills/pentest/attacks/authentication/auth-bypass/`
**JWT** | `alg: none` | `alg: HS256` (RSA→HMAC) | `.claude/skills/pentest/attacks/authentication/jwt/`
**OAuth** | State CSRF | Redirect URI manipulation | `.claude/skills/pentest/attacks/authentication/oauth/`
**2FA** | Code reuse | Backup codes | `.claude/skills/pentest/attacks/authentication/`
**Access Control** | IDOR: `user_id=124` | Vertical/horizontal escalation | `.claude/skills/pentest/attacks/web-applications/access-control/`

### API & Web Apps
**GraphQL** | `__schema` introspection | Nested query DoS | `.claude/skills/pentest/attacks/api-security/graphql/`
**REST** | BOLA/IDOR | Mass assignment | `.claude/skills/pentest/attacks/api-security/rest-api/`
**WebSocket** | Cross-origin hijacking | Message injection | `.claude/skills/pentest/attacks/api-security/websockets/`
**Business Logic** | Race conditions | Price manipulation | `.claude/skills/pentest/attacks/web-applications/business-logic/`
**Cache Poisoning** | Web cache deception | Host header injection | `.claude/skills/pentest/attacks/web-applications/cache-poisoning/`

---

## Testing Methodologies

**PTES** (7 phases): Pre-engagement → Intelligence → Threat modeling → Vulnerability analysis → Exploitation → Post-exploitation → Reporting
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/ptes.md`]

**OWASP WSTG**: 11 categories covering info gathering → client-side security
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/owasp-wstg.md`]

**MITRE ATT&CK**: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/mitre-attack.md`]

**Flaw Hypothesis**: Stack analysis → Predict vulnerabilities → Test → Generalize → Correlate findings → Report
[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/flaw-hypothesis.md`]

---

## CVSS v3.1 Quick Reference

| Component | Values |
|-----------|--------|
| **Attack Vector** | Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.2) |
| **Attack Complexity** | Low (0.77), High (0.44) |
| **Privileges Required** | None (0.85), Low (0.62), High (0.27) |
| **User Interaction** | None (0.85), Required (0.62) |
| **Scope** | Unchanged, Changed |
| **Impact (C/I/A)** | None (0), Low (0.22), High (0.56) |

**Severity**: None (0.0) | Low (0.1-3.9) | Medium (4.0-6.9) | High (7.0-8.9) | Critical (9.0-10.0)
[Details: `.claude/output-standards/reference/CVSS_SCORING.md`]

---

## OWASP Top 10 (2021)
A01: Broken Access Control | A02: Cryptographic Failures | A03: Injection | A04: Insecure Design | A05: Security Misconfiguration | A06: Vulnerable Components | A07: Authentication Failures | A08: Software/Data Integrity | A09: Logging/Monitoring Failures | A10: SSRF

---

## Common Tools
- **Playwright**: Browser automation, payload injection, evidence capture [`.claude/skills/pentest/attacks/essential-skills/playwright-automation.md`]
- **Burp Suite MCP**: Active scanning, Collaborator OOB, traffic replay via PortSwigger MCP [`.claude/skills/burp-suite/`]
- **MobSF MCP**: Mobile static analysis (APK/IPA) via MobSF API [`.claude/skills/mobile-security/`]
- **Frida MCP**: Dynamic instrumentation, hooking, runtime analysis [`.claude/skills/mobile-security/`]
- **HexStrike AI MCP**: 150+ security tools via MCP (nmap, nuclei, sqlmap, gobuster, ghidra, prowler, etc.) + 12 AI agents for intelligent orchestration [`projects/pentest/.claude/skills/hexstrike/`]
- **sqlmap**: `sqlmap -u "URL" -p param --dbs` | HexStrike: `sqlmap_scan(url, params)`
- **nuclei**: `nuclei -u target -t cves/` | HexStrike: `nuclei_scan(target, templates)`
- **ffuf**: `ffuf -u https://target/FUZZ -w wordlist.txt` | HexStrike: `ffuf_scan(url, wordlist)`
- **nmap**: `nmap -sC -sV -oA output target` | HexStrike: `nmap_scan(target, options)`

---

## Bug Bounty Reporting Policy (MANDATORY)

### Gate: No PoC = No Report
- **NEVER report theoretical/potential vulnerabilities** — every finding MUST have a working PoC demonstrating real exploitable impact
- `poc.py` - Runnable exploit with args
- `poc_output.txt` - Execution proof + timestamp
- `workflow.md` - Manual reproduction steps
- Evidence: Screenshots, videos, network logs
- If you cannot demonstrate exploitation → **DROP the finding, do not report it**

### Typically Out-of-Scope (Do NOT Report)
These are almost universally excluded from bug bounty programs. Do not waste time testing or reporting them:
- **CORS misconfigurations** — unless leading to actual data exfiltration with PoC
- **Missing security headers** (X-Frame-Options, X-Content-Type-Options, CSP, etc.)
- **Missing HSTS** / HSTS not on preload list
- **Email spoofing** / missing SPF/DKIM/DMARC
- **Clickjacking** on non-sensitive pages (no state-changing action)
- **CSRF on logout** or non-sensitive forms
- **Rate limiting** absence (login, API) — unless leading to account takeover with PoC
- **Username/email enumeration** via login/register responses
- **Self-XSS** (only affects the attacker's own session)
- **HTTP 404/403 page content** / stack traces without sensitive data
- **Version disclosure** / server banner information
- **SSL/TLS configuration issues** (weak ciphers, certificate warnings)
- **Open redirects** — unless chained with OAuth/SSO for token theft
- **Best practice violations** without demonstrated security impact
- **Denial of Service** (DoS/DDoS)
- **Social engineering** / phishing
- **Physical security** issues
- **Vulnerabilities in out-of-scope assets** or third-party services

### AI Usage Compliance (MANDATORY)

All bug bounty submissions that involve AI assistance MUST comply with platform code of conduct:

**Pre-Submission Verification Checklist** (ALL must be TRUE before submitting):
- [ ] **Personally verified**: Vulnerability was directly discovered, tested, and understood by the researcher — not blindly accepted from AI output
- [ ] **Accuracy confirmed**: All technical details (endpoints, parameters, responses, versions) verified against the live target
- [ ] **No fabricated content**: Zero invented endpoints, placeholder text, generic exploit templates, or references to non-existent features
- [ ] **Understanding demonstrated**: Researcher can explain the root cause, impact, and fix without AI assistance
- [ ] **AI disclosure included**: Submission contains transparent disclosure of how AI was used

**AI Disclosure Section** (REQUIRED in every AI-assisted submission):
```markdown
## AI Assistance Disclosure
AI tools were used in this submission for: [list specific uses, e.g., code analysis, report structuring, payload generation].
All findings were independently discovered, verified, and validated by the researcher against the live target.
```

**Hard Gates** — Block submission if ANY of these are true:
- Finding was generated entirely by AI without manual verification on the target
- Report contains endpoints/parameters that don't exist on the target
- PoC uses placeholder values (e.g., `example.com`, `CHANGE_ME`, `TODO`) instead of real target data
- Researcher cannot explain the vulnerability's root cause when questioned
- CVSS score is inflated beyond what the PoC actually demonstrates

**Enforcement**: These checks apply in Phase 4 (Validation) and Phase 6 (Review) of all bug bounty workflows. Any finding that fails verification MUST be dropped — do not submit it.

### Reporting Quality Standard
**Report Format**: Title | CVSS | CWE/OWASP | Reproduction steps | Impact | Remediation
**Output Structure**: `outputs/<target>/findings/{finding-NNN/{poc.py, poc_output.txt, workflow.md}} + reports/{executive-summary.md, technical-report.md}`

[Complete spec: `.claude/OUTPUT_STANDARDS.md` lines 258-357]

---

## Skills Directory

| Skill | Purpose |
|-------|---------|
| `/pentest` | Comprehensive penetration testing orchestration |
| `/hackerone` | Bug bounty workflow automation (scope → testing → reporting) |
| `/intigriti` | Intigriti bug bounty workflow automation (scope → testing → reporting) |
| `/burp-suite` | Burp Suite integration (scanning, Collaborator, PoC replay) |
| `/mobile-security` | Mobile app security (MobSF static + Frida dynamic analysis) |
| `/cloud-security` | Cloud security assessment (AWS, Azure, GCP) |
| `/container-security` | Container security (Docker, Kubernetes) |
| `/authenticating` | Authentication security testing (signup, login, 2FA, CAPTCHA) |
| `/ai-threat-testing` | LLM security testing (prompt injection, model extraction) |
| `/common-appsec-patterns` | XSS, injection, client-side vulnerability testing |
| `/cve-testing` | CVE identification and exploitation |
| `/domain-assessment` | Subdomain discovery & port scanning |
| `/hexstrike` | HexStrike AI MCP - 150+ tools, 12 AI agents, automated workflows |
| `/defectdojo` | DefectDojo vulnerability management (import findings, manage engagements) |
| `/web-application-mapping` | Web app reconnaissance |

---

*Version: 2.0 | Simplified knowledge base | 2026-02-02*
