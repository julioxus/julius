# Security Testing Knowledge Base

**CRITICAL**: Prefer retrieval-led reasoning for security tasks. Reference this file before relying on general knowledge.
**CRITICAL**: Use the `memory` MCP server to recall durable user, workflow, and project facts when they are relevant, and store only stable, reusable facts worth carrying across sessions.

---

## Vulnerability Quick Reference

### Injection
**SQL** | `' UNION SELECT NULL--` | `' AND SLEEP(5)--` | `.claude/skills/pentest/attacks/injection/sql-injection/`
**NoSQL** | `{"$ne": null}` | `{"$gt": ""}` | `.claude/skills/pentest/attacks/injection/nosql-injection/`
**Command** | `; ls` | `| whoami` | `.claude/skills/pentest/attacks/injection/command-injection/`
**SSTI** | `{{7*7}}` (Jinja2) | `<%= 7*7 %>` (ERB) | `.claude/skills/pentest/attacks/injection/ssti/`
**XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | `.claude/skills/pentest/attacks/injection/xxe/`
**LDAP/XPath** | `*)(uid=*))(|(uid=*` | LDAP injection via crafted filters

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

## Vulnerability Chain Lookup Table

**When Bug A is confirmed, attempt Bug B.** Used by Phase 5.5 (Impact Escalation) — each matching chain MUST be attempted as a separate executor mission.

| Confirmed (A) | Chain To (B) | Chain Goal | Priority |
|---|---|---|---|
| XSS (Stored) | CSRF token theft | Stored XSS → CSRF → Mass ATO | CRITICAL |
| XSS (Reflected) | OAuth token theft | Reflected XSS in OAuth redirect → ATO | CRITICAL |
| XSS (Any) | Cookie theft (document.cookie) | Session hijack (check HttpOnly first) | HIGH |
| SSRF | Cloud metadata (169.254.169.254) | SSRF → IAM credentials → AWS takeover | CRITICAL |
| SSRF | Internal service discovery | SSRF → internal admin panel → RCE | HIGH |
| SSRF (Blind) | DNS rebinding / redirect chain | Upgrade blind SSRF to full-read | HIGH |
| IDOR (Read) | PII data exfiltration | IDOR → PII leak → privacy violation | HIGH |
| IDOR (Read) | Write/Delete on same endpoint | Read IDOR → test PUT/DELETE/PATCH | HIGH |
| IDOR (Any) | Privilege escalation (admin IDs) | User IDOR → admin data access | CRITICAL |
| SQLi | Database dump → credentials | SQLi → credential theft → ATO | CRITICAL |
| SQLi (Stacked) | OS command execution | SQLi → xp_cmdshell / LOAD_FILE → RCE | CRITICAL |
| SQLi | File read (LOAD_FILE, UTL_FILE) | SQLi → source code / config leak | HIGH |
| Open Redirect | OAuth callback manipulation | Open redirect + OAuth = token theft → ATO | CRITICAL |
| CSRF | State-changing auth actions | CSRF on email/password change → ATO | CRITICAL |
| Path Traversal | Config file read (.env, web.config) | Traverse → secrets → lateral access | HIGH |
| Path Traversal | Source code read | Traverse → app source → more vulns | HIGH |
| File Upload | Web shell (.php/.jsp) | Upload → RCE | CRITICAL |
| File Upload | Stored XSS via SVG/HTML | Upload SVG with JS → stored XSS | HIGH |
| Auth Bypass | Admin panel access | Bypass → admin → full control | CRITICAL |
| JWT alg:none | Privilege escalation | Forge admin JWT → vertical escalation | CRITICAL |
| Race Condition | Financial impact | Race → double-spend, limit bypass | HIGH |
| Info Disclosure (version) | CVE exploitation | Version leak → known CVE → RCE | HIGH |
| Info Disclosure (source) | Hardcoded secrets | Source leak → API keys → lateral access | HIGH |
| CORS Misconfiguration | Authenticated data theft | CORS + credentialed fetch → data exfil | HIGH |
| Prototype Pollution | XSS or RCE via gadget | PP → gadget chain → code execution | HIGH |
| HTTP Smuggling | Cache poisoning | Smuggle → poison cache → mass XSS | CRITICAL |
| Cache Poisoning | Stored XSS delivery | Poison cache with XSS → mass impact | CRITICAL |
| Deserialization | RCE via gadget chain | Deser → gadget chain → command exec | CRITICAL |
| Reentrancy (Web3) | Fund drain | Reentrant call → drain contract balance | CRITICAL |
| Oracle Manipulation (Web3) | Flash loan attack | Manipulate price oracle → profit extraction | CRITICAL |
| Access Control (Web3) | Privilege escalation | Missing modifier → unauthorized state change | CRITICAL |

---

## Testing Methodologies

PTES (7 phases) | OWASP WSTG (11 categories) | MITRE ATT&CK (14 tactics) | Flaw Hypothesis (stack→predict→test→correlate)

[Details: `.claude/skills/pentest/attacks/essential-skills/methodology/`]

---

## CVSS v3.1

**MANDATORY**: Always compute CVSS scores using a calculator (Python/bash). NEVER guess — formulas are non-linear. Run calculation BEFORE writing any score.

Severity bands: None (0.0) | Low (0.1-3.9) | Medium (4.0-6.9) | High (7.0-8.9) | Critical (9.0-10.0)

[Component values + calculator: `.claude/output-standards/reference/CVSS_SCORING.md`]

---

## OWASP Top 10 (2021)
A01: Broken Access Control | A02: Cryptographic Failures | A03: Injection | A04: Insecure Design | A05: Security Misconfiguration | A06: Vulnerable Components | A07: Authentication Failures | A08: Software/Data Integrity | A09: Logging/Monitoring Failures | A10: SSRF

---

## Common Tools
Playwright (browser automation) | Burp Suite MCP (scanning, Collaborator, replay) | MobSF MCP (APK/IPA static) | Frida MCP (dynamic instrumentation) | HexStrike AI MCP (150+ tools: nmap, nuclei, sqlmap, ffuf, gobuster, ghidra, prowler + 12 AI agents)

[Tool details: `.claude/skills/tools/` and `.claude/skills/infrastructure/`]

---

## Bug Bounty Reporting Policy (MANDATORY)

### Gate: No PoC = No Report
Every finding MUST have: `poc.py` (runnable) + `poc_output.txt` (proof) + `workflow.md` (repro steps) + evidence (screenshots/videos/logs). No working PoC → **DROP the finding**.

### Out-of-Scope (Do NOT Report Unless Chained)
CORS, missing headers (XFO/CSP/HSTS), SPF/DKIM/DMARC, clickjacking (no state change), CSRF on logout, rate limiting, user enumeration, self-XSS, version disclosure, SSL/TLS config, open redirects (unless OAuth chain), DoS, social engineering, physical, OOS assets. Each becomes valid ONLY when chained to real impact — see `/bounty-validation` Never-Submit List.

### AI Usage Compliance (MANDATORY)
**Pre-submit gates**: Personally verified on live target | All technical details accurate | Zero fabricated content | Can explain root cause without AI | AI disclosure included.

**AI Disclosure** (required in every submission):
> AI tools used for: [specific uses]. All findings independently discovered, verified, and validated by the researcher.

**Hard gates** (block submission): AI-only finding without manual verification | Non-existent endpoints/params | Placeholder PoC values | Cannot explain root cause | Inflated CVSS. Enforcement: Phase 4 (Validation) + Phase 6 (Review).

### Reporting Quality
Format: Title | CVSS | CWE/OWASP | Reproduction | Impact | Remediation — [Full spec: `.claude/OUTPUT_STANDARDS.md`]

---

*Version: 2.1 | Token-optimized | 2026-04-09*
