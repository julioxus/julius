# Julius - AI Security Testing Toolkit

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Claude AI](https://img.shields.io/badge/Powered%20by-Claude%20AI-blue)](https://claude.ai)
[![GitHub issues](https://img.shields.io/github/issues/CroquetteHunters/julius)](https://github.com/CroquetteHunters/julius/issues)

**Claude Code skills, agents, and tools for penetration testing, bug bounty hunting, and vulnerability management**

</div>

---

## What is Julius?

Julius is a security testing toolkit built as **Claude Code skills and agents**. It provides AI-orchestrated workflows for pentesting, bug bounty programs, and vulnerability management — all invoked via slash commands inside Claude Code. `/pentest` is the canonical testing engine, invoked by `/hackerone`, `/intigriti`, and `/defectdojo` as sub-orchestrator.

Built on top of [Transilience AI Community Tools](https://github.com/transilienceai/communitytools).

### At a glance

| | |
|-|-|
| **50+ skills** | Pentesting, recon, bug bounty, vendor assessment, cloud, mobile, SAST, Web3 audit, reporting |
| **8 agents** | Orchestrator, executor, validator, DOM XSS scanner, script generator, payload fetcher, HackTheBox, skill creator |
| **186 attack docs** | PortSwigger Academy solutions, cheat sheets, methodology guides |
| **2 bug bounty platforms** | HackerOne, Intigriti (with autopilot mode) |
| **Vulnerability management** | DefectDojo orchestrator (scope analysis, SAST/DAST via /pentest, API import) |
| **Vendor assessment** | Non-intrusive third-party security evaluation (DNS, supply chain, SAST, compliance) |
| **Safety tools** | Deterministic scope checker, circuit breaker + rate limiter, cross-target hunt memory |
| **Tool integrations** | Burp Suite MCP, HexStrike AI (150+ tools), Playwright, Kali toolset, RecoX |

---

## Bug Bounty Workflow

The primary use case. Two entry points depending on platform:

```bash
/intigriti <program_url_or_pdf>    # Intigriti programs (API scope fetch, tier prioritization)
/hackerone <program_url_or_csv>    # HackerOne programs (CSV scope parsing)
```

### What happens when you run `/intigriti` or `/hackerone`

```
1. SCOPE PARSING (/intigriti or /hackerone)
   Parse program scope → extract assets, tiers, bounty table, OOS list
   Intigriti: Researcher API → domains, tiers, testing requirements (User-Agent, headers)
   HackerOne: CSV → eligible assets, max severity, instructions
   Generate scope.json → deterministic scope enforcement (tools/scope_checker.py)
   Mobile assets → /mobile-app-acquisition

2. RECONNAISSANCE (/bounty-recon — recon only, no agent deployment)
   ├── Bounty-driven prioritization: map vuln types → bounty amounts, rank by payout
   ├── Hunt memory query: cross-target intelligence (tools/hunt_memory.py suggest)
   ├── Endpoint recon: tools/recox (Wayback, CommonCrawl, OTX, URLScan)
   ├── Post-enumeration: httpx → naabu → ffuf → nuclei
   ├── Extended recon (6 skills in parallel):
   │   ├── /code-repository-intel     — GitHub/GitLab leaked secrets, CI configs
   │   ├── /api-portal-discovery      — OpenAPI/Swagger specs, dev docs
   │   ├── /web-application-mapping   — Headless browsing, endpoint discovery
   │   ├── /security-posture-analyzer — Headers, CSP, WAF, security.txt
   │   ├── /cdn-waf-fingerprinter     — CDN/WAF identification for bypass strategy
   │   └── /hexstrike                 — 150+ tools for large-scope parallel recon
   └── Output: testing_recommendations.md (consumed by /pentest)
       ├── Per-asset priority, detected technologies, DOM XSS candidates
       ├── Conditional skill triggers (CVE, SAST, AI, auth, cloud, container, Burp)
       ├── Chain opportunities, WAF/CDN info for payload selection
       └── Mobile assets for /mobile-security

2b. AUTOPILOT DECISION (optional)
   User chooses: /autopilot (paranoid/normal/yolo) or /pentest directly
   Autopilot: iterates surface-by-surface with checkpoints + safety rails
   ├── Circuit breaker: stops after 5 failures per host (300s cooldown)
   ├── Rate limiter: 10 req/s recon, 2 req/s active testing
   ├── Safe method policy: PUT/DELETE/PATCH always require human approval
   └── Findings from surface N inform surface N+1 via hunt memory

3. TESTING (/pentest in sub-orchestrator mode — Phase 3-5)
   ├── Phase 3: Attack plan from recon + recommendations → user approves
   ├── Phase 4: pentester-orchestrator dispatches parallel executor batches:
   │   ├── pentester-executor agents (3-5 per batch, up to 15 concurrent, 100 max):
   │   │   ├── 40+ attack types across 11 categories
   │   │   ├── 3+ escalation levels per test (quickstart → cheat-sheet → patt-fetcher)
   │   │   └── Each produces writeup-style findings with inline visual evidence
   │   ├── DOM XSS scanner: auto for JS-heavy targets (React, Vue, Angular)
   │   ├── Conditional skills: /cve-testing, /source-code-scanning, /ai-threat-testing,
   │   │   /authenticating, /cloud-security, /container-security, /burp-suite
   │   └── /mobile-security: MobSF + Frida for mobile assets
   └── Phase 5: Aggregate findings, deduplicate, identify chains

4. IMPACT ESCALATION (/pentest Phase 5.5 — 3 rounds, early stop if no new findings)
   ├── Chain Lookup Table (AGENTS.md): 30+ "Bug A → try Bug B" mappings, each attempted
   ├── Round 1: Chain exploitation + privilege escalation on initial findings
   │   ├── SSRF→metadata→creds, XSS+CSRF→ATO, IDOR+email change→takeover
   │   └── user→admin, authenticated→unauthenticated, read→write/delete
   ├── Round 2: Scope widening + impact amplification using Round 1 results
   │   ├── Tier 3 vuln → test on Tier 1, subdomain A → subdomain B
   │   └── reflected→stored XSS, blind→full-read SSRF
   ├── Round 3: Deep chains + severity re-assessment on ALL findings
   │   ├── Multi-step chains from Rounds 1-2 results (new attack surface)
   │   └── CVSS adjusted for real environment (WAF, CSP, rate limiting)
   │       └── "Prove it or downgrade it": demonstrate claimed impact or lower severity
   └── Re-deploy executors in each round if escalation opens new attack surface

4b. FINDING VALIDATION (/pentest Phase 5.6 — after all 3 escalation rounds)
   ├── pentester-validator (per-finding, all in parallel — including escalated chains):
   │   ├── 5 anti-hallucination checks (CVSS, evidence, PoC, claims vs raw data, logs)
   │   ├── Inline evidence verification (screenshots embedded in writeup, not just referenced)
   │   ├── Chain evidence check: every intermediate step must have request/response
   │   └── Rejected findings → data/false-positives/ (preserved, excluded from report)
   └── Only validated findings proceed to submission or reporting

5. VALIDATION (/bounty-validation)
   ├── Never-Submit List: 17 conditional items (open redirect, CORS, self-XSS, etc.)
   │   └── Each blocked unless specific chain condition is demonstrated with evidence
   ├── Pre-submission gate (on top of Phase 5.6 validation):
   │   ├── OOS check (general + mobile-specific exclusions)
   │   ├── Business logic verification: is this "by design"?
   │   ├── Impact honesty: confirmed vs theoretical, environment defenses factored in
   │   ├── Developer reproducibility review (copy-pasteable, no contradictions)
   │   └── If claim lacks evidence → REJECT back to /pentest Phase 5.5
   └── AI disclosure section (mandatory)

6. RECORDING & SUBMISSION
   Record validated findings to hunt memory (cross-target intelligence for future engagements)
   Platform-ready reports (INTI_SEVERITY_NNN.md or H1_SEVERITY_NNN.md)
   with CVSS, CWE, steps to reproduce, full evidence chain, remediation
```

### Bug bounty rules (enforced)

- **No PoC = No Report** — Every finding needs a working exploit demo
- **Writeup-style evidence** — Every finding is a self-contained writeup: screenshots embedded inline (`![caption](evidence/screenshot.png)`), HTTP request/response as code blocks, PoC code inline. Validator rejects findings that only reference evidence as file paths.
- **Prove it or downgrade it** — Claimed impact must be demonstrated with evidence, or severity is lowered to confirmed-only impact
- **CVSS must be calculated** — Never guessed. Computed with Python/bash calculator, adjusted for real environment (WAF, CSP, rate limiting)
- **Business logic verification** — Verify findings are not "by design" before reporting
- **AI disclosure mandatory** — All reports include AI usage transparency
- **Out of scope** — CORS, missing headers, self-XSS, version disclosure, rate limiting (unless ATO), username enumeration

---

## DefectDojo Workflow

Full security assessment orchestrator driven by DefectDojo engagements. Analyzes scope (SAST, DAST, or both), invokes `/pentest` as testing engine, converts findings to DefectDojo format, and uploads via API. Also imports existing findings from other sources.

```bash
/defectdojo <product> [engagement]
```

### Workflow (Option 1: Active Testing)

```
1. AUTHENTICATE
   ├── Reads DEFECTDOJO_URL + DEFECTDOJO_TOKEN env vars
   └── Google Cloud IAP auth via Playwright (cookie cache with ~1h TTL)

2. SCOPE ANALYSIS (Phase 0 — determine test types from engagement)
   ├── Fetch engagement details from DefectDojo API
   ├── Fetch product metadata (name, description, prod_type)
   └── Determine test_types:
       ├── Repo URL or "code review" in description → SAST
       ├── Target URLs or "penetration" in description → DAST
       ├── Both present → SAST + DAST
       └── Unclear → ask user

3. TESTING (Phase 1 — invoke /pentest in sub-orchestrator mode)
   ├── /pentest receives scope contract with test_types from Phase 0
   ├── pentester-orchestrator dispatches parallel executor batches:
   │   ├── SAST: /source-code-scanning (OWASP Top 10, CWE Top 25, secrets)
   │   └── DAST: pentester-executor agents + dom-xss-scanner
   ├── Phase 4.5: pentester-validator (per-finding, inline evidence check)
   ├── Phase 5.5: Impact escalation + severity re-assessment
   └── Findings (writeup-style) land in outputs/defectdojo-{engagement}/processed/findings/

4. LOCAL REPORTS (Phase 2 — convert to DefectDojo format)
   ├── Convert /pentest findings to report.md with YAML frontmatter
   ├── DAST findings: title, cwe, cvssv3, severity, endpoint (valid URL)
   ├── SAST findings: title, cwe, cvssv3, severity, file_path, line, sast_source_*
   ├── Reproducibility review on all reports
   └── Present summary table → user reviews locally

5. UPLOAD (Phase 3 — only after explicit user approval)
   ├── Create "Manual Review" test in engagement
   ├── Import findings with CWE mapping and evidence
   ├── Findings created as active=false, verified=false (user reviews in DD)
   └── Deduplication against existing findings
```

### Other import options (no active testing)

| Source | How |
|--------|-----|
| Existing pentest findings | Option 2: Read from `outputs/{engagement}/findings/` |
| Scanner output | Option 3: Reimport nuclei, ZAP, Burp, Trivy, Semgrep, etc. (150+ formats) |
| Bug bounty findings | Option 4: Sync from `outputs/hackerone-*` or `outputs/intigriti-*` |
| CVE PoCs | Option 5: Import from `outputs/processed/cve-pocs/` |
| Source code scanning | Option 6: SAST findings with `static_finding=true`, `file_path`, `sast_source_*` fields |

### SAST fields for code review findings

```yaml
---
title: "SSRF via unvalidated URL input"
cwe: 918
cvssv3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N"
cvssv3_score: 7.5
severity: High
static_finding: true
dynamic_finding: false
file_path: "src/app/Domain/Action.php"
line: 42
sast_source_file_path: "src/app/Http/Controllers/ExampleController.php"
sast_source_line: 15
sast_source_object: "$request->input('url')"
sast_sink_object: "Http::get()"
---
```

---

## Pentest Skill

```bash
/pentest                          # Standalone: full 7-phase engagement
/hackerone → /pentest             # Sub-orchestrator: receives scope, runs Phase 3-5.5
/intigriti → /pentest             # Sub-orchestrator: receives scope + testing_requirements
/defectdojo → /pentest            # Sub-orchestrator: receives scope with SAST/DAST types
```

Canonical testing engine. Runs standalone or as sub-orchestrator invoked by `/hackerone`, `/intigriti`, and `/defectdojo`. 8 phases (0→1→2→3→4→4.5→5→5.5→6), 40+ attack types across 11 categories.

**Agent architecture**: `/pentest` delegates to `pentester-orchestrator` (pure manager, dispatches parallel batches) → `pentester-executor` agents (thin runners, 3+ escalation levels) → `pentester-validator` (per-finding, 5 mandatory checks). The orchestrator runs up to 15 concurrent executors and 100 total experiments before stopping.

| Category | Types |
|----------|-------|
| Injection | SQL, NoSQL, command, SSTI, XXE |
| Client-side | XSS (reflected/stored/DOM), CSRF, clickjacking, CORS, prototype pollution |
| Server-side | SSRF, HTTP smuggling, file upload, path traversal, deserialization, race conditions, cache poisoning, access control, business logic, host header, info disclosure, web cache deception |
| Authentication | JWT, OAuth, auth bypass, password attacks, default credentials |
| API | GraphQL, REST, WebSockets, Web LLM |
| Cloud/Containers | AWS, Azure, GCP, Docker, Kubernetes |
| Infrastructure | DNS, port scanning, MITM, SMB/NetBIOS |

Each attack type has PortSwigger Academy solutions, cheat sheets, and methodology docs in `.claude/skills/pentest/attacks/`.

---

## Other Skills

### Vendor Security Assessment

| Skill | Command | What it does |
|-------|---------|-------------|
| Vendor Assessment | `/vendor-security-assessment` | Non-intrusive third-party evaluation: DNS/infrastructure, supply chain (npm/pip audit, provenance, maintainer risk), SAST of open-source SDKs, compliance (SOC 2, ISO 27001), breach history. Produces executive report with scoring and approval verdict. |

### Offensive Testing

| Skill | Command | What it does |
|-------|---------|-------------|
| Source Code Scanning | `/source-code-scanning` | SAST: OWASP Top 10, CWE Top 25, secrets, dependency CVEs |
| AI/LLM Threats | `/ai-threat-testing` | OWASP LLM Top 10 — prompt injection, model extraction |
| Auth Testing | `/authenticating` | Signup/login automation, 2FA bypass, CAPTCHA, bot evasion |
| CVE Testing | `/cve-testing` | Known CVE testing with public exploits |
| CVE PoC Generator | `/cve-poc-generator` | Research CVE → Python PoC + report |
| OWASP Quick Test | `/common-appsec-patterns` | OWASP Top 10 quick-hit testing |
| Web3 Audit | `/web3-audit` | Smart contract security: 10 vuln classes, Foundry PoCs, Slither SAST |

### Infrastructure

| Skill | Command | What it does |
|-------|---------|-------------|
| Cloud Security | `/cloud-security` | AWS/Azure/GCP — IAM, storage, serverless, CIS Benchmarks |
| Container Security | `/container-security` | Docker/K8s — RBAC, pod security, escape testing |
| Mobile Security | `/mobile-security` | MobSF static + Frida dynamic (OWASP Mobile Top 10) |

### Reconnaissance (10 skills)

`/domain-assessment` `/web-application-mapping` `/subdomain-enumeration` `/dns-intelligence` `/certificate-transparency` `/domain-discovery` `/code-repository-intel` `/api-portal-discovery` `/job-posting-analysis` `/web-archive-analysis`

### Technology Detection (15 skills)

`/frontend-inferencer` `/backend-inferencer` `/http-fingerprinting` `/tls-certificate-analysis` `/cdn-waf-fingerprinter` `/cloud-infra-detector` `/devops-detector` `/third-party-detector` `/ip-attribution` `/security-posture-analyzer` `/html-content-analysis` `/javascript-dom-analysis` `/confidence-scorer` `/conflict-resolver` `/signal-correlator`

---

## Safety & Intelligence Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **Scope Checker** | `python3 tools/scope_checker.py check <target> --scope scope.json` | Deterministic in-scope/OOS validation. Anchored suffix matching (prevents `evil-target.com` matching `*.target.com`). CIDR support. OOS deny-first. |
| **Safety Rails** | `python3 tools/safety_rails.py preflight <METHOD> <URL>` | Circuit breaker (5 failures → 300s cooldown), rate limiter (10 rps recon / 2 rps active), safe method policy (PUT/DELETE blocked). |
| **Hunt Memory** | `python3 tools/hunt_memory.py suggest --tech "rails,pg"` | Cross-target pattern DB. Records what worked where, sorted by payout. "IDOR succeeded on Rails app A → suggest IDOR first on Rails app B." Also feeds bounty-forecast probability calibration. |
| **Autopilot** | `/autopilot --mode normal` | Autonomous surface-by-surface hunt loop. 3 modes: paranoid (pause per finding), normal (pause per surface), yolo (minimal stops). Integrates all safety tools. |

---

## Tool Integrations

| Tool | Integration | Used for |
|------|-------------|----------|
| **Burp Suite** | MCP (PortSwigger) | Active scanning, Collaborator OOB, traffic replay, sitemap |
| **HexStrike AI** | MCP server | 150+ tools: nmap, nuclei, sqlmap, gobuster, subfinder, etc. |
| **Playwright** | MCP | DOM XSS, auth testing, screenshot evidence, IAP auth |
| **Kali tools** | CLI | nmap, ffuf, sqlmap, nikto, gobuster, testssl, dig |
| **RecoX** | Script | Wayback Machine, Common Crawl, OTX, URLScan endpoint discovery |

---

## Agents

8 specialized agents in `.claude/agents/`, coordinated by shared rules in `agents/CLAUDE.md` (artifact discipline, credential loading, safety rails, scope checking). Each agent has explicit model routing: haiku for data retrieval, sonnet for testing/coordination, opus for the validator gate.

### Core testing pipeline

```
pentester-orchestrator → pentester-executor (×N parallel) → pentester-validator (×N parallel)
```

| Agent | Role | Tools |
|-------|------|-------|
| **pentester-orchestrator** | Pure manager. Plans, dispatches parallel executor batches (up to 15 concurrent, 100 max experiments), adapts based on results, loops until critical found or exhausted. Never executes directly. | Agent, Task* |
| **pentester-executor** | Thin runner. Receives missions with objectives + skill folder, loads attack docs, tries 3+ escalation levels, produces writeup-style findings with inline evidence. | Bash, Read, Write, Agent, Glob, Grep |
| **pentester-validator** | Anti-hallucination gate. 5 mandatory checks per finding: CVSS consistency, real evidence (visual for browser vulns), PoC syntax, claims vs raw data, log corroboration. Also verifies inline evidence in description.md (writeup format). | Bash, Read, Write, Glob, Grep |

### Support agents

| Agent | Purpose |
|-------|---------|
| **dom-xss-scanner** | Injects canary tokens through DOM sources, hooks sinks, detects taint flow via Playwright |
| **script-generator** | Generates parallelized, syntax-validated PoC scripts (>30 lines) |
| **patt-fetcher** | Fetches PayloadsAllTheThings payloads on demand when local payloads exhausted |
| **hackthebox** | Orchestrates HackTheBox challenges — VPN, login, solving, writeup |
| **skiller** | Automated skill directory creation and validation |

---

## Quick Start

```bash
# Clone
git clone https://github.com/CroquetteHunters/julius.git
cd julius

# Open in Claude Code
claude .

# Bug bounty (scope → recon → /pentest → validation → submission)
/intigriti <program_url>
/hackerone <scope_csv>

# Standalone pentest (full 7-phase engagement)
/pentest

# DefectDojo assessment (scope analysis → /pentest SAST/DAST → upload)
/defectdojo <product> <engagement>

# Vendor/SDK security evaluation (non-intrusive)
/vendor-security-assessment <vendor_name> [package_or_url]

# Source code review (standalone SAST)
/source-code-scanning
```

Skills auto-load from `.claude/skills/`. No additional configuration needed.

### Optional tool setup

```bash
# Kali tools (nmap, ffuf, sqlmap, nikto...)
bash tools/kali/install.sh

# Playwright (browser automation)
bash tools/playwright/install.sh
```

---

## Repository Structure

```
julius/
├── AGENTS.md                        # Passive knowledge base (always loaded)
├── CLAUDE.md                        # Repository instructions
├── .claude/
│   ├── skills/
│   │   ├── pentest/                 # Canonical testing engine (11 attack categories, 186 docs)
│   │   │   └── autopilot/           # Autonomous hunt loop (paranoid/normal/yolo)
│   │   ├── hackerone/               # HackerOne orchestrator (scope → recon → /pentest → submit)
│   │   ├── intigriti/               # Intigriti orchestrator (API scope → recon → /pentest → submit)
│   │   ├── defectdojo/              # DefectDojo orchestrator (scope analysis → /pentest → upload)
│   │   ├── vendor-security-assessment/ # Third-party vendor/SDK security evaluation
│   │   ├── offensive/               # SAST, CVE, auth, AI threats, Web3 audit (7 skills)
│   │   ├── recon/                   # Reconnaissance (10 skills)
│   │   ├── detection/               # Technology detection (15 skills)
│   │   ├── bounty/                  # Shared bounty pipelines: recon, validation, mobile (3 skills)
│   │   ├── infrastructure/          # Cloud, container, mobile (3 skills)
│   │   ├── tools/                   # Burp Suite, HexStrike (2 skills)
│   │   ├── reporting/               # Formatters and exporters (3 skills)
│   │   └── skiller/                 # Skill creation
│   ├── agents/                      # 8 specialized agents
│   │   ├── CLAUDE.md                # Shared rules (artifact discipline, credentials, safety rails, scope)
│   │   ├── pentester-orchestrator   # Pure manager: parallel batches, adaptation loops
│   │   ├── pentester-executor       # Thin runner: missions, escalation, writeup evidence
│   │   ├── pentester-validator      # 5-check anti-hallucination + inline evidence verification
│   │   └── reference/               # Output structure + test plan templates
│   └── tools/                       # env-reader.py (credential loading utility)
├── tools/                           # Safety tools + external installers
│   ├── scope_checker.py             # Deterministic scope validation
│   ├── safety_rails.py              # Circuit breaker + rate limiter + safe method policy
│   ├── hunt_memory.py               # Cross-target pattern DB (JSONL)
├── outputs/                         # Engagement outputs (gitignored)
└── CONTRIBUTING.md
```

---

## Contributing

```bash
/skiller    # Automated skill creation

# Or manually:
git checkout -b feature/skill-name
# feat(scope): description | fix(scope): description
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Upstream

Fork of [Transilience AI Community Tools](https://github.com/transilienceai/communitytools).

## License

MIT — See [LICENSE](LICENSE).

---

<div align="center">

**Built on [Transilience AI Community Tools](https://github.com/transilienceai/communitytools)**

[Report Issue](https://github.com/CroquetteHunters/julius/issues) | [Upstream](https://github.com/transilienceai/communitytools)

</div>
