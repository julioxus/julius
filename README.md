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
| **Bounty Intel dashboard** | Cloud Run web app — programs, findings, reports, submissions, forecast, hunt memory |
| **Vulnerability management** | DefectDojo orchestrator (scope analysis, SAST/DAST via /pentest, API import) |
| **Vendor assessment** | Non-intrusive third-party security evaluation (DNS, supply chain, SAST, compliance) |
| **Safety tools** | Deterministic scope checker, circuit breaker + rate limiter, cross-target hunt memory |
| **MCP server** | 36 `bounty_*` tools auto-loaded — programs, findings, reports, evidence, payouts, hunt memory, forecast |
| **Tool integrations** | Burp Suite MCP, HexStrike AI (150+ tools), Playwright, Kali toolset, RecoX |

---

## Bounty Intel — Operations Center

All operational data lives in a **PostgreSQL database** (Cloud SQL) served by a **FastAPI dashboard on Cloud Run**. A **MCP server** (`bounty-intel`) auto-loads 36 tools when Claude starts in this project, making all operations naturally available without explicit instructions. Skills and agents use these `bounty_*` MCP tools as the single source of truth — no local files.

**Dashboard URL**: `https://bounty-dashboard-887002731862.europe-west1.run.app`

### Features

| Feature | Description |
|---------|-------------|
| **Programs** | 40 tracked programs across Intigriti and HackerOne with company logos, platform links, and submission stats |
| **Findings** | 403 vulnerability findings with severity, CVSS, vuln class, PoC code/output, steps to reproduce |
| **Recon Data** | Structured recon per engagement: subdomains, endpoints, API specs, live hosts, summaries (26 engagements) |
| **Attack Surface** | Scope domains, subdomain/endpoint/host counts, coverage checklist (34 engagements) |
| **Evidence** | 3,204 cataloged evidence files with metadata and inline preview |
| **Report Manager** | Kanban pipeline: draft → ready → submitted → accepted/rejected. Live markdown editor with split preview |
| **Submissions** | Synced from platform APIs (Intigriti + HackerOne). Bidirectional linking with internal reports |
| **Activity** | 1,941 historical activity log entries from engagement missions |
| **Forecast** | Monte Carlo earnings forecast with AI-evaluated acceptance probability per submission |
| **Hunt Intel** | Cross-target pattern memory — what worked where, sorted by payout |

### Data flow

```
MCP Server (bounty-intel, 36 tools, auto-loaded via .mcp.json)
  │
  ├── bounty_save_finding()                     → findings table
  ├── bounty_create_report()                    → submission_reports table
  ├── bounty_record_hunt()                      → hunt_memory table
  ├── bounty_log_activity()                     → activity_log table
  ├── bounty_upload_evidence()                  → evidence_files + GCS
  ├── bounty_update_engagement(recon_data=...)  → recon data (JSONB)
  └── bounty_update_engagement(attack_surface=...) → attack surface (JSONB)
  
Skills (/pentest, /intigriti, /hackerone)
  │
  └── Call bounty_* MCP tools directly (no imports needed)
  
Platform Sync (Intigriti API, HackerOne API)
  │
  └── bounty_sync(source="all")       → submissions + payouts + dispositions
  
Queries (natural language → MCP tool discovery)
  │
  ├── bounty_get_findings(program_id=...)       → vulnerability list
  ├── bounty_search_findings(query="SSRF")      → text search
  ├── bounty_get_program(program_id)            → scope, OOS, tech stack
  ├── bounty_get_recon(program_id)              → structured recon data
  ├── bounty_get_payouts(program_id=...)        → earnings data
  ├── bounty_suggest_attacks(tech_stack=[...])  → hunt intelligence
  └── bounty_forecast()                         → earnings projection

Dashboard (web UI, 12 pages)
  │
  ├── Programs → Findings → Reports → Submissions (full drill-down)
  ├── Program detail: 6 tabs (Findings, Building Blocks, Reports, Submissions, Recon, Attack Surface)
  ├── Finding detail: description, PoC, evidence files with inline preview
  ├── Report editor with platform linking
  └── Forecast with monthly breakdown and scenario analysis
```

### Infrastructure

| Component | Details |
|-----------|---------|
| **Cloud SQL** | PostgreSQL, europe-west1, 12 tables |
| **Cloud Run** | bounty-dashboard, Google OAuth + API key auth |
| **GCS** | julius-bounty-evidence (binary evidence storage) |
| **Secret Manager** | DB password, API keys, OAuth creds |

### Security

- Google OAuth2 authentication (single allowed email)
- API key auth on all `/api/v1/` endpoints (constant-time comparison)
- Markdown rendering sanitized with `nh3` (prevents stored XSS)
- Pydantic schemas on all PATCH endpoints (prevents mass assignment)
- Session cookies: `httponly=True`, `secure=True`, `samesite="lax"`
- No CORS (server-rendered, no separate frontend)

---

## Bug Bounty Workflow

Two entry points depending on platform:

```bash
/intigriti <program_url_or_pdf>    # Intigriti programs (API scope fetch, tier prioritization)
/hackerone <program_url_or_csv>    # HackerOne programs (CSV scope parsing)
```

### What happens when you run `/intigriti` or `/hackerone`

```
1. SCOPE PARSING (/intigriti or /hackerone)
   Parse program scope → extract assets, tiers, bounty table, OOS list
   Register program + engagement in Bounty Intel DB
   Generate scope.json → deterministic scope enforcement (tools/scope_checker.py)
   Mobile assets → /mobile-app-acquisition

2. RECONNAISSANCE (/bounty-recon — recon only, no agent deployment)
   ├── Bounty-driven prioritization: map vuln types → bounty amounts, rank by payout
   ├── Hunt memory query: cross-target intelligence (api.suggest_attacks())
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

3. TESTING (/pentest in sub-orchestrator mode — Phase 3-5)
   ├── Phase 3: Attack plan from recon + recommendations → user approves
   ├── Phase 4: pentester-orchestrator dispatches parallel executor batches
   │   ├── pentester-executor agents (3-5 per batch, up to 15 concurrent)
   │   ├── Each finding → bounty_save_finding() via MCP
   │   └── DOM XSS scanner, conditional skills (/cve-testing, /source-code-scanning, etc.)
   └── Phase 5: Aggregate findings, deduplicate, identify chains

4. IMPACT ESCALATION (/pentest Phase 5.5 — 3 rounds)
   ├── Chain Lookup Table (AGENTS.md): 30+ "Bug A → try Bug B" mappings
   ├── Round 1: Chain exploitation + privilege escalation
   ├── Round 2: Scope widening + impact amplification
   └── Round 3: Deep chains + severity re-assessment

5. VALIDATION (/bounty-validation)
   ├── pentester-validator: 5 anti-hallucination checks per finding
   ├── Never-Submit List: 17 conditional items
   ├── Pre-submission gate: OOS, business logic, impact honesty
   └── Validated findings → bounty_create_report() + bounty_record_hunt()

6. SUBMISSION
   Reports reviewed in Bounty Intel dashboard (Report Manager)
   Platform linking via submission ID → bidirectional sync
   Hunt memory updated for cross-target intelligence
```

### Bug bounty rules (enforced)

- **No PoC = No Report** — Every finding needs a working exploit demo
- **Writeup-style evidence** — Screenshots inline, HTTP request/response as code blocks, PoC code inline
- **Prove it or downgrade it** — Claimed impact must be demonstrated
- **CVSS must be calculated** — Never guessed, computed with calculator
- **AI disclosure mandatory** — All reports include AI usage transparency

---

## DefectDojo Workflow

Full security assessment orchestrator driven by DefectDojo engagements. Only workflow that maintains local report files (reviewed before DD API upload).

```bash
/defectdojo <product> [engagement]
```

```
1. SCOPE ANALYSIS → Determine SAST/DAST from engagement metadata
2. TESTING → /pentest sub-orchestrator (findings in local outputs/)
3. LOCAL REPORTS → Convert to report.md with YAML frontmatter (user reviews locally)
4. UPLOAD → Create findings in DefectDojo API after explicit approval
```

---

## Pentest Skill

```bash
/pentest                          # Standalone: full 7-phase engagement
/hackerone → /pentest             # Sub-orchestrator: receives scope, runs Phase 3-5.5
/intigriti → /pentest             # Sub-orchestrator: receives scope + testing_requirements
/defectdojo → /pentest            # Sub-orchestrator: receives scope with SAST/DAST types
```

Canonical testing engine. 8 phases, 40+ attack types across 11 categories.

| Category | Types |
|----------|-------|
| Injection | SQL, NoSQL, command, SSTI, XXE |
| Client-side | XSS (reflected/stored/DOM), CSRF, clickjacking, CORS, prototype pollution |
| Server-side | SSRF, HTTP smuggling, file upload, path traversal, deserialization, race conditions, cache poisoning, access control, business logic, host header, info disclosure, web cache deception |
| Authentication | JWT, OAuth, auth bypass, password attacks, default credentials |
| API | GraphQL, REST, WebSockets, Web LLM |
| Cloud/Containers | AWS, Azure, GCP, Docker, Kubernetes |
| Infrastructure | DNS, port scanning, MITM, SMB/NetBIOS |

---

## Other Skills

### Vendor Security Assessment

| Skill | Command | What it does |
|-------|---------|-------------|
| Vendor Assessment | `/vendor-security-assessment` | Non-intrusive third-party evaluation: DNS/infrastructure, supply chain, SAST, compliance, breach history. Executive report with scoring and approval verdict. |

### Offensive Testing

| Skill | Command | What it does |
|-------|---------|-------------|
| Source Code Scanning | `/source-code-scanning` | SAST: OWASP Top 10, CWE Top 25, secrets, dependency CVEs |
| AI/LLM Threats | `/ai-threat-testing` | OWASP LLM Top 10 — prompt injection, model extraction |
| Auth Testing | `/authenticating` | Signup/login automation, 2FA bypass, CAPTCHA, bot evasion |
| CVE Testing | `/cve-testing` | Known CVE testing with public exploits |
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
| **Scope Checker** | `python3 tools/scope_checker.py check <target> --scope scope.json` | Deterministic in-scope/OOS validation. Anchored suffix matching, CIDR support, OOS deny-first. |
| **Safety Rails** | `python3 tools/safety_rails.py preflight <METHOD> <URL>` | Circuit breaker (5 failures → 300s cooldown), rate limiter (10 rps recon / 2 rps active), safe method policy. |
| **Hunt Memory** | `bounty_suggest_attacks(tech_stack=[...])` | Cross-target pattern DB in PostgreSQL. Records what worked where, sorted by payout. |
| **Autopilot** | `/autopilot --mode normal` | Autonomous surface-by-surface hunt loop. 3 modes: paranoid, normal, yolo. |

---

## Agents

8 specialized agents in `.claude/agents/`, coordinated by shared rules in `agents/CLAUDE.md` (DB persistence, artifact discipline, credential loading, safety rails, scope checking).

### Core testing pipeline

```
pentester-orchestrator → pentester-executor (×N parallel) → pentester-validator (×N parallel)
```

| Agent | Role |
|-------|------|
| **pentester-orchestrator** | Pure manager. Plans, dispatches parallel executor batches, adapts. Never executes directly. |
| **pentester-executor** | Thin runner. Missions + skill folder, 3+ escalation levels, writeup-style findings. Persists via `bounty_save_finding()` MCP tool. |
| **pentester-validator** | 5 mandatory anti-hallucination checks per finding. |
| **dom-xss-scanner** | Canary tokens through DOM sources, hooks sinks, detects taint flow via Playwright. |
| **script-generator** | Parallelized, syntax-validated PoC scripts. |
| **patt-fetcher** | PayloadsAllTheThings payloads on demand. |
| **hackthebox** | HackTheBox challenge automation. |
| **skiller** | Skill directory creation and validation. |

---

## Repository Structure

```
julius/
├── AGENTS.md                        # Passive knowledge base (always loaded)
├── CLAUDE.md                        # Repository instructions
├── .mcp.json                        # MCP server auto-start config
├── bounty_intel/                    # Bounty Intel ops center (Cloud Run app)
│   ├── mcp_server.py                # MCP server (36 tools, FastMCP)
│   ├── db.py                        # SQLAlchemy models (12 tables)
│   ├── service.py                   # Database service layer (CRUD)
│   ├── client.py                    # HTTP client (BountyIntelClient, used by MCP server)
│   ├── config.py                    # Environment config (pydantic-settings)
│   ├── cli.py                       # CLI: migrate, sync, forecast, serve, mcp, stats
│   ├── web/                         # FastAPI dashboard (12 pages)
│   │   ├── app.py                   # Routes, OAuth, evidence preview
│   │   ├── api.py                   # REST API (/api/v1/* — recon, surface, evidence, CRUD)
│   │   ├── auth.py                  # Google OAuth2 + session middleware
│   │   └── templates/               # Jinja2 + HTMX + TailwindCSS
│   ├── sync/                        # Platform API sync
│   │   ├── hackerone.py             # H1 REST API → reports + bounties + dispositions
│   │   ├── intigriti.py             # BFF API → submissions + logos + payouts
│   │   └── delta.py                 # Watermark coordinator
│   ├── forecast/                    # Monte Carlo earnings forecast
│   │   ├── engine.py                # Scoring + scenarios
│   │   └── fx.py                    # ECB exchange rates
│   └── migration/                   # Schema + data import
│       ├── schema.py                # Table creation + column migrations
│       └── import_existing.py       # Full import: recon, evidence, findings, activity logs
├── .claude/
│   ├── skills/                      # 50+ skills
│   │   ├── pentest/                 # Canonical testing engine (11 categories, 186 docs)
│   │   │   └── autopilot/           # Autonomous hunt loop
│   │   ├── hackerone/               # HackerOne orchestrator
│   │   ├── intigriti/               # Intigriti orchestrator
│   │   ├── defectdojo/              # DefectDojo orchestrator
│   │   ├── vendor-security-assessment/
│   │   ├── offensive/               # SAST, CVE, auth, AI threats, Web3 (7 skills)
│   │   ├── recon/                   # Reconnaissance (10 skills)
│   │   ├── detection/               # Technology detection (15 skills)
│   │   ├── bounty/                  # Shared pipelines: recon, validation, mobile
│   │   ├── infrastructure/          # Cloud, container, mobile
│   │   ├── tools/                   # Burp Suite, HexStrike
│   │   ├── reporting/               # Formatters and exporters
│   │   └── skiller/                 # Skill creation
│   ├── agents/                      # 8 specialized agents
│   │   ├── CLAUDE.md                # Shared rules (DB persistence, safety rails, scope)
│   │   ├── pentester-orchestrator.md
│   │   ├── pentester-executor.md
│   │   ├── pentester-validator.md
│   │   └── reference/
│   └── tools/                       # env-reader.py
├── tools/                           # Safety tools + installers
│   ├── scope_checker.py             # Deterministic scope validation
│   └── safety_rails.py              # Circuit breaker + rate limiter
├── Dockerfile                       # Cloud Run deployment
├── pyproject.toml                   # Python dependencies
└── CONTRIBUTING.md
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/CroquetteHunters/julius.git
cd julius

# Open in Claude Code
claude .

# Bug bounty
/intigriti <program_url>
/hackerone <scope_csv>

# Standalone pentest
/pentest

# DefectDojo assessment
/defectdojo <product> <engagement>

# Vendor evaluation
/vendor-security-assessment <vendor_name>
```

### Environment setup

```bash
# .env — Required for Bounty Intel API access (MCP server reads these)
BOUNTY_INTEL_API_URL=https://bounty-dashboard-887002731862.europe-west1.run.app
BOUNTY_INTEL_API_KEY=<your-api-key>

# Platform credentials (for sync)
HACKERONE_USERNAME=<username>
HACKERONE_API_TOKEN=<token>

# Install dependencies (includes MCP server)
pip install -e .

# Bounty Intel CLI
python -m bounty_intel migrate     # Create/update schema
python -m bounty_intel sync        # Sync submissions from platforms
python -m bounty_intel forecast    # Compute earnings forecast
python -m bounty_intel serve       # Run dashboard locally
python -m bounty_intel mcp         # Start MCP server (stdio transport)
python -m bounty_intel stats       # DB inventory

# Optional tools
bash tools/kali/install.sh        # Kali tools
bash tools/playwright/install.sh   # Browser automation (needed for Intigriti sync)
```

### MCP Server

The `bounty-intel` MCP server starts automatically when Claude Code opens this project (configured in `.mcp.json`). It exposes 36 tools covering the full Bounty Intel API:

| Domain | Tools | Examples |
|--------|-------|---------|
| Programs (3) | list, get detail, upsert | `bounty_list_programs(platform="hackerone")` |
| Engagements (4) | list, get, create, update | `bounty_list_engagements(status="active")` |
| Recon (2) | get recon, get attack surface | `bounty_get_recon(program_id=5)` |
| Findings (7) | list, get, search, save, update, evidence, delete | `bounty_search_findings("SSRF")` |
| Reports (7) | list, get, create, update, delete, submit, evidence | `bounty_get_report(report_id=12)` |
| Submissions (1) | list with filters | `bounty_get_submissions(disposition="triaged")` |
| Payouts (1) | list with filters | `bounty_get_payouts(program_id=5)` |
| Hunt Memory (3) | record, suggest, query | `bounty_suggest_attacks(tech_stack=["react"])` |
| Evidence (2) | upload, get signed URL | `bounty_upload_evidence(finding_id=42, ...)` |
| Activity (2) | log, list | `bounty_get_activity(engagement_id=10)` |
| AI Eval (1) | save evaluation | `bounty_save_ai_evaluation(submission_id=1, ...)` |
| Ops (3) | sync, forecast, stats | `bounty_forecast()` |

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
