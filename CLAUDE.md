# Community Security Tools Repository

This repo provides Claude Code skills and agents for security testing, bug bounty hunting, and pentesting workflows.

## Architecture: AGENTS.md + Skills + Bounty Intel DB

**IMPORTANT**: Based on Vercel research, this repository uses a hybrid architecture:

**AGENTS.md** (`/AGENTS.md` in root):
- **Passive context** - Always loaded, available in every conversation turn
- **100% pass rate** in Vercel agent evals (vs 53-79% for skills alone)
- Contains compressed security testing knowledge (80% reduction: ~40KB → ~8KB)
- Pipe-delimited indexing: `Vulnerability|Payloads|Details|Reference`
- "Prefer retrieval-led reasoning" directive for security tasks
- Includes: Vulnerability payloads, methodologies (PTES, OWASP, MITRE), CVSS scoring, PoC standards, vulnerability chain lookup table (30+ chains for Phase 5.5 escalation)

**Skills** (`.claude/skills/`):
- **User-triggered workflows** - Invoked explicitly with `/skill-name`
- Orchestration and coordination (parallel agents, aggregation, reporting)
- Complex multi-step processes with checkpointing
- User preference gathering and decision workflows
- Examples: `/pentest`, `/hackerone`, `/authenticating`

**Bounty Intel** (`bounty_intel/`):
- **PostgreSQL database** (Cloud SQL) — single source of truth for all engagement data
- **Web dashboard** (Cloud Run) — operations center with recon, findings, reports, submissions
- **REST API** — programmatic access for skills and agents
- **Sync engine** — auto-syncs submissions from HackerOne and Intigriti APIs
- **Forecast engine** — earnings projections with AI evaluation

**Why this works better**:
- Eliminates decision-making friction (no "should I load the skill?" question)
- Consistent availability (AGENTS.md always present, skills loaded on-demand)
- No sequencing problems (passive knowledge + explicit workflows)
- Faster context access (no async skill loading delay)
- All operational data centralized in DB (no scattered local files)

**Reference**: [Vercel Blog - AGENTS.md outperforms skills in our agent evals](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals)

## Repository Structure

- `AGENTS.md` - **Passive security testing knowledge base** (always loaded)
- `bounty_intel/` - **Bounty Intelligence System** (DB-backed ops center):
    - `db.py` - 12 SQLAlchemy models (programs, engagements, findings, submissions, payouts, evidence, etc.)
    - `service.py` - Database service layer (CRUD for all entities)
    - `client.py` - HTTP client for skills/agents (`BountyIntelClient`)
    - `config.py` - Environment config (DB, GCS, OAuth, API keys)
    - `cli.py` - CLI: `python -m bounty_intel {migrate|sync|forecast|serve|stats}`
    - `sync/` - Platform sync (HackerOne delta, Intigriti auto-browser-login)
    - `forecast/` - Earnings projection engine
    - `migration/` - Schema creation + data import from legacy files
    - `web/` - FastAPI dashboard (12 pages, HTMX, TailwindCSS, Google OAuth)
        - `app.py` - Routes + template rendering
        - `api.py` - REST API endpoints (all CRUD + sync + forecast)
        - `templates/` - Jinja2 templates (dashboard, programs, findings, reports, etc.)
- `.claude/skills/` - **Workflow orchestration skills** (user-triggered):
  - **Orchestrators** (top-level for slash command discovery):
    - `pentest/` - Canonical testing engine (11 attack categories, 186 docs)
    - `pentest/autopilot/` - Autonomous hunt loop (paranoid/normal/yolo modes)
    - `hackerone/` - HackerOne bug bounty orchestrator
    - `intigriti/` - Intigriti bug bounty orchestrator
    - `defectdojo/` - DefectDojo vulnerability management orchestrator
    - `vendor-security-assessment/` - Third-party vendor/SDK security evaluation
  - **Categories** (supporting skills):
    - `offensive/` - Targeted testing (SAST, CVE, auth, AI threats, Web3 audit)
    - `recon/` - Reconnaissance (10 skills)
    - `detection/` - Technology detection (15 skills)
    - `bounty/` - Shared bounty pipelines (recon, validation, mobile)
    - `infrastructure/` - Cloud, container, mobile security
    - `tools/` - Burp Suite, HexStrike integrations
    - `reporting/` - Evidence formatting and report export
    - `skiller/` - Skill creation and management
- `.claude/agents/` - Reusable specialized agents (orchestrator, executor, validator, DOM XSS, script-gen, etc.)
    - `CLAUDE.md` - Shared agent rules (artifact discipline, credential loading, safety rails, scope checking)
    - `pentester-orchestrator.md` - Pure manager: plans, dispatches parallel executor batches, adapts
    - `pentester-executor.md` - Thin runner: receives missions, loads skills, escalates, returns results
    - `pentester-validator.md` - Finding validator: 5 mandatory checks including real evidence verification
    - `reference/` - Agent output structure and test plan templates
- `tools/` - Shared Python tools and external tool installers:
    - `scope_checker.py` - Deterministic scope validation (anchored suffix matching, CIDR, OOS deny-first)
    - `safety_rails.py` - Circuit breaker + rate limiter + safe method policy
    - Installers: Playwright, Kali, RecoX
- `templates/` - Skill templates

## Bounty Intel API — Source of Truth

**CRITICAL**: When asked about bug bounty programs, engagements, findings, recon data, attack surface, submissions, or any engagement context, **always query the Bounty Intel API first**. This is the single source of truth for all operational data. The legacy `outputs/` directory has been removed — all data lives in the database.

**How to access** — Use `bounty_*` MCP tools (auto-loaded via `.mcp.json`):
- `bounty_list_programs(platform="hackerone")` — list programs
- `bounty_get_program(program_id)` — full detail with scope/OOS
- `bounty_get_recon(program_id)` — subdomains, endpoints, API specs
- `bounty_get_attack_surface(program_id)` — scope coverage stats
- `bounty_get_findings(program_id=...)` — list findings
- `bounty_get_finding(finding_id)` — full finding detail
- `bounty_search_findings(query="SSRF")` — text search across findings
- `bounty_save_finding(program_id=..., title=..., ...)` — save new finding
- `bounty_get_finding_evidence(finding_id)` — PoC files, HTTP logs
- `bounty_upload_evidence(finding_id, filename, local_path=...)` — attach evidence
- `bounty_get_submissions(program_id=...)` — platform-synced status
- `bounty_get_payouts(program_id=...)` — bounty payments
- `bounty_suggest_attacks(tech_stack=["react", "graphql"])` — attack suggestions
- `bounty_forecast()` — earnings projection
- `bounty_get_stats()` — DB summary

**Fallback** (for Python scripts): `from bounty_intel.client import BountyIntelClient`

**Available endpoints**: `/api/v1/programs`, `/programs/{id}/detail`, `/programs/{id}/recon`, `/programs/{id}/attack-surface`, `/engagements`, `/findings`, `/findings/{id}`, `/findings/search`, `/findings/{id}/evidence`, `/findings/{id}/evidence/upload`, `/evidence/{id}/url`, `/submissions`, `/payouts`, `/reports`, `/reports/{id}`, `/reports/{id}/evidence`, `/hunt`, `/hunt/suggest`, `/forecast`, `/stats`, `/sync`, `/activity`, `/evaluations`

**Dashboard**: https://bounty-dashboard-887002731862.europe-west1.run.app

**DB contents** (40 programs, 403 findings, 3,204 evidence files, 1,941 activity logs, recon data for 26 engagements, attack surface for 34 engagements)

**Infrastructure**: Cloud SQL (europe-west1), Cloud Run, GCS (julius-bounty-evidence), Secret Manager, Google OAuth

Do NOT rely on memory files or local directories for engagement state — always check the API for current data.

## Git Conventions

IMPORTANT: Always follow these git workflows:

**Branches:**
- Create from main: `feature/skill-name`, `bugfix/description`, `docs/update`
- NEVER commit directly to main

**Commits:**
- Format: `type(scope): description`
- Types: feat, fix, docs, refactor, test, chore
- Example: `feat(pentest): add JWT testing agent`

**Pull Requests:**
- MUST link to issue: "Fixes #123" or "Closes #123"
- Create issue BEFORE starting work
- Use PR template in `.github/pull_request_template.md`

## Common Workflows

**Contributing a new skill (Recommended - Using /skiller):**
```bash
# Easy way: Use the /skiller slash command
/skiller
# Then select: CREATE → provide details → choose GitHub workflow
# This automates: issue creation, branch, skill generation, validation, commit, PR
```

**Contributing a new skill (Manual):**
```bash
# 1. Create issue first (using gh or GitHub UI)
gh issue create --title "Add skill: X" --body "Description..."

# 2. Create branch
git checkout -b feature/skill-name

# 3. Use skill scaffolding tools in templates/ or /skiller command
# 4. Commit with conventional format
# 5. Push and create PR linking to issue
```

**Testing changes:**
```bash
# The skills are used directly by Claude Code
# Test by invoking the skill in a Claude session
```

## Output Standards

**CRITICAL**: All skills write results to the Bounty Intel database via `BountyIntelClient`, not to local files.

See `.claude/OUTPUT_STANDARDS.md` for format specification.

**Workflow**: Skill runs → saves findings/evidence to DB via API → dashboard displays results → user reviews and submits

**Data flow**:
- **Reconnaissance**: `db.update_engagement(id, recon_data=...)` + `db.update_engagement(id, attack_surface=...)`
- **Vulnerability testing**: `db.save_finding(program_id=..., title=..., poc_code=..., ...)` + evidence files
- **Bug bounty**: `db.create_report(...)` → validate → `db.mark_report_submitted(...)`

## Critical Rules

**AGENTS.md vs Skills Decision** (for contributors):

**Add to AGENTS.md when:**
- General framework/library knowledge (APIs, patterns)
- Frequently referenced information (payloads, scoring, mappings)
- Methodology frameworks (PTES, OWASP, MITRE ATT&CK)
- Quick reference data that doesn't require user action
- Content that benefits from always being available

**Create a Skill when:**
- Multi-step workflow orchestration (parallel agents, aggregation)
- User-triggered explicit actions (/pentest, /hackerone)
- Complex processes with checkpointing
- User preference gathering (AskUserQuestion patterns)
- Task coordination requiring state management

**Compression Guidelines**:
- Aim for 80% reduction in AGENTS.md content
- Use pipe-delimited indexing: `Topic|Key Info|Details|Reference Path`
- Keep critical info inline, link to detailed documentation
- Example: `SQL Injection|Union: ' UNION SELECT|Time: SLEEP(5)|.claude/skills/pentest/attacks/injection/sql-injection/`

**Security Testing Rules**:
- All testing MUST be authorized and legal
- Never perform destructive operations
- Always document findings using standardized formats (see OUTPUT_STANDARDS.md)
- Follow responsible disclosure practices
- Generate complete evidence (screenshots, HTTP captures, videos)
- Create actionable reports with remediation guidance

**Skill Structure**: Requirements are in `.claude/skills/CLAUDE.md` (auto-loaded when working in that directory)
