# Community Security Tools Repository

This repo provides Claude Code skills and agents for security testing, bug bounty hunting, and pentesting workflows.

## Architecture

Hybrid: **AGENTS.md** (passive, always loaded — payloads, methodologies, chain tables) + **Skills** (user-triggered workflows — `/pentest`, `/hackerone`, etc.) + **Bounty Intel DB** (PostgreSQL source of truth — programs, findings, evidence, submissions).

## Repository Structure

Key directories (explore with `glob`/`ls` for full detail):
- `AGENTS.md` — Passive security knowledge (payloads, chains, methodologies)
- `bounty_intel/` — DB-backed ops center: `db.py` (models), `service.py` (CRUD), `client.py` (HTTP client), `web/` (FastAPI dashboard), `sync/`, `forecast/`
- `.claude/skills/` — Orchestrators: `pentest/`, `hackerone/`, `intigriti/`, `defectdojo/`, `vendor-security-assessment/` | Categories: `offensive/`, `recon/`, `detection/`, `bounty/`, `infrastructure/`, `tools/`, `reporting/`
- `.claude/agents/` — Specialized agents: orchestrator, executor, validator, DOM XSS, script-gen
- `tools/` — `scope_checker.py`, `safety_rails.py`, installers

## Bounty Intel API — Source of Truth

**CRITICAL**: Always query `bounty_*` MCP tools first for any engagement context. This is the single source of truth — never rely on memory or local files.

**Access**: `bounty_*` MCP tools (auto-loaded via `.mcp.json`). Pattern: `bounty_{list|get|save|search|update|upload}_{programs|findings|evidence|submissions|payouts|reports|recon|attack_surface}`. Also: `bounty_suggest_attacks()`, `bounty_forecast()`, `bounty_get_stats()`.

**Fallback**: `from bounty_intel.client import BountyIntelClient`

**Dashboard**: https://bounty-dashboard-887002731862.europe-west1.run.app | **DB stats**: use `bounty_get_stats()` dynamically

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

**New skill**: `/skiller` (recommended) or manual: `gh issue create` → `git checkout -b feature/skill-name` → build → commit → PR linking issue.

**Output**: All results go to Bounty Intel DB via API, not local files. See `.claude/OUTPUT_STANDARDS.md`.

## Critical Rules

**AGENTS.md vs Skills**: Always-available reference data → AGENTS.md. Multi-step workflows requiring user action → Skill. Compress at 80% using pipe-delimited format.

**Security**: Authorized testing only | No destructive ops | Standardized findings (OUTPUT_STANDARDS.md) | Responsible disclosure | Complete evidence chain.

**Skill structure**: `.claude/skills/CLAUDE.md` (auto-loaded in that directory).

## Token Budget Discipline

Always-loaded files (CLAUDE.md + AGENTS.md + MEMORY.md) MUST stay under **15KB combined** (~4K tokens). Rules:
- **CLAUDE.md**: Max 4KB. Directives only — no file trees, no endpoint lists, no stats. Use `glob`/`bounty_get_stats()` dynamically.
- **AGENTS.md**: Max 10KB. Payloads, chains, methodologies. No duplicating CLAUDE.md content. Reference skill paths, don't inline docs.
- **MEMORY.md**: Max 25 entries. Sections: Feedback, User, Active engagements, Completed/reference. Archive to `memory/archived/` when CLOSED/DEPRIORITIZED/ABANDONED. One-line entries under 120 chars.
- **Before adding content**: Ask "will this be read every turn?" If not, it belongs in a skill doc, memory file, or the DB — not in always-loaded files.
- **Quarterly review**: Prune stale entries, verify archived memories are still in `archived/`, check combined size with `wc -c`.
