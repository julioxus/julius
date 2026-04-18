# /bounty-forecast - Bug Bounty Earnings Analysis & AI Forecast

Analyzes Intigriti + HackerOne + Bugcrowd submissions, evaluates each pending report from a triager's perspective using engagement context from the database, and recommends the best programs to focus on.

**Source of truth rule**: The platform dashboards are authoritative. Local DB `reports.status` and `submissions.disposition` can drift. Every run MUST re-sync all three platforms and reconcile local state from platform state — never the other way around.

**Scope rule — bug bounty platforms only**: This forecast covers ONLY Intigriti, HackerOne, and Bugcrowd submissions. DefectDojo is NOT a bug bounty platform and MUST NEVER be included in the forecast.
- Do NOT sync, ingest, or create programs from `outputs/defectdojo-*/` directories.
- Do NOT call `bounty_upsert_program(platform="defectdojo", ...)` or any variant — the skill does not accept "defectdojo" as a platform and never will.
- If you encounter a `custom`-platform program that looks DefectDojo-related (handle/company mentions `dd-*`, `defectdojo`, `dojo`, `REDACTED`, `freepik`), flag it to the user and offer to delete it — do not include it in EV calculations.
- DefectDojo findings/reports/evidence live exclusively in `outputs/defectdojo-{engagement}/` and are uploaded to the real DefectDojo instance (`defectdojo.internal`), never to bounty-intel. See `.claude/skills/defectdojo/SKILL.md` and `.claude/agents/CLAUDE.md` (exception rule, line 33).

## Trigger
When user says: "bounty forecast", "bounty analysis", "how much money", "intigriti earnings", "intigriti forecast", "hackerone earnings", "hackerone forecast", "bugcrowd earnings", "bugcrowd forecast", "all bounties", "combined forecast", "analyze my bounties", "which programs should I focus on"

## Requirements & Credentials

### HackerOne (API token — automatic, no user action needed)
- Credentials: `HACKERONE_USERNAME` + `HACKERONE_API_TOKEN` in `.env` and Secret Manager
- Used by: `bounty_sync(source="hackerone")` — fully automatic delta sync

### Intigriti (PAT + session cookie)
Two auth mechanisms, each used for different data:

**PAT** (`INTIGRITI_PAT` in `.env`) — for program metadata:
- External API: `api.intigriti.com/external/researcher/v1/programs`
- Used for: program states (open/suspended) — always available, no expiry
- Auth: `Authorization: Bearer $INTIGRITI_PAT`

**Session cookie** — for submission data:
- Core API: `app.intigriti.com/api/core/researcher/submissions`
- Used for: submissions, submission detail (PoC body, payouts)
- Cookie sources (priority order):
  1. `INTIGRITI_COOKIE` env var
  2. Cached cookie at `~/.intigriti/session_cookie.txt` (if still valid)
  3. Playwright browser login (local only — auto-launches browser, user logs in)
- **If cookie is expired**: the sync returns `error: no_cookie` for submissions, but program states still sync via PAT. Ask the user to either:
  - Sync from the dashboard (which has an active session)
  - Run `! python -m bounty_intel sync --source intigriti` to trigger Playwright login
  - Provide a fresh cookie manually

### Bugcrowd (session cookies — researcher dashboard)
Bugcrowd's public `api.bugcrowd.com` is **program-owner only**; researchers do not get API tokens. We authenticate against `bugcrowd.com/submissions.json` using session cookies.

- Cookie sources (priority order):
  1. `BUGCROWD_COOKIES_JSON` env var (JSON dict)
  2. Cached cookies at `~/.bugcrowd/session_cookies.json` (validated against `session_meta.json` expiry)
  3. DB-persisted cookies (pushed to server via `/admin/bugcrowd-cookies`)
  4. Playwright browser login (local only — auto-launches browser)
- **If cookies are expired**: sync returns `error: no_cookie`. Auto-fix via Playwright (see Step 1).
- **List-view limitation**: The researcher endpoint does NOT include severity or bounty amount per submission. The sync records `substate` → disposition correctly (including `nue`, `not_reproducible`, `not_applicable`, `duplicate`, `resolved`), but severity defaults to Medium and bounty to 0. Forecast uses historical `payouts` for EV where available.

### Bounty Intel API
- `BOUNTY_INTEL_API_KEY` in `.env` — for admin endpoints (refresh statuses, backfill)
- Dashboard: https://bounty-dashboard-887002731862.europe-west1.run.app

## Pipeline

### Step 1: Sync platform data + refresh program statuses

**MANDATORY before any forecast.** Sync all three platforms with automatic cookie refresh and refresh derived data:

1. **Initial sync attempt**: `bounty_sync(source="all")` — delta sync HackerOne + Intigriti + Bugcrowd (NEVER DefectDojo; `source` only accepts `hackerone|intigriti|bugcrowd|all`)
2. **Auto-fix Intigriti cookie issues**:
   - HackerOne: should show `upserted: N` (automatic via API token)
   - Intigriti: if `error: no_cookie`, **AUTOMATICALLY execute**:
     ```bash
     # Step 2a: Generate fresh cookie via Playwright
     cd .claude/skills/intigriti/tools && python intigriti_auth.py

     # Step 2b: Push cookie to server and retry sync
     PYTHONPATH=/Users/jmartinez/repos/julius python -c "
     from bounty_intel.sync.intigriti import _push_cookie_to_server
     from pathlib import Path
     cookie = (Path.home() / '.intigriti' / 'session_cookie.txt').read_text().strip()
     _push_cookie_to_server(cookie)
     print('Cookie pushed to server')
     "

     # Step 2c: Retry Intigriti sync with fresh cookie
     ```
   - **DO NOT proceed until Intigriti sync succeeds** (no `error: no_cookie`)
3. **Auto-fix Bugcrowd cookie issues**:
   - Bugcrowd: if `error: no_cookie` (or fetched=0), **AUTOMATICALLY execute**:
     ```bash
     # Step 3a: Generate fresh cookies via Playwright
     cd .claude/skills/bugcrowd/tools && python bugcrowd_auth.py

     # Step 3b: Push cookies to server
     PYTHONPATH=/Users/jmartinez/repos/julius python -c "
     from bounty_intel.sync.bugcrowd import _push_cookies_to_server
     from pathlib import Path
     import json
     cookies = json.loads((Path.home() / '.bugcrowd' / 'session_cookies.json').read_text())
     _push_cookies_to_server(cookies)
     print('Bugcrowd cookies pushed to server')
     "

     # Step 3c: Retry Bugcrowd sync
     # bounty_sync(source="bugcrowd")
     ```
   - Alternative MCP path: `bounty_refresh_bugcrowd_session()` then retry `bounty_sync(source="bugcrowd")`
   - **DO NOT proceed until Bugcrowd sync succeeds** — missing Bugcrowd data was the root cause of a past €1,900 EV over-estimate (platform showed 4/5 rejected that local DB still marked pending)
4. **Verify complete data**: All three platforms must show successful sync before continuing
5. **Reconcile local → platform**: If any local `reports.status` disagrees with platform `submissions.disposition` post-sync, update the report to match platform truth. Platform is the source of truth, always.
6. Refresh program statuses via API client:
```python
from bounty_intel.client import BountyIntelClient
import requests
client = BountyIntelClient()
resp = requests.post(f"{client.api_url}/api/v1/admin/refresh-program-statuses",
                    headers={"X-API-Key": client.api_key}, timeout=30)
```

This ensures:
- **Complete data from all three platforms** — never proceed with partial data
- **Fresh cookies** obtained automatically when needed via Playwright browser (Intigriti + Bugcrowd)
- **Cookies pushed to Cloud Run server** so API-based syncs work
- Submissions, payouts, and report statuses are up to date
- Program statuses reflect current platform state (open/active/paused/closed)

**Note**: If any platform login fails or user cancels browser, stop the forecast process and report incomplete data warning.

### Step 2: AI Triager Evaluation (done by Claude Code inline)

Read engagement context via MCP tools:
- `bounty_get_submissions(disposition="new")` + `bounty_get_submissions(disposition="triaged")` — get pending submissions
- `bounty_get_payouts()` — get historical payout data
- `bounty_get_stats()` — overall DB statistics

For each **pending** submission, evaluate from a **senior triager's cognitive perspective** considering:

1. **Impact credibility** — Real and demonstrated, or theoretical/inflated?
2. **PoC quality** — Reproducible by triager in 5 min? Steps clear and complete?
3. **Severity accuracy** — CVSS matches real impact, or inflated?
4. **Duplicate risk** — Common finding type many researchers would report?
5. **Business impact** — Would the company care enough to fix and pay?
6. **Report professionalism** — Clear writing, honest caveats, proper evidence?
7. **Vuln class history** — Cross-reference with hunt memory: `db.suggest_attacks(tech_stack=[...])`

Write evaluations to DB:
```python
db.save_ai_evaluation(
    submission_id=sub.id,
    acceptance_probability=0.65,
    confidence=0.8,
    likely_outcome="accepted",
    severity_assessment="agree",
    strengths=["RCE confirmed", "..."],
    weaknesses=["Requires interaction"],
    triager_reasoning="2-3 sentences from triager perspective",
    suggested_improvements=["improvement1"]
)
```

### Step 3: Compute Forecast
```bash
python -m bounty_intel forecast
```
This reads all submissions, payouts, and AI evaluations from DB, computes:
- Probability-weighted expected value per submission
- Four scenarios: pessimistic, expected, optimistic, maximum
- Monthly breakdown with triage timelines
- Saves engagement snapshot for historical tracking

### Step 4: Present Findings
Summarize to the user:
1. **Monthly breakdown** — past months (actual earnings), current month (confirmed + pending EV), next 3 months (projected)
2. **Earnings** — confirmed total (EUR, historical FX) and pending estimates
3. **AI triager highlights** — which findings are strong vs weak, with reasoning
4. **Top programs to focus on** — ranked by total EV
5. **Programs to avoid/deprioritize** — based on rejection patterns
6. **Platform breakdown** — compare performance on Intigriti vs HackerOne
7. **Key improvements** — actionable changes to increase acceptance rate

### Step 5: Open Dashboard (optional)
The full interactive dashboard is live at:
```
https://bounty-dashboard-887002731862.europe-west1.run.app
```
Direct the user there for the full visual experience with drill-down into programs, findings, and reports.

## Reference

### Close Reasons (Intigriti)
1=Resolved (PAID) | 2=Duplicate | 3=N/A | 4=Informative | 5=OOS | 6=Won't Fix | 7=N/A

### States (HackerOne)
new | triaged | needs-more-info | resolved | informative | duplicate | spam | not-applicable

### Substates (Bugcrowd — from `bugcrowd.com/submissions.json`)
nue (new/pending) | triaged | unresolved | resolved (PAID) | not_reproducible | not_applicable | out_of_scope | duplicate | wont_fix | informational

### Database CLI
```bash
python -m bounty_intel stats        # DB statistics
python -m bounty_intel sync         # Delta sync both platforms
python -m bounty_intel forecast     # Compute forecast from DB
python -m bounty_intel serve        # Start local dashboard
```
