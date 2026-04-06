# /bounty-forecast - Bug Bounty Earnings Analysis & AI Forecast

Analyzes Intigriti + HackerOne submissions, evaluates each pending report from a triager's perspective using engagement context from the database, and recommends the best programs to focus on.

## Trigger
When user says: "bounty forecast", "bounty analysis", "how much money", "intigriti earnings", "intigriti forecast", "hackerone earnings", "hackerone forecast", "all bounties", "combined forecast", "analyze my bounties", "which programs should I focus on"

## Requirements
- `bounty_intel` package installed: `pip install -e .` (from repo root)
- `DATABASE_URL` in `.env` pointing to Cloud SQL (or local PG)
- For sync: `HACKERONE_USERNAME` and `HACKERONE_API_TOKEN` in `.env`
- For Intigriti sync: valid session cookie or Playwright for browser login

## Pipeline

### Step 1: Sync platform data (delta — only fetches changes)
```bash
source .venv/bin/activate
python -m bounty_intel sync
```
This:
- Fetches HackerOne reports via API (token-based, automatic)
- Fetches Intigriti submissions (cookie-based — auto-launches browser if expired)
- Only upserts changed records since last sync (watermark-based delta)

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

### Database CLI
```bash
python -m bounty_intel stats        # DB statistics
python -m bounty_intel sync         # Delta sync both platforms
python -m bounty_intel forecast     # Compute forecast from DB
python -m bounty_intel serve        # Start local dashboard
```
