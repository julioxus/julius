# /bounty-forecast - Bug Bounty Earnings Analysis & AI Forecast

Analyzes Intigriti + HackerOne submissions, evaluates each pending report from a triager's perspective using local engagement context, and recommends the best programs to focus on.

## Trigger
When user says: "bounty forecast", "bounty analysis", "how much money", "intigriti earnings", "intigriti forecast", "hackerone earnings", "hackerone forecast", "all bounties", "combined forecast", "analyze my bounties", "which programs should I focus on"

## Requirements
- Playwright installed (`pip install playwright && playwright install chromium`) — for Intigriti auth
- Or active Intigriti session cookie (from Burp)
- `HACKERONE_USERNAME` and `HACKERONE_API_TOKEN` in `.env` — for HackerOne API

## Authentication

**Intigriti** — handled by `intigriti_auth.py`:
1. **Cached session** — checks `~/.intigriti/session_cookie.txt` (valid ~55 min)
2. **Playwright browser** — if expired, opens Chromium for login + MFA
3. Cookie cached for subsequent runs

```bash
python3 .claude/skills/intigriti/tools/intigriti_auth.py --status   # check
python3 .claude/skills/intigriti/tools/intigriti_auth.py --clear    # force re-login
```

**HackerOne** — HTTP Basic Auth via `.env`:
- `HACKERONE_USERNAME` — your HackerOne username
- `HACKERONE_API_TOKEN` — API token from HackerOne settings
- No browser login needed

## Pipeline

### Step 1: Export Intigriti Inbox (auto-authenticates)
```bash
python3 .claude/skills/intigriti/tools/inbox_exporter.py \
  --fetch-details --output outputs/intigriti-inbox
```

### Step 2: Aggregate Reports (fetches HackerOne via API + merges)
```bash
python3 .claude/skills/intigriti/tools/report_aggregator.py \
  --intigriti outputs/intigriti-inbox/report_latest.json \
  --output outputs/combined-inbox/report_latest.json
```

This fetches all HackerOne reports via API, normalizes them to the same schema as Intigriti, tags each with `platform: "intigriti"|"hackerone"`, and merges into a combined report.

### Step 3: Gather Engagement Context
```bash
python3 .claude/skills/intigriti/tools/engagement_context.py \
  --output outputs/combined-inbox/engagement_context.json
```

This scans:
- **All `outputs/intigriti-*/` directories** — local findings, submissions, PoCs, effort invested
- **All `outputs/hackerone-*/` directories** — same metrics for H1 engagements
- **Memory files** (`~/.claude/projects/.../memory/`) — past engagement decisions, feedback, learnings
- **Submission outcomes** — which programs paid, rejected, and why

### Step 4: AI Triager Evaluation (done by Claude Code inline)

Read `outputs/combined-inbox/engagement_context.json` for full context.

For each **pending** submission from both platforms, evaluate from a **senior triager's cognitive perspective** considering:

1. **Impact credibility** — Real and demonstrated, or theoretical/inflated?
2. **PoC quality** — Reproducible by triager in 5 min? Steps clear and complete?
3. **Severity accuracy** — CVSS matches real impact, or inflated?
4. **Duplicate risk** — Common finding type many researchers would report?
5. **Business impact** — Would the company care enough to fix and pay?
6. **Report professionalism** — Clear writing, honest caveats, proper evidence?
7. **Vuln class history** — Cross-reference with researcher's rejection patterns (e.g., config disclosures → informative)

For Intigriti submissions, fetch full detail via Burp `send_http1_request`:
```
GET /api/core/researcher/submissions/{SUBMISSION_ID}
Host: app.intigriti.com
Cookie: __Host-Intigriti.Web.Researcher=COOKIE
```

For HackerOne submissions, details are already included in the aggregated report.

Write evaluations to `outputs/combined-inbox/ai_evaluation.json`:
```json
[
  {
    "id": "SUBMISSION-ID",
    "acceptance_probability": 0.65,
    "confidence": 0.8,
    "likely_outcome": "accepted|informative|duplicate|out_of_scope|needs_more_info",
    "severity_assessment": "agree|overrated|underrated",
    "strengths": ["strength1"],
    "weaknesses": ["weakness1"],
    "triager_reasoning": "2-3 sentences from triager perspective",
    "suggested_improvements": ["improvement1"]
  }
]
```

### Step 5: Program Recommendations (done by Claude Code inline)

Using the engagement context, generate program recommendations. Write to `outputs/combined-inbox/program_recommendations.json`:

```json
[
  {
    "program": "Company Name",
    "platform": "intigriti|hackerone",
    "action": "focus|continue|deprioritize|abandon|explore",
    "priority": 1,
    "reasoning": "Why this program deserves attention",
    "evidence": {
      "past_results": "2 paid, 0 rejected",
      "local_findings_unused": 5,
      "estimated_roi": "high|medium|low",
      "vuln_surface": "Large unexplored API surface",
      "competition_level": "low|medium|high"
    },
    "next_steps": ["Specific action 1", "Specific action 2"]
  }
]
```

Recommendation criteria:
- **ROI history** — paid vs rejected ratio per program
- **Unexploited work** — programs with local findings never submitted
- **Bounty tiers** — programs with higher payouts
- **Effort already invested** — files, scripts, knowledge accumulated
- **Vuln surface remaining** — what's left to test based on past findings
- **Competition level** — popular programs = more duplicates
- **Memory insights** — past decisions, engagement notes, feedback

### Step 6: Scan Pending Local Reports
```bash
python3 .claude/skills/intigriti/tools/pending_reports_scanner.py \
  --base-dir . \
  --output outputs/combined-inbox/pending_reports.json
```

This scans all `outputs/intigriti-*/reports/submissions/INTI_*_*.md` and
`outputs/hackerone-*/reports/submissions/H1_*_*.md` files, cross-references
with existing submissions via both platform APIs, and checks program status.
Output includes pending reports grouped by program status.

### Step 7: Generate Forecast with AI data + Pending Reports
```bash
python3 .claude/skills/intigriti/tools/bounty_forecast.py \
  outputs/combined-inbox/report_latest.json \
  --ai-evaluations outputs/combined-inbox/ai_evaluation.json \
  --pending-reports outputs/combined-inbox/pending_reports.json \
  --output outputs/combined-inbox/forecast_latest.json
```

### Step 8: Generate HTML Report
```bash
python3 .claude/skills/intigriti/tools/bounty_report_html.py \
  outputs/combined-inbox/forecast_latest.json \
  --report outputs/combined-inbox/report_latest.json \
  --pending-reports outputs/combined-inbox/pending_reports.json \
  --researcher julioxus \
  -o outputs/combined-inbox/bounty_report.html
open outputs/combined-inbox/bounty_report.html
```

### Step 9: Present Findings
Summarize to the user:
1. **Monthly breakdown** — past months (actual earnings), current month (confirmed + pending EV), next 3 months (projected)
2. **Earnings** — confirmed total (EUR, historical FX) and pending estimates
3. **AI triager highlights** — which findings are strong vs weak, with reasoning
4. **Top programs to focus on** — ranked recommendations with evidence
5. **Programs to avoid/deprioritize** — based on rejection patterns
6. **Pending local reports** — INTI/H1 files not yet submitted, grouped by program status (open/suspended)
7. **Platform breakdown** — compare performance on Intigriti vs HackerOne
8. **Key improvements** — actionable changes to increase acceptance rate

## Reference

### Close Reasons (Intigriti)
1=Resolved (PAID) | 2=Duplicate | 3=N/A | 4=Informative | 5=OOS | 6=Won't Fix | 7=N/A

### States (HackerOne)
new | triaged | needs-more-info | resolved | informative | duplicate | spam | not-applicable

### API Endpoints
- Intigriti Submissions: `GET /api/core/researcher/submissions?offset=0&limit=100`
- Intigriti Detail: `GET /api/core/researcher/submissions/{id}`
- Intigriti Auth: Cookie `__Host-Intigriti.Web.Researcher`
- HackerOne Reports: `GET https://api.hackerone.com/v1/hackers/me/reports`
- HackerOne Auth: HTTP Basic Auth (username:token)
- FX rates: `https://api.frankfurter.dev/{date}?from={currency}&to=EUR&amount=1`
