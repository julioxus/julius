---
name: bounty-recon
description: Shared bug bounty reconnaissance pipeline - prioritization, endpoint recon, post-enumeration recon (httpx, naabu, ffuf, nuclei), extended recon (parallel skill deployment), and testing recommendations. Produces recon data and testing plan consumed by /pentest. Referenced by /intigriti and /hackerone.
---

# Bug Bounty Recon Pipeline

Shared reconnaissance pipeline for bug bounty platforms. Invoked by `/intigriti` and `/hackerone` after scope parsing. Produces recon data and testing recommendations consumed by `/pentest` in sub-orchestrator mode.

**This skill does NOT deploy testing agents.** It performs recon only and outputs a `testing_recommendations.md` file that `/pentest` uses to build its attack plan.

## Bounty-Driven Prioritization (MANDATORY FIRST STEP)

**BEFORE any testing, read the program scope and create a prioritized attack plan.**

1. **Parse scope completely FIRST**: Extract from the program page (PDF/URL/CSV/manual):
   - In-scope assets with their tiers/eligibility, severity caps, and instructions
   - Bounty table (amounts per severity per tier)
   - Program's stated worst-case scenarios or priority vulnerability types
   - **Full out-of-scope list** (application-level AND mobile/desktop-specific exclusions)
   - Any program-specific rules or testing limitations
2. **Map each vuln type to the program's bounty table**: Use the ACTUAL reward amounts from this specific program — don't assume generic values. Rank attack vectors from highest to lowest payout.
3. **Start with the program's stated worst-case scenarios** — these are what the triagers care about most and signal what they'll pay top bounty for
4. **Cross-reference every planned test against the OOS list** BEFORE executing it. If a vuln type is excluded, don't waste time testing it regardless of how easy it might be to find.
5. **Chain findings for impact escalation** — a low-severity finding chained with another can reach Critical. Always think about chains that multiply impact.
6. **Drop low-impact findings quickly** if they don't chain into something bigger
7. **Check mobile/desktop-specific exclusions separately** — programs often have a dedicated exclusion list for mobile that differs from web. Read it before any APK/IPA analysis.
8. **VDP vs bounty program assessment**: If the program has no bounty table (listed_bounty = 0 or "Vulnerability Disclosure Program"), it's a VDP. VDPs sometimes award bonuses but it's unpredictable. **Strategy**:
   - VDP: Only invest time if the finding is exceptional (Critical/High with full E2E chain). Do NOT burn hours on Medium/Low findings for VDPs — the expected payout is near zero.
   - Bounty program: Full effort justified. Prioritize by bounty table amounts.
   - If testing multiple programs in parallel, allocate 80%+ time to bounty programs, VDPs only for leftover time or exceptional opportunities.
9. **Duplicate risk assessment**: Before testing, estimate how likely your findings will be duplicates:
   - **High duplicate risk** (reduce time investment): Program has been live for months/years, large researcher community, low-hanging fruit vuln types (open redirect, info disclosure, missing headers, version disclosure). On these programs, hunt business logic flaws and complex chains — not scanner findings.
   - **Low duplicate risk** (invest more): New program (< 30 days), small researcher pool, niche technology stack, complex business logic. On these, speed matters — report quickly with maximum detail.
   - **Live hacking events / time-limited programs**: Pure speed. Report fast with enough detail to hold the finding, then supplement with full PoC.
10. **Program focus strategy (80/20 rule)**: When the researcher works across multiple programs:
    - **Concentrate 80% of effort on 3-5 programs** where you have accumulated context (local findings, environment setup, technology understanding, past submissions).
    - **Use 20% for exploration** of new programs to discover fresh attack surface.
    - **Deprioritize programs** with high rejection rates (>50% rejected) unless you understand why and can change your approach.
    - **Abandon programs** where you've exhausted the attack surface or where triagers consistently reject your finding types.

**Present the prioritized plan to the user BEFORE starting any testing.**

## Endpoint Recon (historical URL discovery)

Run `tools/recox/endpoint_recon.py` to discover historical endpoints from Wayback Machine, Common Crawl, OTX, and URLScan:

```bash
# Full recon for a domain
python3 tools/recox/endpoint_recon.py target.com -o outputs/<program>/recon/endpoints.txt

# Interesting files only (js, json, xml, php, config, env, etc.)
python3 tools/recox/endpoint_recon.py target.com -i -o outputs/<program>/recon/endpoints_interesting.txt

# Specific sources only
python3 tools/recox/endpoint_recon.py target.com --sources wayback,otx
```

Feed discovered endpoints to pentester agents for targeted testing (hidden admin panels, old API versions, exposed config files).

## Post-Enumeration Recon Pipeline (for domain/wildcard assets)

**BEFORE deploying pentester agents**, run this pipeline on wildcard/domain assets to identify the real attack surface:

1. **httpx** live host detection: `httpx -l subs.txt -sc -title -tech-detect -timeout 5 -threads 50 -retries 0`
   - Pre-filter `.internal.*`/`.uat.*` subdomains (cause DNS hangs)
   - Categorize hosts by response code and tech stack
2. **naabu** port scan: `naabu -list hostnames.txt -top-ports 1000` (bare hostnames, NOT URLs)
   - Focus on non-standard ports (not 80/443) — admin panels, dev servers
3. **ffuf** directory fuzzing: `ffuf -w ~/SecLists/Discovery/Web-Content/common.txt -u "https://{host}/FUZZ" -mc 200,301,302`
   - Target non-Cloudflare hosts; filter CF WAF 403s with `-fs 5453`
4. **nuclei** vuln scan: `nuclei -l live.txt -severity medium,high,critical -timeout 10`
   - Run in background (~10-15 min); review for false positives

See `/subdomain-enumeration` skill for detailed lessons learned and gotchas.

## Extended Recon (AUTOMATIC, parallel with post-enumeration pipeline)

Deploy these skills **in parallel** during recon to expand attack surface and inform pentester agents:

1. **`/code-repository-intel`** — Scan GitHub/GitLab for public repos, leaked secrets, CI configs, dependency files. High-value: exposed `.env`, API keys in commit history, internal endpoints in CI pipelines.
2. **`/api-portal-discovery`** — Discover public API portals, developer docs, OpenAPI/Swagger specs. Endpoints found here bypass WAF and often lack rate limiting.
3. **`/web-application-mapping`** — Comprehensive endpoint discovery via passive browsing + headless automation. Maps forms, AJAX calls, WebSocket connections, and hidden functionality.
4. **`/security-posture-analyzer`** — Enumerate security headers (CSP, HSTS, X-Frame-Options), WAF presence, and security.txt. Results directly inform payload selection and bypass strategy.
5. **`/cdn-waf-fingerprinter`** — Identify CDN (Cloudflare, Akamai, Fastly) and WAF. Critical for: filtering ffuf results, selecting XSS payloads that bypass WAF rules, identifying origin IP bypass opportunities.
6. **`/hexstrike`** — Deploy HexStrike AI (150+ tools) for parallel recon automation: nmap, nuclei, gobuster, subfinder, httpx, and more. Especially useful for large scope with many assets.

**Feed results to /pentest**: All discovered endpoints, API specs, security posture data, and WAF fingerprints are included in the testing recommendations for `/pentest` to consume during Phase 3 (Planning & Approval).

## Testing Recommendations (output for /pentest)

After recon completes, produce a `testing_recommendations.md` file at `{output_base}/processed/reconnaissance/testing_recommendations.md`. This file is consumed by `/pentest` in sub-orchestrator mode during Phase 3 to build the attack plan.

### Contents

```markdown
# Testing Recommendations for {program}

## Asset Priority (tier-based)
| Asset | Type | Tier | Priority | Notes |
|-------|------|------|----------|-------|
| api.target.com | API | 1 | Highest | Main API, $5k critical |
| app.target.com | Web App | 2 | High | React SPA |
| *.target.com | Wildcard | 3 | Medium | 12 live subdomains |

## Detected Technologies → Recommended Attacks
- api.target.com: Node.js + Express → injection, SSRF, prototype pollution
- app.target.com: React 18.2 + Next.js → DOM XSS, CSRF, client-side attacks

## DOM XSS Candidates
Assets where httpx detected JS frameworks (React, Vue, Angular, jQuery, Next.js, Nuxt, SvelteKit)
or SPA indicators (`<div id="app">`, `data-reactroot`, `ng-app`, `[data-v-]`):
- app.target.com — React 18.2, SPA confirmed → deploy dom-xss-scanner

## Conditional Skill Triggers
Based on recon discoveries, recommend these specialized skills to /pentest:

- `/cve-testing` + `/cve-poc-generator` — Software versions detected: {list versions from httpx/nuclei}
- `/source-code-scanning` — Source code exposed: {repos, .git dirs, source maps found by /code-repository-intel}
- `/ai-threat-testing` — AI/LLM features detected: {chatbots, /api/chat, SDK references}
- `/authenticating` — Login/signup forms found: {list auth endpoints}
- `/cloud-security` — Cloud infrastructure detected: {S3 buckets, metadata endpoints, cloud headers}
- `/container-security` — K8s/Docker indicators: {healthz endpoints, orchestration signals}
- `/burp-suite` — High-value endpoints for active scanning + Collaborator OOB testing

## Chain Opportunities (identified during recon)
- open redirect at /oauth/callback + OAuth flow = potential ATO
- SSRF candidate at /api/proxy + cloud metadata = credential theft
- {other chain hypotheses from recon data}

## WAF/CDN Info (for payload selection)
- Cloudflare on *.target.com — filter ffuf 403s, use CF-bypass XSS payloads
- No WAF on api-internal.target.com — standard payloads work

## Mobile Assets
- com.target.app (Android) — downloaded via /mobile-app-acquisition → recommend /mobile-security
```

### How /pentest Consumes This

1. `/pentest` reads `testing_recommendations.md` during Phase 3 (Planning & Approval)
2. Uses asset priority to determine executor deployment order
3. Uses conditional skill triggers to decide which specialized executors to deploy
4. Uses DOM XSS candidates to deploy `dom-xss-scanner` agents
5. Uses WAF/CDN info to configure payload selection
6. Presents the combined plan to user for approval before Phase 4

## Recon Output Format

All recon data is written using the format defined in `/pentest/reference/RECONNAISSANCE_OUTPUT.md`:

```
{output_base}/processed/reconnaissance/
├── inventory/                    # JSON inventories per asset type
├── analysis/                     # Analysis reports
├── reconnaissance_report.md      # Summary report
└── testing_recommendations.md    # NEW: recommendations for /pentest
```

## Chain Discovery Notes

Chain hypotheses identified during recon are documented in `testing_recommendations.md` for `/pentest` to evaluate during testing:
- Common high-value chains: open redirect + OAuth = ATO, SSRF + cloud metadata = credential theft, XSS + CSRF = stored ATO
- `/pentest` Phase 4 actively tests these chains and Phase 5 combines confirmed chains to maximize severity
