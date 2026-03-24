---
name: intigriti
description: Intigriti bug bounty automation - parses program scope from user-provided data (PDF, URL, manual input), deploys parallel pentesting agents for domain-based assets with tier prioritization, auto-downloads mobile apps from running emulators, validates PoCs, and generates Intigriti-formatted submission reports with vulnerability type taxonomy. Use when testing Intigriti programs or preparing European bug bounty submissions.
---

# Intigriti Bug Bounty Hunting

Automates Intigriti workflows: scope parsing → tier-prioritized testing → mobile app acquisition → PoC validation → submission reports.

## Quick Start

```
1. Input: Intigriti program URL, PDF, or manual scope description
2. If URL provided and $INTIGRITI_PAT is set:
   → Resolve program handle to ID via Researcher API
   → Fetch domains, tiers, rules of engagement, and testing requirements
   → Apply required User-Agent/headers from testingRequirements
3. Parse scope: extract assets, tiers, types, and program rules
4. For mobile assets: detect running emulators and download apps from marketplace
5. Deploy Pentester agents in parallel (tier-prioritized)
6. Validate PoCs (poc.py + poc_output.txt required)
7. Generate Intigriti-formatted reports
```

## Bounty-Driven Prioritization (MANDATORY FIRST STEP)

**BEFORE any testing, read the program scope and create a prioritized attack plan.**

1. **Parse scope completely FIRST**: Extract from the program page (PDF/URL/manual):
   - In-scope assets with their tiers and types
   - Bounty table (amounts per severity per tier)
   - Program's stated worst-case scenarios or priority vulnerability types
   - **Full out-of-scope list** (application-level AND mobile/desktop-specific exclusions)
   - Any program-specific rules or testing limitations
2. **Map each vuln type to the program's bounty table**: Use the ACTUAL reward amounts from this specific program — don't assume generic values. Rank attack vectors from highest to lowest payout.
3. **Start with the program's stated worst-case scenarios** — these are what the triagers care about most and signal what they'll pay top bounty for
4. **Cross-reference every planned test against the OOS list** BEFORE executing it. If a vuln type is excluded, don't waste time testing it regardless of how easy it might be to find.
5. **Chain findings for impact escalation** — a low-severity finding chained with another can reach Critical. Always think about chains that multiply impact.
6. **Drop low-impact findings quickly** if they don't chain into something bigger
7. **Check mobile/desktop-specific exclusions separately** — programs often have a dedicated exclusion list for mobile that differs from web (e.g., certificate pinning, obfuscation, path disclosure, root detection). Read it before any APK/IPA analysis.

**Present the prioritized plan to the user BEFORE starting any testing.**

## Scope Input Methods

**Option 1: Program URL via Researcher API** (recommended)
```
- [ ] User provides Intigriti program URL (e.g., https://app.intigriti.com/programs/<company>/<handle>/detail)
- [ ] Extract program handle from URL
- [ ] Resolve handle to programId: GET /v1/programs?limit=500, match by handle field
- [ ] Fetch program details: GET /v1/programs/{programId}
      → Returns: domains (assets with type, tier, endpoint), rules of engagement, status, bounty range
- [ ] Fetch full domains: GET /v1/programs/{programId}/domains/{versionId}
      → Returns: each domain with id, type, endpoint, tier, description, requiredSkills
- [ ] Fetch rules: GET /v1/programs/{programId}/rules-of-engagements/{versionId}
      → Returns: description, testingRequirements (automatedTooling, userAgent, requestHeader), safeHarbour, attachments
- [ ] Parse into structured scope for agent deployment
```

**Researcher API Configuration:**
```
Base URL: https://api.intigriti.com/external/researcher
Auth:     Authorization: Bearer $INTIGRITI_PAT
Version:  v1 (BETA)
```

**Key API Endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | /v1/programs | List all accessible programs (filter: statusId, typeId, following) |
| GET | /v1/programs/{programId} | Program details with domains and rules |
| GET | /v1/programs/{programId}/domains/{versionId} | Full domain/asset list for a version |
| GET | /v1/programs/{programId}/rules-of-engagements/{versionId} | Rules, testing requirements, attachments |
| GET | /v1/programs/activities | Program change events (scope updates, rule changes) |

**API Response → Scope Mapping:**
- `domains[].endpoint` → Asset name (domain, wildcard, app bundle)
- `domains[].type.value` → Asset type (Web Application, API, iOS, Android, etc.)
- `domains[].tier.value` → Tier (1-5, Tier 1 = highest bounty)
- `domains[].description` → Per-asset testing instructions
- `rulesOfEngagement.content.description` → Program rules, OOS list, bounty table
- `rulesOfEngagement.content.testingRequirements.userAgent` → Required User-Agent header
- `rulesOfEngagement.content.testingRequirements.requestHeader` → Required custom request header
- `rulesOfEngagement.content.testingRequirements.automatedTooling` → Automated tool policy
- `rulesOfEngagement.content.safeHarbour` → Safe harbour status

**Handle Resolution from URL:**
```bash
# Extract handle from URL: https://app.intigriti.com/programs/<company>/<handle>/detail
HANDLE=$(echo "$URL" | grep -oP 'programs/[^/]+/\K[^/]+')

# Resolve to programId via API
curl -s -H "Authorization: Bearer $INTIGRITI_PAT" \
  "https://api.intigriti.com/external/researcher/v1/programs?limit=500" \
  | jq -r ".records[] | select(.handle == \"$HANDLE\") | .id"
```

**Option 2: PDF of program page**
```
- [ ] Read PDF with program details
- [ ] Extract assets table (name, type, tier)
- [ ] Extract bounty table, rules, out-of-scope items
- [ ] Parse into structured scope for agent deployment
```

**Option 3: Program URL (browser scraping fallback)**
```
- [ ] Use when API is unavailable or PAT not configured
- [ ] Use Playwright MCP or browser tools to load the page
- [ ] Extract scope table, bounty table, and rules
- [ ] Parse into structured scope
```

**Option 4: Manual input**
```
- [ ] AskUserQuestion: "Provide the in-scope assets (domain/app, type, tier):"
- [ ] AskUserQuestion: "Any specific program rules or exclusions?"
- [ ] Build scope from user responses
```

## Scope Format

Intigriti uses domain-based scope (not CSV like HackerOne):
- **Asset name**: Target domain, wildcard, app bundle ID, or description
- **Type**: Web Application, API, iOS, Android, Device, Network
- **Tier**: 1-5 (Tier 1 = highest bounty)
- **Instructions**: Per-asset testing guidelines

Use `tools/scope_parser.py` to parse structured scope data.

## Mobile App Acquisition (AUTOMATIC)

**When iOS or Android assets appear in scope, automatically download them from running emulators.**

### Detection: Find Running Emulators

```bash
# Android emulators
adb devices | grep -E "emulator|device$"

# iOS simulators
xcrun simctl list devices booted
```

### Android App Download

```bash
# 1. Identify the target package from scope (e.g., de.bmw.connected.mobile20.row)
PACKAGE="<package_id_from_scope>"

# 2. Open Play Store on the emulator to install
adb shell am start -a android.intent.action.VIEW -d "market://details?id=${PACKAGE}"

# 3. Wait for user to complete install, then verify
adb shell pm list packages | grep "${PACKAGE}"

# 4. Pull APK for static analysis
APK_PATH=$(adb shell pm path "${PACKAGE}" | sed 's/package://')
adb pull "${APK_PATH}" "./outputs/apps/${PACKAGE}.apk"

# 5. If multiple splits (split APKs), pull all
adb shell pm path "${PACKAGE}" | while read -r line; do
  path=$(echo "$line" | sed 's/package://')
  filename=$(basename "$path")
  adb pull "$path" "./outputs/apps/${filename}"
done
```

### iOS App Download

```bash
# 1. Identify the App Store ID from scope (e.g., 1519034860)
APP_ID="<appstore_id_from_scope>"

# 2. Get booted simulator UDID
UDID=$(xcrun simctl list devices booted -j | python3 -c "
import json, sys
data = json.load(sys.stdin)
for runtime, devices in data['devices'].items():
    for d in devices:
        if d['state'] == 'Booted':
            print(d['udid']); break
")

# 3. Open App Store on simulator
xcrun simctl openurl "${UDID}" "itms-apps://apps.apple.com/app/id${APP_ID}"

# 4. Alternative: use ipatool if available for direct IPA download
ipatool download -b "<bundle_id>" -o "./outputs/apps/"

# 5. For real devices connected via USB
ideviceinstaller -l | grep "<bundle_id>"
```

### Post-Download Analysis

```
- [ ] Static analysis with MobSF (if /mobile-security skill available)
- [ ] Extract AndroidManifest.xml / Info.plist
- [ ] Identify API endpoints, hardcoded secrets, certificate pinning
- [ ] Feed discovered endpoints back to web/API Pentester agents
```

## Post-Enumeration Recon Pipeline (for domain-based assets)

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

See `/subdomain_enumeration` skill for detailed lessons learned and gotchas.

## Extended Recon (AUTOMATIC, parallel with post-enumeration pipeline)

Deploy these skills **in parallel** during recon to expand attack surface and inform pentester agents:

1. **`/code-repository-intel`** — Scan GitHub/GitLab for public repos, leaked secrets, CI configs, dependency files. High-value: exposed `.env`, API keys in commit history, internal endpoints in CI pipelines.
2. **`/api-portal-discovery`** — Discover public API portals, developer docs, OpenAPI/Swagger specs. Endpoints found here bypass WAF and often lack rate limiting.
3. **`/web-application-mapping`** — Comprehensive endpoint discovery via passive browsing + headless automation. Maps forms, AJAX calls, WebSocket connections, and hidden functionality.
4. **`/security-posture-analyzer`** — Enumerate security headers (CSP, HSTS, X-Frame-Options), WAF presence, and security.txt. Results directly inform payload selection and bypass strategy.
5. **`/cdn-waf-fingerprinter`** — Identify CDN (Cloudflare, Akamai, Fastly) and WAF. Critical for: filtering ffuf results, selecting XSS payloads that bypass WAF rules, identifying origin IP bypass opportunities.

**Feed results to pentester agents**: All discovered endpoints, API specs, security posture data, and WAF fingerprints are passed as context to each Pentester agent to enable targeted testing.

## Agent Deployment

**Pentester Agent** per asset (tier-prioritized):
- Tier 1 assets: Deploy first, allocate most resources
- Tier 2-3 assets: Deploy in parallel, standard resources
- Tier 4-5 assets: Deploy last, lower priority
- Has access to `patt-fetcher` agent for on-demand PayloadsAllTheThings payloads (30+ categories: SQLi, XSS, SSTI, SSRF, deserialization, OAuth, etc.)
- Has access to `script-generator` agent for optimized PoC scripts (>30 lines, parallelized, syntax-validated)

**Mobile assets**: Deploy `/mobile-security` skill agents after app download

**DOM XSS scanning (AUTOMATIC for JS-heavy targets)**:
When httpx tech-detect or page analysis reveals JavaScript frameworks (React, Vue, Angular, jQuery, Next.js, Nuxt, SvelteKit) or the target is a SPA:
- Deploy `dom-xss-scanner` agent **in parallel** with the Pentester agent for that asset
- The scanner hooks sinks (innerHTML, document.write, eval, jQuery.html), injects canaries through all DOM sources, and detects taint flow automatically
- Findings feed back into the Pentester agent's results for chain analysis
- Trigger criteria: httpx `tech-detect` output contains JS framework names, OR page has `<div id="app">`, `data-reactroot`, `ng-app`, `[data-v-]`, OR `Content-Type` indicates SPA (HTML shell + JS bundles)

**Parallel Execution**:
- 8 assets = 8 Pentester Orchestrators + dom-xss-scanner where applicable
- Each spawns specialized agents
- Tier 1 findings reviewed first
- Mobile app analysis + DOM XSS scanning run alongside web testing

**Conditional Specialized Testing (AUTOMATIC based on recon results)**:
Deploy these skills when recon or tech detection identifies specific conditions:

- **`/cve-testing`** + **`/cve-poc-generator`** — When httpx, nuclei, or tech-detect identifies specific software versions (e.g., Apache 2.4.49, jQuery 3.4.1, Spring 5.3.x). `/cve-testing` researches known CVEs and tests with public exploits. When a CVE is confirmed, `/cve-poc-generator` creates a standalone Python PoC script + detailed report with NVD data, CVSS vector, and remediation. High-value: unpatched services on non-standard ports.
- **`/source-code-scanning`** — When `/code-repository-intel` discovers exposed source code (public repos, leaked repos, `.git` directories, source maps). Runs SAST for OWASP Top 10 + CWE Top 25, scans dependencies for CVEs, detects hardcoded secrets (API keys, tokens, passwords), and identifies insecure patterns. Chain: exposed secrets → account takeover, dependency CVEs → RCE.
- **`/ai-threat-testing`** — When recon discovers AI/LLM features: chatbots, AI assistants, `/api/chat`, `/api/completions`, prompt-based interfaces, or OpenAI/Anthropic SDK references in JS bundles. Tests OWASP LLM Top 10 (prompt injection, model extraction, data poisoning).
- **`/authenticating`** — When login/signup forms are discovered. Automates credential testing, 2FA bypass, CAPTCHA solving, session management analysis via Playwright MCP. Deploy for each unique auth endpoint found.
- **`/cloud-security`** — When `/cloud-infra-detector` or recon identifies AWS/Azure/GCP infrastructure (S3 buckets, Azure blobs, metadata endpoints, cloud-specific headers). Tests IAM misconfigs, storage enumeration, SSRF to metadata service.
- **`/container-security`** — When Kubernetes/Docker indicators are found (K8s headers, `/healthz` endpoints, container orchestration signals, `.docker` files in repos). Tests RBAC, pod security, network policies, container escape vectors.
- **`/burp-suite`** — When Burp Suite MCP is available. Deploy for active scanning + Collaborator OOB testing on high-value endpoints. Essential for blind XSS, blind SSRF, and out-of-band data exfiltration detection.

**Chain Discovery (DURING testing)**:
- After each finding, actively evaluate: "Can this chain with another finding to escalate severity?"
- Common high-value chains: open redirect + OAuth = ATO, SSRF + cloud metadata = credential theft, XSS + CSRF = stored ATO
- When a chain opportunity is identified, prioritize testing the complementary finding immediately
- Document chain potential in findings even if the complementary vuln hasn't been confirmed yet

## PoC Validation (CRITICAL)

**Every finding MUST have**:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. `workflow.md` - Manual steps (if applicable)
4. Evidence screenshots/videos

## Automated Finding Validation (Phase 4.5 — BEFORE Pre-Submission Gate)

Deploy **`pentester-validator`** agent per finding (all in parallel) to run 5 anti-hallucination checks:

1. **CVSS consistency** — Severity label must exactly match CVSS score range (no tolerance)
2. **Evidence exists** — `poc.py`, `poc_output.txt`, `description.md`, and `evidence/` directory must all exist
3. **PoC validation** — Valid Python syntax, references target URL, output matches `poc_output.txt`
4. **Claims vs raw evidence** — Every technical claim (HTTP codes, ports, versions, CVEs, ciphers) must appear in raw scan output. One uncorroborated claim = REJECTED
5. **Log corroboration** — All 4 workflow phases (recon, experiment, test, verify) must be present with distinct timestamps. Bulk timestamps indicate fabricated verification = REJECTED

**Only VALIDATED findings proceed to the Pre-Submission Gate.** Rejected findings are logged to `false-positives/` with detailed failure reasons.

## Pre-Submission Gate (MANDATORY before reporting)

**Before submitting ANY finding, validate it passes ALL these checks:**

1. **OOS check**: Re-read the program's out-of-scope list. Is this vuln type explicitly excluded? Is the asset in scope? Check BOTH the general OOS and any platform-specific OOS (mobile/desktop).
2. **Business logic verification (CRITICAL — prevents "by design" rejections)**:
   Before reporting any data exposure, information leak, or access control finding, verify it's NOT intended behavior:
   - **Understand the core service**: What does this company actually do? Search the company's website, About page, and marketing materials. If they are a people-search engine, exposing personal data IS the product. If they are a public registry, open access IS the feature.
   - **Check public documentation**: Read ToS, Privacy Policy, FAQ, API docs, and help pages. Do they describe or justify the behavior you found? Look for phrases like "publicly available information", "data provided by users", "open access".
   - **Compare with competitors**: Do similar services in the same industry expose the same data or behave the same way? If all competitors do it, it's likely an industry norm, not a vulnerability.
   - **Test the "would a customer complain?" heuristic**: If a regular user of this service saw this behavior, would they be surprised? Or is it exactly what they signed up for?
   - **Check for explicit access controls**: Is there a login wall, paywall, or robots.txt restriction that the data bypasses? If the data is freely browsable without authentication, it's likely public by design.
   - **Document your conclusion**: In the finding, explicitly state why this behavior is NOT by design. If you cannot articulate a clear reason, DO NOT report it.
   - **When in doubt, ASK the user** before reporting — a "by design" rejection wastes everyone's time and damages researcher reputation.
3. **Submission requirements check**: Does the report include everything the program requires? Common Intigriti requirements:
   - Role(s) used during testing
   - Raw HTTP requests/responses in text format
   - Clear step-by-step reproduction instructions
   - Affected plan/tier if applicable
4. **Impact honesty check**: Does the claimed severity match the demonstrated impact? Don't inflate.
5. **Present findings to user for review**: Show a summary of each finding with severity, evidence quality, OOS risk assessment, and business logic verification result. Let the user decide which to submit.

## Report Format

Required fields (Intigriti standard):
1. **Title** (vulnerability description, no URL)
2. **Severity** (CVSS v3.1 or v4.0 vector + score)
3. **Domain** (affected in-scope asset)
4. **Vulnerability Type** (from Intigriti taxonomy dropdown)
5. **Description** (Markdown, detailed explanation)
6. **Steps to Reproduce** (numbered, clear)
7. **Impact** (realistic attack scenario)
8. **Raw HTTP requests/responses** (text format, not screenshots)
9. **Role used** (e.g., user, admin, guest, unauthenticated)

Use `tools/report_validator.py` to validate.

## Output Structure

```
outputs/intigriti-<program>/
├── apps/                         # Downloaded mobile apps
│   ├── <package>.apk
│   └── <bundle>.ipa
├── findings/
│   ├── finding-001/
│   │   ├── report.md             # Intigriti report
│   │   ├── poc.py                # Validated PoC
│   │   ├── poc_output.txt        # Proof
│   │   └── workflow.md           # Manual steps
├── reports/
│   ├── submissions/
│   │   ├── INTI_CRITICAL_001.md  # Ready to submit
│   │   └── INTI_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/
    ├── screenshots/
    └── http-logs/
```

## Platform Differences (vs HackerOne)

| Aspect | Intigriti | HackerOne |
|--------|-----------|-----------|
| Scope format | Domain-based (tiers, types) | CSV file |
| Scope retrieval | Researcher API (PAT) / PDF / URL / manual | CSV download / API |
| Triage | Managed by Intigriti team | Company-triaged |
| Currency | EUR | USD |
| Vuln classification | Taxonomy dropdown | Free-text |
| Bounty tiers | 1-5 (Tier 1 highest) | Per-severity |
| Report title | No URL in title | URL in title |

See `reference/PLATFORM_GUIDE.md` for full comparison.

## Critical Rules

**MUST DO**:
- When a program URL is provided, use the Researcher API with `$INTIGRITI_PAT` to fetch scope (preferred over scraping)
- If `$INTIGRITI_PAT` is not set, ask the user for it or fall back to PDF/scraping/manual input
- Apply `testingRequirements` from the API (User-Agent, custom headers) to all testing agents
- Parse scope from user-provided program data (API, PDF, URL, or manual input)
- **Auto-download mobile apps** from running emulators when iOS/Android assets are in scope
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only in-scope assets
- Follow program-specific rules
- Include CVSS vector string
- Select correct vulnerability type from taxonomy

**NEVER**:
- Report without validated PoC
- Test out-of-scope assets or cause service disruption
- Include real user data
- Skip mobile app download when emulators are available and mobile assets are in scope

## AI Usage Compliance (MANDATORY)

Both Intigriti and HackerOne permit AI tools but require responsible use. **Every report MUST comply:**

1. **AI Disclosure**: Add a section at the end of every report:
   ```
   ## AI Disclosure
   AI tools (Claude Code) were used to assist with [specific tasks: static analysis, script generation,
   report structuring, etc.]. The vulnerability was identified by the researcher through [method].
   All [evidence type] was [how it was obtained]. [What was NOT tested and why].
   ```

2. **No fabricated content**: NEVER include invented endpoints, placeholder URLs, generic exploit templates, or references to features/behaviors that were not actually observed in the target.

3. **All claims verified**: Every code snippet, logcat line, HTTP response, and technical detail MUST come from actual testing or analysis. If a code snippet is from decompiled source, say so. If logcat is from an emulator, say so with timestamp.

4. **Methodology transparency**: Clearly distinguish between:
   - Runtime-verified (executed on device/emulator with real output)
   - Static analysis (found in decompiled/source code but not triggered at runtime)
   - Inferred (reasonable conclusion based on code patterns but not directly confirmed)

5. **Honest CVSS & impact**: Score only confirmed impact. State mitigations and caveats upfront. Never present theoretical worst-case as confirmed impact. **ALWAYS compute CVSS scores using a calculator (Python/bash script), NEVER guess or estimate — the formulas are non-linear and guessing produces wrong scores.**

6. **No unverified escalation**: Don't claim "full account takeover" if only information leakage was demonstrated. Don't claim "remote code execution" from a code pattern without runtime proof.

**Reports that violate these rules will be closed without response and may lead to platform removal.**

## Quality Checklist

- [ ] Working PoC with poc_output.txt + visual evidence
- [ ] Accurate CVSS score with vector string (computed with calculator, not guessed)
- [ ] Correct vulnerability type from taxonomy
- [ ] Step-by-step reproduction + impact + remediation
- [ ] Sensitive data sanitized
- [ ] Mobile apps downloaded and analyzed (if in scope)
- [ ] **Business logic verified: behavior is NOT by design** (checked company service, docs, competitors)
- [ ] **AI Disclosure section included**
- [ ] **All technical claims verified against real evidence**
- [ ] **No fabricated endpoints, placeholders, or generic templates**
- [ ] **Methodology (runtime vs static vs inferred) clearly stated**

## Tools

- `tools/scope_parser.py` - Parse Intigriti scope from structured data
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Core testing functionality
- `/mobile-security` skill - Mobile app analysis
- `dom-xss-scanner` agent - Automated DOM XSS via Playwright (auto for JS targets)
- **Recon skills** (auto-parallel): `/code-repository-intel`, `/api-portal-discovery`, `/web-application-mapping`, `/security-posture-analyzer`, `/cdn-waf-fingerprinter`
- **Conditional skills**: `/cve-testing` + `/cve-poc-generator`, `/source-code-scanning`, `/ai-threat-testing`, `/authenticating`, `/cloud-security`, `/container-security`, `/burp-suite`
- **Utility agents**: `patt-fetcher` (PATT payloads on-demand), `script-generator` (optimized PoC scripts), `pentester-validator` (anti-hallucination checks)
- Pentester agent - Orchestrates testing

## Usage

```
/intigriti <program_pdf_or_url>
```
