---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, deploys parallel pentesting agents for each asset, auto-downloads mobile apps from running emulators, validates PoCs, and generates platform-ready submission reports. Use when testing HackerOne programs or preparing professional vulnerability submissions.
---

# HackerOne Bug Bounty Hunting

Automates HackerOne workflows: scope parsing → mobile app acquisition → parallel testing → PoC validation → submission reports.

## Quick Start

```
1. Input: HackerOne program URL or CSV file
2. Parse scope and program guidelines
3. Deploy Pentester agents in parallel (one per asset)
4. Validate PoCs (poc.py + poc_output.txt required)
5. Generate HackerOne-formatted reports
```

## Bounty-Driven Prioritization (MANDATORY FIRST STEP)

**BEFORE any testing, read the program scope and create a prioritized attack plan.**

1. **Parse scope completely FIRST**: Extract from the program page or CSV:
   - In-scope assets with eligibility, severity caps, and instructions
   - Bounty table or reward ranges per severity
   - Program's stated priority impacts or worst-case scenarios
   - **Full out-of-scope list** (application-level AND mobile/desktop-specific exclusions)
   - Any program-specific rules or testing limitations
2. **Map each vuln type to the program's bounty table**: Use the ACTUAL reward amounts from this specific program — don't assume generic values. Rank attack vectors from highest to lowest payout.
3. **Start with the program's stated priority vulnerabilities** — these are what the triagers care about most and signal what they'll pay top bounty for
4. **Cross-reference every planned test against the OOS list** BEFORE executing it. If a vuln type is excluded, don't waste time testing it regardless of how easy it might be to find.
5. **Chain findings for impact escalation** — a low-severity finding chained with another can reach Critical. Always think about chains that multiply impact.
6. **Drop low-impact findings quickly** if they don't chain into something bigger
7. **Check mobile/desktop-specific exclusions separately** — programs often have a dedicated exclusion list for mobile that differs from web. Read it before any APK/IPA analysis.

**Present the prioritized plan to the user BEFORE starting any testing.**

## Workflows

**Option 1: HackerOne URL**
```
- [ ] Fetch program data and guidelines
- [ ] Download scope CSV
- [ ] Parse eligible assets
- [ ] Deploy agents in parallel
- [ ] Validate PoCs
- [ ] Generate submissions
```

**Option 2: CSV File**
```
- [ ] Parse CSV scope file
- [ ] Extract eligible_for_submission=true assets
- [ ] Collect program guidelines
- [ ] Deploy agents
- [ ] Validate and generate reports
```

## Scope CSV Format

Expected columns:
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR
- `eligible_for_submission` - Must be "true"
- `max_severity` - critical, high, medium, low
- `instruction` - Asset-specific notes

Use `tools/csv_parser.py` to parse.

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
# 1. Identify target package from scope CSV (asset_type contains GOOGLE_PLAY_APP_ID or similar)
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
# 1. Identify App Store ID from scope
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

## Post-Enumeration Recon Pipeline (for WILDCARD/domain assets)

**BEFORE deploying pentester agents**, run this pipeline on wildcard/domain assets:

1. **httpx** live host detection: `httpx -l subs.txt -sc -title -tech-detect -timeout 5 -threads 50 -retries 0`
   - Pre-filter `.internal.*`/`.uat.*` subdomains (cause DNS hangs)
2. **naabu** port scan: `naabu -list hostnames.txt -top-ports 1000` (bare hostnames, NOT URLs)
   - Focus on non-standard ports (not 80/443)
3. **ffuf** directory fuzzing: `ffuf -w ~/SecLists/Discovery/Web-Content/common.txt -u "https://{host}/FUZZ" -mc 200,301,302`
   - Filter CF WAF 403s with `-fs 5453`; target non-CF hosts
4. **nuclei** vuln scan: `nuclei -l live.txt -severity medium,high,critical -timeout 10`
   - Run in background; hardened targets may yield 0 findings

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

**Pentester Agent** per asset:
- Passes program-specific guidelines
- Tests all vulnerability types
- Returns validated findings with PoCs
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
- 10 assets = 10 Pentester agents + dom-xss-scanner where applicable
- Each spawns 30+ specialized agents
- Total: 300+ concurrent tests
- Time: 2-4 hours vs 20-40 sequential
- Mobile app analysis + DOM XSS scanning run alongside web testing

**Conditional Specialized Testing (AUTOMATIC based on recon results)**:
Deploy these skills when recon or tech detection identifies specific conditions:

- **`/cve-testing`** + **`/cve-poc-generator`** — When httpx, nuclei, or tech-detect identifies specific software versions (e.g., Apache 2.4.49, jQuery 3.4.1, Spring 5.3.x). `/cve-testing` researches known CVEs and tests with public exploits. When a CVE is confirmed, `/cve-poc-generator` creates a standalone Python PoC script + detailed report with NVD data, CVSS vector, and remediation. High-value: unpatched services on non-standard ports.
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

**Experimentation**: Test edge cases, verify impact, document failures.

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
3. **Submission requirements check**: Does the report include everything the program requires? Read the program's submission requirements — each program has its own (e.g., role used, raw HTTP requests, affected plans, reproduction steps).
4. **Impact honesty check**: Does the claimed severity match the demonstrated impact? Don't inflate.
5. **Present findings to user for review**: Show a summary of each finding with severity, evidence quality, OOS risk assessment, and business logic verification result. Let the user decide which to submit.

## Report Format

Required sections (HackerOne standard):
1. Summary (2-3 sentences)
2. Severity (CVSS + business impact)
3. Steps to Reproduce (numbered, clear)
4. Raw HTTP requests/responses (text format)
5. Visual Evidence (screenshots/video)
6. Impact (realistic attack scenario)
7. Remediation (actionable fixes)

Use `tools/report_validator.py` to validate.

## Output Structure

Per OUTPUT.md - Bug Bounty format:

```
outputs/<program>/
├── apps/                         # Downloaded mobile apps
│   ├── <package>.apk
│   └── <bundle>.ipa
├── findings/
│   ├── finding-001/
│   │   ├── report.md           # HackerOne report
│   │   ├── poc.py              # Validated PoC
│   │   ├── poc_output.txt      # Proof
│   │   └── workflow.md         # Manual steps
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md  # Ready to submit
│   │   └── H1_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/
    ├── screenshots/
    └── http-logs/
```

## Program Selection

**High-Value**:
- New programs (< 30 days)
- Fast response (< 24 hours)
- High bounties (Critical: $5,000+)
- Large attack surface

**Avoid**:
- Slow response (> 1 week)
- Low bounties (Critical: < $500)
- Overly restrictive scope

## Critical Rules

**MUST DO**:
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only `eligible_for_submission=true` assets
- Follow program-specific guidelines
- Compute CVSS scores using a calculator (Python/bash), never guess or estimate
- **Auto-download mobile apps** from running emulators when iOS/Android assets are in scope

**NEVER**:
- Report without validated PoC
- Test out-of-scope assets
- Include real user data
- Cause service disruption
- Skip mobile app download when emulators are available and mobile assets are in scope

## AI Usage Compliance (MANDATORY)

Both HackerOne and Intigriti permit AI tools but require responsible use. **Every report MUST comply:**

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

Before submission:
- [ ] Working PoC with poc_output.txt
- [ ] Accurate CVSS score (computed with calculator, not guessed)
- [ ] Step-by-step reproduction
- [ ] Visual evidence
- [ ] Impact analysis
- [ ] Remediation guidance
- [ ] Sensitive data sanitized
- [ ] **Business logic verified: behavior is NOT by design** (checked company service, docs, competitors)
- [ ] **AI Disclosure section included**
- [ ] **All technical claims verified against real evidence**
- [ ] **No fabricated endpoints, placeholders, or generic templates**
- [ ] **Methodology (runtime vs static vs inferred) clearly stated**

## Tools

- `tools/csv_parser.py` - Parse HackerOne scope CSVs
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Core testing functionality
- `/mobile-security` skill - Mobile app analysis
- `dom-xss-scanner` agent - Automated DOM XSS via Playwright (auto for JS targets)
- **Recon skills** (auto-parallel): `/code-repository-intel`, `/api-portal-discovery`, `/web-application-mapping`, `/security-posture-analyzer`, `/cdn-waf-fingerprinter`
- **Conditional skills**: `/cve-testing` + `/cve-poc-generator`, `/ai-threat-testing`, `/authenticating`, `/cloud-security`, `/container-security`, `/burp-suite`
- **Utility agents**: `patt-fetcher` (PATT payloads on-demand), `script-generator` (optimized PoC scripts), `pentester-validator` (anti-hallucination checks)
- Pentester agent - Orchestrates testing

## Integration

Uses `/pentest` skill and Pentester agent. Follows OUTPUT.md for submission format.

## Common Rejections

**Out of Scope**: Check `eligible_for_submission=true`
**By Design / Not a Bug**: The reported behavior is the intended functionality of the service. ALWAYS verify business logic before reporting — understand what the company does and whether the "vulnerability" is actually their core product feature.
**Cannot Reproduce**: Validate PoC, include poc_output.txt
**Duplicate**: Search disclosed reports, submit quickly
**Insufficient Impact**: Show realistic attack scenario

## Usage

```bash
/hackerone <program_url_or_csv_path>
```
