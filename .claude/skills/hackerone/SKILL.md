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

## Agent Deployment

**Pentester Agent** per asset:
- Passes program-specific guidelines
- Tests all vulnerability types
- Returns validated findings with PoCs

**Mobile assets**: Deploy `/mobile-security` skill agents after app download

**Parallel Execution**:
- 10 assets = 10 Pentester agents
- Each spawns 30+ specialized agents
- Total: 300+ concurrent tests
- Time: 2-4 hours vs 20-40 sequential
- Mobile app analysis runs alongside web testing

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

## Pre-Submission Gate (MANDATORY before reporting)

**Before submitting ANY finding, validate it passes ALL these checks:**

1. **OOS check**: Re-read the program's out-of-scope list. Is this vuln type explicitly excluded? Is the asset in scope? Check BOTH the general OOS and any platform-specific OOS (mobile/desktop).
2. **Submission requirements check**: Does the report include everything the program requires? Read the program's submission requirements — each program has its own (e.g., role used, raw HTTP requests, affected plans, reproduction steps).
3. **Impact honesty check**: Does the claimed severity match the demonstrated impact? Don't inflate.
4. **Present findings to user for review**: Show a summary of each finding with severity, evidence quality, and OOS risk assessment. Let the user decide which to submit.

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
- [ ] **AI Disclosure section included**
- [ ] **All technical claims verified against real evidence**
- [ ] **No fabricated endpoints, placeholders, or generic templates**
- [ ] **Methodology (runtime vs static vs inferred) clearly stated**

## Tools

- `tools/csv_parser.py` - Parse HackerOne scope CSVs
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Core testing functionality
- `/mobile-security` skill - Mobile app analysis
- Pentester agent - Orchestrates testing

## Integration

Uses `/pentest` skill and Pentester agent. Follows OUTPUT.md for submission format.

## Common Rejections

**Out of Scope**: Check `eligible_for_submission=true`
**Cannot Reproduce**: Validate PoC, include poc_output.txt
**Duplicate**: Search disclosed reports, submit quickly
**Insufficient Impact**: Show realistic attack scenario

## Usage

```bash
/hackerone <program_url_or_csv_path>
```
