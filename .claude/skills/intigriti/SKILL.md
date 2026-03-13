---
name: intigriti
description: Intigriti bug bounty automation - parses program scope from user-provided data (PDF, URL, manual input), deploys parallel pentesting agents for domain-based assets with tier prioritization, auto-downloads mobile apps from running emulators, validates PoCs, and generates Intigriti-formatted submission reports with vulnerability type taxonomy. Use when testing Intigriti programs or preparing European bug bounty submissions.
---

# Intigriti Bug Bounty Hunting

Automates Intigriti workflows: scope parsing → tier-prioritized testing → mobile app acquisition → PoC validation → submission reports.

## Quick Start

```
1. Input: Intigriti program page (PDF, URL, or manual scope description)
2. Parse scope: extract assets, tiers, types, and program rules
3. For mobile assets: detect running emulators and download apps from marketplace
4. Deploy Pentester agents in parallel (tier-prioritized)
5. Validate PoCs (poc.py + poc_output.txt required)
6. Generate Intigriti-formatted reports
```

## Scope Input Methods

**Intigriti does NOT provide a public researcher API. Scope is obtained from the program page.**

**Option 1: PDF of program page** (recommended)
```
- [ ] Read PDF with program details
- [ ] Extract assets table (name, type, tier)
- [ ] Extract bounty table, rules, out-of-scope items
- [ ] Parse into structured scope for agent deployment
```

**Option 2: Program URL (browser scraping)**
```
- [ ] User provides Intigriti program URL
- [ ] Use Playwright MCP or browser tools to load the page
- [ ] Extract scope table, bounty table, and rules
- [ ] Parse into structured scope
```

**Option 3: Manual input**
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

## Agent Deployment

**Pentester Agent** per asset (tier-prioritized):
- Tier 1 assets: Deploy first, allocate most resources
- Tier 2-3 assets: Deploy in parallel, standard resources
- Tier 4-5 assets: Deploy last, lower priority

**Mobile assets**: Deploy `/mobile-security` skill agents after app download

**Parallel Execution**:
- 8 assets = 8 Pentester Orchestrators
- Each spawns specialized agents
- Tier 1 findings reviewed first
- Mobile app analysis runs alongside web testing

## PoC Validation (CRITICAL)

**Every finding MUST have**:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. `workflow.md` - Manual steps (if applicable)
4. Evidence screenshots/videos

## Report Format

Required fields (Intigriti standard):
1. **Title** (vulnerability description, no URL)
2. **Severity** (CVSS v3.1 or v4.0 vector + score)
3. **Domain** (affected in-scope asset)
4. **Vulnerability Type** (from Intigriti taxonomy dropdown)
5. **Description** (Markdown, detailed explanation)
6. **Steps to Reproduce** (numbered, clear)
7. **Impact** (realistic attack scenario)

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
| Scope format | Domain-based (program page) | CSV file |
| Scope retrieval | PDF / URL / manual | CSV download |
| Triage | Managed by Intigriti team | Company-triaged |
| Currency | EUR | USD |
| Vuln classification | Taxonomy dropdown | Free-text |
| Bounty tiers | 1-5 (Tier 1 highest) | Per-severity |
| Report title | No URL in title | URL in title |

See `reference/PLATFORM_GUIDE.md` for full comparison.

## Critical Rules

**MUST DO**:
- Parse scope from user-provided program data (PDF, URL, or manual input)
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

5. **Honest CVSS & impact**: Score only confirmed impact. State mitigations and caveats upfront. Never present theoretical worst-case as confirmed impact.

6. **No unverified escalation**: Don't claim "full account takeover" if only information leakage was demonstrated. Don't claim "remote code execution" from a code pattern without runtime proof.

**Reports that violate these rules will be closed without response and may lead to platform removal.**

## Quality Checklist

- [ ] Working PoC with poc_output.txt + visual evidence
- [ ] Accurate CVSS score with vector string
- [ ] Correct vulnerability type from taxonomy
- [ ] Step-by-step reproduction + impact + remediation
- [ ] Sensitive data sanitized
- [ ] Mobile apps downloaded and analyzed (if in scope)
- [ ] **AI Disclosure section included**
- [ ] **All technical claims verified against real evidence**
- [ ] **No fabricated endpoints, placeholders, or generic templates**
- [ ] **Methodology (runtime vs static vs inferred) clearly stated**

## Tools

- `tools/scope_parser.py` - Parse Intigriti scope from structured data
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Core testing functionality
- `/mobile-security` skill - Mobile app analysis
- Pentester agent - Orchestrates testing

## Usage

```
/intigriti <program_pdf_or_url>
```
