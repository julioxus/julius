# Core Agents

7 agents: security testing orchestration + execution + validation + deep exploitation + bug bounty automation + threat intelligence.

## Artifact Discipline (ALL AGENTS)

**NEVER write any file to the project root or current working directory.** Every file an agent produces — tool output, downloads, scripts, certificates, keys, tickets, captures, dumps, reports, evidence — MUST go into a structured `outputs/` subtree.

### Directory Structure

```
outputs/{engagement-name}/
├── processed/              # All working/testing artifacts
│   ├── reconnaissance/     # Nmap, dirsearch, fingerprinting results
│   ├── findings/           # Per-finding descriptions, PoCs, workflows
│   │   └── finding-NNN/
│   │       ├── description.md
│   │       ├── poc.py
│   │       ├── poc_output.txt
│   │       ├── workflow.md
│   │       └── evidence/
│   ├── activity/           # NDJSON activity logs
│   ├── helpers/            # Testing utilities
│   ├── test-frameworks/    # Testing scripts
│   └── intermediate-reports/
├── report/                 # Final deliverables only
│   ├── Penetration-Test-Report.docx
│   ├── pentest-report.json
│   └── appendix/
│       └── finding-NNN/
└── data/                   # Validation results
    ├── validated/
    └── false-positives/
```

### Enforcement Rules

1. **Before running any tool that generates output files** (certipy, impacket, openssl, nmap, secretsdump, bloodhound, sqlmap, dirsearch, etc.), either:
   - Use the tool's `-o`/`-out`/`-output`/`-oN` flag to write directly into the right subdirectory, OR
   - `cd` into the target subdirectory first, OR
   - `mv` the file immediately after generation
2. **Create directories on first use**: `mkdir -p outputs/{engagement}/processed/{reconnaissance,findings,activity,helpers,test-frameworks,intermediate-reports}`
3. **Orchestrators**: create the full directory tree before spawning sub-agents, pass the output path in the prompt
4. **Applies to ALL file types**: certificates, keys, tickets, pcaps, wordlists, scripts, hash files, database dumps, downloaded source code, git dumps, screenshots — no exceptions
5. **Two-folder deliverable rule**: `report/` = final deliverables only. ALL intermediate files go to `processed/`

## Credential & Environment Variable Loading (ALL AGENTS)

**MANDATORY**: Before using `AskUserQuestion` to ask the user for credentials, API keys, tokens, or any configuration value, ALWAYS read from `.env` first:

```bash
python3 .claude/tools/env-reader.py VAR1 VAR2 VAR3
```

Only ask the user if `env-reader.py` returns `NOT_SET` for the needed variable. This applies to ALL agents.

**NEVER** try to read `.env` files directly via `source .env`, `cat .env`, or `echo $VAR` in Bash — these will always fail because each Bash invocation is a fresh shell with no `.env` loaded. The `env-reader.py` tool parses `.env` files reliably via Python.

## Safety Rails (ALL EXECUTOR AGENTS)

**MANDATORY**: Before sending any outbound HTTP request, run:
```bash
python3 tools/safety_rails.py preflight <METHOD> <URL>
```
This enforces circuit breaking (stop after 5 consecutive failures per host, 300s cooldown), rate limiting (10 req/s recon, 2 req/s active), and safe method policy (GET/HEAD auto-allowed, DELETE/PATCH blocked). Never bypass safety rails.

## Scope Checker (ALL EXECUTOR AGENTS)

**MANDATORY**: Before any outbound request, verify the target is in scope:
```bash
python3 tools/scope_checker.py check <target> --scope <SCOPE_FILE>
```
Exit code 0 = in scope, exit code 1 = out of scope. SCOPE_FILE path is provided in the mission prompt.

## Agents

| Agent | Role | Delegates To |
|-------|------|-------------|
| pentester-orchestrator | Plan, dispatch parallel executors, adapt, aggregate | pentester-executor, pentester-validator |
| pentester-executor | Execute specific vulnerability tests | patt-fetcher (for fresh payloads) |
| hackerone-intel-fetcher | On-demand program/vuln intelligence from 14.5K disclosed reports | None |
| pentester-validator | Validate individual findings against raw evidence | None |
| dom-xss-scanner | Automated DOM XSS detection via Playwright | None |
| script-generator | Generate optimized, validated scripts | None |
| skiller | Skill creation and management | None |

## Interaction Model

**Single asset**: User → `/pentest` → Orchestrator (plans → dispatches) → Executors → Validator → Report

**Bug bounty**: User → `/hackerone` or `/intigriti` (parses scope) → `/pentest` (sub-orchestrator mode) → Orchestrator → Executors → Validator → Platform Submissions

**DefectDojo**: User → `/defectdojo` (manages engagement) → `/pentest` (sub-orchestrator mode, SAST+DAST) → Orchestrator → Executors → Validator → DefectDojo Import

**Script generation**: Any agent → `script-generator` (recommended for scripts >30 lines, parallel operations, or multi-library patterns)

**PayloadsAllTheThings**: Any executor → `patt-fetcher` (when local payloads exhausted, fetch fresh payloads from PATT GitHub)

**HackerOne Intel**: Orchestrator Phase 1.5 → `hackerone-intel-fetcher` (program-specific disclosed reports, bounty data, attack surface signals → informs Phase 3 planning)

## Executor Specializations (30+)

- **Injection** (6): SQL, NoSQL, Command, SSTI, XXE, LDAP
- **Client-Side** (6): XSS, CSRF, Clickjacking, CORS, Prototype Pollution, DOM
- **Server-Side** (6): SSRF, HTTP Smuggling, Path Traversal, File Upload, Deserialization, Host Header
- **Authentication** (4): Bypass, JWT, OAuth, Password Attacks
- **API** (4): GraphQL, REST, WebSocket, Web LLM
- **Business Logic** (6): Logic Flaws, Race Conditions, Access Control, Cache Poisoning, Cache Deception, Info Disclosure

Each: Mounts attack skill → 4-phase workflow (Recon → Experiment → Test → Verify) → Outputs activity log + findings

## Skill Reference (for Orchestrator mission prompts)

All attack skills live in `.claude/skills/pentest/attacks/<category>/`. The orchestrator specifies the **category folder** and **escalation level** in the mission prompt. The executor picks the right file(s) within that folder.

| Category | Folder | Covers |
|----------|--------|--------|
| Injection | `attacks/injection/` | SQLi, NoSQLi, Command Injection, SSTI, XXE |
| Client-Side | `attacks/client-side/` | XSS, CSRF, CORS, Clickjacking, DOM XSS, Prototype Pollution |
| Server-Side | `attacks/server-side/` | SSRF, Path Traversal, File Upload, HTTP Smuggling, Deserialization, Host Header |
| Authentication | `attacks/authentication/` | Auth Bypass, JWT, OAuth, Password Attacks, 2FA |
| API Security | `attacks/api-security/` | GraphQL, REST API, WebSockets, Web LLM |
| Web Applications | `attacks/web-applications/` | Access Control/IDOR, Race Conditions, Business Logic, Cache Poisoning, Info Disclosure |
| Cloud & Containers | `attacks/cloud-containers/` | AWS, Azure, GCP, Docker, Kubernetes |
| System | `attacks/system/` | Active Directory, Privilege Escalation, Exploit Development |
| IP Infrastructure | `attacks/ip-infrastructure/` | Port Scanning, DNS, SMB, MitM, Sniffing, VLAN, IPv6 |

**Escalation levels** (specified in mission prompt, executor selects file):
- **quickstart** — first attempt (`quickstart.md`)
- **hackerone-intel** — real-world attack patterns + techniques from 14.5K disclosed reports (`hackerone-intel.md`, `hackerone-techniques.md`)
- **cheat-sheet** — bypass/escalation (`cheat-sheet.md`)
- **full** — all references in the folder including HackerOne writeups

## Validator

Deployed per-finding by the orchestrator after all executors complete. Reads all evidence, runs PoCs, cross-references claims against raw scan data. ALL 5 checks must pass or finding is rejected. See `pentester-validator.md`.

## Reference

- `reference/OUTPUT_STRUCTURE.md` - Log/finding formats for agents
- `reference/TEST_PLAN_FORMAT.md` - Test plan template
- `pentester-validator.md` - Finding validator agent definition
- `pentester-orchestrator.md` - Orchestrator agent definition
- `pentester-executor.md` - Executor agent definition
