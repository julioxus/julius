# Agent Output Structure

All pentest agents follow standardized output formats. This supplements the main output structure at `.claude/skills/pentest/reference/OUTPUT_STRUCTURE.md` with agent-specific log and validation formats.

## Activity Log (NDJSON)

**Location**: `outputs/{engagement}/processed/activity/{agent-name}.log`

**Format**: One JSON object per line

**Orchestrator logs**:
```json
{"timestamp":"2026-01-15T10:00:00Z","agent":"pentester-orchestrator","phase":"init","target":"example.com","result":"success"}
{"timestamp":"2026-01-15T10:05:00Z","agent":"pentester-orchestrator","phase":"recon","action":"deploy-executors","result":"4 recon agents deployed"}
{"timestamp":"2026-01-15T10:20:00Z","agent":"pentester-orchestrator","phase":"planning","action":"create-plan","executors":15,"result":"plan-ready"}
{"timestamp":"2026-01-15T10:30:00Z","agent":"pentester-orchestrator","phase":"testing","action":"deploy-executors","count":15,"result":"success"}
```

**Executor logs**:
```json
{"timestamp":"2026-01-15T10:30:45Z","agent":"sql-injection-executor","action":"recon","target":"https://target.com/login","result":"found 3 parameters"}
{"timestamp":"2026-01-15T10:31:12Z","agent":"sql-injection-executor","action":"experiment","payload":"' OR '1'='1","result":"error - WAF blocked"}
{"timestamp":"2026-01-15T10:32:05Z","agent":"sql-injection-executor","action":"test","payload":"' UNION SELECT NULL--","result":"success - 200 OK"}
{"timestamp":"2026-01-15T10:33:20Z","agent":"sql-injection-executor","action":"verify","finding":"finding-001","result":"PoC confirmed"}
```

**Fields**:
- `timestamp` - ISO 8601 format
- `agent` - Agent name (lowercase-hyphenated)
- `phase` - Orchestrator: init, recon, planning, testing, aggregate, reporting
- `action` - Specific action: recon, experiment, test, verify, deploy-executors, create-plan
- `target` - URL or endpoint tested
- `payload` - Attack payload (if applicable)
- `result` - Outcome description

## Finding Structure

**Location**: `outputs/{engagement}/processed/findings/finding-{NNN}/`

**Required files**:
```
finding-NNN/
├── description.md    # Writeup-style: details, inline evidence, PoC, remediation
├── poc.py           # Automated exploit script
├── poc_output.txt   # Script execution proof
├── workflow.md      # Manual reproduction steps
└── evidence/        # Screenshots, HTTP logs, videos
    ├── raw-source.txt   # Raw tool output (required for validator cross-reference)
    ├── request.txt
    ├── response.txt
    └── screenshot.png   # Required for browser-renderable vulns
```

### description.md — Writeup Format

Each `description.md` is a self-contained writeup. A reader should understand the vulnerability, see the proof, and know how to fix it without opening any other file.

**MANDATORY inline evidence**:
- Screenshots embedded as `![Caption](evidence/screenshot.png)` with descriptive captions
- HTTP request/response included as fenced code blocks (```http)
- Core PoC code shown inline (not just "see poc.py")
- Each image must have a `*Figure N: description*` caption explaining what it proves

This format feeds directly into the final report — the report generator copies these writeup sections into the findings body, so inline evidence here = inline evidence in the DOCX/PDF.

## Validation Results

**Validated findings**: `outputs/{engagement}/data/validated/{finding-id}.json`
**Rejected findings**: `outputs/{engagement}/data/false-positives/{finding-id}.json`

One JSON file per finding, written by the `pentester-validator` agent during Phase 4.5. Contains per-check pass status and detail strings.

Rejected findings are preserved for human review — they do NOT appear in the final report, but this directory is the sole record.

## Aggregated Report

**JSON**: `outputs/{engagement}/report/pentest-report.json`
**DOCX**: `outputs/{engagement}/report/Penetration-Test-Report.docx`

## Rules

- **Always log**: Every action to activity log
- **Always capture**: Real evidence for every finding (visual for browser vulns, raw output for server vulns)
- **Always verify**: Working PoC required
- **No theoreticals**: Only confirmed vulnerabilities
- **Always preserve rejected findings**: Write to `data/false-positives/` for human review
