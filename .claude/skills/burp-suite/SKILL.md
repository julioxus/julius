---
name: burp-suite
description: Burp Suite Professional integration via PortSwigger MCP - active scanning, Collaborator OOB testing, traffic replay, PoC reproduction, and sitemap analysis. Use when performing professional web application security testing with Burp Suite.
---

# Burp Suite Integration

Orchestrates Burp Suite Professional via PortSwigger MCP for active scanning, Collaborator testing, and PoC reproduction.

## Quick Start

```
1. Ensure Burp Suite Professional is running with MCP extension loaded
2. Verify MCP connection (SSE on http://127.0.0.1:9876)
3. Select workflow: Active Scan, Collaborator, Replay, or Sitemap Analysis
4. Execute testing and collect findings
```

## Prerequisites

- Burp Suite Professional (Community edition lacks scanner/Collaborator)
- MCP extension loaded (see `reference/MCP_SETUP.md`)
- Target in Burp scope

## Workflows

### Active Scanning

```
- [ ] Add target to Burp scope
- [ ] Configure scan profile (see reference/ACTIVE_SCAN_PROFILES.md)
- [ ] Launch active scan via MCP
- [ ] Monitor scan progress
- [ ] Review findings: filter by severity, deduplicate
- [ ] Validate findings with manual verification
- [ ] Export validated findings to output format
```

### Collaborator OOB Testing

```
- [ ] Generate Collaborator payloads via MCP
- [ ] Inject payloads into target parameters (SSRF, XXE, blind SQLi, blind XSS)
- [ ] Poll Collaborator for interactions
- [ ] Correlate interactions with injected payloads
- [ ] Document OOB findings with interaction evidence
```

See `reference/COLLABORATOR.md` for payload patterns and polling workflow.

### Traffic Replay & PoC Reproduction

```
- [ ] Capture baseline request in Burp proxy
- [ ] Send to Repeater via MCP
- [ ] Modify parameters with attack payloads
- [ ] Compare responses (status, length, content)
- [ ] Build PoC from successful replays
- [ ] Generate poc.py from validated request/response pairs
```

### Sitemap Analysis

```
- [ ] Crawl target via Burp spider
- [ ] Export sitemap tree via MCP
- [ ] Identify: hidden endpoints, admin panels, API routes, file uploads
- [ ] Cross-reference with web-application-mapping results
- [ ] Feed discovered endpoints to attack workflows
```

## MCP Tool Reference

| Capability | Description |
|------------|-------------|
| Scanner | Launch/monitor active scans, retrieve issues |
| Collaborator | Generate payloads, poll interactions |
| Sitemap | Export site tree, filter by path/type |
| Repeater | Send/modify requests, compare responses |
| Proxy | Intercept/modify traffic |

## Integration

**With Pentester Executor**: Burp as primary attack tool
- Executor mounts attack skill → uses Burp MCP for payload delivery
- Collaborator for blind vulnerability confirmation
- Repeater for manual PoC reproduction

**With Web Application Mapping**: Sitemap data feeds reconnaissance
- Spider results → endpoint inventory
- Content discovery → hidden paths

## Output Structure

```
outputs/<target>/
├── findings/
│   ├── finding-NNN/
│   │   ├── report.md          # Finding details
│   │   ├── poc.py             # Reproduced from Burp Repeater
│   │   ├── poc_output.txt     # Execution proof
│   │   └── burp-evidence/     # Burp-specific artifacts
│   │       ├── request.txt    # Raw HTTP request
│   │       ├── response.txt   # Raw HTTP response
│   │       └── collaborator/  # OOB interaction logs
├── scans/
│   ├── active-scan-results.json
│   └── scan-config.json
└── sitemap/
    └── sitemap-export.json
```

## Critical Rules

- **Burp Pro required** - Community edition lacks scanner and Collaborator
- **MCP extension must be loaded** before invoking this skill
- **Verify MCP connectivity** at start of each session
- **Respect scan scope** - only scan authorized targets
- **Validate all scanner findings** - automated results need manual confirmation
- Never run active scans without explicit authorization
- Rate-limit scans to avoid target disruption

## Tools

- `reference/MCP_SETUP.md` - Installation and configuration
- `reference/ACTIVE_SCAN_PROFILES.md` - Scan profile selection
- `reference/COLLABORATOR.md` - OOB testing workflow
