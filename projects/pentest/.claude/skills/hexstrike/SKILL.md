---
name: hexstrike
description: HexStrike AI MCP integration for autonomous security testing - 150+ tools across network recon, web app testing, binary analysis, cloud security, and bug bounty workflows. Use when orchestrating multi-tool pentesting via HexStrike MCP server.
---

# HexStrike AI Integration

Orchestrates HexStrike AI MCP server (v6.0) for autonomous security testing with 150+ tools and 12+ AI agents.

## Quick Start

```
1. Ensure HexStrike server is running (python3 hexstrike_server.py)
2. Verify MCP connection on http://localhost:8888
3. Select workflow: Recon, Web Testing, Bug Bounty, or Full Pentest
4. Execute and collect findings
```

## Prerequisites

- Python 3.8+ with `requests` and `fastmcp`
- HexStrike AI cloned and installed (see `reference/SETUP.md`)
- HexStrike Flask server running locally
- MCP server connected to Claude

## Workflows

### Network Reconnaissance

```
- [ ] Run subfinder/amass for subdomain enumeration
- [ ] Execute nmap_scan() for port/service discovery
- [ ] Use httpx_scan() for live host detection
- [ ] Run rustscan_scan() for fast port sweep
- [ ] Correlate results into target inventory
- [ ] Feed inventory to web testing workflows
```

### Web Application Testing

```
- [ ] Run gobuster_scan()/ffuf for directory discovery
- [ ] Execute nuclei_scan() with relevant templates
- [ ] Use sqlmap_scan() for injection testing
- [ ] Run dalfox for XSS detection
- [ ] Test JWT with jwt_tool if auth tokens found
- [ ] Check WAF with wafw00f before aggressive testing
- [ ] Validate findings manually
```

### Bug Bounty Automation

```
- [ ] Use ai_analyze_target() for initial assessment
- [ ] Run bugbounty_reconnaissance() for asset discovery
- [ ] Deploy parallel tool chains per asset type
- [ ] Correlate findings with ai_select_tools()
- [ ] Validate and deduplicate results
- [ ] Generate platform-ready submissions
```

### Binary Analysis

```
- [ ] Use ghidra_analyze() for static analysis
- [ ] Run radare2_analyze() for disassembly
- [ ] Execute gdb_debug() for dynamic analysis
- [ ] Check with binwalk for embedded files
- [ ] Use checksec for binary protections
```

### Cloud & Container Security

```
- [ ] Run prowler_assess() for AWS/Azure/GCP
- [ ] Execute trivy_scan() for container vulnerabilities
- [ ] Use kube_hunter_scan() for Kubernetes
- [ ] Check Docker Bench Security
```

## Tool Categories (Quick Reference)

| Category | Count | Key Tools |
|----------|-------|-----------|
| Network & Recon | 25+ | nmap, rustscan, amass, subfinder, httpx |
| Web App Security | 40+ | nuclei, sqlmap, gobuster, ffuf, dalfox |
| Auth & Credentials | 12+ | hydra, john, hashcat, jwt-tool |
| Binary Analysis | 25+ | ghidra, radare2, gdb, binwalk, pwntools |
| Cloud & Container | 20+ | prowler, trivy, kube-hunter, checkov |
| Bug Bounty & OSINT | 20+ | amass, subfinder, shodan, recon-ng |
| CTF & Forensics | 20+ | volatility, steghide, exiftool, cyberchef |

See `reference/TOOLS.md` for complete tool listing with MCP function signatures.

## AI Agents

HexStrike provides 12+ autonomous agents for intelligent orchestration:

| Agent | Purpose |
|-------|---------|
| IntelligentDecisionEngine | Tool selection & parameter optimization |
| BugBountyWorkflowManager | Automated bug hunting workflows |
| CVEIntelligenceManager | Real-time CVE tracking & exploit matching |
| TechnologyDetector | Target tech stack identification |
| VulnerabilityCorrelator | Attack chain discovery |
| AIExploitGenerator | Automated exploit development |

See `reference/AI_AGENTS.md` for full agent descriptions and usage patterns.

## Integration with Pentest Workflow

**With Pentester Orchestrator**: HexStrike as primary tool backend
- Orchestrator deploys executors → executors call HexStrike MCP tools
- AI agents handle tool selection and parameter tuning
- Results feed back to orchestrator for aggregation

**With Bug Bounty Agents (HackerOne/Intigriti)**:
- HexStrike recon tools for asset discovery phase
- Web testing tools for vulnerability detection
- AI agents for finding correlation and deduplication

**With Burp Suite**: Complementary coverage
- HexStrike for automated scanning (nuclei, sqlmap)
- Burp for manual testing and PoC reproduction
- Cross-validate findings between both

## Output Structure

```
outputs/{target}/
├── findings/
│   └── finding-NNN/
│       ├── report.md
│       ├── poc.py
│       ├── poc_output.txt
│       └── hexstrike-evidence/
│           ├── tool-output.json
│           └── scan-results/
├── recon/
│   ├── subdomains.json
│   ├── ports.json
│   └── technologies.json
└── scans/
    ├── nuclei-results.json
    ├── nmap-results.xml
    └── sqlmap-results/
```

## Critical Rules

- **HexStrike server must be running** before invoking any tool
- **Verify MCP connectivity** at session start
- **Only test authorized targets** - respect scope boundaries
- **Validate automated findings** - AI-generated results need manual confirmation
- **Rate-limit aggressive scans** to avoid target disruption
- **Never use AIExploitGenerator** without explicit authorization
- Log all tool invocations to activity log
