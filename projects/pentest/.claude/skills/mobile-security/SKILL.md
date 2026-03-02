---
name: mobile-security
description: Mobile application security testing combining MobSF static analysis (APK/IPA) and Frida dynamic instrumentation. Tests for OWASP Mobile Top 10 vulnerabilities including insecure data storage, weak cryptography, and insufficient transport security.
---

# Mobile Application Security

Orchestrates mobile app security testing via MobSF (static) and Frida (dynamic) MCP integrations.

## Quick Start

```
1. Input: APK (Android) or IPA (iOS) file path
2. Run static analysis via MobSF MCP
3. Run dynamic analysis via Frida MCP (if device available)
4. Map findings to OWASP Mobile Top 10
5. Generate mobile security report
```

## Prerequisites

- **MobSF**: Running locally on `http://localhost:8000` (see `reference/MOBSF_SETUP.md`)
- **Frida**: Python 3.8+, `frida-mcp` installed (see `reference/FRIDA_SETUP.md`)
- **Device/Emulator**: Android emulator or rooted device (for dynamic analysis)

## Workflows

### Static Analysis (MobSF)

```
- [ ] Upload APK/IPA to MobSF via MCP scanFile tool
- [ ] Review manifest/plist analysis (permissions, exported components)
- [ ] Check code analysis (hardcoded secrets, weak crypto, insecure APIs)
- [ ] Review network security config (cleartext traffic, cert pinning)
- [ ] Check binary protections (PIE, stack canary, ARC)
- [ ] Map findings to OWASP Mobile Top 10 (reference/OWASP_MOBILE_TOP10.md)
- [ ] Prioritize findings by severity
```

### Dynamic Analysis (Frida)

```
- [ ] Connect to target device/emulator via Frida MCP
- [ ] Attach to running application process
- [ ] Bypass SSL pinning (reference/FRIDA_SCRIPTS.md)
- [ ] Bypass root/jailbreak detection
- [ ] Hook sensitive API calls (crypto, file I/O, network)
- [ ] Inspect runtime data (tokens, keys, credentials)
- [ ] Test for insecure data storage (SharedPreferences, Keychain abuse)
- [ ] Capture and analyze API traffic
```

### Combined Assessment

```
- [ ] Run static analysis first → identify targets for dynamic testing
- [ ] Static findings guide Frida hooks (e.g., hardcoded key → hook crypto functions)
- [ ] Dynamic testing validates static findings (e.g., exported activity → test exploitation)
- [ ] Cross-reference: static secrets + dynamic runtime behavior
- [ ] Generate combined report with both analysis types
```

## MCP Tool Reference

| Tool | Source | Capabilities |
|------|--------|--------------|
| MobSF `scanFile` | mobsf-mcp-server | Upload + scan APK/IPA, full static analysis |
| Frida process management | frida-mcp | List/attach processes, spawn apps |
| Frida JS REPL | frida-mcp | Execute JavaScript in target process |
| Frida script injection | frida-mcp | Load and run Frida scripts |

## Output Structure

```
outputs/<app-name>/
├── findings/
│   ├── finding-NNN/
│   │   ├── report.md           # Finding with OWASP Mobile mapping
│   │   ├── poc.py              # Exploitation PoC (Frida script or HTTP)
│   │   ├── poc_output.txt      # Execution proof
│   │   └── evidence/
│   │       ├── mobsf-scan.json # MobSF scan results
│   │       └── frida-logs/     # Frida hook outputs
├── static-analysis/
│   ├── mobsf-report.json       # Full MobSF output
│   ├── manifest-analysis.md    # Permissions and components
│   └── code-analysis.md        # Source code findings
├── dynamic-analysis/
│   ├── frida-session.log       # Runtime hook logs
│   ├── api-traffic.json        # Captured API calls
│   └── runtime-secrets.md      # Discovered secrets/tokens
└── reports/
    └── mobile-security-report.md
```

## Integration

**With Pentester Orchestrator**: Mobile-specific attack vector
- API endpoints discovered → feed to web testing workflows
- Authentication tokens captured → test for session vulnerabilities

**OWASP Mobile Top 10 Mapping**: See `reference/OWASP_MOBILE_TOP10.md`

## Critical Rules

- **Static analysis first** — always run MobSF before dynamic testing
- **Never test on production devices** with real user data
- **Obtain authorization** before instrumenting apps
- **Sanitize captured data** — tokens, keys, user data must be redacted in reports
- **Document Frida scripts used** — include in PoC for reproducibility
- Root/jailbreak bypass is for testing only — document findings, not evasion techniques

## Tools

- `reference/MOBSF_SETUP.md` - MobSF installation and MCP config
- `reference/FRIDA_SETUP.md` - Frida MCP installation
- `reference/OWASP_MOBILE_TOP10.md` - Vulnerability classification
- `reference/FRIDA_SCRIPTS.md` - Common Frida scripts
