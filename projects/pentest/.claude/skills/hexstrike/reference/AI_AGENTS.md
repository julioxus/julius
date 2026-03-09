# HexStrike AI - Autonomous Agents Reference

12+ AI agents built into HexStrike for intelligent security testing orchestration.

## Core Agents

### IntelligentDecisionEngine

**Purpose**: Selects optimal tools and parameters based on target context.

**When to use**: At the start of any engagement, or when switching between testing phases.

**How it works**:
- Analyzes target technology stack, exposed services, and known vulnerabilities
- Recommends tool chain with optimized parameters
- Adapts recommendations based on previous scan results

**Integration**: Call `ai_select_tools(context)` with target info and phase.

### BugBountyWorkflowManager

**Purpose**: Automates the full bug bounty lifecycle from recon to reporting.

**When to use**: Bug bounty engagements on HackerOne, Intigriti, or Bugcrowd.

**Workflow**:
1. Asset discovery and enumeration
2. Technology detection and fingerprinting
3. Vulnerability scanning with prioritized templates
4. Finding validation and deduplication
5. Report generation in platform format

**Integration**: Call `bugbounty_reconnaissance(target)` to start.

### CVEIntelligenceManager

**Purpose**: Real-time CVE tracking, correlation with target services, and exploit matching.

**When to use**: After service detection (nmap/httpx) to identify known vulns.

**Capabilities**:
- Matches detected services/versions against CVE databases
- Provides CVSS scores and exploit availability
- Suggests Nuclei templates for detected CVEs
- Tracks emerging vulnerabilities in real-time

### TechnologyDetector

**Purpose**: Identifies target technology stack (frameworks, languages, servers, CMS).

**When to use**: During reconnaissance phase before selecting attack tools.

**Detection methods**:
- HTTP header analysis
- Response fingerprinting
- JavaScript framework detection
- CMS identification (WordPress, Drupal, Joomla)
- API framework detection (REST, GraphQL, gRPC)

### VulnerabilityCorrelator

**Purpose**: Discovers attack chains by correlating individual findings.

**When to use**: After initial scanning to find compound vulnerabilities.

**Examples**:
- SSRF + internal service → internal network access
- Open redirect + OAuth → account takeover
- XSS + CSRF → stored attack chain
- Info disclosure + known CVE → RCE

### AIExploitGenerator

**Purpose**: Generates proof-of-concept exploits for confirmed vulnerabilities.

**When to use**: After vulnerability confirmation, with explicit authorization only.

**Capabilities**:
- Generates PoC scripts (Python, Bash)
- Creates reproduction steps
- Builds curl-based one-liners
- Adapts exploits to target environment

**WARNING**: Only use with explicit authorization in scope.

## Support Agents

### CTFWorkflowManager

Automates CTF challenge solving across categories: web, crypto, pwn, reverse, forensics, misc.

### RateLimitDetector

Detects and adapts to rate limiting, WAF blocking, and IP-based restrictions. Adjusts scan speed and rotation strategies.

### FailureRecoverySystem

Handles tool failures, timeouts, and crashes. Retries with alternative parameters or fallback tools.

### PerformanceMonitor

Tracks resource usage, scan progress, and estimated completion times. Alerts on bottlenecks.

### ParameterOptimizer

Tunes tool parameters based on target responsiveness. Adjusts threads, delays, and wordlists dynamically.

### GracefulDegradation

When tools fail or are unavailable, provides alternative approaches and manual testing guidance.

## Agent Orchestration Pattern

```
User Request
    ↓
IntelligentDecisionEngine → selects tools & params
    ↓
TechnologyDetector → identifies target stack
    ↓
[Parallel tool execution via MCP]
    ↓
CVEIntelligenceManager → correlates with known vulns
    ↓
VulnerabilityCorrelator → discovers attack chains
    ↓
AIExploitGenerator → generates PoCs (if authorized)
    ↓
BugBountyWorkflowManager → formats submissions
```

## Integration with Community Tools Agents

HexStrike AI agents complement (not replace) our orchestrator/executor pattern:

- **Pentester Orchestrator** delegates tool selection to `IntelligentDecisionEngine`
- **Pentester Executor** calls HexStrike tools directly via MCP
- **HackerOne/Intigriti agents** use `BugBountyWorkflowManager` for recon phase
- **CVEIntelligenceManager** feeds into vulnerability correlation during testing
