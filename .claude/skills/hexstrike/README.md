# HexStrike AI MCP Integration

Integration skill for [HexStrike AI](https://www.hexstrike.com/) v6.0 - an AI-powered offensive security framework with 150+ tools and 12+ autonomous agents accessible via MCP.

## Features

- 150+ security tools across 7 categories (network, web, binary, cloud, OSINT, CTF, auth)
- 12+ AI agents for intelligent tool selection and workflow automation
- Bug bounty workflow automation with asset discovery and finding correlation
- Integration with existing pentest orchestrator and bug bounty agents
- Complementary to Burp Suite MCP for comprehensive coverage

## Setup

1. Clone and install HexStrike AI (see `reference/SETUP.md`)
2. Start the Flask server: `python3 hexstrike_server.py`
3. Configure MCP connection in Claude settings
4. Invoke with `/hexstrike` or through pentest orchestrator

## Usage

```
/hexstrike           # Launch hexstrike workflow selection
/pentest             # Uses hexstrike tools via orchestrator
/hackerone            # HexStrike recon feeds bug bounty workflow
/intigriti            # HexStrike recon feeds Intigriti workflow
```

## Requirements

- Python 3.8+
- HexStrike AI repository cloned locally
- Network access to target (authorized testing only)
- Kali Linux recommended for full tool availability

## Reference

- `reference/SETUP.md` - Installation & MCP configuration
- `reference/TOOLS.md` - Complete tool listing (150+)
- `reference/AI_AGENTS.md` - AI agent descriptions and patterns
