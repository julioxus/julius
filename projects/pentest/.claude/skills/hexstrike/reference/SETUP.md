# HexStrike AI - Setup & Configuration

## Installation

```bash
# Clone repository
git clone https://github.com/0x4m4/hexstrike-ai.git
cd hexstrike-ai

# Create virtual environment
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Start Flask server
python3 hexstrike_server.py
# Server runs on http://localhost:8888
```

## MCP Configuration

### Claude Desktop

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/path/to/hexstrike_mcp.py", "--server", "http://localhost:8888"],
      "description": "HexStrike AI v6.0 - Cybersecurity Automation",
      "timeout": 300,
      "disabled": false
    }
  }
}
```

### Claude Code (settings.json)

Add to `.claude/settings.local.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__hexstrike-ai__*"
    ]
  }
}
```

### VS Code / Cursor

Add to user settings JSON:

```json
"mcp.servers": {
  "hexstrike-ai": {
    "command": "stdio",
    "env": {
      "MCP_SERVER_URL": "http://localhost:8888"
    },
    "timeout": 300
  }
}
```

## Standalone MCP Server (Alternative)

There's also a standalone MCP server package:

```bash
git clone https://github.com/b-bogus/hexstrike-ai_mcp_server.git
cd hexstrike-ai_mcp_server
pip install -r requirements.txt

# Start Flask API backend
python3 hexstrike_server.py

# Start MCP server (separate process)
python3 hexstrike_mcp_server.py --host 0.0.0.0 --port 8889
```

## Verification

```bash
# Check server is running
curl http://localhost:8888/health

# Test a simple tool
curl -X POST http://localhost:8888/api/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "options": "-sV -p 80"}'
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Server won't start | Check Python 3.8+, install deps |
| MCP not connecting | Verify server URL and port |
| Tool not found | Ensure tool is installed on system (e.g., `which nmap`) |
| Timeout errors | Increase timeout in MCP config (default 300s) |
| Permission denied | Run tools that need root with appropriate permissions |

## Network Architecture

```
Claude Code → MCP Protocol → hexstrike_mcp.py → Flask API → Security Tools
                                                  (8888)      (system)
```

The MCP server acts as a bridge between Claude and the HexStrike Flask API, which orchestrates the actual security tool execution on the system.
