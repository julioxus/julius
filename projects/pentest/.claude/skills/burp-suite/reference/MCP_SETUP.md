# Burp Suite MCP Setup

## Prerequisites

- Burp Suite Professional (v2024.x+)
- Java 17+ in PATH
- Claude Desktop or Claude Code

## Installation

### 1. Build MCP Extension

```bash
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
# Output: build/libs/burp-mcp-all.jar
```

### 2. Load Extension in Burp

1. Open Burp Suite Professional
2. Extensions → Add → Select `burp-mcp-all.jar`
3. Extension loads → MCP server starts on `http://127.0.0.1:9876`
4. Verify: Check extension output tab for "MCP server started"

### 3. Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp-suite": {
      "command": "java",
      "args": ["-jar", "/path/to/burp-mcp-all.jar", "--stdio"],
      "env": {}
    }
  }
}
```

### 4. Configure Claude Code

Add to `.claude/settings.json` or project settings:

```json
{
  "mcpServers": {
    "burp-suite": {
      "command": "java",
      "args": ["-jar", "/path/to/burp-mcp-all.jar", "--stdio"]
    }
  }
}
```

## Connection Modes

| Mode | Transport | Use Case |
|------|-----------|----------|
| SSE | `http://127.0.0.1:9876` | Direct connection when Burp is local |
| stdio | `java -jar burp-mcp-all.jar --stdio` | Claude Desktop/Code integration |

## Verification

```bash
# Check Burp extension is loaded
curl http://127.0.0.1:9876/health

# Test MCP connection (stdio mode)
echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | java -jar burp-mcp-all.jar --stdio
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Java not found | Ensure `java` is in PATH: `java -version` |
| Port 9876 in use | Change port in Burp extension settings or kill conflicting process |
| Extension won't load | Verify Burp Pro (not Community), check Java version compatibility |
| MCP timeout | Restart extension, check Burp isn't paused/suspended |
| SSL errors | Ensure Burp CA is installed if proxying HTTPS |

## Security Notes

- MCP server binds to localhost only (127.0.0.1)
- No authentication on SSE endpoint — ensure no untrusted local users
- Extension has full access to Burp project data
- Do not expose port 9876 to network
