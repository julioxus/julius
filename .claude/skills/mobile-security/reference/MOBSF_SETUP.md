# MobSF MCP Setup

## Prerequisites

- Docker (recommended) or Python 3.8+
- Node.js 18+ (for MCP server)
- 4GB+ RAM available

## Install MobSF

### Docker (Recommended)

```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

### Python

```bash
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh  # or setup.bat on Windows
./run.sh     # Starts on http://localhost:8000
```

## Get API Key

1. Open `http://localhost:8000` in browser
2. Navigate to API Docs: `http://localhost:8000/api_docs`
3. Copy the REST API key from the page header

## Install MCP Server

```bash
git clone https://github.com/pullkitsan/mobsf-mcp-server.git
cd mobsf-mcp-server
npm install
```

Create `.env` in the MCP server directory:

```env
MOBSF_URL=http://localhost:8000
MOBSF_API_KEY=your_api_key_here
```

## Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mobsf": {
      "command": "npx",
      "args": ["tsx", "/path/to/mobsf-mcp-server/server.ts"],
      "env": {
        "MOBSF_URL": "http://localhost:8000",
        "MOBSF_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Configure Claude Code

Add to project `.claude/settings.json`:

```json
{
  "mcpServers": {
    "mobsf": {
      "command": "npx",
      "args": ["tsx", "/path/to/mobsf-mcp-server/server.ts"],
      "env": {
        "MOBSF_URL": "http://localhost:8000",
        "MOBSF_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Supported File Types

| Type | Extension | Platform |
|------|-----------|----------|
| Android APK | `.apk` | Android |
| Android App Bundle | `.aab` | Android |
| iOS IPA | `.ipa` | iOS |
| Source ZIP | `.zip` | Android/iOS |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| MobSF not accessible | Verify Docker container running: `docker ps` |
| API key invalid | Regenerate from `http://localhost:8000/api_docs` |
| Scan timeout | Increase timeout in MCP server config, check app size |
| Upload fails | Check file format (APK/IPA), verify disk space |
