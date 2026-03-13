# Frida MCP Setup

## Prerequisites

- Python 3.8+
- Frida 16.0+
- USB-connected device or emulator (for dynamic analysis)

## Install Frida MCP

```bash
pip install frida-mcp
```

This installs both `frida` and the MCP server wrapper.

## Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "frida": {
      "command": "frida-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

## Configure Claude Code

Add to project `.claude/settings.json`:

```json
{
  "mcpServers": {
    "frida": {
      "command": "frida-mcp",
      "args": []
    }
  }
}
```

## Device Setup

### Android Emulator

```bash
# Start emulator
emulator -avd <avd_name> -writable-system

# Push frida-server
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Android Physical Device (Rooted)

```bash
adb push frida-server /data/local/tmp/
adb shell su -c "/data/local/tmp/frida-server -D &"
```

### Remote Device

```bash
# On device: start frida-server with network listener
frida-server -l 0.0.0.0:27042

# MCP config with remote host
frida-mcp --host 192.168.1.100
```

## MCP Tools Available

| Tool | Description |
|------|-------------|
| `list_devices` | List connected Frida devices |
| `list_processes` | List running processes on device |
| `attach` | Attach to running process by name/PID |
| `spawn` | Spawn app with Frida attached |
| `execute_script` | Run JavaScript in target process |
| `load_script_file` | Load Frida script from file |

## Verification

```bash
# Check Frida installation
frida --version

# List connected devices
frida-ls-devices

# List processes on device
frida-ps -U

# Test MCP server
frida-mcp --help
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| frida-server not running | Push and start on device: `adb shell /data/local/tmp/frida-server &` |
| Permission denied | Device must be rooted or use frida-gadget for non-rooted |
| USB device not found | Check `adb devices`, ensure USB debugging enabled |
| Python version conflict | Use `python3 -m pip install frida-mcp` |
| Frida version mismatch | Match frida-server version to pip frida version exactly |
