# IDA Pro Proxy MCP

Multi-binary analysis proxy for ida-pro-mcp. Enables simultaneous analysis of multiple binary files by managing multiple idalib-mcp processes.

## Features

- **Multi-binary support**: Open and analyze multiple binary files simultaneously
- **LRU eviction**: Automatically manages process count with LRU replacement
- **Session management**: Track and switch between analysis sessions
- **Transparent routing**: Analysis tools automatically route to correct process
- **MCP compatible**: Works with any MCP-compatible client

## Installation

### Prerequisites

Before installing ida-pro-proxy-mcp, you need to install [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) first:

```bash
# Clone and install ida-pro-mcp
git clone https://github.com/mrexodia/ida-pro-mcp.git
cd ida-pro-mcp
uv pip install -e .

# Verify the installation
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

Make sure the `idalib-mcp` command is available before proceeding.

### Install ida-pro-proxy-mcp

```bash
cd ida-pro-proxy-mcp
uv pip install -e .
```

## Usage

Start the proxy server:

```bash
ida-proxy-mcp --host 127.0.0.1 --port 8744 --max-processes 2
```

### Command Line Options

- `--host`: Host to listen on (default: 127.0.0.1)
- `--port`: Port to listen on (default: 8744)
- `--max-processes`: Maximum concurrent idalib-mcp processes (default: 2)
- `--config`: Path to configuration file
- `--verbose, -v`: Enable verbose logging

### Configuration File

Create a JSON config file:

```json
{
  "host": "127.0.0.1",
  "port": 8744,
  "max_processes": 3,
  "base_port": 8745,
  "request_timeout": 30
}
```

## MCP Tools

### Session Management

- `idalib_open(input_path, run_auto_analysis)`: Open a binary file
- `idalib_close(session_id)`: Close a session
- `idalib_switch(session_id)`: Switch to a different session
- `idalib_list()`: List all active sessions
- `idalib_current()`: Get current session info

### Analysis Tools

All analysis tools from ida-pro-mcp are available with an additional `session` parameter:

```json
{
  "name": "decompile",
  "arguments": {
    "addr": "0x401000",
    "session": "binary.elf-1fd76"
  }
}
```

If `session` is not specified, the current active session is used.

## Session ID Format

Session IDs follow the format: `[binary-name]-[ida-session-id]`

Example: `crackme.elf-1fd76`

## Architecture

```
┌─────────────────┐
│   MCP Client    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Proxy Server   │
│  (port 8744)    │
├─────────────────┤
│ Session Manager │
│ (LRU Cache)     │
├─────────────────┤
│ Process Manager │
└────────┬────────┘
         │
    ┌────┴────┬────────┐
    ▼         ▼        ▼
┌───────┐ ┌───────┐ ┌───────┐
│idalib │ │idalib │ │idalib │
│:8745  │ │:8746  │ │:8747  │
└───────┘ └───────┘ └───────┘
```

## License

MIT
