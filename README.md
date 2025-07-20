# Pwno MCP Server

An MCP (Model Context Protocol) server for autonomous low-level security research, providing GDB/pwndbg functionality for LLM interaction.

## Overview

Pwno MCP is designed to run in containerized environments (K8s) and expose debugging capabilities through the Model Context Protocol. Each container runs an isolated instance with its own GDB session, making it perfect for parallel security research tasks.

## Architecture

```
┌─────────────┐     MCP Protocol      ┌──────────────┐
│ LLM/Client  │ ◄─────────────────────► │ Pwno MCP     │
└─────────────┘                        │   Server     │
                                       └──────┬───────┘
                                              │
                                       ┌──────▼───────┐
                                       │ GDB/pwndbg   │
                                       │  Controller  │
                                       └──────┬───────┘
                                              │
                                       ┌──────▼───────┐
                                       │   Target     │
                                       │   Binary     │
                                       └──────────────┘
```

## Features

- **Execute Tool**: Run arbitrary GDB/pwndbg commands
- **Launch Tool**: Load and run binaries with full control
- **Step Control**: Support for all stepping commands (run, c, n, s, ni, si)
- **Context Retrieval**: Get registers, stack, disassembly, code, and backtrace
- **Breakpoint Management**: Set conditional breakpoints
- **Memory Operations**: Read memory in various formats
- **Session State**: Track debugging session state and history

## Installation

### From Source

```bash
git clone https://github.com/your-org/pwno-mcp.git
cd pwno-mcp
pip install -e .
```

### Using pip

```bash
pip install pwno-mcp
```

## Prerequisites

- GDB with Python support
- pwndbg installed and configured in `~/.gdbinit`
- Python 3.8+

## Usage

### Running the Server

```bash
python -m pwnomcp
```

### Docker Deployment

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    git \
    wget

# Install pwndbg
RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

# Install pwno-mcp
COPY . /app
WORKDIR /app
RUN pip install -e .

# Run the MCP server
CMD ["python", "-m", "pwnomcp"]
```

### MCP Tools

#### 1. Execute
Execute any GDB/pwndbg command:
```json
{
  "tool": "execute",
  "arguments": {
    "command": "info registers"
  }
}
```

#### 2. Launch
Launch a binary for debugging:
```json
{
  "tool": "launch",
  "arguments": {
    "binary_path": "/path/to/binary",
    "args": "arg1 arg2",
    "mode": "run"
  }
}
```

#### 3. Step Control
Control program execution:
```json
{
  "tool": "step_control",
  "arguments": {
    "command": "n"
  }
}
```

#### 4. Get Context
Retrieve debugging context:
```json
{
  "tool": "get_context",
  "arguments": {
    "context_type": "all"
  }
}
```

#### 5. Set Breakpoint
Set breakpoints with optional conditions:
```json
{
  "tool": "set_breakpoint",
  "arguments": {
    "location": "main",
    "condition": "$rax == 0"
  }
}
```

#### 6. Get Memory
Read memory at specific addresses:
```json
{
  "tool": "get_memory",
  "arguments": {
    "address": "0x400000",
    "size": 128,
    "format": "hex"
  }
}
```

#### 7. Get Session Info
Get current debugging session information:
```json
{
  "tool": "get_session_info",
  "arguments": {}
}
```

## Development

### Project Structure

```
pwnomcp/
├── __init__.py
├── __main__.py
├── server.py          # FastMCP server implementation
├── gdb/
│   ├── __init__.py
│   └── controller.py  # GDB/pygdbmi interface
├── state/
│   ├── __init__.py
│   └── session.py     # Session state management
└── tools/
    ├── __init__.py
    └── pwndbg.py      # MCP tool implementations
```

### Key Design Decisions

1. **Synchronous Tool Execution**: Unlike pwndbg-gui, each MCP tool invocation returns complete results immediately, suitable for LLM interaction.

2. **State Management**: The server maintains session state including binary info, breakpoints, watches, and command history.

3. **GDB/MI Native Commands**: Leverages GDB Machine Interface commands for structured output, as recommended in the [pygdbmi documentation](https://cs01.github.io/pygdbmi/):
    - `-file-exec-and-symbols` instead of `file` for loading binaries
    - `-break-insert` instead of `break` for structured breakpoint data
    - `-exec-run`, `-exec-continue`, `-exec-next`, etc. for execution control
    - `-data-evaluate-expression` for expression evaluation
    - `-break-list`, `-break-delete`, `-break-enable/disable` for breakpoint management
    
    This provides structured JSON-like responses instead of parsing text output, making the server more reliable and efficient.

4. **Per-Container Isolation**: Each container runs its own GDB instance, ensuring complete isolation between debugging sessions.

## Future Enhancements

- WebSocket endpoint for streaming I/O
- Advanced memory analysis tools
- Heap exploitation helpers
- ROP chain generation
- Symbolic execution integration

## License

MIT License

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.