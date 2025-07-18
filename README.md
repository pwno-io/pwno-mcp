# Pwno MCP

MCP server for Pwno, the Autonomous low-level security research agent. This server provides debugging capabilities through pwndbg/GDB integration for automated security research in containerized environments.

## Overview

PwnoMCP is a Model Context Protocol (MCP) server that exposes pwndbg functionality for autonomous security research agents. Each container runs its own MCP server instance with pre-configured pwndbg environment, allowing the autonomous agent to perform low-level debugging and analysis tasks.

## Features

### Core Debugging Tools

- **pwnodbg_execute**: Execute arbitrary GDB commands
- **pwnodbg_launch**: Launch binaries or attach to processes
- **pwnodbg_run**: Start execution of loaded binaries
- **pwnodbg_continue**: Continue execution after breakpoints
- **pwnodbg_step**: Single-step execution (step, next, stepi, nexti)
- **pwnodbg_context**: Display debugging context (registers, stack, code)

### Memory Analysis Tools

- **pwnodbg_heap**: Analyze heap chunks, bins, arenas, tcache
- **pwnodbg_vmmap**: Display virtual memory mappings
- **pwnodbg_search**: Search memory for patterns
- **pwnodbg_telescope**: Recursively dereference pointers
- **pwnodbg_rop**: Find and analyze ROP gadgets

### Breakpoint Management

- **pwnodbg_breakpoint**: Set, list, delete breakpoints with conditions
- **pwnodbg_watchpoint**: Set memory watchpoints (read/write/access)
- **pwnodbg_catch**: Set catchpoints for system events

### Special Features

- **pwnodbg_try_free**: Attempt to free memory chunks (heap exploitation)

### Output Management

- **pwnodbg_stdio**: Check buffered output from GDB and inferior process
- **pwnodbg_clear_stdio**: Clear all stdio buffers  
- **pwnodbg_wait_for_output**: Wait for specific output patterns

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd pwno-mcp

# Install dependencies
pip install -e .
```

## Usage

### Running the Server

```bash
python run_server.py
```

Or using the module directly:

```bash
python -m pwnomcp
```

### Docker Integration

The server is designed to run inside Docker containers with pwndbg pre-installed:

```dockerfile
FROM ubuntu:22.04

# Install pwndbg and dependencies
RUN apt-get update && apt-get install -y \
    gdb python3 python3-pip git \
    && git clone https://github.com/pwndbg/pwndbg \
    && cd pwndbg && ./setup.sh

# Install PwnoMCP
COPY . /app/pwno-mcp
WORKDIR /app/pwno-mcp
RUN pip install -e .

# Expose MCP server
CMD ["python", "-m", "pwnomcp"]
```

### Example Tool Usage

```python
# Launch a binary
{
    "tool": "pwnodbg_launch",
    "arguments": {
        "binary": "/path/to/binary",
        "args": ["arg1", "arg2"],
        "env": {"VAR": "value"}
    }
}

# Set a breakpoint
{
    "tool": "pwnodbg_breakpoint",
    "arguments": {
        "action": "set",
        "location": "main",
        "condition": "$rax == 0x1337"
    }
}

# Search memory
{
    "tool": "pwnodbg_search",
    "arguments": {
        "pattern": "flag{",
        "type": "string",
        "writable": false
    }
}

# Analyze heap
{
    "tool": "pwnodbg_heap",
    "arguments": {
        "command": "chunks"
    }
}
```

## Architecture

The server uses a modular architecture with FastMCP:

- **Core**: GDB controller wrapper with thread-safe async operations
- **Tools**: MCP tool implementations using `@mcp.tool()` decorator
- **Server**: FastMCP server with automatic tool registration
- **WebSocket**: Real-time output streaming for frontend integration

Key design patterns:

- **Non-blocking execution**: Commands execute immediately without waiting for output
- **Buffered stdio**: All output is buffered and can be retrieved via stdio tools
- **Live updates**: WebSocket server broadcasts GDB output in real-time
- **Context routing**: Intelligent routing of output to appropriate contexts
- **FastMCP integration**: Simplified tool registration and server management
- **Thread separation**: Separate threads for reading/writing GDB commands
- **State management**: Tracks inferior process state
- **Automatic .gdbinit loading**: Ensures pwndbg is properly initialized

### Output Handling Strategy

Unlike traditional approaches, this server separates command execution from output retrieval:

1. All commands execute immediately and return confirmation
2. Output is buffered in separate streams (stdout, stderr, console)
3. Agents check output using `pwnodbg_stdio` tool when needed
4. Frontend clients receive live updates via WebSocket
5. This prevents blocking and timeout issues common with GDB integration

### WebSocket Live Updates

The server includes a WebSocket server (default port 8765) that broadcasts:

- **Console output**: GDB command results
- **Context updates**: Registers, stack, code, disassembly (automatically after each command)
- **State changes**: Inferior process state transitions
- **Memory/Heap**: Memory dumps and heap analysis
- **Stdout/Stderr**: Program output streams

#### Automatic Context Updates (pwndbg-gui pattern)

Following pwndbg-gui's design, contexts are automatically updated after every user command:

1. User executes any command (via MCP tools)
2. Command output goes to console (USER token)
3. Context update commands are automatically sent
4. Context data is routed to specific components via tokens
5. Context data is cached for `pwnodbg_context` tool

This ensures the frontend always shows current state after commands like `step`, `next`, `continue`, etc.

#### WebSocket Message Format

```json
{
  "type": "console|stdout|stderr|registers|stack|code|state|...",
  "data": "output content",
  "token": 123,  // Optional command token
  "timestamp": 1234567890.123
}
```

#### Using the WebSocket Client

**HTML Client** (for web frontends):
```bash
# Open examples/websocket_client.html in a browser
```

**Python Client** (for debugging):
```bash
python examples/websocket_client.py --url ws://localhost:8765
```

**JavaScript Integration**:
```javascript
const ws = new WebSocket('ws://localhost:8765');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`${data.type}: ${data.data}`);
};
```

## Development

### Adding New Tools

Create a new tool function in `pwnomcp/tools/`:

```python
from pwnomcp.server import mcp
from pwnomcp.core.gdb_controller import gdb_controller

@mcp.tool()
async def pwnodbg_mytool(param: str) -> str:
    """
    Description of the tool
    
    Args:
        param: Parameter description
    """
    await ensure_gdb_initialized()
    
    # Tool implementation
    result = gdb_controller.execute_and_wait(f"gdb command {param}")
    return result or "Command completed"
```

The FastMCP framework automatically:
- Registers the tool with the MCP server
- Generates JSON schema from type hints
- Handles parameter validation
- Manages async execution

## License

[License information]