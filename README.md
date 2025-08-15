# `pwno-mcp`

MCP Container for Autonomous & Agentic Binary Level Security Research.

## Overview

`PwnoMCP` is designed to run in containerized environments (K8s) and expose debugging capabilities through the Model Context Protocol. Each container runs an isolated instance with its own GDB session.

## Features

- **Execute Tool**: Run arbitrary GDB/pwndbg commands
- **Launch Tool**: Load and run binaries with full control
- **Step Control**: Support for all stepping commands (run, c, n, s, ni, si)
- **Context Retrieval**: Get registers, stack, disassembly, code, and backtrace
- **Breakpoint Management**: Set conditional breakpoints
- **Memory Operations**: Read memory in various formats
- **Session State**: Track debugging session state and history
- **Subprocess Tools**: 
  - Compile binaries with sanitizers (ASAN, MSAN, etc.)
  - Spawn and manage background processes
  - Track process status and resource usage

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

### Using Docker

Build and run with Docker:

```bash
# Build the image
docker build -t pwno-mcp:latest .

# Run with required capabilities
docker run -it \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v $(pwd)/workspace:/workspace \
  pwno-mcp:latest
```

Or use Docker Compose:

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Execute commands in the container
docker-compose exec pwno-mcp bash
```

The Docker image includes:
- Ubuntu 24.04 LTS base
- GDB with pwndbg pre-installed
- Build tools (gcc, g++, clang, make, cmake)
- Address sanitizer libraries
- Python with uv package manager
- All required dependencies

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

#### 2. Set File
Load a binary file for debugging:
```json
{
  "tool": "set_file",
  "arguments": {
    "binary_path": "/path/to/binary"
  }
}
```

#### 3. Run
Run the loaded binary (set breakpoints first or use interrupt_after):
```json
{
  "tool": "run",
  "arguments": {
    "args": "arg1 arg2",
    "interrupt_after": 5.0
  }
}
```
Note: Either set breakpoints before running (recommended) or use `interrupt_after` to pause execution.

#### 4. Step Control
Control program execution:
```json
{
  "tool": "step_control",
  "arguments": {
    "command": "n"
  }
}
```

#### 5. Get Context
Retrieve debugging context:
```json
{
  "tool": "get_context",
  "arguments": {
    "context_type": "all"
  }
}
```

#### 6. Set Breakpoint
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

#### 7. Get Memory
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

#### 8. Get Session Info
Get current debugging session information:
```json
{
  "tool": "get_session_info",
  "arguments": {}
}
```

#### 9. Run Command
Execute system commands (primarily for compilation):
```json
{
  "tool": "run_command",
  "arguments": {
    "command": "gcc -g -fsanitize=address vuln.c -o vuln",
    "cwd": "/path/to/src",
    "timeout": 30.0
  }
}
```

#### 10. Spawn Process
Start a background process and get its PID:
```json
{
  "tool": "spawn_process",
  "arguments": {
    "command": "python3 -m http.server 8080",
    "cwd": "/path/to/serve"
  }
}
```

#### 11. Get Process Status
Check status of a spawned process:
```json
{
  "tool": "get_process_status",
  "arguments": {
    "pid": 12345
  }
}
```

#### 12. Kill Process
Terminate a process:
```json
{
  "tool": "kill_process",
  "arguments": {
    "pid": 12345,
    "signal": 15
  }
}
```

#### 13. List Processes
List all tracked background processes:
```json
{
  "tool": "list_processes",
  "arguments": {}
}
```

### Typical Workflow

1. Load a binary:
   ```json
   {"tool": "set_file", "arguments": {"binary_path": "/path/to/binary"}}
   ```

2. Choose your debugging approach:
   
   **Option A: Set breakpoints (recommended)**
   ```json
   {"tool": "set_breakpoint", "arguments": {"location": "main"}}
   {"tool": "run", "arguments": {"args": ""}}
   ```
   
   **Option B: Run with timed interrupt**
   ```json
   {"tool": "run", "arguments": {"args": "", "interrupt_after": 3.0}}
   ```

3. Use stepping commands and examine state:
   ```json
   {"tool": "step_control", "arguments": {"command": "n"}}
   {"tool": "get_context", "arguments": {"context_type": "all"}}
   ```

### Compilation Workflow Example

1. Compile with AddressSanitizer:
   ```json
   {"tool": "run_command", "arguments": {"command": "gcc -g -fsanitize=address -fno-omit-frame-pointer vuln.c -o vuln"}}
   ```

2. Load and debug the compiled binary:
   ```json
   {"tool": "set_file", "arguments": {"binary_path": "./vuln"}}
   {"tool": "set_breakpoint", "arguments": {"location": "main"}}
   {"tool": "run", "arguments": {"args": ""}}
   ```

3. If running a server for exploitation:
   ```json
   {"tool": "spawn_process", "arguments": {"command": "./vulnerable_server 8080"}}
   ```
   Then check its status:
   ```json
   {"tool": "get_process_status", "arguments": {"pid": 12345}}
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

This project is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License (CC BY-NC-ND 4.0).

- Non-commercial use only
- No derivatives or modifications may be distributed
- Attribution required

See the `LICENSE` file for the full legal text or visit the license page: https://creativecommons.org/licenses/by-nc-nd/4.0/

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.