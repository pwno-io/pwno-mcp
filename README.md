# `pwno-mcp`


MCP-equipped container for autonomous & agentic binary-level security research interactions (for LLMs agents).

## Overview

`PwnoMCP` is designed to run in scalable containerized environments (k8s) and expose stateful interaction, debugging capabilities through the Model Context Protocol (MCP). Each container runs an isolated instance with its own research self-sufficient environment.

*We does it came from?*: This version was a result of literation of redesigning, thinking and researching for around 6 month on this problem of "making a Pwn MCP for LLMs":

1. I first tried writing a `gdb` pluging and executing via gdb python api ([autogdb.io](https://autogdb.io)), integrating MCP backend on a single backend, authorization by rewriting bit low-level implementation of early MCP's SSE (this was around March, see [this post](https://x.com/retr0reg/status/1906206719576883670)): **Didn't work out well**, since first of capturing program stdio was a problem for `gdb` apis (we did tried delimeters but another story regarding timing we will mention later), while stopping multi-thread binary is bit problematic (makes the entire part of actual executing pretty much unusable) although this version was pretty scalable with only one command backend was enough. (autogdb was only solving the problem of connecting from you're debugging (research) machine to agent client for research), it sounds easy but it was mixed with jumping between frontend, auth and specific compatibilization problem.
2. After realizing the scability problem of [autogdb.io](https://autogdb.io), I started this idea of bring even the entire research environment on cloud with scable pre-configured environments. Tons of time learning and making mistakes in k8s specifically gke, pretty much starting learning everything fron thin air. We got a working MVP on around 2 weeks diving into this (back then I still have my AP exams). Anyway backend it's still a major problem of "how to start a environment for everyone, and how to let everyone access their own environment?" We still sticked with the original centralized MCP backend approach, but this time we assign a k8s stream channel for each users, and use these io channels on one hand to natively interact with gdb (with delimiters), *this was still intended to solve the problem of program IO capturing, it's a trick problem*, I then thought about you should also let users see their gdb session on cloud, so I came up with the approach of duplicating a stdio channel back into frontend via k8s's stream and websockets, with around 2 months of development, we got our pwno.io up-and-running, but still tons of problem that spent incredible amount of time that i didnt mentioned, from gke integration to network issues.
3. [pwno.io](https://pwno.io) was working *I can't say well, but at a working level*, there's still asynchroization problems and gke native problems but we managed to solve the most pain-in-the-ass scability, interactive IO problem that we spent around by far 3 months on. This is when I started working on pwnuous our cooperation with GGML, which will need a new thing like the previous version of pwno-mcp but for more stable support. Since for previous version, we're plugged into GDB via direct IO stream, asynchroization problem as I mentioned was another huge pain-in-the-ass, some IO slipped away and it just not stable enough for use. This is when I started thinking rewriting everything, and throw away some part just for usability for LLMs and it's full agentic compatabilization. I was working on my black hat talk back then so thought a little about statefulness, learnt about this wonderful thing that just seem to be born for us [GDB/MI (Debugging with GDB)](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html), I spent few days rewriting the entire thing by reading docs. I definited did spent less time conceptualizing backend architecture for pwno.io for this version of `pwno-mcp` *(around 2 days mainly on gke gateway things)*, it's definite not a very elaborate or sophisticated framework by all mean, but it did came from a shit tons of experience of trial-and-erroring my self while thinking about the question of making something that's can scale *(multi-agent, researcher using it)*, so I will say it's by far the best conceptualizations and work to best serve for the purpose of LLMs using it stabiliy and scability. And I do think it's the best time or the now-or-never time to open-source it, or this project or Pwno will die from lack of feedback loop, despite `pwno-mcp` is a little part of what we're doing.

## Features

- `pwndbg` machine-interface, stateful execution with debugging (designed deliberately toward LLMs)
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
- **RetDec**: RetDec decompiler service
  - *note: to use pwno's retdec server, you need to `export BINARY_URL=<your-binary-url>`*
- **Auth**: Authentication via a nonce

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