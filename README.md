# `pwno-mcp`

stateful system for autonomous `pwn` and binary research, designed for LLMs agents.

## Overview

`PwnoMCP` is designed to run in scalable containerized environments (k8s) and expose stateful interaction, debugging capabilities through the Model Context Protocol (MCP). Each container runs an isolated instance with its own research self-sufficient environment.

*We does it came from?*: This version was a result of literation of redesigning, thinking and researching for around 6 month on this problem of "making a Pwn MCP for LLMs":

1. I first tried writing a `gdb` pluging and executing via gdb python api ([autogdb.io](https://autogdb.io)), integrating MCP backend on a single backend, authorization by rewriting bit low-level implementation of early MCP's SSE (this was around March, see [this post](https://x.com/retr0reg/status/1906206719576883670)): **Didn't work out well**, since first of capturing program stdio was a problem for `gdb` apis (we did tried delimeters but another story regarding timing we will mention later), while stopping multi-thread binary is bit problematic (makes the entire part of actual executing pretty much unusable) although this version was pretty scalable with only one command backend was enough. (autogdb was only solving the problem of connecting from you're debugging (research) machine to agent client for research), it sounds easy but it was mixed with jumping between frontend, auth and specific compatibilization problem.
2. After realizing the scability problem of [autogdb.io](https://autogdb.io), I started this idea of bring even the entire research environment on cloud with scable pre-configured environments. Tons of time learning and making mistakes in k8s specifically gke, pretty much starting learning everything fron thin air. We got a working MVP on around 2 weeks diving into this (back then I still have my AP exams). Anyway backend it's still a major problem of "how to start a environment for everyone, and how to let everyone access their own environment?" We still sticked with the original centralized MCP backend approach, but this time we assign a k8s stream channel for each users, and use these io channels on one hand to natively interact with gdb (with delimiters), *this was still intended to solve the problem of program IO capturing, it's a trick problem*, I then thought about you should also let users see their gdb session on cloud, so I came up with the approach of duplicating a stdio channel back into frontend via k8s's stream and websockets, with around 2 months of development, we got our pwno.io up-and-running, but still tons of problem that spent incredible amount of time that i didnt mentioned, from gke integration to network issues.
3. [pwno.io](https://pwno.io) was working *I can't say well, but at a working level*, there's still asynchroization problems and gke native problems but we managed to solve the most pain-in-the-ass scability, interactive IO problem that we spent around by far 3 months on. This is when I started working on pwnuous our cooperation with GGML, which will need a new thing like the previous version of pwno-mcp but for more stable support. Since for previous version, we're plugged into GDB via direct IO stream, asynchroization problem as I mentioned was another huge pain-in-the-ass, some IO slipped away and it just not stable enough for use. This is when I started thinking rewriting everything, and throw away some part just for usability for LLMs and it's full agentic compatabilization. I was working on my black hat talk back then so thought a little about statefulness, learnt about this wonderful thing that just seem to be born for us [GDB/MI (Debugging with GDB)](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html), I spent few days rewriting the entire thing by reading docs. I definited did spent less time conceptualizing backend architecture for pwno.io for this version of `pwno-mcp` *(around 2 days mainly on gke gateway things)*, it's definite not a very elaborate or sophisticated framework by all mean, but it did came from a shit tons of experience of trial-and-erroring my self while thinking about the question of making something that's can scale *(multi-agent, researcher using it)*, so I will say it's by far the best conceptualizations and work to best serve for the purpose of LLMs using it stabiliy and scability. And I do think it's the best time or the now-or-never time to open-source it, or this project or Pwno will die from lack of feedback loop, despite `pwno-mcp` is a little part of what we're doing.

**Can I use it?**:

- non-profit: *yes, feel free to*
- commercial: [oss@pwno.io](mailto:oss@pwno.io)

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

*`pwno-mcp`*

## Installation

### Using Docker

#### Prebuilt image (recommended)

```bash
# Pull the image
docker pull ghcr.io/pwno-io/pwno-mcp:latest

# Run with required capabilities (HTTP mode by default)
docker run -p 5500:5500 \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v $(pwd)/workspace:/workspace \
  ghcr.io/pwno-io/pwno-mcp:latest

# Open a shell instead of starting the server
docker run --entrypoint /bin/bash -it \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v $(pwd)/workspace:/workspace \
  ghcr.io/pwno-io/pwno-mcp:latest
```

The image is built for `linux/amd64`; on Apple Silicon, add `--platform linux/amd64` to `docker pull` and `docker run`.
If `:latest` is not available, use `:edge` to track the `main` branch.

Tags:
- `latest`: stable default
- `edge`: tracks `main`
- `sha-<short>`: pin to a commit
- `X.Y.Z`, `X.Y`, `X`: release tags from `vX.Y.Z`

#### Build locally

```bash
docker build -t pwno-mcp:latest . --platform linux/amd64
```

If you build locally, replace `ghcr.io/pwno-io/pwno-mcp:latest` with `pwno-mcp:latest` in the commands above.

Or use Docker Compose (builds locally by default):

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
- Python 3.12+

## Usage

### Quick Start (Docker, recommended)

Create a `./workspace` folder in your current project directory, put your target
binary there, start the server, then connect your MCP client.

1. From your current project directory, create `./workspace` and place your target binary there (name it `target`):

```bash
mkdir -p ./workspace
cp ./path/to/your/binary ./workspace/target
chmod +x ./workspace/target
```

2. Pick transport:

- Use **Streamable HTTP** when your client asks for a `url`.
- Use **stdio** when your client asks for `command` + `args`.

3. Start server.

#### Streamable HTTP mode (default transport)

```bash
docker run --rm -p 5500:5500 \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "$PWD/workspace:/workspace" \
  ghcr.io/pwno-io/pwno-mcp:latest
```

Run this from the host shell in the directory that contains `./workspace`.

This mount makes your local `./workspace` available inside the container at `/workspace`.

MCP URL for clients in this mode:

- `http://127.0.0.1:5500/debug`

#### stdio mode (for local MCP clients)

Run this from the host shell in the directory that contains `./workspace`.

```bash
docker run --rm -i \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "$PWD/workspace:/workspace" \
  ghcr.io/pwno-io/pwno-mcp:latest \
  --stdio
```

Notes:

- `streamable_http_path` defaults to `/debug`.
- Attach helper API defaults to `127.0.0.1:5501` inside the server runtime.

### First Debug Session (what to do)

After your MCP client is connected to `pwno-mcp`, run tools in this order.
If you followed Quick Start, your binary is named `target`: `./workspace/target` on the host and
`/workspace/target` inside tool calls.

1. Load binary:

```json
{"tool":"set_file","arguments":{"binary_path":"/workspace/target"}}
```

2. Set breakpoint (recommended so execution stops predictably):

```json
{"tool":"set_breakpoint","arguments":{"location":"main"}}
```

3. Run target:

```json
{"tool":"run","arguments":{"args":""}}
```

4. Inspect context:

```json
{"tool":"get_context","arguments":{"context_type":"all"}}
```

5. Step as needed:

```json
{"tool":"step_control","arguments":{"command":"n"}}
```

Common stepping commands: `c`, `n`, `s`, `ni`, `si`.

### MCP Client Setup

All snippets below use the server name `pwno-mcp`.

<details>
<summary><strong>Claude Desktop (stdio)</strong></summary>

Config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Use an absolute host path for the workspace mount (your project's `workspace` directory):

```json
{
  "mcpServers": {
    "pwno-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--cap-add=SYS_PTRACE",
        "--cap-add=SYS_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "--security-opt",
        "apparmor=unconfined",
        "-v",
        "/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace:/workspace",
        "ghcr.io/pwno-io/pwno-mcp:latest",
        "--stdio"
      ]
    }
  }
}
```

</details>

<details>
<summary><strong>Claude Code (plugin MCP config, stdio)</strong></summary>

Claude Code loads MCP servers via plugin configuration.

1. Create a plugin folder (example):

```bash
mkdir -p "$HOME/pwno-claude-plugin/.claude-plugin"
```

2. Create `~/pwno-claude-plugin/.claude-plugin/plugin.json`:

```json
{
  "name": "pwno-mcp-plugin",
  "version": "0.1.0",
  "description": "pwno-mcp integration"
}
```

3. Create `~/pwno-claude-plugin/.mcp.json` (use an absolute host path to your project's `workspace` directory):

```json
{
  "mcpServers": {
    "pwno-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--cap-add=SYS_PTRACE",
        "--cap-add=SYS_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "--security-opt",
        "apparmor=unconfined",
        "-v",
        "/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace:/workspace",
        "ghcr.io/pwno-io/pwno-mcp:latest",
        "--stdio"
      ]
    }
  }
}
```

4. Launch Claude Code with that plugin directory:

```bash
cc --plugin-dir "$HOME/pwno-claude-plugin"
```

5. In Claude Code, run `/mcp` to verify `pwno-mcp` and its tools are loaded.

</details>

<details>
<summary><strong>Cursor (HTTP or stdio)</strong></summary>

Cursor MCP config locations:

- Project: `.cursor/mcp.json`
- Global: `~/.cursor/mcp.json`

If you use project config, keep your binary at `PROJECT_ROOT/workspace/target`.

HTTP example:

```json
{
  "mcpServers": {
    "pwno-mcp": {
      "url": "http://127.0.0.1:5500/debug"
    }
  }
}
```

Stdio example (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "pwno-mcp": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--cap-add=SYS_PTRACE",
        "--cap-add=SYS_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "--security-opt",
        "apparmor=unconfined",
        "-v",
        "${workspaceFolder}/workspace:/workspace",
        "ghcr.io/pwno-io/pwno-mcp:latest",
        "--stdio"
      ]
    }
  }
}
```

</details>

<details>
<summary><strong>OpenCode (remote HTTP or local stdio)</strong></summary>

Config file:

- Global: `~/.config/opencode/opencode.json`
- Project-specific also supported via `opencode.json` in project root

Remote HTTP server example:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "pwno-mcp": {
      "type": "remote",
      "url": "http://127.0.0.1:5500/debug",
      "enabled": true
    }
  }
}
```

Local stdio server example:

Replace `/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace` with the absolute path to your project's `workspace` directory.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "pwno-mcp": {
      "type": "local",
      "command": [
        "docker",
        "run",
        "--rm",
        "-i",
        "--cap-add=SYS_PTRACE",
        "--cap-add=SYS_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "--security-opt",
        "apparmor=unconfined",
        "-v",
        "/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace:/workspace",
        "ghcr.io/pwno-io/pwno-mcp:latest",
        "--stdio"
      ],
      "enabled": true
    }
  }
}
```

CLI helpers:

- `opencode mcp add`
- `opencode mcp list`

</details>

<details>
<summary><strong>Codex CLI (HTTP or stdio)</strong></summary>

Config file: `~/.codex/config.toml`

HTTP example:

```toml
[mcp_servers.pwno-mcp]
url = "http://127.0.0.1:5500/debug"
```

Stdio example:

Replace `/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace` with the absolute path to your project's `workspace` directory.

```toml
[mcp_servers.pwno-mcp]
command = "docker"
args = [
  "run",
  "--rm",
  "-i",
  "--cap-add=SYS_PTRACE",
  "--cap-add=SYS_ADMIN",
  "--security-opt",
  "seccomp=unconfined",
  "--security-opt",
  "apparmor=unconfined",
  "-v",
  "/ABSOLUTE/PATH/TO/YOUR/PROJECT/workspace:/workspace",
  "ghcr.io/pwno-io/pwno-mcp:latest",
  "--stdio"
]
```

Check configuration:

```bash
codex mcp list
```

</details>

### Tool Reference

<details>
<summary><strong>Detailed tool reference (arguments + examples)</strong></summary>

`set_file` loads an executable into GDB/pwndbg.

```json
{"tool":"set_file","arguments":{"binary_path":"/workspace/target"}}
```

`set_breakpoint` sets a breakpoint by symbol/address/file:line, with optional condition.

```json
{"tool":"set_breakpoint","arguments":{"location":"main","condition":"$rax == 0"}}
```

`run` starts the loaded program.

```json
{"tool":"run","arguments":{"args":"arg1 arg2","start":false}}
```

`step_control` controls execution using `c`, `n`, `s`, `ni`, `si`.

```json
{"tool":"step_control","arguments":{"command":"n"}}
```

`get_context` returns debugger context. `context_type` can be `all`, `regs`, `stack`, `disasm`, `code`, `backtrace`.

```json
{"tool":"get_context","arguments":{"context_type":"all"}}
```

`get_memory` reads memory from an address.

```json
{"tool":"get_memory","arguments":{"address":"$rsp","size":64,"format":"hex"}}
```

`execute` runs raw GDB/pwndbg commands.

```json
{"tool":"execute","arguments":{"command":"info registers"}}
```

`get_session_info` returns current session + debugger state.

```json
{"tool":"get_session_info","arguments":{}}
```

`run_command` executes shell commands (compile/build helpers) in `/workspace` by default.

```json
{"tool":"run_command","arguments":{"command":"gcc -g vuln.c -o target","cwd":"/workspace","timeout":30.0}}
```

`spawn_process` starts a background process.

```json
{"tool":"spawn_process","arguments":{"command":"./target","cwd":"/workspace"}}
```

`get_process_status` checks spawned process status.

```json
{"tool":"get_process_status","arguments":{"pid":12345}}
```

`kill_process` terminates a spawned process.

```json
{"tool":"kill_process","arguments":{"pid":12345,"signal":15}}
```

`list_processes` lists tracked background processes.

```json
{"tool":"list_processes","arguments":{}}
```

</details>

### Troubleshooting

- `No binary loaded. Use set_file first.`: call `set_file` before `run`.
- `binary_path` not found: path must exist inside server runtime (Docker usually means `/workspace/...`).
- GDB attach/ptrace permission errors: keep `SYS_PTRACE`, `SYS_ADMIN`, and unconfined seccomp/apparmor flags.
- HTTP connection failures: ensure container publishes `-p 5500:5500` and client URL is exactly `http://127.0.0.1:5500/debug` unless you changed the path.

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
