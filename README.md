<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/pwno-mcp-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/pwno-mcp-light.png">
  <img alt="pwno-mcp banner" src="assets/pwno-mcp-light.png">
</picture>

<p align="center">stateful system for autonomous <code>pwn</code> and binary research, designed for LLM agents.</p>

## Overview

`pwno-mcp` runs GDB + pwndbg in an isolated environment and exposes stateful debugging, exploit I/O, and helper tooling over MCP for agentic coding clients.

## Features

- Stateful debugger sessions via GDB + pwndbg
- Deterministic execution control via GDB/MI
- Fast context snapshots for registers, stack, disassembly, source, and backtrace
- Interactive exploit-driver workflows with `pwncli`
- Multi-session support for parallel workflows
- Workspace automation helpers for commands, processes, Python, repos, and RetDec
- HTTP and stdio transport support

## Documentation

The full documentation now lives at `https://docs.pwno.io`.

- Docs home: `https://docs.pwno.io`
- Quick start: `https://docs.pwno.io/quickstart`
- Client setup: `https://docs.pwno.io/client-setup/index`
- Guides: `https://docs.pwno.io/guides/index`
- Reference: `https://docs.pwno.io/tool-reference/index`
- Operations: `https://docs.pwno.io/operations/configuration`

Use the docs site for:

- Docker and stdio setup
- client-specific MCP configuration
- workflow guides like first debug session, attach flows, and `pwncli`
- complete tool reference and response shapes
- troubleshooting, architecture, and development notes

## Quick Start

Create a local `workspace` directory, put your target binary there, then run the container.

```bash
mkdir -p ./workspace
cp ./path/to/your/binary ./workspace/chal
chmod +x ./workspace/chal
```

```bash
docker run --rm -p 5500:5500 \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "$PWD/workspace:/workspace" \
  ghcr.io/pwno-io/pwno-mcp:latest
```

Default MCP endpoint:

```text
http://127.0.0.1:5500/mcp
```

For stdio mode, client configs, health checks, and attach-helper details, use the docs site: `https://docs.pwno.io/quickstart`.

## Development

For local development, architecture, and contributing guidance, see:

- `https://docs.pwno.io/development`
- `https://docs.pwno.io/architecture`
- `https://docs.pwno.io/contributing`

## Usage

- non-profit: yes
- commercial: `oss@pwno.io`

## Future Enhancements
- WebSocket endpoint for streaming I/O
- Advanced memory analysis tools
- Heap exploitation helpers
- ROP chain generation
- Symbolic execution integration

## License

This project is licensed under CC BY-NC-ND 4.0.

See `LICENSE` or `https://docs.pwno.io/license` for details.

## Contributing

Issues and pull requests are welcome.
