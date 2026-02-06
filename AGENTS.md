# AGENTS

Guide for agentic coding tools working in this repository.

## Repository facts
- Language: Python (requires 3.13.x; see `pyproject.toml`).
- Packaging: `pyproject.toml` + `uv.lock` (uv is used in Docker).
- Entry point: `python -m pwnomcp` (see `pwnomcp/__main__.py`).
- Runtime modes: Streamable HTTP (default) and stdio (`--stdio`).
- Docker-first workflow is supported (see `Dockerfile`, `docker-compose.yml`).

## Setup (local dev)
Use uv when available (matches Dockerfile).

```bash
uv sync
```

Alternative (pip):

```bash
python -m pip install -e ".[dev]"
```

## Build / Run

### Run locally
```bash
python -m pwnomcp
```

stdio transport:
```bash
python -m pwnomcp --stdio
```

### Build Docker image
```bash
docker build -t pwno-mcp:latest . --platform linux/amd64
```

Local helper script:
```bash
./docker-build.local.sh
```

### Run via docker-compose
```bash
docker-compose up -d
```

## Lint / Format / Type-check
No config files are present, so tools use defaults.

Format (Black default settings):
```bash
python -m black .
```

Type-check (mypy defaults):
```bash
python -m mypy pwnomcp
```

## Tests
There are no tests in the repo right now, but pytest is in dev deps.

Run all tests (if/when added):
```bash
python -m pytest
```

Run a single test file:
```bash
python -m pytest path/to/test_file.py
```

Run a single test case:
```bash
python -m pytest path/to/test_file.py::TestClass::test_name
```

Run by keyword match:
```bash
python -m pytest -k "keyword"
```

## Code style guidelines

### Imports
- Prefer standard library, then third-party, then local imports.
- Keep import groups separated by a blank line.
- Use explicit imports from `typing` (e.g., `Dict`, `Any`, `Optional`).

### Formatting
- 4-space indentation, PEP 8 spacing.
- Black defaults are acceptable (line length 88).
- Keep string quotes consistent within a file (most files use double quotes).

### Types and data modeling
- Use type hints on public functions and tool handlers.
- Use `Optional[T]` for nullable values; avoid `None`-only sentinel logic.
- Prefer `dataclasses` for lightweight state objects (see `pwnomcp/state/session.py`).
- Tool responses are structured dicts with `success`/`error` keys when failing.

### Naming
- `snake_case` for functions/variables.
- `PascalCase` for classes.
- `UPPER_SNAKE_CASE` for module constants (e.g., `DEFAULT_WORKSPACE`).

### Docstrings
- Keep module and class docstrings brief but descriptive.
- Follow existing style in the file:
  - Some files use `Args/Returns` blocks.
  - Others use `:param` style.
- Maintain the existing style when editing a file.

### Logging
- Use `logger = logging.getLogger(__name__)` per module.
- Prefer `logger.info/debug/warning` for status.
- Use `logger.exception` inside `except` blocks to capture tracebacks.

### Error handling
- MCP tool handlers should not raise; return a structured error response.
- Use `@catch_errors()` (or `tuple_on_error=True`) for tool endpoints
  in `pwnomcp/router/mcp.py`.
- Include `"type": type(e).__name__` when returning exceptions.
- Keep error strings actionable and short.

### Tool and router structure
- FastMCP tools live in `pwnomcp/router/mcp.py`.
- Core logic belongs in `pwnomcp/tools/*` and is called by the router.
- Update session state via `SessionState` when state changes.

### Files and paths
- Use `/workspace` for runtime command execution (see `DEFAULT_WORKSPACE`).
- Do not assume a host OS path; code runs in containers often.

## Notes for agentic changes
- Keep API responses consistent with existing tool output patterns.
- Avoid introducing new dependencies without updating `pyproject.toml`.
- Prefer small, focused changes; update README if behavior changes.
