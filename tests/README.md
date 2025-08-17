# Pwno MCP Server Tests

This directory contains the test suite for the Pwno MCP Server, including unit tests, integration tests, and end-to-end tests.

## Test Structure

```
tests/
├── unit/                 # Unit tests for individual components
│   ├── test_gdb_controller.py
│   └── test_session_state.py
├── integration/          # Integration tests with running MCP server
│   └── test_mcp_tools.py
├── e2e/                  # End-to-end scenario tests
│   └── test_e2e_scenarios.py
└── mcp_client_test.py   # Standalone MCP client test harness
```

## Running Tests

### Prerequisites

Install development dependencies:
```bash
make install-dev
# or
uv sync
uv pip install -e ".[dev]"
```

### Run All Tests

```bash
make test
# or
pytest tests/ -v
```

### Run Specific Test Types

**Unit Tests:**
```bash
make test-unit
# or
pytest tests/unit -v --cov=pwnomcp
```

**Integration Tests:**
```bash
make test-integration
# or
pytest tests/integration -v
```

**End-to-End Tests:**
```bash
make test-e2e
# or
docker compose up -d
pytest tests/e2e -v
docker compose down
```

**MCP Client Tests:**
```bash
make test-mcp
# or
python tests/mcp_client_test.py
```

## Test Coverage

Generate coverage reports:
```bash
pytest tests/ --cov=pwnomcp --cov-report=html
open htmlcov/index.html
```

## Environment Variables

Tests can be configured with environment variables:

- `MCP_URL`: MCP server URL (default: `http://localhost:5500`)
- `MCP_NONCE`: Authentication nonce if server requires auth
- `PYTEST_TIMEOUT`: Global test timeout in seconds (default: 60)

Example:
```bash
MCP_URL=http://mcp-server:5500 MCP_NONCE=secret123 pytest tests/
```

## Writing Tests

### Unit Tests

Unit tests should:
- Test individual components in isolation
- Use mocks for external dependencies
- Be fast and deterministic
- Follow the pattern `test_<component>.py`

Example:
```python
def test_gdb_initialization(mock_gdbmi):
    controller = GdbController()
    assert controller._state == "idle"
```

### Integration Tests

Integration tests should:
- Test with a real MCP server instance
- Verify tool functionality
- Test error handling
- Use async/await for MCP calls

Example:
```python
@pytest.mark.asyncio
async def test_run_command(mcp_client):
    result = await mcp_client.call_tool(
        "run_command", 
        {"command": "echo test"}
    )
    assert json.loads(result)["success"] is True
```

### End-to-End Tests

E2E tests should:
- Test complete workflows
- Simulate real-world scenarios
- Test multiple tools in combination
- Clean up resources after testing

Example:
```python
async def test_buffer_overflow_analysis(mcp_client):
    # Create vulnerable program
    # Compile with specific flags
    # Load in GDB
    # Analyze vulnerability
    # Clean up
```

## Continuous Integration

The test suite runs automatically on:
- Push to main/develop branches
- Pull requests
- Manual workflow dispatch

See `.github/workflows/ci.yml` for the complete CI pipeline.

## Debugging Failed Tests

### Verbose Output
```bash
pytest tests/ -vv -s
```

### Run Single Test
```bash
pytest tests/unit/test_gdb_controller.py::TestGdbController::test_initialization -v
```

### Debug with PDB
```bash
pytest tests/ --pdb
```

### Check Server Logs
```bash
docker compose logs pwno-mcp
```

## Test Fixtures

Common fixtures are available:

- `mcp_client`: Async MCP client for testing
- `mcp_url`: MCP server URL from environment
- `mcp_nonce`: Authentication nonce
- `temp_binary`: Creates temporary test binaries

## Performance Testing

Run performance benchmarks:
```bash
pytest tests/ --benchmark-only
```

## Security Testing

Run security-focused tests:
```bash
make security
# or
bandit -r pwnomcp/ -f json
```

## Troubleshooting

### Server Not Starting
- Check if port 5500 is available
- Verify Docker is running
- Check server logs: `docker compose logs`

### Authentication Failures
- Ensure MCP_NONCE environment variable is set correctly
- Check server authentication configuration

### Timeout Issues
- Increase timeout: `PYTEST_TIMEOUT=120 pytest tests/`
- Check for deadlocks in async code
- Verify server responsiveness

## Contributing

When adding new tests:
1. Follow existing patterns and naming conventions
2. Add appropriate fixtures if needed
3. Document complex test scenarios
4. Ensure tests are deterministic
5. Clean up resources in finally blocks
6. Run the full test suite before submitting
