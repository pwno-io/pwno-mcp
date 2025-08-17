# CI/CD Pipeline Documentation

## Overview

The Pwno MCP Server uses a comprehensive CI/CD pipeline to ensure code quality, security, and reliability. The pipeline includes automated testing, linting, security scanning, and Docker image building.

## Pipeline Components

### 1. GitHub Actions Workflow

Location: `.github/workflows/ci.yml`

The workflow runs on:
- Push to `main` and `develop` branches
- Pull requests to `main`
- Manual workflow dispatch

### 2. Pipeline Jobs

#### Lint & Type Check
- **Tools**: ruff, mypy
- **Purpose**: Ensure code quality and type safety
- **Configuration**: `pyproject.toml`

#### Unit Tests
- **Framework**: pytest
- **Coverage**: pytest-cov
- **Location**: `tests/unit/`
- **Uploads**: Coverage reports to Codecov

#### Docker Build Test
- **Purpose**: Verify Docker image builds successfully
- **Cache**: Uses GitHub Actions cache for faster builds

#### MCP Integration Tests
- **Purpose**: Test MCP tools with a real server
- **Environment**: Containerized MCP server
- **Location**: `tests/integration/`

#### Security Scan
- **Tools**: Trivy, Bandit
- **Reports**: SARIF format uploaded to GitHub Security

#### End-to-End Tests
- **Purpose**: Test complete workflows
- **Environment**: Docker Compose stack
- **Location**: `tests/e2e/`

## Local Development

### Setup

```bash
# Install development dependencies
make install-dev

# Setup pre-commit hooks
pre-commit install

# Run complete dev setup
make dev-setup
```

### Running Tests Locally

```bash
# Run all CI checks
make ci

# Run specific test types
make test-unit
make test-integration
make test-e2e

# Run linting
make lint

# Format code
make format

# Security scan
make security
```

### Pre-commit Hooks

The project uses pre-commit hooks to catch issues before commit:

- Trailing whitespace removal
- End-of-file fixing
- YAML/JSON/TOML validation
- Python formatting (ruff)
- Type checking (mypy)
- Security scanning (bandit, gitleaks)

Install hooks:
```bash
pre-commit install
```

Run manually:
```bash
pre-commit run --all-files
```

## Docker Testing

### Build and Test

```bash
# Build Docker image
make docker-build

# Run Docker tests
make docker-test

# Run with live code mounting
make docker-dev
```

### Docker Compose Testing

```bash
# Start services
make docker-compose-up

# Run E2E tests
make test-e2e

# View logs
make docker-compose-logs

# Stop services
make docker-compose-down
```

## MCP Client Testing

The project includes a comprehensive MCP client test harness:

### Standalone Test

```bash
python tests/mcp_client_test.py
```

### Environment Variables

- `MCP_SERVER_URL`: Server URL (default: `http://localhost:5500`)
- `MCP_NONCE`: Authentication nonce (if required)

### Test Coverage

The MCP client tests cover:
- Health checks
- Tool listing
- Command execution
- Process management
- Python execution
- GDB operations
- Git operations
- Session management

## Quality Gates

### Required Checks

All of the following must pass for merge:

1. **Linting**: No ruff errors
2. **Type Checking**: No mypy errors
3. **Unit Tests**: 80% minimum coverage
4. **Docker Build**: Image builds successfully
5. **Security Scan**: No high/critical vulnerabilities

### Optional Checks

These provide additional insights:

1. **Integration Tests**: Tool functionality
2. **E2E Tests**: Complete workflows
3. **Performance Tests**: Response times

## Continuous Deployment

### Docker Registry

Images are automatically pushed to:
- GitHub Container Registry (ghcr.io)
- Google Container Registry (if configured)

### Deployment Triggers

- **Production**: Tags matching `v*.*.*`
- **Staging**: Pushes to `main`
- **Development**: Pushes to `develop`

## Monitoring

### Health Checks

The server provides health endpoints:

```bash
# Basic health
curl http://localhost:5500/health

# Detailed status
curl http://localhost:5500/health | jq
```

### Metrics

Track:
- Response times
- Error rates
- Active processes
- Memory usage

## Troubleshooting

### Common Issues

#### 1. Tests Failing Locally

```bash
# Clean environment
make clean

# Reinstall dependencies
make install-dev

# Run with verbose output
pytest -vv -s
```

#### 2. Docker Build Issues

```bash
# Clear Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t pwno-mcp .
```

#### 3. MCP Server Not Responding

```bash
# Check server logs
docker logs <container-id>

# Verify port is open
netstat -an | grep 5500

# Test health endpoint
curl -v http://localhost:5500/health
```

### Debug Mode

Enable debug logging:

```python
# In pwnomcp/logger.py
logger.setLevel(logging.DEBUG)
```

Run with debug output:

```bash
DEBUG=1 python -m pwnomcp
```

## Best Practices

### Code Quality

1. **Format before commit**: `make format`
2. **Run linting**: `make lint`
3. **Check types**: `make mypy`
4. **Test coverage**: Maintain >80%

### Testing

1. **Write tests first**: TDD approach
2. **Mock external dependencies**: Use pytest-mock
3. **Clean up resources**: Use try/finally blocks
4. **Test edge cases**: Include error scenarios

### Security

1. **No secrets in code**: Use environment variables
2. **Scan dependencies**: Regular security updates
3. **Validate inputs**: Prevent injection attacks
4. **Use authentication**: Enable X-Nonce header

### Documentation

1. **Update docs with code**: Keep in sync
2. **Document complex logic**: Add inline comments
3. **Provide examples**: Show usage patterns
4. **Maintain changelog**: Track changes

## Release Process

### Version Bumping

```bash
# Patch release (0.1.0 -> 0.1.1)
make version-bump-patch

# Minor release (0.1.0 -> 0.2.0)
make version-bump-minor

# Major release (0.1.0 -> 1.0.0)
make version-bump-major
```

### Release Checklist

1. [ ] All tests passing
2. [ ] Documentation updated
3. [ ] Changelog updated
4. [ ] Version bumped
5. [ ] Tag created
6. [ ] Docker image built
7. [ ] Release notes written

### Automated Release

On tag push:
1. Run full CI pipeline
2. Build Docker images
3. Push to registries
4. Create GitHub release
5. Deploy to production

## Contributing

### Development Workflow

1. Fork repository
2. Create feature branch
3. Make changes
4. Run tests locally
5. Submit pull request
6. Address review feedback
7. Merge when approved

### PR Requirements

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Linting passes
- [ ] Type checking passes
- [ ] Security scan clean
- [ ] Changelog entry added

## Support

### Resources

- [GitHub Issues](https://github.com/your-org/pwno-mcp/issues)
- [Documentation](./README.md)
- [Test Guide](../tests/README.md)

### Contact

- Security issues: security@example.com
- General support: support@example.com
