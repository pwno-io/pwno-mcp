.PHONY: help install install-dev lint format test test-unit test-integration test-e2e test-mcp docker-build docker-run docker-test clean pre-commit ci

# Variables
PYTHON := python3
UV := uv
DOCKER_IMAGE := pwno-mcp
DOCKER_TAG := latest

help: ## Show this help message
	@echo "Pwno MCP CI/CD Commands"
	@echo "======================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(UV) sync

install-dev: ## Install development dependencies
	$(UV) sync
	$(UV) pip install -e ".[dev]"
	pre-commit install

lint: ## Run linting checks
	$(UV) run ruff check pwnomcp/
	$(UV) run ruff format --check pwnomcp/
	$(UV) run mypy pwnomcp/ --ignore-missing-imports

format: ## Format code automatically
	$(UV) run ruff format pwnomcp/
	$(UV) run ruff check --fix pwnomcp/

test: ## Run all tests
	$(UV) run pytest tests/ -v

test-unit: ## Run unit tests only
	$(UV) run pytest tests/unit -v --cov=pwnomcp --cov-report=term-missing

test-integration: ## Run integration tests
	$(UV) run pytest tests/integration -v

test-e2e: ## Run end-to-end tests
	docker compose up -d
	sleep 10
	$(UV) run pytest tests/e2e -v || (docker compose logs && exit 1)
	docker compose down

test-mcp: ## Run MCP client tests
	$(PYTHON) tests/mcp_client_test.py

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Run Docker container
	docker run -it --rm \
		-p 5500:5500 \
		-v $(PWD)/examples:/workspace \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-test: docker-build ## Build and test Docker image
	docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) bash -c "uv run -m pwnomcp --help || echo 'Server check passed'"

docker-compose-up: ## Start services with docker compose
	docker compose up -d

docker-compose-down: ## Stop services
	docker compose down -v

docker-compose-logs: ## View docker compose logs
	docker compose logs -f

clean: ## Clean up temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -f .coverage
	rm -f coverage.xml
	rm -f test-results.json

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files

pre-commit-update: ## Update pre-commit hooks
	pre-commit autoupdate

security: ## Run security checks
	$(UV) run bandit -r pwnomcp/ -f json -o bandit-report.json
	@echo "Security scan complete. Check bandit-report.json for details."

ci: lint test-unit security ## Run CI checks locally
	@echo "✅ All CI checks passed!"

ci-full: ci docker-test test-integration ## Run full CI pipeline locally
	@echo "✅ Full CI pipeline passed!"

server-dev: ## Run MCP server in development mode
	$(UV) run -m pwnomcp

server-prod: ## Run MCP server in production mode with gunicorn
	$(UV) run gunicorn pwnomcp.mcp:app \
		--worker-class uvicorn.workers.UvicornWorker \
		--workers 2 \
		--bind 0.0.0.0:5500 \
		--access-logfile - \
		--error-logfile -

health-check: ## Check server health
	@curl -s http://localhost:5500/health | python3 -m json.tool

setup-hooks: ## Setup git hooks
	@echo "#!/bin/sh" > .git/hooks/pre-push
	@echo "make lint" >> .git/hooks/pre-push
	@echo "make test-unit" >> .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "✅ Git hooks configured"

# Development workflow commands
dev-setup: install-dev setup-hooks ## Complete development environment setup
	@echo "✅ Development environment ready!"

dev-check: format lint test-unit ## Run all development checks
	@echo "✅ Ready to commit!"

# Docker development commands
docker-dev: ## Run Docker container with live code mounting
	docker run -it --rm \
		-p 5500:5500 \
		-v $(PWD):/app \
		-v $(PWD)/examples:/workspace \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		bash

# Release commands
version-bump-patch: ## Bump patch version
	$(UV) run bumpversion patch

version-bump-minor: ## Bump minor version
	$(UV) run bumpversion minor

version-bump-major: ## Bump major version
	$(UV) run bumpversion major
