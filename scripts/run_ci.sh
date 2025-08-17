#!/bin/bash
# Run CI/CD checks locally
# This script simulates the GitHub Actions CI pipeline

set -e

echo "========================================="
echo "       Pwno MCP CI/CD Check             "
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2 passed${NC}"
    else
        echo -e "${RED}❌ $2 failed${NC}"
        exit 1
    fi
}

# Check if running in CI environment
if [ -n "$CI" ]; then
    echo "Running in CI environment"
else
    echo "Running locally"
fi

# 1. Check Python version
echo -e "\n${YELLOW}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
required_version="3.11"
if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo -e "${GREEN}✅ Python $python_version (>= $required_version)${NC}"
else
    echo -e "${RED}❌ Python $python_version is below required version $required_version${NC}"
    exit 1
fi

# 2. Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
if command -v uv &> /dev/null; then
    uv sync
    uv pip install -e ".[dev]"
    print_status $? "Dependency installation"
else
    echo -e "${RED}❌ UV not found. Please install UV first.${NC}"
    exit 1
fi

# 3. Run linting
echo -e "\n${YELLOW}Running linting checks...${NC}"
uv run ruff check pwnomcp/ --output-format=github
lint_status=$?
print_status $lint_status "Linting"

# 4. Run formatting check
echo -e "\n${YELLOW}Checking code formatting...${NC}"
uv run ruff format pwnomcp/ --check
format_status=$?
print_status $format_status "Formatting"

# 5. Run type checking
echo -e "\n${YELLOW}Running type checking...${NC}"
uv run mypy pwnomcp/ --ignore-missing-imports
mypy_status=$?
print_status $mypy_status "Type checking"

# 6. Run unit tests
echo -e "\n${YELLOW}Running unit tests...${NC}"
uv run pytest tests/unit -v --cov=pwnomcp --cov-report=term-missing
test_status=$?
print_status $test_status "Unit tests"

# 7. Run security scan
echo -e "\n${YELLOW}Running security scan...${NC}"
uv run bandit -r pwnomcp/ -f json -o bandit-report.json || true
if [ -f bandit-report.json ]; then
    issues=$(python3 -c "import json; data=json.load(open('bandit-report.json')); print(len(data.get('results', [])))")
    if [ "$issues" -eq 0 ]; then
        echo -e "${GREEN}✅ Security scan (no issues found)${NC}"
    else
        echo -e "${YELLOW}⚠️  Security scan found $issues potential issues (see bandit-report.json)${NC}"
    fi
fi

# 8. Check Docker build (optional)
if command -v docker &> /dev/null; then
    echo -e "\n${YELLOW}Testing Docker build...${NC}"
    docker build -t pwno-mcp:ci-test . > /dev/null 2>&1
    docker_status=$?
    if [ $docker_status -eq 0 ]; then
        echo -e "${GREEN}✅ Docker build${NC}"
        # Clean up test image
        docker rmi pwno-mcp:ci-test > /dev/null 2>&1
    else
        echo -e "${YELLOW}⚠️  Docker build failed (optional check)${NC}"
    fi
else
    echo -e "\n${YELLOW}⚠️  Docker not available, skipping Docker build test${NC}"
fi

# 9. Check for integration tests (informational)
echo -e "\n${YELLOW}Checking for integration tests...${NC}"
if [ -d "tests/integration" ] && [ "$(ls -A tests/integration/*.py 2>/dev/null)" ]; then
    echo -e "${GREEN}✅ Integration tests found${NC}"
    echo "  Run 'make test-integration' to execute integration tests"
else
    echo -e "${YELLOW}⚠️  No integration tests found${NC}"
fi

# 10. Summary
echo ""
echo "========================================="
echo "           CI/CD Check Complete          "
echo "========================================="
echo ""
echo -e "${GREEN}All required checks passed!${NC}"
echo ""
echo "Next steps:"
echo "  1. Run integration tests: make test-integration"
echo "  2. Run E2E tests: make test-e2e"
echo "  3. Run MCP client tests: make test-mcp"
echo ""
echo "To run all tests: make ci-full"
