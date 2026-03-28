#!/bin/bash
# Routine quality verification for development: linting, formatting, and unit testing

set -e

# Detect project root directory (two levels up from docs/scripts/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==== Running MCH Developer Verification Suite ===="

cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    echo "Error: Virtual environment ('venv') not found. Please run 'setup-dev.sh' first."
    exit 1
fi

# Activate venv
source venv/bin/activate

# 1. Automated code formatting (Ruff)
echo "Checking for formatting issues and applying fixes..."
ruff check --fix .
ruff format .

# 2. Static Type Analysis (Ty)
echo "Performing static type checking with Ty..."
ty check

# 3. Unit and Integration Tests (Pytest)
echo "Executing automated test suite..."
pytest tests/ --cov=mch --cov-report=term-missing

echo "==== All Checks Passed! ===="
