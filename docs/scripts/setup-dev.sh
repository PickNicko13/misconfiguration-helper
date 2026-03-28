#!/bin/bash
# Local development automation: environment setup and verification

set -e

# Detect project root directory (two levels up from docs/scripts/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==== Initializing MCH Development Environment ===="

cd "$PROJECT_DIR"

# 1. Ensure Python 3.14+ is present
if ! command -v python3.14 &> /dev/null; then
    echo "Error: Python 3.14 is required for MCH development."
    exit 1
fi

# 2. Re-create or refresh virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3.14 -m venv venv
fi

# 3. Upgrade basic tools
./venv/bin/pip install --upgrade pip setuptools wheel

# 4. Install project in editable mode with development dependencies
echo "Installing documentation, testing, and linting suites..."
./venv/bin/pip install -e ".[dev,docs]"

# 5. Install pre-commit hooks for automatic quality gating
if command -v pre-commit &> /dev/null; then
    echo "Setting up pre-commit hooks..."
    pre-commit install
else
    echo "Warning: pre-commit not found in system PATH. Skipping hook installation."
fi

echo "==== Setup Complete! ===="
echo "To begin developement, run: source venv/bin/activate"
