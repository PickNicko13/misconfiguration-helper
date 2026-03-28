#!/bin/bash
# Unified deployment script for MCH locally for development and production testing

set -e

# Detect project root directory (one level up from this script)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==== Starting MCH Local Deployment ===="

# Ensure latest source code
if [ -d "$PROJECT_DIR" ]; then
    echo "Updating local repository..."
    # If this were a real git repo, I'd git pull here, but in this session we assume it's updated or being updated by the agent.
else
    echo "Repository not found at $PROJECT_DIR"
    exit 1
fi

# Ensure Python 3.14 environment
if ! command -v python3.14 &> /dev/null; then
    echo "Python 3.14 not found. Please install it first."
    exit 1
fi

# Create/Update Virtual Environment
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "Creating virtual environment..."
    python3.14 -m venv "$PROJECT_DIR/venv"
fi

# Update dependencies and install project in editable mode
echo "Installing/Updating dependencies..."
"$PROJECT_DIR/venv/bin/pip" install --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install -e "$PROJECT_DIR[dev,docs]"

# Run quality checks
echo "Running code quality checks..."
"$PROJECT_DIR/venv/bin/ruff" check "$PROJECT_DIR"
"$PROJECT_DIR/venv/bin/ty" check

# Run tests
echo "Running automated tests..."
"$PROJECT_DIR/venv/bin/pytest" "$PROJECT_DIR/tests"

# Build documentation
echo "Building technical documentation..."
"$PROJECT_DIR/venv/bin/mkdocs" build

echo "==== MCH Deployment Successful! ===="
echo "You can now run 'mch' after sourcing the venv: source venv/bin/activate"
