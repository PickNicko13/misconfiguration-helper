#!/bin/bash
# Production routine: execute a baseline infrastructure scan across critical hostsets

set -e

# Detect project root directory (two levels up from docs/scripts/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==== Starting MCH Production Scan Session ===="

cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    echo "Error: Virtual environment ('venv') not found. Please install the project first."
    exit 1
fi

# Activate production venv
source venv/bin/activate

# 1. Check if mch is available
if ! command -v mch &> /dev/null; then
    echo "Error: 'mch' command not found in virtual environment."
    exit 1
fi

# 2. Run a baseline scan for all modules against production hostset
# (Replace 'production-hosts.txt' with your actual host list)
if [ ! -f "production-hosts.txt" ]; then
    echo "Warning: 'production-hosts.txt' not found. Scanning localhost as a fallback."
    mch scan all localhost --no-notify
else
    echo "Scanning nodes listed in 'production-hosts.txt'..."
    mch scan all --host-list production-hosts.txt --no-notify
fi

# 3. Generate summary of new issues
echo "Reporting new issues found during the session..."
mch report all --type warnings

echo "==== Production Scan Complete! Logged to ~/.local/share/mch/mch.log ===="
