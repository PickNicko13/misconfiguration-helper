#!/bin/bash
# Routine state cleanup: clear scan history and persistent configuration

set -e

# Detect project root directory (two levels up from docs/scripts/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "==== Cleaning up MCH State and Logs ===="

cd "$PROJECT_DIR"

# 1. Clear target host states (Database equivalent)
if [ -d "$HOME/.local/share/mch/targets" ]; then
    echo "Clearing Host Identification (JSON) records..."
    rm -rf "$HOME/.local/share/mch/targets/*"
fi

# 2. Clear application logs
if [ -f "$HOME/.local/share/mch/mch.log" ]; then
    echo "Clearing scan and error logs..."
    cat /dev/null > "$HOME/.local/share/mch/mch.log"
fi

# 3. Clear transient local caches (Pytest/Ruff)
echo "Removing development caches (.pytest_cache, .ruff_cache)..."
rm -rf .pytest_cache .ruff_cache

echo "==== Cleanup Complete! ===="
