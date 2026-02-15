.PHONY: lint check format typecheck tests all

# Default target
all: lint tests

# Run all linting checks (ruff and ty)
lint: check format typecheck

# Ruff linting
check:
	./venv/bin/ruff check .

# Ruff formatting check
format:
	./venv/bin/ruff format --check .

# Static type checking
typecheck:
	./venv/bin/ty check

# Run tests
tests:
	./venv/bin/pytest
