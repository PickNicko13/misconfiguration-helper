# Building the Project

This document describes how to build the **MCH (Misconfiguration Scanner)** package and how the build process interacts with our code quality tools.

## Standard Build Process

The project uses a standard `pyproject.toml` based build system with `setuptools`. To build a distributable package (wheel and source distribution), we recommend using the `build` tool.

### 1. Install Build Dependencies
Ensure you have the `build` package installed in your environment:

```bash
pip install build
```

### 2. Build the Package
Run the following command from the project root:

```bash
python -m build
```

The resulting artifacts (`.whl` and `.tar.gz`) will be located in the `dist/` directory.

## Integrated Linting

As part of our commitment to code quality, **linting is mandatory during the build process**.

When you run `python -m build` (or `pip install .`), the following steps occur automatically via our custom `setup.py` hooks:

1.  **Ruff Check**: Runs linting rules to identify potential bugs and anti-patterns.
2.  **Ruff Format Check**: Verifies that the code adheres to our styling standards (tabs, single quotes, etc.).

**If any of these checks fail, the build process will terminate immediately with an error**, and no package will be created. This ensures that every released version of MCH meets our quality standards.

## Troubleshooting Build Failures

If your build fails due to linting errors:

1.  Check the console output to identify the specific files and lines causing the issues.
2.  Run the following commands to automatically fix most styling issues:
    ```bash
    ruff check --fix
    ruff format
    ```
3.  Once the issues are resolved, attempt the build again.

## Local Installation (Editable)

For development purposes, you can install the package in "editable" mode. Note that this also triggers the linting hooks:

```bash
pip install -e .
```
