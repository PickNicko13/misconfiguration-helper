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

## Quality Assurance during Build
To maintain high standards, we recommend running the full suite of linting and type checks before building or distributing the package.

While the build process itself (`python -m build`) focuses on packaging, our CI/CD pipeline and local `Makefile` act as the quality gates.

### 1. Local Verification
Before running a build, use the `Makefile` to verify the code quality:

```bash
make lint
```

This runs:
1.  **Ruff Check**: Identifies potential bugs and anti-patterns.
2.  **Ruff Format**: Verifies adherence to styling standards.
3.  **Static Typing (ty check)**: Performs fast static analysis.

### 2. CI/CD Gating
Our GitHub Actions workflow (`.github/workflows/lint.yml`) performs these same checks on every push. We ensure that no code is merged or released if it fails these checks.

## Local Installation (Editable)
For development, install the package in "editable" mode:

```bash
pip install -e .
```
