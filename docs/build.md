# Building the Project

This document describes how to build the **MCH (Misconfiguration Scanner)** package and how the build process interacts with the code quality tools.

## Standard Build Process

The project uses a standard `pyproject.toml` based build system with `setuptools`. To build a distributable package (wheel and source distribution), I recommend using the `build` tool.

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
To maintain high standards, I recommend running the full suite of linting and type checks before building or distributing the package.

While the build process itself (`python -m build`) focuses on packaging, the CI/CD pipeline and local `Makefile` act as the quality gates.

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
The GitHub Actions workflow (`.github/workflows/lint.yml`) performs these same checks on every push. I ensure that no code is merged or released if it fails these checks.

## Local Installation (Editable)
For development, install the package in "editable" mode:

```bash
pip install -e .
```

## Documentation Maintenance

Maintain and preview the project documentation locally using the provided `Makefile` targets:

- **Build Documentation**: `make docs` (outputs to the `site/` folder).
- **Live Preview**: `make serve-docs` (starts a local developer server).

For detailed standards on **what and how to document**, see the comprehensive [Documentation Generation](generate_docs.md) guide.
