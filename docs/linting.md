# Code Quality and Linting

This document outlines the code quality standards and the linting/formatting tools used in the **MCH (Misconfiguration Scanner)** project.

## Chosen Tool: Ruff

For this project, we have selected **Ruff** as our primary linter and formatter.

### Rationale

While exploring available tools supported by modern editors (such as NeoVim via NeoFormat), several options were considered, including `yapf`, `autopep8`, `black`, `pydevf`, `isort`, `docformatter`, `pyment`, and `ruff`. Ruff was chosen for the following reasons:

- **Speed & Efficiency**: Written in Rust, Ruff is incredibly fast, providing near-instant feedback during development.
- **All-in-One Solution**: It combines both linting and formatting capabilities, replacing the need for multiple disparate tools (like `flake8`, `isort`, and `black`).
- **Active Development**: Ruff is under very active development with frequent updates and a growing ecosystem.
- **Comparison with alternatives**:
    - **PyDev Formatter (pydevf)** and **pyment** were excluded due to long periods of inactivity (several years since the last commit).
    - **docformatter** was excluded as it focuses exclusively on docstrings.
    - Ruff provides a modern, high-performance alternative to older tools like `autopep8` or `black`.

## Configuration Strategy

Instead of using a separate `.toml` or Ruff-specific file, we consolidate all configurations within `pyproject.toml`. This approach keeps the project root clean and ensures that the tool settings are managed in a single, authoritative location.

## Core Styling Rules

To maintain consistency and bridge the gap between better technical standards and common Python conventions, we have established the following rules:

### 1. Indentation: Tabs over Spaces
We use **tabs** for indentation instead of spaces. 
- **Consistency**: One tab character always represents exactly one level of indentation, unlike spaces where multiple characters are used to represent a single logical intent. 
- **Efficiency**: Using 4 spaces is a redundant multiplication of characters. 
- **Accessibility**: Tabs allow developers to adjust the visual width of indents in their own editors without changing the source code.
- **Clarification**: While spaces are the common Python convention, explicitly defining tabs in our configuration avoids mismatched expectations and ensures a unified style.

### 2. String Quoting: Single Quotes
We use **single quotes** (`'`) for strings. In Python, there is no functional difference between single and double quotes, but single quotes are easier to type as they do not require holding the Shift key.

### 3. Consistency and Formatting
- **Line Length**: The maximum line length is set to **88** characters.
- **Docstrings**: Docstring formatting is enabled, with a dedicated maximum line length of **60** characters to ensure readability.
- **Trailing Commas**: We utilize "magic trailing commas" to force multi-line collection formatting when a comma is present at the end of a list or tuple.
- **Unused Variables**: Variables that are intentionally unused can be ignored by the linter if they are prefixed with an underscore (e.g., `_variable`).
- **Line Endings**: We enforce LF (`\n`) line endings for all files.
- **Exclusions**: Directories such as `.git`, `venv`, and `.ruff_cache` are excluded from linting.

### 4. Target Version
The project targets **Python 3.14**, ensuring compatibility with upcoming language features and standards.

## Running the Linter

To run the linter and check your code, use:

```bash
ruff check .
```

To automatically fix issues and format the code:

```bash
ruff check --fix .
ruff format .
```

## Installation

For detailed installation instructions, please refer to the official [Ruff Repository](https://github.com/astral-sh/ruff).
