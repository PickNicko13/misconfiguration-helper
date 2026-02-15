# Documentation Generation

This document provides a detailed overview of the documentation system for **MCH (Misconfiguration Scanner)** and how to maintain it.

## Infrastructure

The project uses a static site generator coupled with automated discovery tools to ensure the documentation stays in sync with the source code.

- **[MkDocs](https://www.mkdocs.org/)**: The core static site generator.
- **[Terminal](https://github.com/Gioni06/mkdocs-terminal)**: Our customized, high-contrast, terminal-like CSS theme.
- **[mkdocstrings](https://mkdocstrings.github.io/)**: A plugin that parses Python docstrings and injects them into the Markdown site.
- **[mkdocs-typer2](https://github.com/marcelog/mkdocs-typer2)**: A plugin that renders the Typer CLI app help screens as beautiful Markdown tables.

## Developer Workflow

### 1. Daily Maintenance
To build and preview changes as you work, use the local `Makefile` commands:

- **Build**: `make docs` (outputs to the `site/` directory).
- **Live Preview**: `make serve-docs` (hosts the site at `http://127.0.0.1:8000`).

### 2. Documenting New Code
To maintain high-quality technical references, follow these requirements:

- **Google-Style Docstrings**: All public APIs must include docstrings following the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings).
- **Module Registration**: New modules must be added to the `nav` section in `mkdocs.yml` and a corresponding `.md` file must be created in `docs/api/` using the `::: <module_path>` identifier.
- **CLI Updates**: If you add new commands or arguments to `mch/cli.py`, ensure the `help` strings are descriptive, as they are used to generate the [Usage Guide](usage.md).

## Markdown Styles

We use the following extensions to enhance readability:

- **Admonitions**: Use `!!! note`, `!!! warning`, or `!!! critical` for callouts.
- **Syntax Highlighting**: Code blocks are automatically styled using our custom Gruvbox palette.
- **Tables**: Use standard Markdown tables for structured data.

---
See also:
- [Building the Project](build.md)
- [Usage Guide](usage.md)
