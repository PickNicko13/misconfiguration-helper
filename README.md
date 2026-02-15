# MCH - Misconfiguration Scanner

**MCH** (Misconfiguration Scanner) is a command-line tool designed to identify security misconfigurations in networked systems. It supports scanning for open ports, exposed files/directories via fuzzing, and Access-Control-Allow-Origin (ACAO) vulnerabilities. This project is in **early alpha**, so expect breaking changes and limited documentation as it evolves.

## Features

- **Port Scanning**: Identifies open TCP ports on a target host within a configurable range.
- **Fuzzing**: Detects exposed files and directories using customizable wordlists and extensions.
- **ACAO Scanning**: Checks for misconfigured CORS headers, detecting issues like arbitrary origin reflection, leaked IPs/domains, and weak regex patterns.
- **Interactive Acknowledgment**: Allows users to mark issues as false positives, won't fix, or resolved.
- **Rich Console Output**: Uses `rich` for colorful, user-friendly progress and reports.
- **Configuration**: Supports TOML-based configuration with command-line overrides.
- **State Management**: Persists scan results for tracking issue status across runs.

## Installation

MCH requires Python 3.14+ and is installed via `pip`. Clone the repository and install dependencies:

```bash
git clone <repository-url>
cd mch
pip install .
```

### Dependencies

- `typer`: CLI framework
- `httpx`: Asynchronous HTTP requests
- `tomli`, `tomli-w`: TOML parsing and writing
- `desktop-notifier`: System notifications
- `rich`: Rich text and console formatting
- `platformdirs`: Platform-agnostic user data directories

## Usage

MCH provides three main commands: `scan`, `report`, and `ack`. For a complete reference of all arguments and flags, see the [Full Usage Guide](docs/usage.md).

### Quick Start Examples

- **Scan a host**: `mch scan all pma.localhost`
- **Scan with overrides**: `mch scan acao target.com --override acao.timeout=10.0`
- **View issues**: `mch report pma.localhost --type warnings`
- **Acknowledge issues**: `mch ack pma.localhost`

## Configuration and State

MCH uses a TOML configuration file at `~/.config/mch/config.toml` (created automatically on first run) and persists scan results in the user's data directory to track the lifecycle of each issue.

For a deeper dive into the priority of configuration layers and how issue states are managed, see the [Core Concepts](docs/concepts.md) guide.

## Logging

Detailed debug logs are written to `~/.local/share/mch/mch.log` and displayed in the console (info level, or debug with `--verbose`).

## Code Quality
I maintain high code quality standards using:
- **Ruff**: For lightning-fast linting and formatting.
- **Ty**: For static type checking.
- **Pytest**: For automated testing.

See [Linting & Quality](docs/linting.md) and [Building](docs/build.md) for details on the quality gating and build process.

## Documentation

The project documentation is built with **MkDocs** and the **Terminal** theme. Detailed information about the documentation build process, standards, and maintenance can be found in the [Documentation Generation Guide](docs/generate_docs.md).

Deep-dives into the project's internal logic, algorithms, and component design are available in the [Architecture Guide](docs/architecture.md).

### Documentation Commands

- **Build**: `make docs`
- **Preview**: `make serve-docs`

## Code Quality
We maintain high code quality standards using:
- **Ruff**: For lightning-fast linting and formatting.
- **Ty**: For static type checking.
- **Pytest**: For automated testing.

See [Linting & Quality](docs/linting.md) and [Building](docs/build.md) for details on our quality gating and build process.

## Known Limitations

- Early alpha: Expect bugs and evolving features.
- Fuzz scanner may generate false positives on custom 404 pages.
- ACAO scanner assumes HTTP/HTTPS schemes; other protocols are unsupported.

## License

GPL-3.0-only
