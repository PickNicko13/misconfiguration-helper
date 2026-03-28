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

## Developer Onboarding

This step-by-step guide is designed for new developers working on a fresh Arch Linux installation. It covers everything from system setup to your first successful scan.

### 1. Prerequisites (Arch Linux)

Install the necessary system dependencies using `pacman`. This includes Git for cloning, Python, and the tools needed to create virtual environments.

```bash
sudo pacman -S --needed git python python-pip python-virtualenv base-devel
```

> [!NOTE]
> `base-devel` is often required for Python packages that need to compile C extensions during installation, though most `mch` dependencies provide pre-built wheels.

### 2. Clone the Repository

Clone the project to your local machine:

```bash
git clone <repository-url>
cd misconfiguration-helper
```

### 3. Environment Configuration

Create a virtual environment to isolate the project's dependencies from your system-wide Python installation. This is especially important on Arch Linux to avoid PEP 668 conflicts.

```bash
python -m venv venv
source venv/bin/activate
```

Once activated, your shell prompt will typically show `(venv)`.

### 4. Dev Mode Installation

Install the project in editable mode (`-e`) along with all development, testing, and documentation dependencies:

```bash
pip install -e ".[dev]"
```

Editable mode allows you to see changes in the source code immediately without having to reinstall the package.

### 5. Verify Installation

Confirm that the installation was successful by running the help command for the CLI:

```bash
mch --help
```

You should see a list of available commands: `scan`, `report`, and `ack`.

### 6. Success: Your First Scan

To verify everything is working as expected, try scanning a test target:

```bash
mch scan all pma.localhost
```

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

## Common Developer Tasks

### Resetting the Warnings Database
If you want to clear all saved scan results and start with a fresh slate, you can delete the local state directory:
```bash
rm -rf ~/.local/share/mch/targets/
```

### Configuration
The main configuration file is located at `~/.config/mch/config.toml`. It is automatically generated with default values when you first run the application. You can modify this file to change default ports, wordlists, or timeouts.

### Quality & Testing
I maintain high code quality standards using:
- **Ruff**: For lightning-fast linting and formatting (`make lint`).
- **Ty**: For static type checking (`make typecheck`).
- **Pytest**: For automated testing (`make tests`).

See [Linting & Quality](docs/linting.md) and [Building](docs/build.md) for details on the quality gating and build process.

## Documentation

The project documentation is built with **MkDocs** and the **Terminal** theme. Detailed information about the documentation build process, standards, and maintenance can be found in the [Documentation Generation Guide](docs/generate_docs.md).

Deep-dives into the project's internal logic, algorithms, and component design are available in the [Architecture Guide](docs/architecture.md).

### Documentation Commands

- **Build**: `make docs`
- **Preview**: `make serve-docs`


## Known Limitations

- Early alpha: Expect bugs and evolving features.
- Fuzz scanner may generate false positives on custom 404 pages.
- ACAO scanner assumes HTTP/HTTPS schemes; other protocols are unsupported.
- Hasn't been tested on Mac and Windows (although should presumably work fine).

## License

GPL-3.0-only
