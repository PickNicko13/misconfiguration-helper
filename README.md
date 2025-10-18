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

MCH requires Python 3.8+ and is installed via `pip`. Clone the repository and install dependencies:

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

MCH provides three main commands: `scan`, `report`, and `ack`. Run `mch --help` for details.

### Scan

Scan hosts for misconfigurations:

```bash
mch scan [TYPES] [HOSTS] [OPTIONS]
```

- **Types**: Comma-separated scan types (`ports`, `fuzz`, `acao`) or `all` (default).
- **Hosts**: One or more target hosts (IP or URL).
- **Options**:
  - `--host-list FILE`: File with hosts, one per line.
  - `--no-notify`: Disable system notifications.
  - `--warn-html-errors`: Warn on HTML parsing errors (fuzz scanner).
  - `--override SECTION.KEY=VALUE`: Override config (e.g., `ports.range=1-1000`).
  - `-v, --verbose`: Enable debug output.

Example:

```bash
mch scan acao pma.localhost --override acao.endpoints=/,/admin --verbose
```

### Report

View scan results:

```bash
mch report HOSTS [--type TYPE]
```

- **Hosts**: Hosts to report on.
- **Type**: Report type:
  - `warnings` (default): Unacknowledged ports, fuzz issues, and uncategorized/will-fix ACAO issues.
  - `critical`: ACAO issues with `arbitrary` or `leaked_ip` types.
  - `all`: All scan results and statuses.

Example:

```bash
mch report pma.localhost --type warnings
```

### Acknowledge

Interactively acknowledge issues:

```bash
mch ack HOST
```

- **Host**: Host to acknowledge issues for.
- Options for ports: `acknowledge`, `skip`.
- Options for fuzz/ACAO issues: `false_positive`, `wont_fix`, `skip`.

Example:

```bash
mch ack pma.localhost
```

## Configuration

MCH uses a TOML configuration file at `~/.config/mch/config.toml` (created automatically with defaults).

Config overrides are possible via the `--override` CLI option:

```bash
mch scan fuzz pma.localhost --override fuzz.extensions=.php,.html
```

## State Management

Scan results are stored in `~/{user_data_dir}/mch/targets/<hash>.json` per host, tracking:

- Open ports and acknowledged ports.
- Fuzz issues (exposed paths) with statuses (`issues`, `will_fix`, `false_positive`, `wont_fix`).
- ACAO issues with statuses (`uncategorized`, `will_fix`, `false_positive`, `wont_fix`, `resolved`).

**Note**: user_data_dir is system-dependent. For most linux setups it is `~/.local/share`.

## Logging

Logs are written to `~/.local/share/mch/mch.log` (debug level) and displayed in the console (info level, or debug with `--verbose`).

## Known Limitations

- Early alpha: Expect bugs and missing features.
- No comprehensive test suite yet.
- Fuzz scanner may generate false positives on custom 404 pages.
- ACAO scanner assumes HTTP/HTTPS schemes; other protocols are unsupported.

## License

GPL-3.0-only
