# Production Deployment Guide for MCH (Misconfiguration Helper)

This document provides instructions for Release Engineers and DevOps professionals for deploying MCH in a production or management environment. MCH is a CLI-based security scanner designed to be run from a centralized management box or jump host.

## 1. Hardware Requirements

| Component | Minimum Requirement | Recommended |
| :--- | :--- | :--- |
| **Architecture** | x86_64 / ARM64 | x86_64 |
| **CPU** | 1 vCPU | 2 vCPU (for improved async performance) |
| **Memory (RAM)** | 512 MB | 1 GB+ |
| **Disk Space** | 1 GB | 5 GB+ (to accommodate growing logs and state files) |

## 2. Software Requirements

*   **Operating System**: Linux (LTS distributions recommended: Ubuntu 24.04+, Debian 12+, RHEL 9+).
*   **Python**: Version 3.14 or higher.
*   **Package Manager**: `pip` and `python-venv` for environment isolation.
*   **Dependencies**: All Python dependencies are handled via `pip` (Typer, httpx, Rich, etc.).

## 3. Network Configuration

MCH is an outbound-heavy application. It does not require any inbound connections.

*   **Egress (Outbound)**: The server must have direct or proxied access to the target infrastructure. Port scanning and fuzzing require the ability to open TCP connections to a wide range of ports.
*   **DNS**: Outbound DNS resolution must be functional for scanning hostnames.
*   **Firewall/IDS**: Ensure that the scanning activity is whitelisted on internal firewalls and IDS/IPS systems to prevent the scanning IP from being automatically blocked during high-concurrency scans.
*   **Connection Limits**: If scanning large ranges, ensure the OS `ulimit -n` (open file descriptors) is set high enough (e.g., `65535`).

## 4. Server Configuration

### Service Account
Run MCH under a dedicated, non-privileged system user (e.g., `mch-runner`). Do **not** run as root.

### Environment & Permissions
The service user must have a home directory with write permissions. MCH follows XDG specifications for storage:
*   **Configuration**: `~/.config/mch/`
*   **Logs & State**: `~/.local/share/mch/`

### System Tuning
For high-concurrency port scanning, adjust the local port range and timeout settings in the OS if necessary, though the application handles most of this via `asyncio`.

## 5. Data Storage (DBMS)

MCH does **not** requires an external database management system (like PostgreSQL or MySQL).

*   **Storage Model**: File-based persistence using JSON.
*   **Path**: Results are stored per-host in `~/.local/share/mch/targets/`.
*   **Backup Strategy**: Include the `~/.local/share/mch/` directory in your standard backup rotations to preserve historical scan data and issue acknowledgments.

## 6. Code Deployment

### Manual Deployment
1.  Clone the production branch:
    ```bash
    git clone https://github.com/pn13/misconfiguration-helper.git
    cd misconfiguration-helper
    ```
2.  Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
3.  Install the package:
    ```bash
    pip install .
    ```

### Automated (CI/CD) Deployment
It is recommended to package MCH as a Python wheel and distribute it to the production server:
1.  Build: `python -m build`
2.  Transfer: `scp dist/mch-*.whl prod-server:/tmp/`
3.  Install: `pip install /tmp/mch-*.whl`

## 7. Health Check and Verification

To ensure MCH is correctly deployed and functional, perform the following checks:

1.  **Version/Help Check**:
    ```bash
    mch --help
    ```
    *Expectation*: Returns exit code 0 and displays the help menu.

2.  **Functional Smoke Test**:
    Scan the local loopback to verify network stack integration:
    ```bash
    mch scan ports 127.0.0.1 --override ports.range=22-80
    ```
    *Expectation*: Completes without errors and generates a state file.

3.  **Log Verification**:
    Check the log file for any initialization errors:
    ```bash
    cat ~/.local/share/mch/mch.log
    ```

4.  **State Persistence Check**:
    Verify that the `~/.local/share/mch/targets/` directory contains a JSON file corresponding to the scan target.
