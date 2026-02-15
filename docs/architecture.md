# Architectural Guide

This document explains the internal architecture of **MCH (Misconfiguration Scanner)**, its component interactions, and the specialized algorithms used for detection.

## Component Interaction

The system is designed with a clear separation between the command-line interface, configuration management, and the scanning engines.

### 1. The Orchestration Flow
When a user executes `mch scan`:

1.  **`cli.py` (Entry Point)**: Parses arguments and initializes the `ConfigManager` and `StateManager`.
2.  **`ConfigManager` & `StateManager`**: Load the project configuration and the persistent data for the target hosts (identified by MD5 hashes for privacy and file-system compatibility).
3.  **The Orchestrator (`async_scan`)**:
    -   Validates targets using `utils.validate_target`.
    -   Instantiates requested scanners (ports, fuzz, acao) with the shared config/state.
    -   Starts an asynchronous `Live` display using **Rich** to provide real-time feedback.
4.  **Scanner execution**: Each scanner runs its logic concurrently using `asyncio` semaphores to prevent network congestion.
5.  **State Persistence**: Results are merged into the `StateManager` and written to disk only after the host scan completes.

## Interaction Design & UX

MCH prioritizes a responsive and interactive user experience through two key systems:

### 1. Real-time Orchestration
The `async_scan` function uses **Rich's Live** display to update a multi-target progress bar (50fps). It dynamically queries each scanner for its `get_progress()` string, allowing users to see exactly where a long-running scan (like a 65k port scan) currently stands.

### 2. Cross-Platform Single-Keypress Input
The `ack` command utilizes a custom `SingleKeyPrompt` (`mch/prompt.py`) that implements low-level terminal control:
-   **Linux/macOS**: Uses `tty` and `termios` to set the terminal to cbreak mode, capturing single characters without requiring an "Enter" keypress.
-   **Windows**: Uses `msvcrt.getch()` for native console interaction.
-   **Auto-Mapping**: The system automatically assigns unique underlined shortcuts (e.g., [a]cknowledge, [s]kip) based on available letters in the option names.

---

## The Scanner Contract

All scanners inherit from `BaseScanner` (`mch/scanners/base.py`). This abstract base class enforces a uniform interface:

-   `run_async()`: The core entry point for the scanning logic.
-   `get_progress()`: Optional method for the UI to query the current percentage completion.
-   `state`: A local reference to the host-specific state, allowing scanners to compare new findings with previously acknowledged ones.

---

## Technical Logic & Algorithms

### Network Robustness: Exponential Backoff
All scanners implement a unified retry strategy to handle transient network failures or rate-limiting (HTTP 429).
-   **Strategy**: Max 3 retries.
-   **Backoff**: Doubling delay (0.1s, 0.2s, 0.4s for ports; 1s, 2s, 4s for HTTP) between attempts.
-   **Error Handling**: Connection timeouts and refused connections are logged silently at the debug level to avoid UI clutter during high-volume scans.

### ACAO: Broad Origin Reflection Detection
The `AcaoScanner` doesn't just check for `*`. It tests for a common developer mistake: **incomplete regex matching**.

**Algorithm**:
1.  **Arbitrary Origin**: Tests if `evil.com` is reflected.
2.  **Prefix/Suffix Crafting**: If the server accepts `target.com`, the scanner crafts origins like `http://evil-target.com`.
3.  **IP Leakage**: Scans response headers for any leaked internal IPv4 addresses using a specialized regex (`r'\b(?:\d{1,3}\.){3}\d{1,3}\b'`) and validating them with the `ipaddress` module.

### Fuzzing: Smart 404 Detection
Many modern web applications return a custom HTML page with a `200 OK` status code even when a resource is missing. Standard fuzzers often report these as "exposed files".

**Algorithm**:
-   **Status Check**: Any non-200 or 404 response is analyzed (3xx, 5xx).
-   **Heuristic Analysis**: If the status is `200`, the scanner inspects the response body for common "Not Found" or "404" strings.
-   **False Positive Mitigation**: This hybrid approach reduces "junk" findings significantly.

### Port Scanning: High-Concurrency Probing
To scan 65,535 ports efficiently without triggering network rate-limiters or exhausting system file handles:

-   **Semaphore Gating**: We use `asyncio.Semaphore(100)` to strictly limit the number of simultaneous connection attempts.
-   **Non-Blocking Scopes**: We use `asyncio.open_connection` with a short timeout. If a port doesn't respond quickly, it's marked as closed and the worker immediately moves to the next port.

## Severity & Reporting Logic

The `report` command doesn't just display raw data; it applies business logic to categorize findings:

-   **Critical**: Scoped to ACAO issues that reflect an **arbitrary origin** (`evil.com`) or **leaked internal IPs**. These represent high-impact exposures.
-   **Warning (Default)**: Includes all unacknowledged open ports and any fuzzing results (including 3xx redirects which may indicate hidden structural information).
-   **Suppression**: Issues marked as `false_positive` or `wont_fix` are excluded from both Critical and Warning views, allowing users to focus on actionable data.

## Interaction with Ecosystem

-   **`desktop-notifier`**: Interacts with the local DBus (Linux), Notification Center (macOS), or Action Center (Windows). Notifications are sent as a **summary alert** only after the entire session (all hosts) completes to minimize user interruption.
-   **`typer`**: Handles the mapping of Python function signatures to the CLI help system, ensuring that docstrings are correctly rendered to the user.
