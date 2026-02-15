# Core Concepts

This guide explains the underlying architecture and logic of **MCH (Misconfiguration Scanner)**, specifically how it manages its internal state and user settings.

## Configuration System

MCH is designed to be flexible, allowing configuration through three layers of priority:

1. **Default Settings**: Embedded in the `mch/config.py` module.
2. **Persistent Settings**: Stored in a TOML file at `~/.config/mch/config.toml`. This file is created automatically on the first run.
3. **Runtime Overrides**: Provided via the `--override` CLI option (e.g., `mch scan --override ports.timeout=2.0`).

### Config File Structure
The `config.toml` is organized into sections for each scanner (`[ports]`, `[fuzz]`, `[acao]`). Modifying this file allows you to set your own baseline for timeouts, wordlists, and scan ranges.

## State Management

MCH tracks the status of identified issues across multiple sessions. This prevents you from being alerted to the same "accepted" vulnerability repeatedly.

### Storage Location
States are stored per host in the user's data directory:
- **Linux**: `~/.local/share/mch/targets/<hash>.json`
- **macOS/Windows**: Corresponding platform-specific data folders.

### Issue Lifecycle

MCH tracks the status of identified issues across multiple sessions. This prevents you from being alerted to the same "accepted" vulnerability repeatedly.

-   **Uncategorized**: The default status for newly discovered issues. These appear in `report` and `scan` summaries as warnings.
-   **Will Fix**: Identified issues that are acknowledged but not yet resolved.
-   **False Positive / Won't Fix**: Findings that have been manually suppressed via `mch ack`. These are excluded from standard reports.
-   **Acknowledged (Ports only)**: Open ports that are expected (e.g., 80, 443) or manually approved.
-   **Resolved**: If an issue (like a misconfigured ACAO header) was present in a previous scan but is no longer detected, MCH automatically updates its status to `resolved`. If it is re-detected later, it reverts to `uncategorized`.
-   **Fixed (Internal)**: Status used for issues that were explicitly marked as fixed by the user (currently handled via state transition).

## Logging

MCH maintains a detailed debug log at `~/.local/share/mch/mch.log`. This is the go-to resource for troubleshooting scanner failures or connection timeouts.
