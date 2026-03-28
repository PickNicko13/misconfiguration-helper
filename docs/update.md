# Update and Rollback Guide for MCH (Misconfiguration Scanner)

This document provides Release Engineers and DevOps professionals with a structured procedure for upgrading MCH to newer versions and rolling back in the event of failure.

## 1. Preparation for Update

### Backup Scan State and Configuration
Before any update, perform a full backup of the state and configuration directories as described in the [Backup Guide](backup.md). This is critical because some updates may modify the JSON schema of the target states.

### Compatibility Check
Review the `pyproject.toml` or `CHANGELOG.md` for:
*   **Python Version**: Verify if a newer version of Python (e.g., 3.15) is now required.
*   **Breaking Dependencies**: Check for major version bumps in core libraries like `httpx` or `rich`.

### Planning Downtime
As a CLI tool, MCH does not have "downtime" in the traditional sense. However, if you have scheduled scans (e.g., via `cron` or Kubernetes `CronJob`), you should temporarily disable them to ensure no scan is running during the file replacement process.

## 2. Update Process

### Step 1: Pause Scheduled Scans
Suspend your automation to prevent MCH from starting a new session mid-update:
```bash
# Example for systemd/cron
crontab -l > /tmp/crontab.bak
crontab -r
```

### Step 2: Deploy New Code
If using the standard [Deployment Guide](deployment.md) structure:
1.  **Pull latest source**:
    ```bash
    cd /opt/mch
    git pull origin master
    ```
2.  **Update Virtual Environment**:
    ```bash
    source venv/bin/activate
    pip install .
    ```

### Step 3: Migration and Configuration
1.  **Data Migration**: Check target logs for schema change warnings. Currently, MCH automatically attempts to handle minor JSON additions. If a formal migration script is provided, run it before restarting scans.
2.  **Configuration Update**: Compare your existing `~/.config/mch/config.toml` with any new default keys introduced in `mch/config.py`. Update your local config to expose new scanner features.

## 3. Rollback Procedure

In the event of a failed update (e.g., dependency conflicts or data corruption), follow these steps to return to a known stable state.

### Step 1: Revert Code
Roll back to the previous stable commit or reinstall the previous Python wheel:
```bash
git checkout <previous-tag-or-commit-hash>
pip install .
```

### Step 2: Restore Data (Rollback State)
If the new version made changes to the JSON state files (`~/.local/share/mch/targets/`) that were not backward compatible, restore the state from your pre-update backup:
1.  Clear the corrupted state:
    ```bash
    rm -rf ~/.local/share/mch/targets/*
    ```
2.  Restore from pre-update archive:
    ```bash
    tar -xzf mch-pre-update-backup.tar.gz -C /
    ```

### Step 3: Resume Scheduled Scans
Once the tool is verified on the previous version, re-enable your automation:
```bash
crontab /tmp/crontab.bak
```

---
**See also:**
- [Production Deployment Guide](deployment.md)
- [Backup and Recovery Instructions](backup.md)
