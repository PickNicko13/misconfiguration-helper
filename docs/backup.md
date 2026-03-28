# Backup and Recovery Guide for MCH (Misconfiguration Helper)

This guide provides DevOps and Release Engineers with instructions for securing and restoring the data used by MCH. As MCH is local-first and uses file-based state management, backup procedures are straightforward and integrated with standard Linux filesystem tools.

## 1. Backup Strategy

Because MCH data primarily consists of JSON and TOML files, the footprint is small, allowing for highly efficient backup strategies.

### Backup Types
*   **Full Backups**: Recommended. Due to the small size of scan results, performing a full archive of the storage directory is the most reliable method.
*   **Incremental Backups**: Optional. Can be used if the number of targets grows into the tens of thousands, utilizing a tool like `rsync`.

### Frequency
*   **Production State**: Daily (or after each major scan session).
*   **Configuration**: Weekly (or whenever settings are changed).

### Storage and Rotation
*   **Retention**: I recommend the following schedule:
    *   7 daily backups.
    *   4 weekly backups.
    *   1 monthly archive.
*   **Encryption**: Ensure backup archives are encrypted if they contain sensitive IP ranges or vulnerability metadata.

## 2. Backup Procedure

The following directories/files must be included in the backup scope. Assuming the service user is `mch-runner`:

### "Database" (Scan State)
MCH stores all scan results, issue status, and acknowledgments as JSON files.
*   **Path**: `~/.local/share/mch/targets/`

### Configuration Files
Contains scanner settings, API timeouts, and custom wordlist paths.
*   **Path**: `~/.config/mch/config.toml`

### User Data (Custom Assets)
If the user utilizes custom wordlists for the `fuzz` scanner, ensure these paths are backed up. By default, MCH uses wordlists bundled with the package, but production overrides usually point to external paths.

### System Logs
Useful for auditing scan history and debugging tool performance.
*   **Path**: `~/.local/share/mch/mch.log`

## 3. Automation and Integrity

### Sample Backup Script (`mch-backup.sh`)
```bash
#!/bin/bash
BACKUP_DIR="/mnt/backups/mch"
DATE=$(date +%Y-%m-%d)
SRC_CONFIG="$HOME/.config/mch"
SRC_SHARE="$HOME/.local/share/mch"

mkdir -p "$BACKUP_DIR"

tar -czf "$BACKUP_DIR/mch-backup-$DATE.tar.gz" "$SRC_CONFIG" "$SRC_SHARE"

# Integrity Check: Verify JSON validity of at least one target
if command -v jq >/dev/null 2>&1; then
    find "$SRC_SHARE/targets/" -name "*.json" | head -n 1 | xargs jq empty
    if [ $? -ne 0 ]; then
        echo "Warning: State files appear corrupted."
    fi
fi

# Clean up backups older than 30 days
find "$BACKUP_DIR" -type f -mtime +30 -delete
```

### Tools Recommendation
*   **Cron**: For scheduling the above script.
*   **Rclone**: For syncing backups to cloud storage (S3, GCS).
*   **GnuPG**: For encrypting archives.

## 4. Recovery Procedure

### Full System Recovery
1.  Re-install MCH on the target server (follow the [Deployment Guide](deployment.md)).
2.  Extract the backup archive to the home directory:
    ```bash
    tar -xzf mch-backup-YYYY-MM-DD.tar.gz -C /
    ```
3.  Verify that permissions are correct for the `mch-runner` user.

### Selective Data Recovery
If you only need to restore specific host data:
1.  Identify the MD5 hash of the hostname (MCH uses hashes for filenames).
2.  Extract only the relevant JSON from the archive:
    ```bash
    tar -xzf mch-backup.tar.gz home/mch-runner/.local/share/mch/targets/<hash>.json
    ```

### Recovery Testing
Periodically (once a month), restore a backup to a staging environment and run:
```bash
mch report <known-host> --type all
```
Ensure that previous acknowledgments and scan dates appear correctly in the output.
