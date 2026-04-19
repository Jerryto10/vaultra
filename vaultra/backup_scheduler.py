# Copyright (c) 2026 Jerly Rojas
# Vaultra — AI Agent Compliance Layer
# AGPL-3.0 License. Commercial use: legal@vaultra.io

"""
backup_scheduler.py — Vaultra Ledger Auto-Backup
=================================================
Runs a background thread that exports a signed ledger backup
every 24 hours (configurable). Closes R-15.

Usage (add to your integration):
    from vaultra.backup_scheduler import start_backup_scheduler
    from vaultra.ledger import ProvenanceLedger

    ledger = ProvenanceLedger("my_ledger.db")
    start_backup_scheduler(ledger, backup_dir="/backups/vaultra")

The backup runs automatically every 24h in a daemon thread.
Each backup file is named: vaultra_ledger_YYYY-MM-DD_HHMMSS.json
"""

import os
import time
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("vaultra.backup")


def _backup_worker(
    ledger,
    backup_dir: str,
    interval_seconds: int,
    max_backups: int,
):
    """Background worker that runs the backup loop."""
    backup_path = Path(backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True)

    logger.info(f"[Vaultra] Backup scheduler started | dir={backup_dir} | interval={interval_seconds}s")

    while True:
        try:
            # Generate timestamped filename
            now = datetime.now(timezone.utc)
            filename = f"vaultra_ledger_{now.strftime('%Y-%m-%d_%H%M%S')}.json"
            output_path = str(backup_path / filename)

            # Export signed backup
            result = ledger.export_backup(output_path)

            if result["success"]:
                logger.info(
                    f"[Vaultra] Backup OK | file={filename} | "
                    f"entries={result['entry_count']} | "
                    f"integrity={result['chain_integrity']} | "
                    f"seal={result['seal']}"
                )
            else:
                logger.warning(f"[Vaultra] Backup failed: {result}")

            # Rotate old backups — keep only max_backups most recent
            existing = sorted(backup_path.glob("vaultra_ledger_*.json"))
            if len(existing) > max_backups:
                for old_file in existing[:-max_backups]:
                    old_file.unlink()
                    logger.info(f"[Vaultra] Old backup removed: {old_file.name}")

        except Exception as e:
            logger.error(f"[Vaultra] Backup error: {e}")

        # Wait for next interval
        time.sleep(interval_seconds)


def start_backup_scheduler(
    ledger,
    backup_dir: str = "./vaultra_backups",
    interval_hours: float = 24.0,
    max_backups: int = 30,
    run_immediately: bool = True,
) -> threading.Thread:
    """
    Start the automatic ledger backup scheduler.

    Args:
        ledger:          ProvenanceLedger instance to back up
        backup_dir:      Directory to store backup files
        interval_hours:  How often to run backup (default: 24h)
        max_backups:     Maximum backup files to keep (default: 30 = 1 month)
        run_immediately: Run first backup immediately on start (default: True)

    Returns:
        The background thread (daemon=True, stops with main process)

    Example:
        from vaultra.ledger import ProvenanceLedger
        from vaultra.backup_scheduler import start_backup_scheduler

        ledger = ProvenanceLedger("production.db")
        start_backup_scheduler(ledger, backup_dir="/data/backups")
    """
    interval_seconds = int(interval_hours * 3600)

    if run_immediately:
        # Run first backup immediately in a separate thread
        def first_backup():
            try:
                backup_path = Path(backup_dir)
                backup_path.mkdir(parents=True, exist_ok=True)
                now = datetime.now(timezone.utc)
                filename = f"vaultra_ledger_{now.strftime('%Y-%m-%d_%H%M%S')}.json"
                output_path = str(backup_path / filename)
                result = ledger.export_backup(output_path)
                logger.info(f"[Vaultra] Initial backup OK | entries={result['entry_count']}")
            except Exception as e:
                logger.error(f"[Vaultra] Initial backup error: {e}")

        t0 = threading.Thread(target=first_backup, daemon=True)
        t0.start()

    # Start the main backup loop
    thread = threading.Thread(
        target=_backup_worker,
        args=(ledger, backup_dir, interval_seconds, max_backups),
        daemon=True,
        name="vaultra-backup",
    )
    thread.start()

    print(
        f"[Vaultra] Backup scheduler active | "
        f"dir={backup_dir} | "
        f"every {interval_hours}h | "
        f"max {max_backups} files"
    )
    return thread
