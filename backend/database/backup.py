"""Automatic backups of the database (and config.yaml), with rotation.

SQLite's online backup copies a consistent snapshot while the service keeps writing
(WAL mode). The copy is checked with `quick_check` before it counts; only files this
module wrote (``backup-auto-*``) are ever rotated away - manual backups are left alone.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import time
from pathlib import Path

PREFIX = "backup-auto-"


def make_backup(db_path: str, dest_dir: Path, config_path: str | None = None, now: float | None = None) -> dict:
    """Blocking: call it in a thread. Raises when the copy is not usable (it is removed then)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(now or time.time()))
    dst = dest_dir / f"{PREFIX}{stamp}.sqlite3"
    size = os.path.getsize(db_path)
    if shutil.disk_usage(dest_dir).free < 3 * size:
        raise OSError(f"Too little free space for a backup ({size // 1048576} MB database)")
    t0 = time.time()
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    try:
        out = sqlite3.connect(dst)
        try:
            src.backup(out)          # one step: a consistent snapshot, writers are not blocked in WAL mode
            out.execute("PRAGMA journal_mode=DELETE")     # a single self-contained file, no -wal/-shm
            check = out.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            out.close()
    finally:
        src.close()
    if check != "ok":
        dst.unlink(missing_ok=True)
        raise RuntimeError(f"The backup copy failed its check: {check}")
    if config_path and os.path.isfile(config_path):
        try:
            shutil.copyfile(config_path, dest_dir / f"{PREFIX}{stamp}.config.yaml")
        except OSError:
            pass                      # the database is the important part; the config may not be readable
    return {"path": str(dst), "size": dst.stat().st_size, "seconds": round(time.time() - t0, 1), "ts": now or time.time()}


def list_backups(dest_dir: Path) -> list[dict]:
    if not dest_dir.is_dir():
        return []
    out = []
    for p in sorted(dest_dir.glob(f"{PREFIX}*.sqlite3"), reverse=True):
        cfg = p.with_name(p.name.replace(".sqlite3", ".config.yaml"))
        out.append({"name": p.name, "size": p.stat().st_size, "ts": p.stat().st_mtime, "config": cfg.exists()})
    return out


def rotate(dest_dir: Path, keep: int) -> list[str]:
    """Removes the oldest automatic backups beyond `keep` (with their config copy)."""
    removed = []
    for b in list_backups(dest_dir)[keep:]:
        p = dest_dir / b["name"]
        p.unlink(missing_ok=True)
        p.with_name(p.name.replace(".sqlite3", ".config.yaml")).unlink(missing_ok=True)
        removed.append(b["name"])
    return removed
