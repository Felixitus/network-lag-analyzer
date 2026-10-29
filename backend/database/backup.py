"""Automatic backups of the database (and config.yaml), with rotation.

SQLite's online backup copies a consistent snapshot while the service keeps writing
(WAL mode). The copy is checked with `quick_check` before it counts; only files this
module wrote (``backup-auto-*``, ``backup-pre-update-*``) are ever rotated away - manual
backups are left alone.

install.sh calls ``python -m backend.database.backup pre-update`` before it restarts the
service, so every update can be undone - also one started from the update command in the UI.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import time
from pathlib import Path

PREFIX = "backup-auto-"
UPDATE_PREFIX = "backup-pre-update-"
FILE_MODE = 0o640                      # like the database: settings and the login hash are inside


def make_backup(db_path: str, dest_dir: Path, config_path: str | None = None, now: float | None = None,
                prefix: str = PREFIX) -> dict:
    """Blocking: call it in a thread. Raises when the copy is not usable (it is removed then)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(now or time.time()))
    dst = dest_dir / f"{prefix}{stamp}.sqlite3"
    size = os.path.getsize(db_path)
    if shutil.disk_usage(dest_dir).free < 3 * size:
        raise OSError(f"Too little free space for a backup ({size // 1048576} MB database)")
    t0 = time.time()
    try:
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
            raise RuntimeError(f"The backup copy failed its check: {check}")
    except BaseException:
        # a half-written copy must not stand in the list as if it were a backup
        dst.unlink(missing_ok=True)
        raise
    # Explicitly, not by umask: the service has 0027, but install.sh runs this through sudo with 0022.
    os.chmod(dst, FILE_MODE)
    if config_path and os.path.isfile(config_path):
        cfg_copy = dest_dir / f"{prefix}{stamp}.config.yaml"
        try:
            shutil.copyfile(config_path, cfg_copy)
            os.chmod(cfg_copy, FILE_MODE)
        except OSError:
            pass                      # the database is the important part; the config may not be readable
    return {"path": str(dst), "size": dst.stat().st_size, "seconds": round(time.time() - t0, 1), "ts": now or time.time()}


def list_backups(dest_dir: Path, prefixes: tuple[str, ...] = (PREFIX,)) -> list[dict]:
    if not dest_dir.is_dir():
        return []
    out = []
    # newest first by the stamp in the name, whatever the kind
    files = {p.name[len(pre):]: p for pre in prefixes for p in dest_dir.glob(f"{pre}*.sqlite3")}
    for _stamp, p in sorted(files.items(), reverse=True):
        cfg = p.with_name(p.name.replace(".sqlite3", ".config.yaml"))
        out.append({"name": p.name, "size": p.stat().st_size, "ts": p.stat().st_mtime, "config": cfg.exists()})
    return out


def rotate(dest_dir: Path, keep: int, prefix: str = PREFIX) -> list[str]:
    """Removes the oldest backups of one kind beyond `keep` (with their config copy)."""
    removed = []
    for b in list_backups(dest_dir, (prefix,))[keep:]:
        p = dest_dir / b["name"]
        p.unlink(missing_ok=True)
        p.with_name(p.name.replace(".sqlite3", ".config.yaml")).unlink(missing_ok=True)
        removed.append(b["name"])
    return removed


UPDATE_KEEP = 2


def main(argv: list[str] | None = None) -> int:
    """`pre-update`: a checked copy before install.sh restarts the service. Exit 1 if it failed."""
    import argparse
    import sys

    from ..config import build_config, load_yaml
    ap = argparse.ArgumentParser(description="Backup of the database before an update")
    ap.add_argument("cmd", choices=["pre-update"])
    ap.parse_args(argv)
    yaml_data, config_path = load_yaml(os.environ.get("NLA_CONFIG"))
    cfg = build_config(yaml_data)
    db_path = os.path.join(cfg.data_dir, "nla.sqlite3")
    if not os.path.isfile(db_path):
        print("No database yet - nothing to back up")
        return 0
    dest = Path(cfg.data_dir) / "backups"
    try:
        res = make_backup(db_path, dest, config_path, prefix=UPDATE_PREFIX)
    except Exception as e:  # noqa: BLE001 - whatever it was, the update must not go on without a copy
        print(f"Backup failed: {e}", file=sys.stderr)
        return 1
    rotate(dest, UPDATE_KEEP, UPDATE_PREFIX)
    print(f"{res['path']} ({res['size'] // 1048576} MB, checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
