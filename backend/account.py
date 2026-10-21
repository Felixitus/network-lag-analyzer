"""Manage the login account on the Raspberry Pi (not possible through the web UI).

    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.account set --username admin
    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.account show
    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.account logout-all

`set` asks for the password twice (nothing is echoed, nothing ends up in the shell
history or in `ps`). `--password-stdin` reads it from standard input instead, for
install.sh. Setting the password ends every open session. Works while the service
is running; no restart needed.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from .api import security as s
from .config import build_config, load_yaml
from .database.repository import Database


def _db() -> Database:
    yaml_data, _path = load_yaml(os.environ.get("NLA_CONFIG"))
    cfg = build_config(yaml_data)
    db = Database(os.path.join(cfg.data_dir, "nla.sqlite3"))
    db.init_sync()          # creates the schema if the service never ran yet
    return db


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_set = sub.add_parser("set", help="create the account or change username/password")
    p_set.add_argument("--username", default=None, help="default: keep the current one, else 'admin'")
    p_set.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    sub.add_parser("show", help="show the username and the number of open sessions")
    sub.add_parser("logout-all", help="end every open session")
    a = ap.parse_args(argv)

    db = _db()
    try:
        if a.cmd == "show":
            acc = db.read_sync(s.get_account)
            n = db.read_sync(lambda c: c.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0])
            print(f"Account: {acc['username']}" if acc else "No account set up yet.")
            print(f"Open sessions: {n}")
            return 0
        if a.cmd == "logout-all":
            n = db.write_sync(lambda c: s.revoke_all(c))
            print(f"Ended {n} session(s).")
            return 0
        current = db.read_sync(s.get_account)
        username = a.username or (current["username"] if current else "admin")
        if a.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = getpass.getpass(f"New password for '{username}': ")
            if getpass.getpass("Repeat it: ") != password:
                print("The passwords do not match - nothing changed.", file=sys.stderr)
                return 2
        err = s.check_new_credentials(username, password)
        if err:
            print(f"{err} - nothing changed.", file=sys.stderr)
            return 2
        db.write_sync(lambda c: s.set_account(c, username, password))
        print(f"Account '{username}' saved. All open sessions were ended.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
