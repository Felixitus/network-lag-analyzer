"""Prints whether Pi-hole's DNS log can be attributed to individual devices.

Read-only. Run as the service user so that the file permissions are the real ones:

    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.dns_mapping_report --hours 24

The output contains IPs, MACs and host names of the local network - it is meant
for the terminal, not for issues or the repository.
"""
from __future__ import annotations

import argparse
import sys
import time

from .analysis.dns_clients import ClientResolver, summarize
from .collectors.ftl_queries import FtlQueryLog, FtlSchemaError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default="/etc/pihole/pihole-FTL.db")
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("--own-ip", action="append", default=[], help="address of this Pi (repeatable)")
    ap.add_argument("--top", type=int, default=40)
    a = ap.parse_args(argv)

    log = FtlQueryLog(a.db)
    try:
        schema = log.schema()
        oldest, newest = log.time_range()
        resolver = ClientResolver(log.network(), own_ips=a.own_ip)
        end = time.time()
        t0 = time.monotonic()
        s = summarize(log.iter_range(end - a.hours * 3600, end), resolver)
        took = time.monotonic() - t0
    except FtlSchemaError as e:
        print(f"Not usable: {e}", file=sys.stderr)
        return 2
    except Exception as e:   # sqlite3.Error, PermissionError: the message is what the user needs
        print(f"FTL database not readable: {e}", file=sys.stderr)
        return 2

    def ts(t):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "-"
    print(f"Schema: {'normalized (query_storage)' if schema.normalized else 'legacy (queries table)'}")
    print(f"Data range in FTL: {ts(oldest)} … {ts(newest)}")
    print(f"Evaluated: last {a.hours:g} h in {took:.1f} s")
    print(f"Queries: {s['queries']} (plus {s['duplicates']} retries/duplicates, not counted)")
    share = s["attributable_share"]
    print("Device queries attributed to a MAC: "
          + (f"{share:.1%}" if share is not None else "Not available (no device queries)")
          + f"  | IP only: {s['by_basis']['ip']}  | this Pi: {s['by_basis']['local']}")
    for w in s["warnings"]:
        print(f"WARNING: {w}")
    if s["devices_with_several_ips"]:
        print(f"Devices with several IPs in this range: {len(s['devices_with_several_ips'])}")
    print()
    print(f"{'basis':5} {'client':28} {'name':28} {'queries':>8} {'blocked':>8} {'domains':>8}  note")
    for st in s["clients"][:a.top]:
        att = st.attribution
        who = att.mac or att.ip
        note = att.reason or (", ".join(sorted(st.ips)) if len(st.ips) > 1 else "")
        print(f"{att.basis:5} {who:28} {(att.name or '-')[:28]:28} {st.queries:8} {st.blocked:8} "
              f"{len(st.domains):8}  {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
