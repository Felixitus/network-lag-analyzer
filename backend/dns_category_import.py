"""Import the UT1 blacklists (Université Toulouse Capitole) as the lowest category layer.

The lists are not shipped: they are large, updated daily and licensed CC BY-SA 4.0.
Download and unpack them yourself, then import offline:

    wget https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz
    tar -xzf blacklists.tar.gz
    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.dns_category_import \\
        --ut1 blacklists --data-dir /var/lib/network-lag-analyzer
    sudo systemctl restart network-lag-analyzer

Only the UT1 categories that map onto ours are read (see MAPPING); adult and
similar lists with millions of entries are skipped on purpose - they would cost
RAM on the Pi and add nothing to these statistics.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .analysis.categories import UT1_FILE, normalize_domain, valid_domain

# UT1 directory → our category. Unlisted UT1 categories are ignored.
MAPPING = {
    "social_networks": "social",
    "games": "gaming",
    "audio-video": "streaming",
    "chat": "communication",
    "webmail": "communication",
    "shopping": "shopping",
    "press": "news",
    "radio": "music",
    "filehosting": "cloud",
    "publicite": "ads_tracking",
    "update": "os_updates",
}


def import_ut1(ut1_dir: Path, out: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    seen: set[str] = set()
    tmp = out.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for ut1_cat, ours in MAPPING.items():
            src = ut1_dir / ut1_cat / "domains"
            if not src.is_file():
                continue
            n = 0
            with open(src, encoding="utf-8", errors="replace") as lines:
                for line in lines:
                    d = normalize_domain(line.split("#", 1)[0])
                    # IP addresses are listed too; they never match a DNS name.
                    if not d or d in seen or d.replace(".", "").isdigit() or not valid_domain(d):
                        continue
                    seen.add(d)
                    f.write(f"{d}\t{ours}\n")
                    n += 1
            counts[ut1_cat] = n
    if not counts:
        tmp.unlink()          # keep a previous, working import
        return counts
    os.replace(tmp, out)      # atomic: a running service never reads half a file
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ut1", required=True, help="unpacked UT1 'blacklists' directory")
    ap.add_argument("--data-dir", required=True, help="data directory of the service")
    a = ap.parse_args(argv)
    src = Path(a.ut1)
    if not src.is_dir():
        print(f"Not a directory: {src}", file=sys.stderr)
        return 2
    counts = import_ut1(src, Path(a.data_dir) / UT1_FILE)
    if not counts:
        print("No known UT1 category found - is this the unpacked 'blacklists' directory?", file=sys.stderr)
        return 2
    for cat, n in counts.items():
        print(f"{cat:16} → {MAPPING[cat]:13} {n:8} domains")
    print(f"Written: {Path(a.data_dir) / UT1_FILE}. Restart the service to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
