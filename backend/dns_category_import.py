"""Import the UT1 blacklists (Université Toulouse Capitole) as the lowest category layer.

The lists are not shipped: they are large, updated daily and licensed CC BY-SA 4.0.
Download and unpack them yourself, then import offline:

    mkdir /tmp/ut1 && cd /tmp/ut1
    curl -O https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz
    tar -xzf blacklists.tar.gz --wildcards '*/domains'
    sudo -u nla /opt/network-lag-analyzer/venv/bin/python -m backend.dns_category_import \\
        --ut1 /tmp/ut1/blacklists --data-dir /var/lib/network-lag-analyzer \\
        --archive /tmp/ut1/blacklists.tar.gz
    sudo systemctl restart network-lag-analyzer

Only the UT1 categories that map onto ours are read (see MAPPING). The result is a
hash index (8 bytes per domain, about 40 MB for 5 million names) that the service
searches on disk instead of loading it into memory.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import time
from array import array
from pathlib import Path
from typing import Callable, Iterator

from .analysis.categories import UT1_INDEX, UT1_META, normalize_domain, ut1_key, valid_domain

# UT1 directory → our category, in priority order: a domain listed twice keeps the first.
# Unlisted UT1 categories are ignored.
MAPPING = {
    "adult": "adult",
    "gambling": "gambling",
    "dating": "dating",
    "malware": "threat",
    "phishing": "threat",
    "vpn": "vpn",
    "doh": "vpn",               # DNS over HTTPS servers: devices that resolve past Pi-hole
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


def _sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _dir_lists(ut1_dir: Path) -> Callable[[str], Iterator[str] | None]:
    def lines(cat: str):
        src = ut1_dir / cat / "domains"
        return open(src, encoding="utf-8", errors="replace") if src.is_file() else None
    return lines


def _tar_lists(archive: Path) -> tuple[Callable[[str], Iterator[str] | None], tarfile.TarFile]:
    """The domain lists straight from blacklists.tar.gz. Nothing is extracted to disk, so no member
    name can write anywhere - the archive comes from the internet."""
    tar = tarfile.open(archive, "r:gz")
    members = {}
    for m in tar:
        parts = m.name.split("/")
        # exactly <top>/<category>/domains, the first one wins: a second entry of the same
        # category elsewhere in the archive must not replace the real list
        if (m.isfile() and len(parts) == 3 and parts[2] == "domains" and parts[1] in MAPPING
                and ".." not in parts and parts[1] not in members):
            members[parts[1]] = m

    def lines(cat: str):
        m = members.get(cat)
        return io.TextIOWrapper(tar.extractfile(m), encoding="utf-8", errors="replace") if m else None
    return lines, tar


def import_ut1(ut1_dir: Path | None, data_dir: Path, archive: Path | None = None) -> dict[str, int]:
    tar = None
    if ut1_dir is not None:
        source = _dir_lists(ut1_dir)
    else:
        source, tar = _tar_lists(archive)
    try:
        return _import(source, data_dir, archive)
    finally:
        if tar is not None:
            tar.close()


def _import(source, data_dir: Path, archive: Path | None) -> dict[str, int]:
    cats = list(dict.fromkeys(MAPPING.values()))
    code = {c: i for i, c in enumerate(cats)}
    keys = array("Q")              # 8 bytes per entry instead of a Python object per domain
    counts: dict[str, int] = {}
    for ut1_cat, ours in MAPPING.items():
        src = source(ut1_cat)
        if src is None:
            continue
        n = 0
        with src as lines:
            for line in lines:
                d = normalize_domain(line.split("#", 1)[0])
                # IP addresses are listed too; they never match a DNS name.
                if not d or d.replace(".", "").isdigit() or not valid_domain(d):
                    continue
                keys.append(ut1_key(d) | code[ours])
                n += 1
        counts[ut1_cat] = n
    if not counts:
        return counts              # keep a previous, working import
    # A domain listed in several categories sorts its entries next to each other, the one
    # with the lowest code first - and codes follow MAPPING's order, so the first one wins.
    ordered, last = [], -1
    for k in sorted(keys):
        if k >> 8 != last:
            ordered.append(k)
            last = k >> 8
    del keys
    idx, meta = data_dir / UT1_INDEX, data_dir / UT1_META
    tmp_idx, tmp_meta = idx.with_name(idx.name + ".tmp"), meta.with_name(meta.name + ".tmp")
    with open(tmp_idx, "wb") as f:
        pack = struct.Struct(">Q").pack
        for i in range(0, len(ordered), 65536):
            f.write(b"".join(pack(k) for k in ordered[i:i + 65536]))
    sha = _sha256(archive)
    lists = archive
    tmp_meta.write_text(json.dumps({
        "categories": cats, "count": len(ordered), "counts": counts, "imported_at": int(time.time()),
        "list_date": int(lists.stat().st_mtime) if lists is not None and lists.is_file() else None,
        "sha256": sha or hashlib.sha256(str(counts).encode()).hexdigest(),
        "source": "https://dsi.ut-capitole.fr/blacklists/", "license": "CC BY-SA 4.0",
    }), encoding="utf-8")
    # Index first, metadata last: the metadata names the entry count, and a reader that
    # finds the two out of step ignores the index instead of reading garbage.
    os.replace(tmp_idx, idx)
    os.replace(tmp_meta, meta)
    old = data_dir / "ut1_categories.tsv"          # format before the hash index
    if old.exists():
        old.unlink()
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ut1", help="unpacked UT1 'blacklists' directory (or give only --archive)")
    ap.add_argument("--data-dir", required=True, help="data directory of the service")
    ap.add_argument("--archive", help="the downloaded blacklists.tar.gz - read directly without --ut1")
    a = ap.parse_args(argv)
    if not a.ut1 and not a.archive:
        print("Give --ut1 <directory> or --archive <blacklists.tar.gz>", file=sys.stderr)
        return 2
    src = Path(a.ut1) if a.ut1 else None
    if src is not None and not src.is_dir():
        print(f"Not a directory: {src}", file=sys.stderr)
        return 2
    try:
        counts = import_ut1(src, Path(a.data_dir), Path(a.archive) if a.archive else None)
    except (OSError, tarfile.TarError) as e:
        print(f"Cannot read the lists: {e}", file=sys.stderr)
        return 2
    if not counts:
        print("No known UT1 category found - is this the unpacked 'blacklists' directory?", file=sys.stderr)
        return 2
    for cat, n in counts.items():
        print(f"{cat:16} → {MAPPING[cat]:13} {n:8} domains")
    print(f"Written: {Path(a.data_dir) / UT1_INDEX}. Restart the service to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
