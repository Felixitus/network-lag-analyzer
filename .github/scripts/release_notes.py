"""Release notes for a tag: the matching section of CHANGELOG.md, without its heading.

    python .github/scripts/release_notes.py v1.5.0 > notes.md

Fails when the tag is not a plain version, does not match backend/__init__.py, or the changelog
has no section for it - a release with empty or wrong notes is worse than none.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def section(changelog: str, version: str) -> str:
    out, inside = [], False
    for line in changelog.splitlines():
        if line.startswith("## ["):
            if inside:
                break
            inside = line.startswith(f"## [{version}]")
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip()


def notes(tag: str, root: Path = ROOT) -> str:
    m = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag)
    if not m:
        raise ValueError(f"not a release tag: {tag!r} (expected v<major>.<minor>.<patch>)")
    version = m.group(1)
    init = (root / "backend" / "__init__.py").read_text(encoding="utf-8")
    code = re.search(r'^__version__ = "([^"]+)"', init, re.M)
    if not code or code.group(1) != version:
        raise ValueError(f"tag {tag} does not match __version__ {code.group(1) if code else None!r}")
    text = section((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    if not text:
        raise ValueError(f"CHANGELOG.md has no section for {version}")
    return text + "\n"


if __name__ == "__main__":
    try:
        text = notes(sys.argv[1] if len(sys.argv) > 1 else "")
    except ValueError as e:
        print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.buffer.write(text.encode("utf-8"))   # not the console code page
