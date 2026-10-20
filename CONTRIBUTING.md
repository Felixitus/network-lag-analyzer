# Contributing & Git workflow

Language throughout the project: **English** - UI, comments, commits, issues.
The domain rules (no made-up data, units in the database, traps that have
already snapped shut) are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and apply to humans just
the same.

## Development environment

```bash
git clone https://github.com/Felixitus/network-lag-analyzer.git
cd network-lag-analyzer
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest tests -q
python -m backend.main --dev --data-dir /tmp/nla --port 8099   # demo, http://localhost:8099
```

Dev mode also runs on Windows and macOS (simulated data, DEMO banner).
Real measurements only happen on Linux with `CAP_NET_RAW`.

## Branches

| Branch | Purpose |
|---|---|
| `main` | Always working, CI green. This is what gets installed. No direct pushes. |
| `feature/<short>` | New feature, e.g. `feature/sni-parser` |
| `fix/<short>` | Bug fix, e.g. `fix/pcap-budget` |
| `docs/<short>` | Documentation only |

## Making a change

```bash
git switch main && git pull
git switch -c fix/short-description
# … change, test …
python -m pytest tests -q
git add -p
git commit
git push -u origin fix/short-description
gh pr create --fill          # or via the GitHub web UI
```

The pull request has to pass CI (tests on Python 3.11 and 3.13, `install.sh`
check, LF line endings). Merging is done by **squash**, so that `main` has one
line per change.

## Commit messages

English, imperative mood, first line ≤ 72 characters, then a blank line and the **why**:

```
Enforce the PCAP budget for incident captures too

max_files × file_size_mb only applied to the running ring. Captures
belonging to incidents lived outside of it and let the directory grow
to 40 GB.
```

## Tests

* Every fixed bug gets a test that pins it down.
* Test names describe the behavior:
  `test_stored_fritzbox_password_is_not_sent_to_a_new_address`.
* Test data only from the documentation ranges (RFC 5737: `192.0.2.x`,
  `203.0.113.x`) and with locally administered MACs (`02:00:00:…`).

## Release

1. Bump the version in `backend/__init__.py` (SemVer: fix → patch, feature → minor,
   incompatible configuration/schema → major).
2. In `CHANGELOG.md`, rename the "Unreleased" section to the new version.
3. Commit `Version 1.2.0`, then tag and release:

```bash
git tag -a v1.2.0 -m "Version 1.2.0"
git push origin main --tags
gh release create v1.2.0 --notes-from-tag
```

Updating on the Pi:

```bash
cd ~/network-lag-analyzer && git pull && sudo ./install.sh
```

## What never belongs in the repo

`config.yaml`, databases (`*.sqlite3`), captures (`*.pcap`), `session.key` -
`.gitignore` covers these. Still, read `git status` before the first `git add .`
in a new clone. If a password was committed anyway: change the password right
away; removing it from the history alone is not enough.
