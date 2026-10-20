## What changes and why?

<!-- One or two sentences. For bug fixes: how did the bug show up? -->

## Checklist

- [ ] `python3 -m pytest tests -q` passes
- [ ] A fixed bug comes with a test that pins it down
- [ ] Schema change → migration step in `migrations.py` + bumped `SCHEMA_VERSION`
- [ ] No made-up values: anything not measured stays `None` / "Not available"
- [ ] Test data only from RFC 5737 (`192.0.2.x`, `203.0.113.x`) and MACs `02:00:00:…`
- [ ] `CHANGELOG.md` updated (section "Unreleased")
