## Was ändert sich und warum?

<!-- Ein, zwei Sätze. Bei Fehlerbehebungen: Wie hat sich der Fehler gezeigt? -->

## Prüfliste

- [ ] `python3 -m pytest tests -q` ist grün
- [ ] Behobener Fehler hat einen Test, der ihn festnagelt
- [ ] Schemaänderung → Migrationsschritt in `migrations.py` + `SCHEMA_VERSION` erhöht
- [ ] Keine erfundenen Werte: nicht Gemessenes bleibt `None` / „Not available"
- [ ] Testdaten nur aus RFC 5737 (`192.0.2.x`, `203.0.113.x`) und MACs `02:00:00:…`
- [ ] `CHANGELOG.md` ergänzt (Abschnitt „Unveröffentlicht")
