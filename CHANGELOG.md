# Änderungen

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unveröffentlicht]

## [1.1.3] – 2026-10-20

### Sicherheit
- Das gespeicherte FRITZ!Box-Passwort wird nur noch an die Adresse geschickt, für die
  es eingegeben wurde. Wer FRITZ!Box-Adresse oder Gateway ändert (auch im
  Verbindungstest), muss das Passwort neu eingeben. Vorher konnte ein Gerät im LAN
  die Adresse auf einen eigenen Server umbiegen und die Login-Antwort abgreifen.
- Login: nach 5 Fehlversuchen je Adresse 15 Minuten Sperre.
- `session.key` wird direkt mit Rechten 0600 angelegt.

### Projekt
- Veröffentlichung auf GitHub: MIT-Lizenz, CI (Tests auf Python 3.11/3.13),
  `CONTRIBUTING.md`, `SECURITY.md`, `.gitattributes` (LF erzwungen).

## [1.1.2]

Erste Version im Repository.
