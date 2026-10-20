# Sicherheit

## Sicherheitslücke melden

Bitte **kein öffentliches Issue** eröffnen. Stattdessen über GitHub
„Security → Report a vulnerability" (private Meldung) melden. Rückmeldung in der
Regel innerhalb einer Woche.

## Bedrohungsmodell

Der Network Lag Analyzer ist ein Werkzeug **für das eigene Heimnetz**. Er ist nicht
dafür gebaut, aus dem Internet erreichbar zu sein.

| Annahme | Folge |
|---|---|
| Port 8088 ist **nicht** im Router freigegeben | Angreifer müssen im LAN sein |
| Ohne aktivierten Login darf jedes Gerät im LAN alles | Einstellungen ändern, Daten löschen, Mitschnitte laden |
| Mit Login: scrypt-Hash, signiertes HttpOnly-Cookie, 5 Fehlversuche / 15 min je Adresse | |
| Gerätenamen und DNS-Namen kommen aus dem Netz und sind **nicht vertrauenswürdig** | Frontend rendert sie nur als Text |

**Empfehlung:** Unter *Setup → Zugriffsschutz* den Login aktivieren, sobald andere
Personen oder fremde Geräte im WLAN sind (Gäste, IoT). Die Oberfläche zeigt
Traffic pro Gerät – das ist eine sensible Information.

## Was geschützt ist

* Dienst läuft als `nla`, nicht als root; einzige Zusatzberechtigung `CAP_NET_RAW`.
  systemd-Härtung (`ProtectSystem=strict`, `NoNewPrivileges`, …).
* CSRF-Schutz (Double-Submit-Token + Origin-Prüfung) für alle schreibenden Requests,
  CSP ohne Inline-Skripte, `X-Frame-Options: DENY`.
* Das FRITZ!Box-Passwort wird nie über die API ausgegeben und nur an die Adresse
  geschickt, für die es eingegeben wurde. Wer Adresse oder Gateway ändert, muss es
  neu eingeben.
* `config.yaml` 0640 (root:nla), Datenverzeichnis 0750, `session.key` 0600.
* Pi-hole-Datenbank nur lesend. Mitschnitte enthalten nur Header (`snaplen`), keine Payload.

## Was bewusst nicht geschützt ist

* Kein HTTPS – im LAN ohne eigene CA nicht sinnvoll umsetzbar. Wer die Oberfläche
  über fremde Netze erreichen will, nutzt ein VPN (WireGuard der FRITZ!Box).
* Abmelden löscht das Cookie im Browser; ein vorher kopiertes Cookie bleibt bis zum
  Ablauf (`session_hours`) gültig. Alle Sitzungen beenden: `session.key` im
  Datenverzeichnis löschen und den Dienst neu starten.
* Das FRITZ!Box-Passwort liegt im Klartext in `config.yaml` bzw. der Datenbank,
  weil es für TR-064 im Klartext gebraucht wird. Deshalb einen **eigenen
  FRITZ!Box-Benutzer** nur mit dem Recht „FRITZ!Box Einstellungen" anlegen.
