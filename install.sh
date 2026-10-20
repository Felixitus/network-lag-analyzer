#!/usr/bin/env bash
# Network Lag Analyzer – Installer für Raspberry Pi OS / Debian (mit Pi-hole)
#
#   sudo ./install.sh            installieren oder aktualisieren
#   sudo ./install.sh --uninstall  Dienst und Programm entfernen (Daten bleiben)
#
# Pi-hole wird NICHT verändert: keine Änderungen an /etc/pihole, dnsmasq,
# lighttpd/FTL-Webserver oder den Pi-hole-Paketen. Es werden nur fehlende
# Python-Pakete per apt nachinstalliert (kein apt upgrade).
set -euo pipefail

APP_DIR=/opt/network-lag-analyzer
CONF_DIR=/etc/network-lag-analyzer
DATA_DIR=/var/lib/network-lag-analyzer
SERVICE=network-lag-analyzer
SVC_USER=nla
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWARNUNG:\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31mFEHLER:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Bitte mit sudo ausführen: sudo ./install.sh"

if [[ "${1:-}" == "--uninstall" ]]; then
  info "Entferne Dienst und Programm (Daten in $DATA_DIR und Konfiguration in $CONF_DIR bleiben erhalten)"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE.service"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  info "Fertig. Zum vollständigen Entfernen: sudo rm -rf $DATA_DIR $CONF_DIR && sudo userdel $SVC_USER"
  exit 0
fi

command -v apt-get >/dev/null || fail "Nur für Debian/Raspberry Pi OS (apt) vorgesehen."
[[ -f "$SRC_DIR/backend/main.py" ]] || fail "install.sh muss im Projektverzeichnis liegen."

# ------------------------------------------------------------------ Pakete
PKGS=(python3 python3-venv python3-pip)
MISSING=()
for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if ((${#MISSING[@]})); then
  info "Installiere fehlende Pakete: ${MISSING[*]}"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${MISSING[@]}"
else
  info "Systempakete vorhanden"
fi
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || fail "Python >= 3.10 benötigt (gefunden: $PYV). Raspberry Pi OS Bookworm oder neuer verwenden."

# ------------------------------------------------------------------ Benutzer
if ! id "$SVC_USER" >/dev/null 2>&1; then
  info "Lege Systembenutzer '$SVC_USER' an"
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
if getent group pihole >/dev/null; then
  usermod -aG pihole "$SVC_USER"   # nur Leserecht auf die FTL-Datenbank
  info "Benutzer '$SVC_USER' zur Gruppe 'pihole' hinzugefügt (lesender Zugriff auf pihole-FTL.db)"
else
  warn "Gruppe 'pihole' nicht gefunden – Pi-hole-Integration wird 'Not available' anzeigen."
fi

# ------------------------------------------------------------------ Programm
info "Kopiere Programm nach $APP_DIR"
mkdir -p "$APP_DIR"
for item in backend frontend deploy requirements.txt README.md ARCHITECTURE.md config.example.yaml install.sh; do
  rm -rf "${APP_DIR:?}/$item"
  cp -a "$SRC_DIR/$item" "$APP_DIR/"
done
find "$APP_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

info "Erstelle Python-Umgebung"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# ------------------------------------------------------------------ Konfiguration & Daten
mkdir -p "$CONF_DIR" "$DATA_DIR"
if [[ ! -f "$CONF_DIR/config.yaml" ]]; then
  cp "$SRC_DIR/config.example.yaml" "$CONF_DIR/config.yaml"
  info "Konfiguration angelegt: $CONF_DIR/config.yaml"
else
  info "Bestehende Konfiguration bleibt erhalten: $CONF_DIR/config.yaml"
fi
chown root:"$SVC_USER" "$CONF_DIR" "$CONF_DIR/config.yaml"
chmod 0750 "$CONF_DIR"
chmod 0640 "$CONF_DIR/config.yaml"      # enthält ggf. das FRITZ!Box-Passwort
chown -R "$SVC_USER":"$SVC_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# ------------------------------------------------------------------ Port prüfen
PORT=$(awk '/^server:/{s=1} s&&/port:/{print $2; exit}' "$CONF_DIR/config.yaml")
PORT=${PORT:-8088}
if command -v ss >/dev/null && ss -ltn "( sport = :$PORT )" | grep -q LISTEN; then
  if ! systemctl is-active --quiet "$SERVICE"; then
    warn "Port $PORT ist bereits belegt. Bitte 'server.port' in $CONF_DIR/config.yaml ändern."
  fi
fi

# ------------------------------------------------------------------ systemd
info "Installiere systemd-Dienst"
install -m 0644 "$APP_DIR/deploy/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
  info "Dienst läuft."
else
  warn "Dienst ist nicht gestartet. Log: journalctl -u $SERVICE -n 50"
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<EOF

  Network Lag Analyzer ist installiert.

  Weboberfläche:  http://$(hostname):$PORT   oder   http://${IP:-IP-DES-PI}:$PORT
  Logs:           journalctl -u $SERVICE -f
  Konfiguration:  $CONF_DIR/config.yaml
  Daten:          $DATA_DIR

  Nächster Schritt: In der Weboberfläche unter "Setup" die FRITZ!Box-Zugangsdaten
  eintragen und die Diagnose ausführen.

EOF
