#!/usr/bin/env bash
# Network Lag Analyzer - installer for Raspberry Pi OS / Debian (with Pi-hole)
#
#   sudo ./install.sh              install or update
#   sudo ./install.sh --uninstall  remove service and program (data is kept)
#
# Pi-hole is NOT modified: no changes to /etc/pihole, dnsmasq,
# lighttpd/FTL web server or the Pi-hole packages. Only missing
# Python packages are installed via apt (no apt upgrade).
set -euo pipefail

APP_DIR=/opt/network-lag-analyzer
CONF_DIR=/etc/network-lag-analyzer
DATA_DIR=/var/lib/network-lag-analyzer
SERVICE=network-lag-analyzer
SVC_USER=nla
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWARNING:\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Please run with sudo: sudo ./install.sh"

if [[ "${1:-}" == "--uninstall" ]]; then
  info "Removing service and program (data in $DATA_DIR and configuration in $CONF_DIR are kept)"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE.service"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  info "Done. To remove everything: sudo rm -rf $DATA_DIR $CONF_DIR && sudo userdel $SVC_USER"
  exit 0
fi

command -v apt-get >/dev/null || fail "Only intended for Debian/Raspberry Pi OS (apt)."
[[ -f "$SRC_DIR/backend/main.py" ]] || fail "install.sh must be located in the project directory."

# ------------------------------------------------------------------ packages
PKGS=(python3 python3-venv python3-pip)
MISSING=()
for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if ((${#MISSING[@]})); then
  info "Installing missing packages: ${MISSING[*]}"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${MISSING[@]}"
else
  info "System packages present"
fi
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || fail "Python >= 3.10 required (found: $PYV). Use Raspberry Pi OS Bookworm or newer."

# ------------------------------------------------------------------ user
if ! id "$SVC_USER" >/dev/null 2>&1; then
  info "Creating system user '$SVC_USER'"
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
if getent group pihole >/dev/null; then
  usermod -aG pihole "$SVC_USER"   # read access to the FTL database only
  info "Added user '$SVC_USER' to group 'pihole' (read access to pihole-FTL.db)"
else
  warn "Group 'pihole' not found - the Pi-hole integration will show 'Not available'."
fi

# ------------------------------------------------------------------ program
info "Copying program to $APP_DIR"
mkdir -p "$APP_DIR"
for item in backend frontend deploy requirements.txt README.md ARCHITECTURE.md LICENSE config.example.yaml install.sh; do
  rm -rf "${APP_DIR:?}/$item"
  cp -a "$SRC_DIR/$item" "$APP_DIR/"
done
find "$APP_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

info "Creating Python environment"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# ------------------------------------------------------------------ configuration & data
mkdir -p "$CONF_DIR" "$DATA_DIR"
if [[ ! -f "$CONF_DIR/config.yaml" ]]; then
  cp "$SRC_DIR/config.example.yaml" "$CONF_DIR/config.yaml"
  info "Configuration created: $CONF_DIR/config.yaml"
else
  info "Existing configuration is kept: $CONF_DIR/config.yaml"
fi
chown root:"$SVC_USER" "$CONF_DIR" "$CONF_DIR/config.yaml"
chmod 0750 "$CONF_DIR"
chmod 0640 "$CONF_DIR/config.yaml"      # may contain the FRITZ!Box password
chown -R "$SVC_USER":"$SVC_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# ------------------------------------------------------------------ check port
PORT=$(awk '/^server:/{s=1} s&&/port:/{print $2; exit}' "$CONF_DIR/config.yaml")
PORT=${PORT:-8088}
if command -v ss >/dev/null && ss -ltn "( sport = :$PORT )" | grep -q LISTEN; then
  if ! systemctl is-active --quiet "$SERVICE"; then
    warn "Port $PORT is already in use. Please change 'server.port' in $CONF_DIR/config.yaml."
  fi
fi

# ------------------------------------------------------------------ systemd
info "Installing systemd service"
install -m 0644 "$APP_DIR/deploy/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
  info "Service is running."
else
  warn "Service did not start. Log: journalctl -u $SERVICE -n 50"
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<EOF

  Network Lag Analyzer is installed.

  Web UI:         http://$(hostname):$PORT   or   http://${IP:-PI-IP-ADDRESS}:$PORT
  Logs:           journalctl -u $SERVICE -f
  Configuration:  $CONF_DIR/config.yaml
  Data:           $DATA_DIR

  Next step: in the web UI under "Setup", enter the FRITZ!Box credentials
  and run the diagnosis. If other people use your network, enable the login
  under "Setup -> Access protection".

EOF
