#!/usr/bin/env bash
#
# Murmur installer - run on a Raspberry Pi Zero 2 W with 64-bit Raspberry Pi OS
# Lite, plugged into your GL.iNet router (which is running Pi-hole).
#
#   curl -sSL .../install.sh | sudo bash      (or: sudo ./install.sh)
#
set -euo pipefail

INSTALL_DIR=/opt/murmur
CONF_DIR=/etc/murmur
DATA_DIR=/var/lib/murmur
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> Murmur installer"
[ "$(id -u)" = "0" ] || { echo "run with sudo"; exit 1; }

ARCH="$(uname -m)"
if [ "$ARCH" != "aarch64" ]; then
  echo "!! Detected $ARCH. curl_cffi ships prebuilt wheels for aarch64 (64-bit"
  echo "!! Raspberry Pi OS). On 32-bit you may have to compile it. Continuing..."
fi

echo "==> Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nftables ca-certificates >/dev/null

echo "==> Creating service user + directories"
id murmur >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin murmur
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$DATA_DIR"

echo "==> Copying files"
cp -r "$SRC/." "$INSTALL_DIR/"
[ -f "$CONF_DIR/config.json" ] || cp "$SRC/config.json" "$CONF_DIR/config.json"
chmod +x "$INSTALL_DIR/harden-ttl.sh"
chown -R murmur:murmur "$INSTALL_DIR" "$DATA_DIR"

echo "==> Python virtualenv + dependencies"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
chown -R murmur:murmur "$INSTALL_DIR/venv"

echo "==> Detecting router / Pi-hole (default gateway)"
GW="$(ip route | awk '/^default/{print $3; exit}')"
echo "    using resolver: ${GW:-unknown}  (override in $CONF_DIR/config.json)"

echo "==> Allowing the TTL fix to run without a password (single script only)"
echo 'murmur ALL=(root) NOPASSWD: /opt/murmur/harden-ttl.sh' > /etc/sudoers.d/murmur
chmod 440 /etc/sudoers.d/murmur

echo "==> Installing systemd service"
cp "$SRC/murmur.service" /etc/systemd/system/murmur.service
systemctl daemon-reload
systemctl enable --now murmur.service

IP="$(hostname -I | awk '{print $1}')"
PORT="$(python3 -c "import json;print(json.load(open('$CONF_DIR/config.json'))['dashboard_port'])")"
echo
echo "============================================================"
echo "  Murmur is running."
echo "  Dashboard:  http://${IP}:${PORT}"
echo "  Logs:       journalctl -u murmur -f"
echo "  Config:     $CONF_DIR/config.json   (edit, then: systemctl restart murmur)"
echo "============================================================"
