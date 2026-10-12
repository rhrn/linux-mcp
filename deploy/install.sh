#!/bin/sh
# Install linux-mcp on a Linux host. Run as root:
#   SSH mode:   sudo ./install.sh ./linux-mcp 'ssh-ed25519 AAAA... you@laptop' [client-id]
#   HTTP only:  sudo ./install.sh ./linux-mcp
# Creates the mcp user, config, log dir; adds the SSH key (if given); installs the
# systemd unit for HTTP mode (not enabled until you add an [http] section).
set -eu

BIN=${1:?usage: install.sh <binary> [ssh-public-key] [client-id]}
PUBKEY=${2:-}
CLIENT_ID=${3:-default}
SCRIPT_DIR=$(dirname "$0")
USER_NAME=mcp
CONF_DIR=/etc/linux-mcp
LOG_DIR=/var/log/linux-mcp

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

install -o root -g root -m 0755 "$BIN" /usr/local/bin/linux-mcp

if ! id "$USER_NAME" >/dev/null 2>&1; then
    # sshd runs the forced command via the login shell, so it must be a real shell.
    useradd --system --create-home --shell /bin/sh "$USER_NAME"
    # '!' (locked) blocks key logins on sshd without PAM; '*' = no password, not locked.
    usermod -p '*' "$USER_NAME"
fi
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)

# Docker access (root-equivalent!). Remove this and set server.env.DOCKER_HOST to a
# read-only socket proxy if you want a stronger boundary.
if getent group docker >/dev/null; then
    usermod -aG docker "$USER_NAME"
fi

install -d -o root -g root -m 0755 "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.toml" ]; then
    SRC_DIR=$SCRIPT_DIR/../config
    sed -e "s#^workdir .*#workdir           = \"$HOME_DIR\"#" \
        -e "s#^allowed_paths .*#allowed_paths     = [\"$HOME_DIR\", \"/var/log\"]#" \
        -e "s#^\# audit_log .*#audit_log         = \"$LOG_DIR/audit.jsonl\"#" \
        "$SRC_DIR/example.toml" > "$CONF_DIR/config.toml"
    # Binary locations differ between distros (e.g. /bin/grep on Alpine).
    for cmd in ls pwd grep cat head tail gawk top dmesg df free swapon journalctl uptime uname ps \
               vmstat strace du lsblk ping ss ip nslookup host docker; do
        path=$(command -v "$cmd" || true)
        case "$path" in
            /*) sed -i "s#^\([[:space:]]*binary[[:space:]]*= \)\"/.*/$cmd\"#\1\"$path\"#" "$CONF_DIR/config.toml" ;;
        esac
    done
    chown root:root "$CONF_DIR/config.toml"
    chmod 0644 "$CONF_DIR/config.toml"
fi

install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$LOG_DIR"

if [ -n "$PUBKEY" ]; then
    # authorized_keys owned by root so the mcp user cannot change its own restrictions.
    install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"
    LINE="restrict,command=\"/usr/local/bin/linux-mcp --config $CONF_DIR/config.toml --client-id $CLIENT_ID\" $PUBKEY"
    touch "$HOME_DIR/.ssh/authorized_keys"
    grep -qxF "$LINE" "$HOME_DIR/.ssh/authorized_keys" || echo "$LINE" >> "$HOME_DIR/.ssh/authorized_keys"
    chown root:root "$HOME_DIR/.ssh/authorized_keys"
    chmod 0644 "$HOME_DIR/.ssh/authorized_keys"
fi

# systemd unit for HTTP mode.
UNIT=/etc/systemd/system/linux-mcp-http.service
if [ -d /run/systemd/system ]; then
    install -o root -g root -m 0644 "$SCRIPT_DIR/linux-mcp-http.service" "$UNIT"
    if ! getent group docker >/dev/null; then
        # A missing supplementary group makes systemd fail with 216/GROUP.
        sed -i 's/^SupplementaryGroups=docker$/# SupplementaryGroups=docker   (no docker group on this host)/' "$UNIT"
    fi
    systemctl daemon-reload
fi

if ! /usr/local/bin/linux-mcp --config "$CONF_DIR/config.toml" --check-config >/dev/null; then
    echo "WARNING: see above. Commands whose binaries are missing will fail until you install" >&2
    echo "         them or remove their [commands.*] section from $CONF_DIR/config.toml." >&2
fi
echo "installed."
if [ -n "$PUBKEY" ]; then
    echo "SSH:  test from your machine:  ssh -T $USER_NAME@$(hostname -f)"
fi
if [ -f "$UNIT" ]; then
    if grep -q '^\[http\]' "$CONF_DIR/config.toml"; then
        echo "HTTP: systemctl enable --now linux-mcp-http"
    else
        echo "HTTP: 1) linux-mcp --gen-key <client-id>"
        echo "      2) add an [http] section + the [[http.keys]] entry to $CONF_DIR/config.toml"
        echo "      3) systemctl enable --now linux-mcp-http"
    fi
fi
