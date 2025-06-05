#!/bin/bash
set -euo pipefail

# --- Konfiguration ---
readonly SCRIPT_NAME="globalping_setup.sh"
readonly INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
readonly VERSION="2.3.0"
readonly MAX_OFFSET_MINUTES=720
readonly CLEANUP_DAYS=30
readonly GP_REPO="https://github.com/jsdelivr/globalping.git"
readonly GP_DIR="/opt/globalping"
readonly DOCKER_COMPOSE_VERSION="1.29.2"
readonly LOG_FILE="/var/log/globalping-update.log"

# --- Farben für Logging ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# --- Logging-Funktionen ---
debug() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${msg}${NC}" >&2
    echo "$msg" >> "$LOG_FILE"
}

die() {
    local err="$1"
    debug "❌ $err"
    [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && send_telegram_error "$err"
    exit 1
}

# --- Telegram Notifications ---
send_telegram_error() {
    local err="$1"
    local netinfo=$(curl -s https://ipinfo.io/json || echo "{}")
    local msg="❌ <b>Fehler auf $(hostname)</b>
🌐 <b>IP:</b> <code>$(jq -r '.ip // "unknown"' <<< "$netinfo")</code>
🔧 <b>Fehler:</b> <pre>$err</pre>"

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode="HTML" >/dev/null || true
}

send_telegram_message() {
    local msg="$1"
    [ -z "${TELEGRAM_BOT_TOKEN:-}" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode="HTML" >/dev/null || true
}

# --- Parameter Parsing ---
parse_parameters() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --telegram-token)
                TELEGRAM_BOT_TOKEN="$2"
                shift 2
                ;;
            --telegram-chat)
                TELEGRAM_CHAT_ID="$2"
                shift 2
                ;;
            --ubuntu-token)
                UBUNTU_PRO_TOKEN="$2"
                shift 2
                ;;
            --adoption-token)
                GP_ADOPTION_TOKEN="$2"
                shift 2
                ;;
            --ssh-key)
                SSH_KEY="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    # Pflichtparameter prüfen
    : "${GP_ADOPTION_TOKEN:?GP_ADOPTION_TOKEN muss gesetzt sein (--adoption-token)}"
}

# --- Systemd Service Setup ---
setup_systemd_units() {
    cat > /etc/systemd/system/globalping-weekly.service <<EOF
[Unit]
Description=Globalping Maintenance Service
After=network.target

[Service]
Type=oneshot
Environment="TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}"
Environment="TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}"
Environment="GP_ADOPTION_TOKEN=${GP_ADOPTION_TOKEN}"
ExecStart=$INSTALL_PATH --cron-exec
EOF

    cat > /etc/systemd/system/globalping-weekly.timer <<EOF
[Unit]
Description=Weekly Globalping Maintenance

[Timer]
OnCalendar=Sun *-*-* 00:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now globalping-weekly.timer
}

# --- Hauptinstallation ---
auto_install() {
    parse_parameters "$@"

    debug "Starte Installation..."
    cp -f "$0" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"

    # Docker installieren
    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com | sh || die "Docker-Installation fehlgeschlagen"
        systemctl enable --now docker
    fi

    # Docker-Compose installieren
    if ! command -v docker-compose &>/dev/null; then
        curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose || die "Docker-Compose-Installation fehlgeschlagen"
        chmod +x /usr/local/bin/docker-compose
    fi

    # Globalping installieren
    if [ ! -d "$GP_DIR" ]; then
        git clone "$GP_REPO" "$GP_DIR" || die "Git-Clone fehlgeschlagen"
    fi

    # SSH-Key einrichten
    if [ -n "${SSH_KEY:-}" ]; then
        mkdir -p /root/.ssh
        echo "$SSH_KEY" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
    fi

    # Systemd einrichten
    setup_systemd_units

    debug "Installation abgeschlossen"
    send_telegram_message "✅ Globalping erfolgreich installiert auf $(hostname)"
}

# --- Wartungsmodus ---
cron_execution() {
    parse_parameters "$@"

    debug "Starte Wartungsroutine..."
    docker system prune -af --filter "until=${CLEANUP_DAYS}d" || true

    # Globalping aktualisieren
    cd "$GP_DIR" && git pull && docker-compose up -d --build

    # Probe Container
    docker pull globalping/globalping-probe
    docker rm -f globalping-probe 2>/dev/null || true
    docker run -d --restart always --name globalping-probe \
        -e GP_ADOPTION_TOKEN="$GP_ADOPTION_TOKEN" \
        globalping/globalping-probe

    debug "Wartung abgeschlossen"
}

# --- Hauptsteuerung ---
main() {
    case "${1:-}" in
        "--cron-exec")
            cron_execution "$@"
            ;;
        "--install")
            auto_install "$@"
            ;;
        *)
            if [[ "$0" != "$INSTALL_PATH" ]]; then
                auto_install "$@"
            else
                cron_execution "$@"
            fi
            ;;
    esac
}

main "$@"
