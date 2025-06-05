#!/bin/bash
set -euo pipefail

# --- Konfiguration ---
readonly SCRIPT_NAME="globalping_setup.sh"
readonly INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
readonly VERSION="2.1.0"
readonly MAX_OFFSET_MINUTES=720  # ±12 Stunden
readonly CLEANUP_DAYS=30
readonly GP_REPO="https://github.com/jsdelivr/globalping.git"
readonly GP_DIR="/opt/globalping"
readonly DOCKER_COMPOSE_VERSION="1.29.2"
readonly LOG_FILE="/var/log/globalping-update.log"

# --- Token und Variablen aus Umgebungsvariablen ---
readonly TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:?Bitte TELEGRAM_BOT_TOKEN setzen}"
readonly TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:?Bitte TELEGRAM_CHAT_ID setzen}"
readonly UBUNTU_PRO_TOKEN="${UBUNTU_PRO_TOKEN:?Bitte UBUNTU_PRO_TOKEN setzen}"
readonly GP_ADOPTION_TOKEN="${GP_ADOPTION_TOKEN:?Bitte GP_ADOPTION_TOKEN setzen}"
readonly SSH_KEY="${SSH_KEY:?Bitte SSH_KEY setzen}"

readonly NTP_SERVERS=("time.cloudflare.com" "ntp.ubuntu.com" "pool.ntp.org" "time.google.com")

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
    send_telegram_error "$err"
    exit 1
}

# --- Telegram Notifications ---
send_telegram_error() {
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    local err="$1"
    local netinfo=$(curl -s https://ipinfo.io/json || echo "{}")
    local ip=$(jq -r '.ip // "unknown"' <<< "$netinfo")
    local asn=$(jq -r '.org // "AS0000 Unknown"' <<< "$netinfo")
    local provider=$(cut -d' ' -f2- <<< "$asn")
    local hostname=$(jq -r '.hostname // "unknown"' <<< "$netinfo")
    local country=$(jq -r '.country // "xx"' <<< "$netinfo")

    local msg="❌ <b>Fehler im Skript</b>
🌍 <b>Country:</b> <code>${country^^}</code>
🖥️ <b>Host:</b> <code>$hostname</code>
🌐 <b>IP:</b> <code>$ip</code>
📡 <b>ASN:</b> <code>$asn</code>
🏢 <b>Provider:</b> <code>$provider</code>
🔧 <b>Fehlermeldung:</b> <pre>$err</pre>"

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode="HTML" >/dev/null || true
}

send_telegram_message() {
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    local msg="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$msg" \
        -d parse_mode="HTML" >/dev/null || true
}

# --- Host-spezifischer Zeitplan ---
generate_random_schedule() {
    local seed=$(echo "${HOSTNAME}-${VERSION}" | sha256sum | cut -d' ' -f1)
    local offset=$(( 0x${seed:0:8} % (MAX_OFFSET_MINUTES*2 + 1) - MAX_OFFSET_MINUTES ))
    local total_min=$(( (24*60 + offset) % (24*60) ))
    printf "%02d %02d * * *" $((total_min%60)) $((total_min/60))
}

# --- Systemd Service Setup ---
setup_systemd_units() {
    local service_file="/etc/systemd/system/globalping-weekly.service"
    local timer_file="/etc/systemd/system/globalping-weekly.timer"

    cat > "$service_file" <<EOF
[Unit]
Description=Globalping Maintenance Service
After=network.target

[Service]
Type=oneshot
ExecStart=$INSTALL_PATH --cron-exec
EOF

    cat > "$timer_file" <<EOF
[Unit]
Description=Weekly Globalping Maintenance with Random Delay

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

# --- OS Detection ---
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# --- Dependency Management ---
install_dependencies() {
    local OS=$(detect_os)
    debug "Installiere Abhängigkeiten für $OS..."
    
    case "$OS" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y curl jq docker.io git chrony
            systemctl enable --now chrony
            ;;
        centos|rhel|almalinux)
            dnf install -y curl jq docker git chrony
            systemctl enable --now chronyd
            ;;
        *)
            die "Nicht unterstütztes OS: $OS"
            ;;
    esac
}

# --- Docker Setup ---
setup_docker() {
    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com | sh || die "Docker-Installation fehlgeschlagen"
    fi
    systemctl enable --now docker
}

# --- Docker Compose Setup ---
setup_docker_compose() {
    if ! command -v docker-compose &>/dev/null; then
        curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose || die "Docker-Compose-Installation fehlgeschlagen"
        chmod +x /usr/local/bin/docker-compose
    fi
}

# --- Globalping Setup ---
setup_globalping() {
    debug "Konfiguriere Globalping..."
    
    # Probe Container
    docker pull globalping/globalping-probe
    docker rm -f globalping-probe 2>/dev/null || true
    docker run -d --restart always --name globalping-probe \
        -e GP_ADOPTION_TOKEN="$GP_ADOPTION_TOKEN" \
        globalping/globalping-probe

    # Hauptinstallation
    if [ ! -d "$GP_DIR" ]; then
        git clone "$GP_REPO" "$GP_DIR" || die "Git-Clone fehlgeschlagen"
    fi
    
    cd "$GP_DIR"
    git pull || debug "Git-Pull fehlgeschlagen"
    docker-compose down && docker-compose up -d || die "Globalping-Start fehlgeschlagen"
}

# --- Hostname Configuration ---
configure_hostname() {
    local netinfo=$(curl -s https://ipinfo.io/json || echo "{}")
    local country=$(jq -r '.country // "xx"' <<< "$netinfo" | tr '[:upper:]' '[:lower:]')
    local provider=$(jq -r '.org // "Unknown Provider"' <<< "$netinfo" | sed 's/^[^ ]* //' | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')
    local asn=$(jq -r '.org // "AS0000"' <<< "$netinfo" | grep -o 'AS[0-9]\+')
    local ip=$(jq -r '.ip // "0.0.0.0"' <<< "$netinfo")
    local first_octet=${ip%%.*}

    local desired_hostname="${country}-${provider}-${asn}-${first_octet}"
    desired_hostname=$(echo "$desired_hostname" | tr -cd 'a-z0-9-' | sed 's/--/-/g' | cut -c1-63)
    
    if [[ "$(hostname)" != "$desired_hostname" ]]; then
        hostnamectl set-hostname "$desired_hostname" || debug "Hostname konnte nicht gesetzt werden"
        send_telegram_message "🔄 Hostname geändert zu: $desired_hostname"
    fi
}

# --- SSH Configuration ---
setup_ssh() {
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    if ! grep -qxF "$SSH_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$SSH_KEY" >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
    fi
}

# --- System Cleanup ---
system_cleanup() {
    debug "Starte Systembereinigung..."
    
    # Docker Bereinigung
    docker system prune -af --filter "until=${CLEANUP_DAYS}d" || debug "Docker-Bereinigung fehlgeschlagen"
    
    # Logrotate
    find /var/log -type f -name "*.log*" -mtime +${CLEANUP_DAYS} -delete 2>/dev/null || true
    
    # Temporäre Dateien
    rm -rf /tmp/* /var/tmp/*
    
    # Paketbereinigung
    case "$(detect_os)" in
        ubuntu|debian) apt-get autoremove -yq ;;
        centos|rhel|almalinux) dnf autoremove -yq ;;
    esac
    
    debug "Systembereinigung abgeschlossen"
}

# --- Main Functions ---
cron_execution() {
    debug "Starte automatische Wartung..."
    system_cleanup
    configure_hostname
    setup_globalping
    debug "Automatische Wartung abgeschlossen"
}

auto_install() {
    debug "Starte automatische Installation..."
    
    # Skript installieren
    cp -f "$0" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    
    # Abhängigkeiten
    install_dependencies
    setup_docker
    setup_docker_compose
    
    # Systemkonfiguration
    configure_hostname
    setup_ssh
    setup_globalping
    
    # Zeitplan einrichten
    setup_systemd_units
    
    debug "Installation abgeschlossen"
    send_telegram_message "✅ System erfolgreich eingerichtet: $(hostname)"
}

# --- Lock Mechanism ---
acquire_lock() {
    exec 200>/tmp/"${SCRIPT_NAME}.lock"
    flock -n 200 || die "Skript läuft bereits"
    trap 'flock -u 200' EXIT
}

# --- Main Control ---
main() {
    acquire_lock
    
    case "${1:-}" in
        "--cron-exec")
            cron_execution
            ;;
        "--uninstall")
            # Deinstallationslogik hier (optional)
            ;;
        *)
            if [[ "$0" != "$INSTALL_PATH" ]]; then
                auto_install
            else
                cron_execution
            fi
            ;;
    esac
}

main "$@"
