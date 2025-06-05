#!/bin/bash
set -euo pipefail

# --- Konfiguration ---
readonly SCRIPT_NAME="globalping-probe-installer.sh"
readonly INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
readonly VERSION="3.0.0"
readonly MAX_OFFSET_MINUTES=720
readonly CLEANUP_DAYS=30
readonly DOCKER_COMPOSE_VERSION="1.29.2"
readonly LOG_FILE="/var/log/globalping-probe.log"
readonly GP_PROBE_IMAGE="globalping/globalping-probe"

# --- Farben für Logging ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# --- Variablen ---
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
UBUNTU_PRO_TOKEN=""
GP_ADOPTION_TOKEN=""
SSH_KEY=""

# --- Logging-Funktionen ---
log() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color=""

    case "$level" in
        "INFO") color="${GREEN}" ;;
        "WARN") color="${YELLOW}" ;;
        "ERROR") color="${RED}" ;;
        "DEBUG") color="${BLUE}" ;;
        *) color="${NC}" ;;
    esac

    echo -e "${color}[${timestamp}] [${level}] ${msg}${NC}" >&2
    echo "[${timestamp}] [${level}] ${msg}" >> "$LOG_FILE"
}

die() {
    log "ERROR" "❌ $1"
    send_telegram_error "$1"
    exit 1
}

# --- Telegram Notifications ---
send_telegram_error() {
    local err="$1"
    [ -z "${TELEGRAM_BOT_TOKEN}" ] && return

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
    [ -z "${TELEGRAM_BOT_TOKEN}" ] && return

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
            --cron-exec)
                CRON_EXEC=1
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    # Pflichtparameter prüfen
    [ -z "${GP_ADOPTION_TOKEN}" ] && die "GP_ADOPTION_TOKEN muss gesetzt sein (--adoption-token)"
}

# --- Docker Installation ---
install_docker() {
    if ! command -v docker &>/dev/null; then
        log "INFO" "Installiere Docker..."
        curl -fsSL https://get.docker.com | sh || die "Docker-Installation fehlgeschlagen"
        systemctl enable --now docker
        log "INFO" "Docker $(docker --version | awk '{print $3}' | tr -d ',') installiert"
    else
        log "INFO" "Docker ist bereits installiert: $(docker --version)"
    fi

    if ! command -v docker-compose &>/dev/null; then
        log "INFO" "Installiere Docker-Compose..."
        curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose || die "Docker-Compose-Installation fehlgeschlagen"
        chmod +x /usr/local/bin/docker-compose
        log "INFO" "Docker-Compose ${DOCKER_COMPOSE_VERSION} installiert"
    else
        log "INFO" "Docker-Compose ist bereits installiert: $(docker-compose --version)"
    fi
}

# --- Systemd Service Setup ---
setup_systemd_units() {
    log "INFO" "Richte Systemd-Services ein..."

    cat > /etc/systemd/system/globalping-weekly.service <<EOF
[Unit]
Description=Globalping Weekly Maintenance
After=network.target

[Service]
Type=oneshot
ExecStart=${INSTALL_PATH} --cron-exec
EOF

    cat > /etc/systemd/system/globalping-weekly.timer <<EOF
[Unit]
Description=Weekly Globalping Maintenance Timer

[Timer]
OnCalendar=Sun *-*-* 00:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now globalping-weekly.timer
    log "INFO" "Systemd-Timer eingerichtet"
}

# --- Ubuntu Pro Setup ---
setup_ubuntu_pro() {
    [ -z "${UBUNTU_PRO_TOKEN}" ] && return

    if command -v ua &>/dev/null && ua status | grep -q "enabled"; then
        log "INFO" "Ubuntu Pro ist bereits aktiviert"
        return
    fi

    log "INFO" "Aktiviere Ubuntu Pro..."
    apt-get update -qq
    apt-get install -y ubuntu-advantage-tools
    ua attach "${UBUNTU_PRO_TOKEN}" --no-auto-enable
    ua enable esm-apps esm-infra livepatch
    log "INFO" "Ubuntu Pro erfolgreich aktiviert"
}

# --- SSH Key Setup ---
setup_ssh_key() {
    [ -z "${SSH_KEY}" ] && return

    local ssh_dir="/root/.ssh"
    local auth_file="${ssh_dir}/authorized_keys"

    mkdir -p "${ssh_dir}"
    if grep -qF "${SSH_KEY}" "${auth_file}" 2>/dev/null; then
        log "INFO" "SSH-Key ist bereits vorhanden"
    else
        echo "${SSH_KEY}" >> "${auth_file}"
        chmod 600 "${auth_file}"
        log "INFO" "SSH-Key wurde hinzugefügt"
    fi
}

# --- Globalping Probe Setup ---
setup_globalping() {
    log "INFO" "Richte Globalping-Probe ein..."

    # Bestehenden Container stoppen
    if docker ps -a --format '{{.Names}}' | grep -q '^globalping-probe$'; then
        log "INFO" "Stoppe bestehenden Globalping-Probe Container..."
        docker stop globalping-probe >/dev/null
        docker rm globalping-probe >/dev/null
    fi

    # Neuen Container starten
    log "INFO" "Starte Globalping-Probe Container..."
    docker run -d \
        --name globalping-probe \
        --network host \
        --restart always \
        --log-driver local \
        --log-opt max-size=10m \
        -e GP_ADOPTION_TOKEN="${GP_ADOPTION_TOKEN}" \
        "${GP_PROBE_IMAGE}" || die "Container konnte nicht gestartet werden"

    log "INFO" "Globalping-Probe erfolgreich gestartet"
}

# --- Maintenance Tasks ---
perform_maintenance() {
    log "INFO" "Starte Wartungsarbeiten..."

    # Docker Cleanup
    log "INFO" "Führe Docker-Systembereinigung durch..."
    docker system prune -af --filter "until=${CLEANUP_DAYS}d" || true

    # Globalping Probe Update
    log "INFO" "Aktualisiere Globalping-Probe..."
    docker pull "${GP_PROBE_IMAGE}"
    setup_globalping

    log "INFO" "Wartungsarbeiten abgeschlossen"
}

# --- Self-Update Funktion ---
self_update() {
    log "INFO" "Prüfe auf Skript-Updates..."
    # Hier könnte eine Update-Logik implementiert werden
    return 0
}

# --- Hauptinstallation ---
install() {
    log "INFO" "Starte Installation der Globalping-Probe (v${VERSION})..."

    # Selbst ins System installieren
    cp -f "$0" "${INSTALL_PATH}"
    chmod +x "${INSTALL_PATH}"
    log "INFO" "Skript installiert nach ${INSTALL_PATH}"

    # Abhängigkeiten installieren
    install_docker
    setup_ubuntu_pro
    setup_ssh_key
    setup_globalping
    setup_systemd_units

    # Abschlussmeldung
    local completion_msg="✅ <b>Globalping-Probe erfolgreich installiert</b> auf $(hostname -f)
- Docker: $(docker --version | awk '{print $3}' | tr -d ',')
- Probe: $(docker inspect -f '{{.State.Status}}' globalping-probe)
- Ubuntu Pro: $(if [ -n "${UBUNTU_PRO_TOKEN}" ]; then ua status | grep -q "enabled" && echo "aktiviert" || echo "fehlgeschlagen"; else echo "nicht konfiguriert"; fi)
- SSH-Key: $(if [ -n "${SSH_KEY}" ]; then echo "installiert"; else echo "nicht konfiguriert"; fi)"

    log "INFO" "${completion_msg}"
    send_telegram_message "${completion_msg}"
}

# --- Hauptsteuerung ---
main() {
    parse_parameters "$@"

    if [ -n "${CRON_EXEC:-}" ]; then
        perform_maintenance
    else
        install
    fi
}

main "$@"
