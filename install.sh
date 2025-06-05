#!/bin/bash
set -eo pipefail

# ==============================================
# KONFIGURATION
# ==============================================
TELEGRAM_API_URL="https://api.telegram.org/bot"
LOG_FILE="/var/log/globalping-install.log"
TMP_DIR="/tmp/globalping_install"
SSH_DIR="$HOME/.ssh"
CRON_JOB="0 3 * * * /usr/local/bin/globalping-maintenance"

# ==============================================
# SYSTEMINFORMATIONEN
# ==============================================
get_system_info() {
    COUNTRY=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/country || echo "UNKNOWN")
    HOSTNAME=$(hostname -f || echo "UNKNOWN")
    IP_ADDRESS=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/ip || echo "UNKNOWN")
    ASN_INFO=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/org || echo "UNKNOWN")
    PROVIDER=$(echo "$ASN_INFO" | cut -d' ' -f2- | sed 's/"/\\"/g' || echo "UNKNOWN")
    ASN=$(echo "$ASN_INFO" | cut -d' ' -f1 | sed 's/AS//g' || echo "UNKNOWN")
    OS_INFO=$(lsb_release -ds 2>/dev/null || echo "UNKNOWN")
    KERNEL=$(uname -r || echo "UNKNOWN")
    UPTIME=$(uptime -p | sed 's/up //' || echo "UNKNOWN")
}

# ==============================================
# LOGGING & BENACHRICHTIGUNGEN
# ==============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

notify() {
    local level=$1
    local message=$2

    case $level in
        "error")
            local emoji="❌"
            local title="Fehler im Skript"
            ;;
        "warning")
            local emoji="⚠️"
            local title="Warnung"
            ;;
        "success")
            local emoji="✅"
            local title="Erfolgreich"
            ;;
        "info")
            local emoji="ℹ️"
            local title="Information"
            ;;
        *)
            local emoji="🔔"
            local title="Benachrichtigung"
            ;;
    esac

    if [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT" ]; then
        local full_message="$emoji $title
🌍 Country: $COUNTRY
🖥️ Host: $HOSTNAME
🌐 IP: $IP_ADDRESS
📡 ASN: $ASN
🏢 Provider: $PROVIDER
💻 OS: $OS_INFO
🐧 Kernel: $KERNEL
⏱️ Uptime: $UPTIME
🔧 $message"

        curl -s -X POST "${TELEGRAM_API_URL}${TELEGRAM_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT}" \
            -d "text=${full_message}" \
            -d "parse_mode=Markdown" >/dev/null
    fi
}

error_handler() {
    local exit_code=$?
    local line_number=$1
    local command=$(sed -n "${line_number}p" "$0")

    log "KRITISCHER FEHLER in Zeile $line_number: $command (Exit-Code: $exit_code)"
    notify "error" "Fehlermeldung: $command (Exit-Code: $exit_code)"
    cleanup
    exit $exit_code
}

# ==============================================
# SYSTEMFUNKTIONEN
# ==============================================
cleanup() {
    log "Starte Bereinigung temporärer Dateien"
    rm -rf "$TMP_DIR" || true
}

create_temp_dir() {
    mkdir -p "$TMP_DIR"
    chmod 700 "$TMP_DIR"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "FEHLER: Dieses Skript muss als root ausgeführt werden"
        notify "error" "Skript muss als root ausgeführt werden"
        exit 1
    fi
}

check_internet() {
    if ! ping -c 1 -W 3 google.com >/dev/null 2>&1; then
        log "FEHLER: Keine Internetverbindung"
        notify "error" "Keine Internetverbindung festgestellt"
        exit 1
    fi
}

install_dependencies() {
    log "Installiere erforderliche Abhängigkeiten"

    local dependencies=(
        curl wget jq apt-transport-https
        ca-certificates software-properties-common
        gnupg2 lsb-release unattended-upgrades
        net-tools docker.io docker-compose
    )

    for pkg in "${dependencies[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            log "Installiere $pkg"
            apt-get install -y "$pkg" | tee -a "$LOG_FILE"
        fi
    done
}

# ==============================================
# SICHERHEITSFUNKTIONEN
# ==============================================
configure_firewall() {
    if command -v ufw >/dev/null; then
        log "Konfiguriere UFW Firewall"
        ufw allow ssh | tee -a "$LOG_FILE"
        ufw allow 80/tcp | tee -a "$LOG_FILE"
        ufw allow 443/tcp | tee -a "$LOG_FILE"
        ufw --force enable | tee -a "$LOG_FILE"
    fi
}

configure_ssh() {
    if [ -n "$SSH_KEY" ]; then
        log "Konfiguriere SSH-Zugang"

        mkdir -p "$SSH_DIR"
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        chmod 600 "$SSH_DIR/authorized_keys"

        # SSH Hardening
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

        systemctl restart sshd | tee -a "$LOG_FILE"
    fi
}

# ==============================================
# UBUNTU PRO FUNKTIONEN
# ==============================================
install_ubuntu_pro() {
    if [ -n "$UBUNTU_TOKEN" ]; then
        log "Verarbeite Ubuntu Pro Konfiguration"

        if ! command -v pro >/dev/null; then
            log "Installiere Ubuntu Pro Client"
            apt-get install -y ubuntu-advantage-tools | tee -a "$LOG_FILE"
        fi

        local status=$(pro status --format json)

        if echo "$status" | grep -q '"attached": true'; then
            log "Ubuntu Pro bereits angehängt"
            notify "info" "Ubuntu Pro bereits aktiviert"
        else
            log "Führe Ubuntu Pro Attachment durch"
            pro attach "$UBUNTU_TOKEN" | tee -a "$LOG_FILE"

            log "Aktiviere wichtige Dienste"
            pro enable livepatch | tee -a "$LOG_FILE"
            pro enable esm-apps | tee -a "$LOG_FILE"
            pro enable esm-infra | tee -a "$LOG_FILE"

            notify "success" "Ubuntu Pro erfolgreich konfiguriert"
        fi
    fi
}

# ==============================================
# GLOBALPING FUNKTIONEN
# ==============================================
install_globalping() {
    log "Starte Globalping Probe Installation"

    # Alte Installation entfernen
    if docker ps -a | grep -q globalping-probe; then
        log "Entferne bestehende Globalping Probe"
        docker stop globalping-probe | tee -a "$LOG_FILE" || true
        docker rm globalping-probe | tee -a "$LOG_FILE" || true
    fi

    # Neue Installation
    log "Starte Globalping Probe Container"
    docker run -d \
        --name globalping-probe \
        --restart always \
        --network host \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        -e ADOPTION_TOKEN="$ADOPTION_TOKEN" \
        ghcr.io/jsdelivr/globalping-probe | tee -a "$LOG_FILE"

    # Überprüfung
    sleep 5
    if docker ps | grep -q globalping-probe; then
        log "Globalping Probe erfolgreich installiert"
        notify "success" "Globalping Probe läuft (Version: $(docker inspect globalping-probe --format '{{.Config.Image}}'))"
    else
        log "FEHLER: Globalping Probe start fehlgeschlagen"
        notify "error" "Globalping Probe konnte nicht gestartet werden"
        exit 1
    fi
}

setup_cron_job() {
    log "Richte Cron-Job für Wartung ein"

    cat > /usr/local/bin/globalping-maintenance << 'EOF'
#!/bin/bash
docker pull ghcr.io/jsdelivr/globalping-probe:latest
docker stop globalping-probe
docker rm globalping-probe
docker run -d \
    --name globalping-probe \
    --restart always \
    --network host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -e ADOPTION_TOKEN="YOUR_TOKEN" \
    ghcr.io/jsdelivr/globalping-probe
EOF

    chmod +x /usr/local/bin/globalping-maintenance
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
}

# ==============================================
# SYSTEMOPTIMIERUNGEN
# ==============================================
system_update() {
    log "Starte vollständiges Systemupdate"

    apt-get update -y | tee -a "$LOG_FILE"
    apt-get upgrade -y --with-new-pkgs | tee -a "$LOG_FILE"
    apt-get dist-upgrade -y | tee -a "$LOG_FILE"
    unattended-upgrade -d | tee -a "$LOG_FILE"

    log "Systemupdate abgeschlossen"
}

system_optimize() {
    log "Starte Systemoptimierungen"

    # Kernel Parameter optimieren
    cat >> /etc/sysctl.conf << EOF
# Optimierungen für Globalping
net.core.rmem_max=4194304
net.core.wmem_max=4194304
net.ipv4.tcp_rmem=4096 87380 4194304
net.ipv4.tcp_wmem=4096 65536 4194304
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
EOF

    sysctl -p | tee -a "$LOG_FILE"

    # SWAP optimieren
    if [ -f /etc/sysctl.conf ]; then
        sed -i '/vm.swappiness/d' /etc/sysctl.conf
        echo "vm.swappiness=10" >> /etc/sysctl.conf
    fi

    log "Systemoptimierungen abgeschlossen"
}

system_cleanup() {
    log "Starte Systembereinigung"

    apt-get autoremove -y | tee -a "$LOG_FILE"
    apt-get clean | tee -a "$LOG_FILE"
    journalctl --vacuum-time=7d | tee -a "$LOG_FILE"
    find /var/log -type f \( -name "*.gz" -o -name "*.1" \) -delete | tee -a "$LOG_FILE"
    rm -rf /tmp/* | tee -a "$LOG_FILE"
    docker system prune -f | tee -a "$LOG_FILE"

    log "Systembereinigung abgeschlossen"
}

# ==============================================
# HAUPTFUNKTION
# ==============================================
main() {
    trap 'error_handler $LINENO' ERR

    get_system_info
    create_temp_dir
    check_root
    check_internet

    log "=== Globalping Installationsskript gestartet ==="
    notify "info" "Installationsprozess gestartet"

    # Parameter verarbeiten
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --adoption-token)
                ADOPTION_TOKEN="$2"
                shift 2
                ;;
            --telegram-token)
                TELEGRAM_TOKEN="$2"
                shift 2
                ;;
            --telegram-chat)
                TELEGRAM_CHAT="$2"
                shift 2
                ;;
            --ubuntu-token)
                UBUNTU_TOKEN="$2"
                shift 2
                ;;
            --ssh-key)
                SSH_KEY="$2"
                shift 2
                ;;
            *)
                log "Unbekannter Parameter: $1"
                exit 1
                ;;
        esac
    done

    # Installationsablauf
    install_dependencies
    system_update
    configure_firewall
    configure_ssh
    install_ubuntu_pro
    system_optimize
    install_globalping
    setup_cron_job
    system_cleanup

    log "=== Installation erfolgreich abgeschlossen ==="
    notify "success" "Globalping Probe erfolgreich installiert und konfiguriert"

    # Statusausgabe
    echo -e "\n🔹 Installationszusammenfassung:"
    echo "Hostname: $HOSTNAME"
    echo "IP: $IP_ADDRESS"
    echo "Globalping Status: $(docker inspect -f '{{.State.Status}}' globalping-probe)"
    echo "Ubuntu Pro: $(pro status --format json | jq -r '.attached')"
}

main "$@"
