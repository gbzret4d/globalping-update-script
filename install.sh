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
    DISK_SPACE=$(df -h / | awk 'NR==2 {print $4}' || echo "UNKNOWN")
    MEMORY=$(free -m | awk 'NR==2 {print $4}' || echo "UNKNOWN")
    CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs || echo "UNKNOWN")
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
        "error") emoji="❌"; title="Fehler im Skript" ;;
        "warning") emoji="⚠️"; title="Warnung" ;;
        "success") emoji="✅"; title="Erfolgreich" ;;
        "info") emoji="ℹ️"; title="Information" ;;
        *) emoji="🔔"; title="Benachrichtigung" ;;
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
💾 Disk: $DISK_SPACE frei
🧠 RAM: $MEMORY MB frei
⚡ CPU: $CPU_INFO
🔧 Details: $message"

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
        net-tools
    )

    for pkg in "${dependencies[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            log "Installiere $pkg"
            apt-get install -y "$pkg" | tee -a "$LOG_FILE"
        fi
    done

    install_docker
}

install_docker() {
    if ! command -v docker &>/dev/null; then
        log "Vorbereitung der Docker-Installation"

        # Bereinige vorhandene Docker-Installationen
        if dpkg -l | grep -qE 'docker|containerd'; then
            log "Entferne vorhandene Docker-Pakete"
            apt-get remove -y docker docker-engine docker.io containerd runc || true
            apt-get autoremove -y | tee -a "$LOG_FILE"
            rm -rf /var/lib/docker /etc/docker
        fi

        # Offizielle Docker-Installation
        log "Füge Docker-Repository hinzu"
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update -y | tee -a "$LOG_FILE"

        log "Installiere Docker-Pakete"
        apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin | tee -a "$LOG_FILE"

        # Docker konfigurieren
        log "Konfiguriere Docker-Dienst"
        systemctl enable --now docker | tee -a "$LOG_FILE"
        usermod -aG docker "$USER" || true

        # Installation verifizieren
        if docker --version &>/dev/null; then
            log "Docker erfolgreich installiert: $(docker --version)"
            notify "success" "Docker installiert: $(docker --version)"
        else
            log "FEHLER: Docker-Installation fehlgeschlagen"
            notify "error" "Docker-Installation fehlgeschlagen"
            exit 1
        fi
    else
        log "Docker ist bereits installiert: $(docker --version)"
    fi
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
        echo "y" | ufw enable | tee -a "$LOG_FILE"
    fi
}

configure_ssh() {
    if [ -n "$SSH_KEY" ]; then
        log "Konfiguriere SSH-Zugang"

        mkdir -p "$SSH_DIR"
        touch "$SSH_DIR/authorized_keys"
        chmod 700 "$SSH_DIR"
        chmod 600 "$SSH_DIR/authorized_keys"

        # Füge SSH-Key hinzu wenn nicht vorhanden
        if ! grep -q "$SSH_KEY" "$SSH_DIR/authorized_keys"; then
            echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        fi

        # SSH Hardening
        log "Härte SSH-Konfiguration"
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

        systemctl restart sshd | tee -a "$LOG_FILE"
        notify "success" "SSH erfolgreich konfiguriert"
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
    sleep 10
    if docker ps | grep -q globalping-probe; then
        local probe_version=$(docker inspect globalping-probe --format '{{.Config.Image}}')
        log "Globalping Probe erfolgreich installiert (Version: $probe_version)"
        notify "success" "Globalping Probe läuft (Version: $probe_version)"
    else
        log "FEHLER: Globalping Probe start fehlgeschlagen"
        docker logs globalping-probe | tee -a "$LOG_FILE"
        notify "error" "Globalping Probe konnte nicht gestartet werden"
        exit 1
    fi
}

setup_cron_job() {
    log "Richte Cron-Job für Wartung ein"

    cat > /usr/local/bin/globalping-maintenance << 'EOF'
#!/bin/bash
LOG="/var/log/globalping-maintenance.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starte Wartung" >> $LOG

# Docker-Images aktualisieren
docker pull ghcr.io/jsdelivr/globalping-probe:latest 2>&1 >> $LOG

# Container neustarten
docker stop globalping-probe 2>&1 >> $LOG
docker rm globalping-probe 2>&1 >> $LOG
docker run -d \
    --name globalping-probe \
    --restart always \
    --network host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -e ADOPTION_TOKEN="YOUR_TOKEN" \
    ghcr.io/jsdelivr/globalping-probe 2>&1 >> $LOG

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Wartung abgeschlossen" >> $LOG
EOF

    chmod +x /usr/local/bin/globalping-maintenance
    sed -i "s/YOUR_TOKEN/$ADOPTION_TOKEN/" /usr/local/bin/globalping-maintenance

    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    log "Cron-Job erfolgreich eingerichtet"
    notify "info" "Automatische Wartung eingerichtet (täglich 3 Uhr)"
}

# ==============================================
# SYSTEMUPDATE & BEREINIGUNG
# ==============================================
system_update() {
    log "Starte vollständiges Systemupdate"

    apt-get update -y | tee -a "$LOG_FILE"
    apt-get upgrade -y --with-new-pkgs | tee -a "$LOG_FILE"
    apt-get dist-upgrade -y | tee -a "$LOG_FILE"
    unattended-upgrade -d | tee -a "$LOG_FILE"

    log "Systemupdate abgeschlossen"
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

    # Initialisierung
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
