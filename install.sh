#!/bin/bash
set -eo pipefail

# ==============================================
# KONFIGURATION
# ==============================================
TELEGRAM_API_URL="https://api.telegram.org/bot"
LOG_FILE="/var/log/globalping-install.log"
TMP_DIR="/tmp/globalping_install"
SSH_DIR="$HOME/.ssh"
SCRIPT_URL="https://raw.githubusercontent.com/ihr-benutzer/ihr-repo/main/install_globalping.sh"
SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
CRON_JOB="0 0 * * 0 /usr/local/bin/globalping-maintenance"
AUTO_UPDATE_CRON="0 0 * * 0 /usr/local/bin/install_globalping.sh --auto-update"

# ==============================================
# SYSTEMINFORMATIONEN
# ==============================================
get_system_info() {
    log "Erfasse Systeminformationen"
    COUNTRY=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/country || echo "UNKNOWN")
    HOSTNAME=$(hostname -f || echo "UNKNOWN")
    IP_ADDRESS=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/ip || echo "UNKNOWN")
    ASN_INFO=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/org || echo "UNKNOWN")
    PROVIDER=$(echo "$ASN_INFO" | cut -d' ' -f2- | sed 's/"/\\"/g' || echo "UNKNOWN")
    ASN=$(echo "$ASN_INFO" | cut -d' ' -f1 | sed 's/AS//g' || echo "UNKNOWN")
    OS_INFO=$(lsb_release -ds 2>/dev/null || echo "UNKNOWN")
    KERNEL=$(uname -r || echo "UNKNOWN")
    UPTIME=$(uptime -p | sed 's/up //' || echo "UNKNOWN")
    DISK_SPACE=$(df -h / | awk 'NR==2 {print \$4}' || echo "UNKNOWN")
    MEMORY=$(free -m | awk 'NR==2 {print \$4}' || echo "UNKNOWN")
    CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs || echo "UNKNOWN")
}

# ==============================================
# LOGGING & BENACHRICHTIGUNGEN
# ==============================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "$LOG_FILE"
}

notify() {
    local level=\$1
    local message=\$2

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
    local line_number=\$1
    local command=$(sed -n "${line_number}p" "\$0")

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

# ==============================================
# ZEITSYNCHRONISATION
# ==============================================
setup_time_sync() {
    log "Konfiguriere Zeitsynchronisation"

    # Prüfe ob bereits ein Dienst läuft
    if systemctl is-active --quiet systemd-timesyncd || systemctl is-active --quiet chrony || systemctl is-active --quiet ntp; then
        log "Zeitsynchronisation ist bereits konfiguriert"
        return 0
    fi

    # Versuche chrony zu installieren
    if apt-cache show chrony >/dev/null 2>&1; then
        log "Installiere chrony für Zeitsynchronisation"
        apt-get install -y chrony | tee -a "$LOG_FILE"
        systemctl enable --now chrony | tee -a "$LOG_FILE"
    elif apt-cache show ntp >/dev/null 2>&1; then
        log "Installiere ntp für Zeitsynchronisation"
        apt-get install -y ntp | tee -a "$LOG_FILE"
        systemctl enable --now ntp | tee -a "$LOG_FILE"
    else
        log "Installiere systemd-timesyncd als Fallback"
        apt-get install -y systemd-timesyncd | tee -a "$LOG_FILE"
        systemctl enable --now systemd-timesyncd | tee -a "$LOG_FILE"
    fi

    notify "info" "Zeitsynchronisation eingerichtet"
}

# ==============================================
# AUTOMATISCHE UPDATES
# ==============================================
check_for_updates() {
    if [ "\$1" = "--auto-update" ]; then
        log "Starte automatische Update-Prüfung"

        # Prüfe auf neue Version
        local current_hash=$(sha256sum "$SCRIPT_PATH" | awk '{print \$1}')
        local remote_hash=$(curl -s "$SCRIPT_URL" | sha256sum | awk '{print \$1}')

        if [ "$current_hash" != "$remote_hash" ]; then
            log "Neue Version gefunden, aktualisiere Skript"
            curl -s "$SCRIPT_URL" -o "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            notify "info" "Skript wurde auf neue Version aktualisiert"
            exec "$SCRIPT_PATH" --resume
            exit 0
        else
            log "Skript ist bereits aktuell"
        fi
    fi
}

setup_auto_updates() {
    log "Richte automatische Updates ein"

    # Erstelle Skript-Kopie falls nicht vorhanden
    if [ ! -f "$SCRIPT_PATH" ]; then
        cp "\$0" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
    fi

    # Füge Cron-Job hinzu
    if ! crontab -l | grep -q "$SCRIPT_PATH --auto-update"; then
        (crontab -l 2>/dev/null; echo "$AUTO_UPDATE_CRON") | crontab -
        log "Automatische Updates eingerichtet (wöchentlich mit Zufalls-Offset)"
    fi
}

# ==============================================
# SSH-KONFIGURATION
# ==============================================
detect_ssh_service() {
    if systemctl is-active --quiet ssh; then
        echo "ssh"
    elif systemctl is-active --quiet sshd; then
        echo "sshd"
    elif service ssh status >/dev/null 2>&1; then
        echo "ssh"
    elif service sshd status >/dev/null 2>&1; then
        echo "sshd"
    else
        echo "none"
    fi
}

configure_ssh() {
    if [ -n "$SSH_KEY" ]; then
        log "Konfiguriere SSH-Zugang"

        local ssh_service=$(detect_ssh_service)

        # Installiere SSH-Server falls nicht vorhanden
        if [ "$ssh_service" = "none" ]; then
            log "Installiere OpenSSH-Server"
            apt-get install -y openssh-server | tee -a "$LOG_FILE"
            ssh_service="ssh"
        fi

        # Erstelle SSH-Verzeichnis und konfiguriere Key
        mkdir -p "$SSH_DIR"
        touch "$SSH_DIR/authorized_keys"
        chmod 700 "$SSH_DIR"
        chmod 600 "$SSH_DIR/authorized_keys"

        # Füge SSH-Key hinzu wenn nicht vorhanden
        if ! grep -q "$SSH_KEY" "$SSH_DIR/authorized_keys"; then
            log "Füge SSH-Key hinzu"
            echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        fi

        # SSH Hardening
        log "Härte SSH-Konfiguration"
        local ssh_config="/etc/ssh/sshd_config"
        cp "$ssh_config" "$ssh_config.bak"

        sed -i 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' "$ssh_config"
        sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$ssh_config"
        sed -i 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' "$ssh_config"
        sed -i 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$ssh_config"

        # Starte SSH-Dienst neu
        log "Starte SSH-Dienst ($ssh_service) neu"
        if systemctl list-unit-files | grep -q "$ssh_service.service"; then
            systemctl restart "$ssh_service" | tee -a "$LOG_FILE"
        else
            service "$ssh_service" restart | tee -a "$LOG_FILE"
        fi

        notify "success" "SSH erfolgreich konfiguriert (Service: $ssh_service)"
    fi
}

# ==============================================
# DOCKER-INSTALLATION
# ==============================================
install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker ist bereits installiert: $(docker --version)"
        return 0
    fi

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
}

# ==============================================
# GLOBALPING-INSTALLATION
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

setup_maintenance() {
    log "Richte Wartungs-Cron-Job ein"

    cat > /usr/local/bin/globalping-maintenance << 'EOF'
#!/bin/bash
LOG="/var/log/globalping-maintenance.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starte Wartung" >> $LOG

# Zufälligen Offset für wöchentlichen Run hinzufügen (0-1440 Minuten)
RANDOM_OFFSET=$((RANDOM % 1440))
sleep ${RANDOM_OFFSET}m

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

    if ! crontab -l | grep -q globalping-maintenance; then
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        log "Wartungs-Cron-Job erfolgreich eingerichtet"
    fi
}

# ==============================================
# HAUPTFUNKTION
# ==============================================
main() {
    trap 'error_handler $LINENO' ERR

    # Initialisierung
    check_for_updates "\$1"
    get_system_info
    create_temp_dir
    check_root
    check_internet

    log "=== Globalping Installationsskript gestartet ==="
    notify "info" "Installationsprozess gestartet"

    # Parameter verarbeiten
    while [[ $# -gt 0 ]]; do
        case "\$1" in
            --adoption-token)
                ADOPTION_TOKEN="\$2"
                shift 2
                ;;
            --telegram-token)
                TELEGRAM_TOKEN="\$2"
                shift 2
                ;;
            --telegram-chat)
                TELEGRAM_CHAT="\$2"
                shift 2
                ;;
            --ubuntu-token)
                UBUNTU_TOKEN="\$2"
                shift 2
                ;;
            --ssh-key)
                SSH_KEY="\$2"
                shift 2
                ;;
            --auto-update)
                shift
                ;;
            --resume)
                shift
                ;;
            *)
                log "Unbekannter Parameter: \$1"
                exit 1
                ;;
        esac
    done

    # Installationsablauf
    setup_time_sync
    configure_ssh
    install_docker
    install_globalping
    setup_maintenance
    setup_auto_updates

    log "=== Installation erfolgreich abgeschlossen ==="
    notify "success" "Globalping Probe erfolgreich installiert und konfiguriert"

    # Statusausgabe
    echo -e "\n🔹 Installationszusammenfassung:"
    echo "Hostname: $HOSTNAME"
    echo "IP: $IP_ADDRESS"
    echo "Globalping Status: $(docker inspect -f '{{.State.Status}}' globalping-probe)"
    echo "Automatische Updates: Aktiviert"
    echo "Wartungsplan: Wöchentlich mit Zufalls-Offset"
}

main "$@"

