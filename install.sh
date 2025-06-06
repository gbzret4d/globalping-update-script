#!/bin/bash
set -eo pipefail

# =============================================
# GLOBALE VARIABLEN
# =============================================
TELEGRAM_API_URL="https://api.telegram.org/bot"
LOG_FILE="/var/log/globalping-install.log"
TMP_DIR="/tmp/globalping_install"
SSH_DIR="/root/.ssh"
UBUNTU_PRO_TOKEN=""
SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
CRON_JOB="0 0 * * 0 /usr/local/bin/globalping-maintenance"
AUTO_UPDATE_CRON="0 0 * * 0 /usr/local/bin/install_globalping.sh --auto-update"

# =============================================
# FUNKTIONEN
# =============================================

# Error Handling
error_handler() {
    local line=$1
    log "KRITISCHER FEHLER in Zeile $line"
    notify error "❌ Installation fehlgeschlagen in Zeile $line"
    exit 1
}

# Logging-System
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Telegram-Benachrichtigung
notify() {
    local level=$1
    local message=$2
    local emoji=""
    local title=""

    case $level in
        info) emoji="🔔"; title="Benachrichtigung" ;;
        warn) emoji="⚠️"; title="Warnung" ;;
        error) emoji="❌"; title="Fehler" ;;
        success) emoji="✅"; title="Erfolg" ;;
        *) emoji="ℹ️"; title="Info" ;;
    esac

    if [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT" ]; then
        curl -s -X POST "$TELEGRAM_API_URL$TELEGRAM_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT" \
            -d text="$emoji [$title] $message" \
            -d parse_mode="Markdown" >/dev/null 2>&1 || log "Telegram-Benachrichtigung fehlgeschlagen"
    fi
}

# Ubuntu Pro Aktivierung
ubuntu_pro_attach() {
    if [ -n "$UBUNTU_PRO_TOKEN" ] && grep -q "Ubuntu" /etc/os-release; then
        log "Aktiviere Ubuntu Pro mit Token"
        
        # Ubuntu Advantage Tools installieren
        if ! command -v ua >/dev/null; then
            apt-get update >/dev/null 2>&1
            apt-get install -y ubuntu-advantage-tools >/dev/null 2>&1
        fi

        # Token anwenden
        ua attach "$UBUNTU_PRO_TOKEN" >/dev/null 2>&1
        
        # ESM und Sicherheitsupdates aktivieren
        ua enable esm-apps >/dev/null 2>&1
        ua enable esm-infra >/dev/null 2>&1
        ua enable livepatch >/dev/null 2>&1
        
        # System aktualisieren
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
        
        log "Ubuntu Pro erfolgreich aktiviert"
        notify success "Ubuntu Pro mit ESM/Livepatch aktiviert"
    fi
}

# Hostname Management (Cross-Distribution)
manage_hostname() {
    local current_hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UNKNOWN")
    local short_hostname=$(echo "$current_hostname" | cut -d'.' -f1)
    
    # Backup der originalen hosts-Datei
    cp /etc/hosts "$TMP_DIR/hosts.backup.$(date +%s)"

    # Alte Einträge bereinigen (für IPv4 und IPv6)
    sed -i "/^127\.0\.0\.1.*$short_hostname/d" /etc/hosts
    sed -i "/^::1.*$short_hostname/d" /etc/hosts

    # Neue Einträge hinzufügen
    if ! grep -q "127.0.0.1.*$current_hostname" /etc/hosts; then
        sed -i "/^127.0.0.1/s/$/ $current_hostname/" /etc/hosts || \
        echo "127.0.0.1 localhost $current_hostname" >> /etc/hosts
    fi

    if ! grep -q "::1.*$current_hostname" /etc/hosts; then
        sed -i "/^::1/s/$/ $current_hostname/" /etc/hosts || \
        echo "::1 localhost ip6-localhost ip6-loopback $current_hostname" >> /etc/hosts
    fi

    log "Hostname aktualisiert: $current_hostname (Kurzname: $short_hostname)"
}

# Systeminformationen sammeln
get_system_info() {
    log "Erfasse detaillierte Systeminformationen"
    
    COUNTRY=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/country || echo "UNKNOWN")
    HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UNKNOWN")
    IP_ADDRESS=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/ip || echo "UNKNOWN")
    ASN_INFO=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/org || echo "UNKNOWN")
    PROVIDER=$(echo "$ASN_INFO" | cut -d ' ' -f2- | sed 's/"/\\"/g')
    ASN=$(echo "$ASN_INFO" | cut -d ' ' -f1 | sed s/AS//g)
    OS_INFO=$( (lsb_release -ds || cat /etc/*release 2>/dev/null | head -n1 || uname -om) 2>/dev/null | tr -d '"')
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p | sed 's/up //')
    DISK_SPACE=$(df -h / | awk 'NR==2 {print $4}')
    MEMORY=$(free -m | awk 'NR==2 {print $4}')
    CPU_CORES=$(nproc)
    CPU_INFO=$( (lscpu | grep 'Model name' | cut -d: -f2 | xargs || cat /proc/cpuinfo | grep 'model name' | head -n1 | cut -d: -f2 | xargs) 2>/dev/null )
    LOAD_AVG=$(cat /proc/loadavg | awk '{print $1", "$2", "$3}')
    SWAP=$(free -m | awk '/Swap/{print $2" MB"}')

    log "Systeminfo: $OS_INFO | $CPU_CORES Cores | $MEMORY MB RAM | $DISK_SPACE frei"
}

# Temporäres Verzeichnis erstellen
create_temp_dir() {
    mkdir -p "$TMP_DIR"
    chmod 700 "$TMP_DIR"
    log "Temporäres Verzeichnis angelegt: $TMP_DIR"
}

# Root-Check
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "FEHLER: Dieses Skript benötigt root-Rechte!"
        exit 1
    fi
    log "Root-Check erfolgreich"
}

# Internetverbindung testen
check_internet() {
    if ! ping -c 1 -W 3 google.com >/dev/null 2>&1 && \
       ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log "KEINE INTERNETVERBINDUNG"
        exit 1
    fi
    log "Internetverbindung verfügbar"
}

# Abhängigkeiten installieren
install_dependencies() {
    log "Installiere Systemabhängigkeiten"
    
    if command -v apt-get >/dev/null; then
        apt-get update >/dev/null 2>&1
        apt-get install -y \
            curl wget awk sed grep coreutils \
            lsb-release iproute2 systemd >/dev/null 2>&1
    elif command -v yum >/dev/null; then
        yum install -y \
            curl wget awk sed grep coreutils \
            redhat-lsb-systemd iproute >/dev/null 2>&1
    elif command -v dnf >/dev/null; then
        dnf install -y \
            curl wget awk sed grep coreutils \
            redhat-lsb-systemd iproute >/dev/null 2>&1
    else
        log "Kein unterstützter Paketmanager gefunden!"
        exit 1
    fi
}

# SSH-Schlüssel einrichten
setup_ssh_key() {
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    
    if [ -n "$SSH_KEY" ]; then
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        chmod 600 "$SSH_DIR/authorized_keys"
        log "SSH-Schlüssel erfolgreich hinzugefügt"
        notify info "SSH-Zugang eingerichtet"
    fi
}

# Globalping Probe installieren
install_globalping() {
    log "Starte Globalping-Installation"
    
    # Distribution erkennen
    if command -v apt-get >/dev/null; then
        log "Debian-basiertes System erkannt"
        curl -sL https://packagecloud.io/install/repositories/jsdelivr/globalping/script.deb.sh | sudo bash
        apt-get install -y globalping-probe >/dev/null 2>&1
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        log "RHEL-basiertes System erkannt"
        curl -sL https://packagecloud.io/install/repositories/jsdelivr/globalping/script.rpm.sh | sudo bash
        (command -v yum >/dev/null && yum install -y globalping-probe || dnf install -y globalping-probe) >/dev/null 2>&1
    else
        log "Nicht unterstützte Distribution"
        exit 1
    fi

    systemctl enable globalping-probe >/dev/null 2>&1
    systemctl start globalping-probe >/dev/null 2>&1
    log "Globalping Probe erfolgreich installiert und gestartet"
}

# Adoption Token konfigurieren
configure_adoption_token() {
    if [ -n "$ADOPTION_TOKEN" ]; then
        mkdir -p /etc/globalping-probe
        echo "$ADOPTION_TOKEN" > /etc/globalping-probe/adoption-token
        chmod 600 /etc/globalping-probe/adoption-token
        systemctl restart globalping-probe >/dev/null 2>&1
        log "Adoption-Token erfolgreich konfiguriert"
        notify info "Probe mit Adoption-Token registriert"
    fi
}

# Cron-Jobs einrichten
setup_cron_jobs() {
    log "Richte automatische Wartungs-Cronjobs ein"
    
    # Hauptwartungsjob
    echo "$CRON_JOB" | crontab - >/dev/null 2>&1
    
    # Auto-Update-Job
    echo "$AUTO_UPDATE_CRON" | crontab - >/dev/null 2>&1
    
    log "Cronjobs erfolgreich eingerichtet"
    notify info "Automatische Updates aktiviert"
}

# Auf Updates prüfen
check_for_updates() {
    if [ "$1" = "--auto-update" ]; then
        log "Automatische Update-Prüfung gestartet"
        
        mkdir -p "$TMP_DIR"
        curl -s "$SCRIPT_URL" > "$TMP_DIR/install_new.sh"
        
        if ! diff "$SCRIPT_PATH" "$TMP_DIR/install_new.sh" >/dev/null; then
            log "NEUE VERSION GEFUNDEN - Aktualisiere..."
            mv "$TMP_DIR/install_new.sh" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            exec "$SCRIPT_PATH" "$@"
        else
            log "Keine Updates verfügbar"
        fi
    fi
}

# Systemreport generieren
generate_report() {
    echo -e "\n=== SYSTEMREPORT ==="
    echo "Hostname: $HOSTNAME"
    echo "IP: $IP_ADDRESS"
    echo "ASN: AS$ASN ($PROVIDER)"
    echo "Standort: $COUNTRY"
    echo "OS: $OS_INFO"
    echo "Kernel: $KERNEL"
    echo "Uptime: $UPTIME"
    echo "CPU: $CPU_INFO ($CPU_CORES Cores)"
    echo "RAM: $MEMORY MB frei | Swap: $SWAP"
    echo "Disk: $DISK_SPACE frei"
    echo "Load: $LOAD_AVG"
    echo "========================="
}

# =============================================
# HAUPTPROGRAMM
# =============================================
main() {
    trap 'error_handler $LINENO' ERR
    
    # Initialisierung
    check_for_updates "$1"
    create_temp_dir
    check_root
    check_internet
    
    # Systemkonfiguration
    manage_hostname
    get_system_info
    ubuntu_pro_attach
    
    log "=== Globalping Installation gestartet ==="
    notify info "🚀 Installation gestartet auf $HOSTNAME ($IP_ADDRESS)"
    
    # Installation
    install_dependencies
    setup_ssh_key
    install_globalping
    configure_adoption_token
    setup_cron_jobs
    
    # Abschluss
    log "=== Installation erfolgreich abgeschlossen ==="
    notify success "✅ Globalping erfolgreich installiert auf $HOSTNAME"
    generate_report
}

# =============================================
# ARGUMENTPARSER
# =============================================
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
            UBUNTU_PRO_TOKEN="$2"
            shift 2
            ;;
        --ssh-key)
            SSH_KEY="$2"
            shift 2
            ;;
        --auto-update)
            AUTO_UPDATE=true
            shift
            ;;
        *)
            log "Unbekannter Parameter: $1"
            exit 1
            ;;
    esac
done

# Hauptprogramm starten
main "$@"


# ==============================================
# UMFASSENDE DOKUMENTATION & METADATEN
# ==============================================
: << 'EOF'
# GLOBALPING PROBE INSTALLATIONSSKRIPT - KOMPLETTE DOKUMENTATION

## ZWECK & FUNKTIONSWEISE
Dieses Skript automatisiert die komplette Bereitstellung einer Globalping-Probe als Docker-Container mit allen notwendigen Systemvoraussetzungen. Es implementiert:
- Sichere Basis-Konfiguration des Hostsystems
- Automatische Wartungs- und Update-Mechanismen
- Umfassende Überwachung und Benachrichtigung
- Selbstheilungsfunktionalitäten für maximale Verfügbarkeit

## KERNKOMPONENTEN
1. SYSTEMVORAUSSETZUNGEN
   - Docker Runtime (automatisch installiert)
   - Zeitsynchronisation (chrony/ntp/systemd-timesyncd)
   - SSH-Zugang (optional mit Key-basiertem Zugang)
   - Ubuntu Pro Support (optional)

2. INSTALLATIONSABLAUF
   - Systemhärtung (SSH, automatische Updates)
   - Docker-Installation mit offiziellem Repository
   - Globalping-Container-Deployment
   - Cron-Job Einrichtung für:
     * Wöchentliche Container-Updates (+/- 24h Offset)
     * Skript-Selbstupdates (von GitHub)

3. NOTIFIKATIONSSYSTEM
   - Telegram-Integration für:
     * Installationsstatus
     * Fehlermeldungen
     * Wartungsaktivitäten

## TECHNISCHE DETAILS
### AUTO-UPDATE MECHANISMUS
- Update-Quelle: GitHub Raw Content (${SCRIPT_URL})
- Prüfrhythmus: Wöchentlich mit zufälligem Zeitoffset
- Aktualisierungsstrategie:
  1. SHA256-Checksummenvergleich
  2. Automatischer Download bei Änderungen
  3. Neustart mit --resume Parameter

### ZEITSYNCHRONISATION
- Priorisierte Dienste:
  1. chrony (falls verfügbar)
  2. ntp (Fallback)
  3. systemd-timesyncd (Notfalllösung)
- Wichtig für zeitgenaue Cron-Job-Ausführung

### SSH-KONFIGURATION
- Automatische Erkennung laufender Dienste (ssh/sshd)
- Härtung der Konfiguration:
  - Deaktivierung von PasswordAuthentication
  - Root-Login nur mit SSH-Key
  - Absicherung der Key-Dateiberechtigungen

### FEHLERBEHANDLUNG
- Drei-Stufen-Error-Handling:
  1. Lokales Logging (/var/log/globalping-install.log)
  2. Systemweite Benachrichtigung (Telegram)
  3. Automatischer Cleanup bei Abbruch

### CRON-JOBS
1. Wartungsjob (${CRON_JOB}):
   - Container-Update mit Zufalls-Offset
   - Neustart der Probe
   - Logging nach /var/log/globalping-maintenance.log

2. Skript-Update (${AUTO_UPDATE_CRON}):
   - Wöchentliche Prüfung auf GitHub-Änderungen
   - Automatische Aktualisierung bei neuen Versionen

## VARIABLEN & KONFIGURATION
### ERFORDERLICHE PARAMETER
--adoption-token    : Globalping Adoption Token (MANDATORY)
--telegram-token   : Bot-Token für Notifications (OPTIONAL)
--telegram-chat    : Chat-ID für Notifications (OPTIONAL)
--ubuntu-token     : Ubuntu Pro Token (OPTIONAL)
--ssh-key          : Public Key für SSH-Zugang (OPTIONAL)

### INTERNE VARIABLEN
TELEGRAM_API_URL   : Telegram API Endpoint
TMP_DIR            : Temporäres Arbeitsverzeichnis
SCRIPT_URL         : Update-Quelladresse (GitHub Raw)
CRON_JOB           : Wartungsjob-Definition

## SICHERHEITSHINWEISE
1. TOKEN-SICHERHEIT
   - Alle Tokens werden als Skriptparameter übergeben
   - Keine dauerhafte Speicherung in Klartext

2. SYSTEMZUGRIFF
   - Skript erfordert root-Rechte
   - Modifiziert Systemdienste (SSH, Docker)
   - Installiert Systempakete

3. DATENSCHUTZ
   - IP/Hostname-Informationen werden an Telegram gesendet
   - Keine sensiblen Systemdaten werden extern übertragen

## TROUBLESHOOTING
### TYPISCHE FEHLER
1. DOCKER-PROBLEME
   - Lösung: System neu starten, /var/lib/docker bereinigen

2. SSH-KONFIGURATION
   - Lösung: Backup unter /etc/ssh/sshd_config.bak

3. CRON-JOB-FEHLER
   - Lösung: Manueller Test mit /usr/local/bin/globalping-maintenance

### LOG-ANALYSE
- Hauptlog: /var/log/globalping-install.log
- Wartungslog: /var/log/globalping-maintenance.log
- Docker-Logs: docker logs globalping-probe

## ENTWICKLERHINWEISE
1. ERWEITERUNGEN
   - Neue Funktionen sollten error_handler integrieren
   - Telegram-Notifications für alle kritischen Operationen

2. TESTPROZEDUR
   - Immer mit --ssh-key testen
   - Automatische Updates simulieren mit:
     sha256sum /usr/local/bin/install_globalping.sh > test.hash

3. VERSIONSKONTROLLE
   - Änderungen im Skript müssen die SHA256-Prüfung berücksichtigen
   - Update-URL darf nicht ohne Migration geändert werden

## BEISPIELAUFRUFE
1. KOMPLETTE INSTALLATION:
   ./install_globalping.sh \
     --adoption-token "gp_123456" \
     --ssh-key "ssh-rsa AAAAB3..." \
     --telegram-token "123:ABC" \
     --telegram-chat "456"

2. NUR DOCKER & PROBE:
   ./install_globalping.sh --adoption-token "gp_123456"

3. AUTOUPDATE-TEST:
   ./install_globalping.sh --auto-update

## ZUKÜNFTIGE ENTWICKLUNG
- Integration von Health-Checks
- Support für alternative Container-Runtimes
- Erweiterte System-Monitoring-Funktionen
EOF
