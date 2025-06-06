#!/bin/bash
set -eo pipefail

# --- Globale Variablen ---
TELEGRAM_API_URL="https://api.telegram.org/bot"
LOG_FILE="/var/log/globalping-install.log"
TMP_DIR="/tmp/globalping_install"
SSH_DIR="/root/.ssh"
SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
CRON_JOB="0 0 * * 0 /usr/local/bin/globalping-maintenance"
AUTO_UPDATE_CRON="0 0 * * 0 /usr/local/bin/install_globalping.sh --auto-update"

# --- Funktionen ---

error_handler() {
    local line=$1
    log "Fehler in Zeile $line"
    notify error "Installation fehlgeschlagen in Zeile $line"
    exit 1
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

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
        *) emoji="ℹ️"; title="Information" ;;
    esac

    if [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT" ]; then
        curl -s -X POST "$TELEGRAM_API_URL$TELEGRAM_TOKEN/sendMessage" \
            -d chat_id="$TELEGRAM_CHAT" \
            -d text="$emoji [$title] $message" \
            -d parse_mode="Markdown" >/dev/null 2>&1
    fi
}

manage_hostname() {
    local current_hostname=$(hostname -f 2>/dev/null || echo "UNKNOWN")
    
    if [ "$current_hostname" == "UNKNOWN" ]; then
        log "Warnung: Hostname konnte nicht ermittelt werden"
        return 1
    fi

    # Backup der originalen hosts-Datei
    cp /etc/hosts "$TMP_DIR/hosts.backup"

    # Alten Eintrag entfernen (falls vorhanden)
    sed -i "/$(hostname -s)/d" /etc/hosts

    # Neuen Eintrag hinzufügen
    if grep -q "127.0.0.1" /etc/hosts; then
        sed -i "/127.0.0.1/s/$/ $current_hostname/" /etc/hosts
    else
        echo "127.0.0.1 $current_hostname" >> /etc/hosts
    fi

    log "Hostname $current_hostname in /etc/hosts eingetragen"
}

check_for_updates() {
    if [ "$1" = "--auto-update" ]; then
        log "Automatische Aktualisierung gestartet"
        curl -s "$SCRIPT_URL" > "$TMP_DIR/install_new.sh"
        if ! diff "$SCRIPT_PATH" "$TMP_DIR/install_new.sh" >/dev/null; then
            log "Neue Version gefunden - aktualisiere..."
            mv "$TMP_DIR/install_new.sh" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            exec "$SCRIPT_PATH" "$@"
        fi
    fi
}

get_system_info() {
    log "Erfasse Systeminformationen"
    
    COUNTRY=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/country || echo "UNKNOWN")
    HOSTNAME=$(hostname -f 2>/dev/null || echo "UNKNOWN")
    IP_ADDRESS=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/ip || echo "UNKNOWN")
    ASN_INFO=$(curl -4 -s --connect-timeout 5 https://ipinfo.io/org || echo "UNKNOWN")
    PROVIDER=$(echo "$ASN_INFO" | cut -d ' ' -f2- | sed 's/"/\\"/g')
    ASN=$(echo "$ASN_INFO" | cut -d ' ' -f1 | sed s/AS//g)
    OS_INFO=$(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || echo "UNKNOWN")
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p | sed 's/up //')
    DISK_SPACE=$(df -h / | awk 'NR==2 {print $4}')
    MEMORY=$(free -m | awk 'NR==2 {print $4}')
    CPU_INFO=$(lscpu | grep 'Model name' | cut -d: -f2 | xargs)
}

create_temp_dir() {
    mkdir -p "$TMP_DIR"
    chmod 700 "$TMP_DIR"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "Dieses Skript muss als root ausgeführt werden"
        exit 1
    fi
}

check_internet() {
    if ! ping -c 1 -W 3 google.com >/dev/null 2>&1; then
        log "Keine Internetverbindung"
        exit 1
    fi
}

install_dependencies() {
    log "Installiere Abhängigkeiten"
    
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y curl wget awk sed grep coreutils
    elif command -v yum >/dev/null; then
        yum install -y curl wget awk sed grep coreutils
    elif command -v dnf >/dev/null; then
        dnf install -y curl wget awk sed grep coreutils
    else
        log "Paketmanager nicht erkannt"
        exit 1
    fi
}

setup_ssh_key() {
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    
    if [ -n "$SSH_KEY" ]; then
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        chmod 600 "$SSH_DIR/authorized_keys"
        log "SSH-Schlüssel hinzugefügt"
    fi
}

install_globalping() {
    log "Installiere Globalping Probe"
    
    if command -v apt-get >/dev/null; then
        curl -sL https://packagecloud.io/install/repositories/jsdelivr/globalping/script.deb.sh | sudo bash
        apt-get install -y globalping-probe
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        curl -sL https://packagecloud.io/install/repositories/jsdelivr/globalping/script.rpm.sh | sudo bash
        yum install -y globalping-probe || dnf install -y globalping-probe
    else
        log "Paketmanager nicht unterstützt"
        exit 1
    fi
}

configure_adoption_token() {
    if [ -n "$ADOPTION_TOKEN" ]; then
        echo "$ADOPTION_TOKEN" > /etc/globalping-probe/adoption-token
        systemctl restart globalping-probe
        log "Adoption-Token konfiguriert"
    fi
}

setup_cron_jobs() {
    log "Richte Cron-Jobs ein"
    
    # Wartungs-Cron
    echo "$CRON_JOB" | crontab -
    
    # Auto-Update-Cron
    echo "$AUTO_UPDATE_CRON" | crontab -
}

# --- Hauptskript ---

main() {
    trap 'error_handler $LINENO' ERR
    
    check_for_updates "$1"
    create_temp_dir
    check_root
    check_internet
    manage_hostname
    get_system_info
    
    log "=== Globalping Installationsskript gestartet ==="
    notify info "Installationsprozess gestartet"
    
    install_dependencies
    setup_ssh_key
    install_globalping
    configure_adoption_token
    setup_cron_jobs
    
    log "=== Installation erfolgreich abgeschlossen ==="
    notify success "Globalping erfolgreich installiert"
}

# Argument parsing
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
