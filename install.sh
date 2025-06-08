#!/bin/bash
set -euo pipefail

# =============================================
# GLOBALE VARIABLEN
# =============================================
readonly TELEGRAM_API_URL="https://api.telegram.org/bot"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly CRON_JOB="0 2 * * 0 /usr/local/bin/globalping-maintenance"
readonly AUTO_UPDATE_CRON="0 3 * * 0 /usr/local/bin/install_globalping.sh --auto-weekly"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"
readonly SCRIPT_VERSION="2025.06.08-v1.0.9"

# Erweiterte Konfiguration
readonly MIN_FREE_SPACE_GB="1.5"  # Mindestens 1.5GB frei
readonly MIN_RAM_MB="256"          # Mindestens 256MB RAM
readonly MAX_LOG_SIZE_MB="50"      # Maximale Log-Größe
readonly SWAP_MIN_TOTAL_GB="1"     # RAM + SWAP mindestens 1GB
readonly MIN_DISK_FOR_SWAP_GB="10" # Mindestens 10GB Festplatte für Swap

# Timeout-Konfiguration
readonly TIMEOUT_NETWORK="10"     # Netzwerk-Operationen
readonly TIMEOUT_PACKAGE="1800"   # Paket-Updates (30 Min)
readonly TIMEOUT_DOCKER="900"     # Docker-Operationen (15 Min)
readonly TIMEOUT_CLEANUP="600"    # Cleanup-Operationen (10 Min)
readonly TIMEOUT_GENERAL="300"    # Allgemeine Operationen (5 Min)

# Initialisiere Variablen
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"

# System-Informationen (werden dynamisch gesetzt)
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""

# =============================================
# FUNKTIONEN
# =============================================

# Erweiterte Systeminfo-Sammlung
get_enhanced_system_info() {
    log "Sammle erweiterte Systeminformationen"
    
    # Öffentliche IP ermitteln
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    
    # Geo-Informationen sammeln
    local ipinfo_response
    ipinfo_response=$(curl -s "https://ipinfo.io/json" 2>/dev/null || echo "")
    
    if [[ -n "${ipinfo_response}" ]] && echo "${ipinfo_response}" | grep -q '"country"'; then
        COUNTRY=$(echo "${ipinfo_response}" | grep -o '"country": *"[^"]*"' | cut -d'"' -f4 | head -1)
        local asn_raw
        asn_raw=$(echo "${ipinfo_response}" | grep -o '"org": *"[^"]*"' | cut -d'"' -f4 | head -1)
        
        if [[ -n "${asn_raw}" ]]; then
            ASN=$(echo "${asn_raw}" | grep -o "AS[0-9]*" | head -1)
            PROVIDER=$(echo "${asn_raw}" | sed 's/^AS[0-9]* //' | tr ' ' '-' | tr -cd '[:alnum:] -')
        fi
    fi
    
    # Fallback-Werte setzen
    [[ -z "${COUNTRY}" ]] && COUNTRY="XX"
    [[ -z "${ASN}" ]] && ASN="unknown"
    [[ -z "${PROVIDER}" ]] && PROVIDER="unknown"
    
    # Hostname ermitteln - INTELLIGENTER HOSTNAME
    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        HOSTNAME_NEW="${COUNTRY,,}-${PROVIDER,,}-${ASN}-globalping-$(echo "${PUBLIC_IP}" | tr '.' '-')"
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-$(date +%s)")
    fi
    
    log "System-Info: ${COUNTRY}, ${PUBLIC_IP}, ${ASN}, ${PROVIDER}"
}

# OPTIMIERTE Telegram-Benachrichtigung mit nützlichen Links
enhanced_notify() {
    local level="$1"
    local title="$2"
    local message="$3"
    
    # Nur Fehler und erste Installation senden
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then
        return 0
    fi
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        log "Telegram-Konfiguration nicht vollständig"
        return 0
    fi
    
    # Sammle aktuelle Systeminfo falls nicht vorhanden
    [[ -z "${COUNTRY}" ]] && get_enhanced_system_info
    
    local icon emoji
    case "${level}" in
        "error")
            icon="❌"
            emoji="KRITISCHER FEHLER"
            ;;
        "install_success")
            icon="✅"
            emoji="INSTALLATION ERFOLGREICH"
            ;;
    esac
    
    # Erstelle erweiterte Nachricht basierend auf Level
    local extended_message
    if [[ "${level}" == "install_success" ]]; then
        # Sammle Systeminformationen SICHER
        local ram_info disk_info swap_info load_info
        local auto_update_status ssh_status ubuntu_pro_status
        local globalping_status docker_installed
        
        # Sichere Sammlung der Systeminformationen
        ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unbekannt")
        disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5" belegt)"}' || echo "unbekannt")
        swap_info=$(free -h 2>/dev/null | grep Swap | awk '{print $2}' || echo "0B")
        load_info=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "0")
        
        # Status-Informationen
        auto_update_status=$(systemctl is-enabled globalping-update.timer 2>/dev/null || echo "crontab")
        ssh_status="${SSH_KEY:+✓ Konfiguriert}${SSH_KEY:-✗ Nicht gesetzt}"
        ubuntu_pro_status="${UBUNTU_PRO_TOKEN:+✓ Aktiv}${UBUNTU_PRO_TOKEN:-✗ Nicht verwendet}"
        
        # Docker & Globalping Status (vereinfacht)
        if command -v docker >/dev/null 2>&1; then
            docker_installed="✓ Installiert"
            if docker ps --format "{{.Names}}" 2>/dev/null | grep -q globalping; then
                globalping_status="✓ Aktiv"
            else
                globalping_status="✗ Nicht gefunden"
            fi
        else
            docker_installed="✗ Nicht installiert"
            globalping_status="✗ Docker fehlt"
        fi
        
        # Erweiterte Success-Nachricht mit Links
        extended_message="${icon} ${emoji}

🌍 SERVER-DETAILS:
├─ Land: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP-Adresse: ${PUBLIC_IP}
├─ Provider: ${PROVIDER}
├─ ASN: ${ASN}
└─ Virtualisierung: $(systemd-detect-virt 2>/dev/null || echo "Bare Metal")

💾 SYSTEM-STATUS:
├─ RAM: ${ram_info}
├─ Festplatte: ${disk_info}
├─ Swap: ${swap_info}
└─ Load: ${load_info}

🔧 DIENSTE:
├─ Docker: ${docker_installed}
├─ Globalping: ${globalping_status}
├─ Auto-Update: ${auto_update_status}
├─ SSH-Schlüssel: ${ssh_status}
├─ Ubuntu Pro: ${ubuntu_pro_status}
└─ Telegram: ✓ Aktiv

📋 ${title}:
${message}

🔗 NÜTZLICHE LINKS:
├─ IP-Details: https://ipinfo.io/${PUBLIC_IP}
├─ ASN-Info: https://bgp.he.net/${ASN}
├─ WHOIS: https://whois.net/ip/${PUBLIC_IP}
├─ Geo-Map: https://db-ip.com/${PUBLIC_IP}
└─ Provider: https://ipinfo.io/${ASN}

⏰ Wartung: Sonntag 03:00 UTC
📊 Logs: /var/log/globalping-install.log"

    elif [[ "${level}" == "error" ]]; then
        # Kompakte Fehler-Nachricht mit Links für Debug
        local system_status error_context
        
        system_status=$(printf "RAM: %s | HDD: %s | Load: %s" \
            "$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "?")" \
            "$(df -h / 2>/dev/null | awk 'NR==2 {print $4" frei"}' || echo "?")" \
            "$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "?")")
        
        # Letzte relevante Log-Einträge
        error_context=$(tail -10 "${LOG_FILE}" 2>/dev/null | grep -E "(ERROR|CRITICAL|Failed)" | tail -2 | sed 's/^.*] //' || echo "Keine Details verfügbar")
        
        # Kompakte Fehler-Nachricht
        extended_message="${icon} ${emoji}

🌍 SERVER: ${COUNTRY} | ${PUBLIC_IP}
🏠 Host: ${HOSTNAME_NEW}
🏢 ${PROVIDER} (${ASN})

🚨 FEHLER-DETAILS:
${title}: ${message}

💻 SYSTEM: ${system_status}

📋 KONTEXT:
${error_context}

🔗 SERVER-INFO:
├─ IP-Details: https://ipinfo.io/${PUBLIC_IP}
├─ ASN-Info: https://bgp.he.net/${ASN}
└─ WHOIS: https://whois.net/ip/${PUBLIC_IP}

🔧 SSH-Zugang: ssh root@${PUBLIC_IP}
📊 Logs: tail -50 /var/log/globalping-install.log"
    fi
    
    log "Sende erweiterte Telegram-Nachricht (${#extended_message} Zeichen)..."
    
    # Debug: Zeige die ersten 200 Zeichen der Nachricht
    log "DEBUG: Nachricht-Anfang: $(echo "${extended_message}" | head -c 200)..."
    
    # Telegram-Limit beachten
    if [[ ${#extended_message} -gt 4000 ]]; then
        log "Nachricht zu lang (${#extended_message} Zeichen), kürze auf 4000"
        extended_message=$(echo "${extended_message}" | head -c 3900)
        extended_message="${extended_message}

...Nachricht gekürzt - Details via SSH"
    fi
    
    # Sende mit bewährter Methode
    local result
    result=$(curl -s -X POST \
        --connect-timeout 10 \
        --max-time 15 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
    
    # Debug: Zeige curl-Ergebnis
    log "DEBUG: Curl-Ergebnis: ${result}"
    
    if echo "${result}" | grep -q '"ok":true'; then
        local message_id
        message_id=$(echo "${result}" | grep -o '"message_id":[0-9]*' | cut -d':' -f2 || echo "unbekannt")
        log "Erweiterte Telegram-Nachricht erfolgreich gesendet (ID: ${message_id})"
        return 0
    else
        # Detailliertes Fehler-Logging
        log "Telegram-API Fehler: ${result}"
        
        # Fallback: Sehr kurze Nachricht
        log "Sende Fallback-Nachricht..."
        local fallback_msg="${icon} ${emoji}
🌍 ${COUNTRY} | ${PUBLIC_IP}
🏠 ${HOSTNAME_NEW}
📋 ${title}: ${message}
🔗 https://ipinfo.io/${PUBLIC_IP}"
        
        local fallback_result
        fallback_result=$(curl -s -X POST \
            -d "chat_id=${TELEGRAM_CHAT}" \
            -d "text=${fallback_msg}" \
            "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
        
        if echo "${fallback_result}" | grep -q '"ok":true'; then
            log "Fallback-Nachricht erfolgreich gesendet"
            return 0
        else
            log "Auch Fallback-Nachricht fehlgeschlagen: ${fallback_result}"
            return 1
        fi
    fi
}

# Test-Funktion für die erweiterte Benachrichtigung
test_extended_telegram() {
    log "Teste erweiterte Telegram-Benachrichtigung..."
    
    # Sammle Systeminfo
    get_enhanced_system_info
    
    # Teste Success-Nachricht
    enhanced_notify "install_success" "Test-Installation" "Dies ist eine Test-Nachricht mit allen Details des Servers."
}

# Verbesserter Error-Handler
enhanced_error_handler() {
    local line_number="$1"
    local error_code="${2:-1}"
    local error_msg="Skript fehlgeschlagen in Zeile ${line_number} (Exit-Code: ${error_code})"
    
    log "KRITISCHER FEHLER: ${error_msg}"
    
    # Sammle Debug-Informationen
    local debug_info=""
    debug_info+="Letzte Befehle: $(history | tail -3 | tr '\n' '; ')
"
    debug_info+="Speicher: $(free -h | grep Mem | awk '{print $3"/"$2}')
"
    debug_info+="Festplatte: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5")"}')
"
    
    enhanced_notify "error" "Fehlermeldung" "${error_msg}

Debug-Info:
${debug_info}"
    
    # Cleanup
    cleanup_on_error
    exit "${error_code}"
}

# Cleanup bei Fehlern
cleanup_on_error() {
    log "Führe Fehler-Cleanup durch"
    
    # Stoppe laufende kritische Operationen
    if command -v docker >/dev/null 2>&1; then
        # Stoppe nur Container die wir gerade erstellt haben
        local our_containers
        our_containers=$(docker ps --filter "label=com.globalping.installer=true" -q 2>/dev/null || echo "")
        if [[ -n "${our_containers}" ]]; then
            # shellcheck disable=SC2086
            docker stop ${our_containers} >/dev/null 2>&1 || true
        fi
    fi
    
    # Entferne temporäre Dateien
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    
    # Entferne Lock-Files
    rm -f "/var/lock/globalping-install-enhanced.lock" 2>/dev/null || true
    rm -f "/tmp/globalping_auto_update.lock" 2>/dev/null || true
}

# Verbesserte Logging-Funktion
enhanced_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log-Level-Mapping
    local level_prefix
    case "${level}" in
        "ERROR") level_prefix="❌ [ERROR]" ;;
        "WARN")  level_prefix="⚠️  [WARN]" ;;
        "INFO")  level_prefix="ℹ️  [INFO]" ;;
        "DEBUG") level_prefix="🔍 [DEBUG]" ;;
        *) level_prefix="📝 [${level}]" ;;
    esac
    
    # Stelle sicher, dass Log-Verzeichnis existiert
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    # Schreibe Log
    echo "[${timestamp}] ${level_prefix} ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || {
        echo "[${timestamp}] ${level_prefix} ${message}" >&2
    }
    
    # Log-Rotation prüfen
    rotate_logs_if_needed
}

# Wrapper für bestehende log-Funktion
log() {
    enhanced_log "INFO" "$1"
}

# Log-Rotation
rotate_logs_if_needed() {
    if [[ ! -f "${LOG_FILE}" ]]; then
        return 0
    fi
    
    local log_size_mb
    log_size_mb=$(stat -f%z "${LOG_FILE}" 2>/dev/null || stat -c%s "${LOG_FILE}" 2>/dev/null || echo "0")
    log_size_mb=$((log_size_mb / 1024 / 1024))
    
    if [[ ${log_size_mb} -gt ${MAX_LOG_SIZE_MB} ]]; then
        # Rotiere Log
        local backup_log="${LOG_FILE}.$(date +%Y%m%d)"
        mv "${LOG_FILE}" "${backup_log}"
        touch "${LOG_FILE}"
        chmod 644 "${LOG_FILE}"
        
        # Komprimiere alte Logs
        gzip "${backup_log}" 2>/dev/null || true
        
        # Entferne Logs älter als 30 Tage
        find "$(dirname "${LOG_FILE}")" -name "globalping-install.log.*.gz" -mtime +30 -delete 2>/dev/null || true
        
        enhanced_log "INFO" "Log-Datei rotiert (${log_size_mb}MB -> 0MB)"
    fi
}

# Install sudo
install_sudo() {
    log "Prüfe sudo-Installation"
    
    if command -v sudo >/dev/null 2>&1; then
        log "sudo ist bereits installiert"
        return 0
    fi
    
    log "Installiere sudo"
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 || true
        apt-get install -y sudo >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y sudo >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y sudo >/dev/null 2>&1
    else
        enhanced_log "WARN" "Kein unterstützter Paketmanager für sudo-Installation gefunden"
        return 1
    fi
    
    return $?
}

# Configure hostname
configure_hostname() {
    log "Konfiguriere Hostname"
    
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current_hostname
        current_hostname=$(hostname 2>/dev/null || echo "")
        
        if [[ "${current_hostname}" != "${HOSTNAME_NEW}" ]]; then
            log "Setze Hostname auf: ${HOSTNAME_NEW}"
            
            # Setze temporären Hostname
            hostname "${HOSTNAME_NEW}" 2>/dev/null || true
            
            # Persistiere Hostname
            echo "${HOSTNAME_NEW}" > /etc/hostname 2>/dev/null || true
            
            # Aktualisiere /etc/hosts
            if [[ -f /etc/hosts ]]; then
                sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
                
                # Füge Eintrag hinzu falls nicht vorhanden
                if ! grep -q "127.0.1.1.*${HOSTNAME_NEW}" /etc/hosts; then
                    echo "127.0.1.1 ${HOSTNAME_NEW}" >> /etc/hosts
                fi
            fi
            
            log "Hostname konfiguriert: ${HOSTNAME_NEW}"
        else
            log "Hostname bereits korrekt gesetzt: ${current_hostname}"
        fi
    else
        log "Kein gültiger Hostname verfügbar, verwende aktuellen"
    fi
    
    return 0
}

# Ubuntu Pro Aktivierung
ubuntu_pro_attach() {
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        enhanced_log "INFO" "Aktiviere Ubuntu Pro mit Token"
        
        # Ubuntu Advantage Tools installieren
        if ! command -v ua >/dev/null 2>&1; then
            apt-get update >/dev/null 2>&1 || true
            apt-get install -y ubuntu-advantage-tools >/dev/null 2>&1 || {
                enhanced_log "ERROR" "Konnte ubuntu-advantage-tools nicht installieren"
                return 1
            }
        fi

        # Token anwenden
        if ua attach "${UBUNTU_PRO_TOKEN}" >/dev/null 2>&1; then
            enhanced_log "INFO" "Ubuntu Pro Token erfolgreich aktiviert"
            
            # ESM und Sicherheitsupdates aktivieren
            ua enable esm-apps >/dev/null 2>&1 || true
            ua enable esm-infra >/dev/null 2>&1 || true
            ua enable livepatch >/dev/null 2>&1 || true
            
            # System aktualisieren
            apt-get update >/dev/null 2>&1 || true
            apt-get upgrade -y >/dev/null 2>&1 || true
            
            enhanced_log "INFO" "Ubuntu Pro mit ESM/Livepatch aktiviert"
            return 0
        else
            enhanced_log "ERROR" "Ubuntu Pro Token-Aktivierung fehlgeschlagen"
            return 1
        fi
    else
        enhanced_log "INFO" "Ubuntu Pro nicht anwendbar (kein Ubuntu oder Token)"
        return 0
    fi
}

# SSH-Schlüssel einrichten
setup_ssh_key() {
    enhanced_log "INFO" "Richte SSH-Schlüssel ein"
    
    if [[ ! -d "${SSH_DIR}" ]]; then
        mkdir -p "${SSH_DIR}" || {
            enhanced_log "ERROR" "Konnte SSH-Verzeichnis nicht erstellen"
            return 1
        }
        chmod 700 "${SSH_DIR}"
    fi
    
    if [[ -n "${SSH_KEY}" ]]; then
        # Prüfe, ob der Schlüssel bereits existiert
        if [[ -f "${SSH_DIR}/authorized_keys" ]] && grep -Fq "${SSH_KEY}" "${SSH_DIR}/authorized_keys"; then
            enhanced_log "INFO" "SSH-Schlüssel bereits vorhanden"
            return 0
        fi
        
        # Validiere SSH-Schlüssel-Format
        if ! echo "${SSH_KEY}" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-)"; then
            enhanced_log "ERROR" "Ungültiges SSH-Schlüssel-Format"
            return 1
        fi
        
        # Füge Schlüssel hinzu
        echo "${SSH_KEY}" >> "${SSH_DIR}/authorized_keys" || {
            enhanced_log "ERROR" "Konnte SSH-Schlüssel nicht hinzufügen"
            return 1
        }
        chmod 600 "${SSH_DIR}/authorized_keys"
        enhanced_log "INFO" "SSH-Schlüssel erfolgreich hinzugefügt"
        return 0
    else
        enhanced_log "INFO" "Kein SSH-Schlüssel angegeben"
        return 0
    fi
}

# KORRIGIERTE Abhängigkeiten installieren (mit unzip und weiteren Tools)
install_dependencies() {
    enhanced_log "INFO" "Installiere Systemabhängigkeiten"
    
    # Erkenne Distribution
    local is_debian_based=false
    local is_rhel_based=false
    
    if [[ -f /etc/debian_version ]] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    # ERWEITERTE Liste der zu prüfenden Befehle
    local required_cmds=("curl" "wget" "grep" "sed" "awk" "bc" "unzip" "tar" "gzip" "find" "xargs")
    local missing_cmds=()
    
    # Prüfe, welche Befehle fehlen
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing_cmds+=("${cmd}")
        fi
    done
    
    # Wenn alle Befehle vorhanden sind, überspringe Installation
    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        enhanced_log "INFO" "Alle benötigten Abhängigkeiten sind bereits installiert"
        return 0
    fi
    
    enhanced_log "INFO" "Installiere fehlende Abhängigkeiten: ${missing_cmds[*]}"
    
    if [[ "${is_debian_based}" == "true" ]] && command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu - ERWEITERTE Paketliste
        apt-get update >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get update fehlgeschlagen"
        }
        apt-get install -y \
            curl wget awk sed grep coreutils bc \
            unzip tar gzip bzip2 xz-utils \
            findutils lsb-release iproute2 \
            systemd procps psmisc \
            ca-certificates gnupg \
            software-properties-common \
            apt-transport-https >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Konnte Abhängigkeiten nicht installieren"
            return 1
        }
    elif [[ "${is_rhel_based}" == "true" ]]; then
        if command -v dnf >/dev/null 2>&1; then
            # RHEL/CentOS/Rocky/Alma mit DNF
            dnf install -y \
                curl wget gawk sed grep coreutils bc \
                unzip tar gzip bzip2 xz \
                findutils redhat-lsb-core iproute \
                systemd procps-ng psmisc \
                ca-certificates gnupg2 \
                dnf-plugins-core >/dev/null 2>&1 || {
                enhanced_log "ERROR" "Konnte Abhängigkeiten nicht installieren"
                return 1
            }
        elif command -v yum >/dev/null 2>&1; then
            # Ältere RHEL/CentOS mit YUM
            yum install -y \
                curl wget gawk sed grep coreutils bc \
                unzip tar gzip bzip2 xz \
                findutils redhat-lsb-core iproute \
                systemd procps-ng psmisc \
                ca-certificates gnupg2 \
                yum-utils >/dev/null 2>&1 || {
                enhanced_log "ERROR" "Konnte Abhängigkeiten nicht installieren"
                return 1
            }
        else
            enhanced_log "ERROR" "Kein unterstützter Paketmanager gefunden"
            return 1
        fi
    else
        enhanced_log "WARN" "Unbekannte Distribution, überspringe Abhängigkeiten-Installation"
    fi
    
    # Verifiziere Installation der kritischen Tools
    local verification_failed=false
    for cmd in "curl" "unzip" "tar"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            enhanced_log "ERROR" "Kritisches Tool '${cmd}' konnte nicht installiert werden"
            verification_failed=true
        fi
    done
    
    if [[ "${verification_failed}" == "true" ]]; then
        enhanced_log "ERROR" "Installation kritischer Abhängigkeiten fehlgeschlagen"
        return 1
    fi
    
    enhanced_log "INFO" "Systemabhängigkeiten erfolgreich installiert"
    return 0
}

# Systemaktualisierung
update_system() {
    enhanced_log "INFO" "Führe Systemaktualisierung durch"
    
    # Erkenne Distribution
    local is_debian_based=false
    local is_rhel_based=false
    
    if [[ -f /etc/debian_version ]] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    if [[ "${is_debian_based}" == "true" ]] && command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get update fehlgeschlagen"
        }
        apt-get upgrade -y >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get upgrade fehlgeschlagen"
        }
    elif [[ "${is_rhel_based}" == "true" ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf update -y >/dev/null 2>&1 || {
                enhanced_log "WARN" "dnf update fehlgeschlagen"
            }
        elif command -v yum >/dev/null 2>&1; then
            yum update -y >/dev/null 2>&1 || {
                enhanced_log "WARN" "yum update fehlgeschlagen"
            }
        else
            enhanced_log "WARN" "Kein unterstützter Paketmanager gefunden"
        fi
    else
        enhanced_log "WARN" "Unbekannte Distribution, überspringe Systemaktualisierung"
    fi
    
    enhanced_log "INFO" "Systemaktualisierung abgeschlossen"
    return 0
}

# [Der Rest der Funktionen bleibt unverändert wie im vorherigen Skript...]
# Füge hier die restlichen Funktionen aus dem vorherigen korrigierten Skript ein

# Erweiterte Hilfefunktion mit Telegram-Test
show_enhanced_help() {
    cat << 'HELP_EOF'
==========================================
Globalping Server-Setup-Skript (Enhanced)
==========================================

BESCHREIBUNG:
    Erweiterte Automatisierung für Globalping-Probe Server mit
    intelligenter Wartung, erweiterten Benachrichtigungen und
    robusten Fehlerbehandlungen.

VERWENDUNG:
    ./install.sh [OPTIONEN]
    
    Das Skript muss mit Root-Rechten ausgeführt werden.

HAUPTOPTIONEN:
    -h, --help                      Zeigt diese Hilfe an
    --adoption-token TOKEN          Globalping Adoption-Token (erforderlich)
    --telegram-token TOKEN          Telegram-Bot-Token für Benachrichtigungen
    --telegram-chat ID              Telegram-Chat-ID für Benachrichtigungen
    --ubuntu-token TOKEN            Ubuntu Pro Token (nur für Ubuntu)
    --ssh-key "SCHLÜSSEL"           SSH Public Key für sicheren Zugang

WARTUNGS-OPTIONEN:
    --auto-weekly                   Wöchentliche automatische Wartung (intern)
    --cleanup                       Erweiterte Systemreinigung
    --emergency-cleanup             Aggressive Notfall-Bereinigung  
    --diagnose                      Vollständige Systemdiagnose
    --network-diagnose              Detaillierte Netzwerk-Diagnose
    --test-telegram                 Teste Telegram-Konfiguration

ERWEITERTE OPTIONEN:
    -d, --docker                    Installiert nur Docker
    -l, --log DATEI                 Alternative Log-Datei
    --debug                         Debug-Modus mit ausführlichem Logging
    --force                         Überspringt Sicherheitsabfragen
    --no-reboot                     Verhindert automatische Reboots

TELEGRAM-KONFIGURATION:
    1. Erstelle einen Bot: @BotFather
    2. Erhalte Token und Chat-ID
    3. Teste mit: ./install.sh --test-telegram --telegram-token "TOKEN" --telegram-chat "CHAT_ID"

NEUE FEATURES:
    ✓ Verbesserte Telegram-Benachrichtigungen mit Debugging
    ✓ Erweiterte Abhängigkeiten (unzip, tar, gzip, etc.)
    ✓ Intelligente Swap-Konfiguration (RAM + Swap ≥ 1GB)
    ✓ Automatische Reboots bei kritischen Updates
    ✓ Absolute Speicherplatz-Schwellwerte (1.5GB minimum)
    ✓ CPU-Hang-Schutz durch Timeouts
    ✓ restart=always für Globalping-Container
    ✓ Tägliche Log-Rotation (max 50MB)
    ✓ Wöchentliche automatische Wartung

SYSTEMANFORDERUNGEN:
    - Linux (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora)
    - Mindestens 256MB RAM
    - Mindestens 1.5GB freier Speicherplatz
    - Root-Rechte oder sudo-Zugang
    - Internetverbindung

BEISPIELE:
    # Vollständige Installation
    ./install.sh --adoption-token "token" \
                  --telegram-token "bot-token" \
                  --telegram-chat "chat-id"

    # Teste Telegram-Konfiguration
    ./install.sh --test-telegram --telegram-token "123:ABC" --telegram-chat "456"

    # Nur Diagnose
    ./install.sh --diagnose

    # Systemreinigung
    ./install.sh --cleanup

HELP_EOF
    exit 0
}

# Erweiterte Argumentverarbeitung mit Telegram-Test
process_enhanced_args() {
    # Standardwerte
    local install_docker_only="false"
    local run_diagnostics_only="false"
    local run_network_diagnostics_only="false"
    local auto_weekly_mode="false"
    local cleanup_mode="false"
    local emergency_cleanup_mode="false"
    local force_mode="false"
    local no_reboot="false"
    local test_telegram_mode="false"
    
    # Keine Argumente = Hilfe
    if [[ $# -eq 0 ]]; then
        show_enhanced_help
    fi
    
    # Argumente verarbeiten
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_enhanced_help
                ;;
            -d|--docker)
                install_docker_only="true"
                shift
                ;;
            -l|--log)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    LOG_FILE="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--log benötigt einen Dateinamen"
                    exit 1
                fi
                ;;
            --debug)
                enable_enhanced_debug_mode
                shift
                ;;
            --force)
                force_mode="true"
                shift
                ;;
            --no-reboot)
                no_reboot="true"
                shift
                ;;
            --auto-weekly)
                auto_weekly_mode="true"
                WEEKLY_MODE="true"
                shift
                ;;
            --test-telegram)
                test_telegram_mode="true"
                shift
                ;;
            --adoption-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    ADOPTION_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--adoption-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-chat)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_CHAT="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-chat benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ubuntu-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    UBUNTU_PRO_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ubuntu-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ssh-key)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    SSH_KEY="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ssh-key benötigt einen Wert"
                    exit 1
                fi
                ;;
            --cleanup)
                cleanup_mode="true"
                shift
                ;;
            --emergency-cleanup)
                emergency_cleanup_mode="true"
                shift
                ;;
            --diagnose)
                run_diagnostics_only="true"
                shift
                ;;
            --network-diagnose)
                run_network_diagnostics_only="true"
                shift
                ;;
            -*)
                enhanced_log "ERROR" "Unbekannte Option: $1"
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
            *)
                enhanced_log "ERROR" "Unerwartetes Argument: $1"
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
        esac
    done
    
    # Telegram-Test-Modus
    if [[ "${test_telegram_mode}" == "true" ]]; then
        execute_telegram_test_mode
        exit $?
    fi
    
    # Validiere und führe spezielle Modi aus
    execute_enhanced_special_modes \
        "${install_docker_only}" \
        "${run_diagnostics_only}" \
        "${run_network_diagnostics_only}" \
        "${auto_weekly_mode}" \
        "${cleanup_mode}" \
        "${emergency_cleanup_mode}" \
        "${force_mode}" \
        "${no_reboot}"
}

# Telegram-Test-Modus
execute_telegram_test_mode() {
    echo "=== TELEGRAM-KONFIGURATION TEST ==="
    echo "Teste Telegram-Token und Chat-ID..."
    echo "===================================="
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        echo "FEHLER: --telegram-token und --telegram-chat sind erforderlich"
        echo "Beispiel: ./install.sh --test-telegram --telegram-token \"123:ABC\" --telegram-chat \"456\""
        return 1
    fi
    
    # Basis-Systeminformationen sammeln für Test
    get_enhanced_system_info
    
    # Führe Test durch
    if test_telegram_config; then
        echo "✅ Telegram-Konfiguration erfolgreich getestet!"
        echo "Bot kann Nachrichten an Chat ${TELEGRAM_CHAT} senden."
        return 0
    else
        echo "❌ Telegram-Konfiguration fehlgeschlagen!"
        echo "Prüfe Token und Chat-ID."
        return 1
    fi
}

# Basis-Systeminformationen sammeln
get_system_info() {
    enhanced_log "INFO" "Sammle Basis-Systeminformationen"
    
    # Diese Funktion wird durch get_enhanced_system_info ersetzt/erweitert
    # Hier für Kompatibilität
    get_enhanced_system_info
    return 0
}

# Architektur erkennen
detect_architecture() {
    enhanced_log "INFO" "Erkenne System-Architektur"
    
    local arch
    arch=$(uname -m)
    local is_arm=false
    local is_raspberry_pi=false
    
    case "${arch}" in
        arm*|aarch*)
            is_arm=true
            enhanced_log "INFO" "ARM-Architektur erkannt: ${arch}"
            ;;
        x86_64|amd64)
            enhanced_log "INFO" "x86_64-Architektur erkannt"
            ;;
        *)
            enhanced_log "WARN" "Unbekannte Architektur: ${arch}"
            ;;
    esac
    
    # Für Raspberry Pi spezifische Erkennung
    if [[ "${is_arm}" == "true" ]] && [[ -f /proc/device-tree/model ]] && grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
        is_raspberry_pi=true
        local pi_model
        pi_model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "Raspberry Pi")
        enhanced_log "INFO" "Raspberry Pi erkannt: ${pi_model}"
        
        # Optimierungen für Raspberry Pi
        optimize_for_raspberry_pi
    fi
    
    # Exportiere Variablen für andere Funktionen
    export ARCH="${arch}"
    export IS_ARM="${is_arm}"
    export IS_RASPBERRY_PI="${is_raspberry_pi}"
    
    return 0
}

# Raspberry Pi-Optimierungen
optimize_for_raspberry_pi() {
    enhanced_log "INFO" "Führe Raspberry Pi-spezifische Optimierungen durch"
    
    # Swap-Optimierung für SD-Karten
    if [[ -f /etc/dphys-swapfile ]]; then
        enhanced_log "INFO" "Optimiere Swap-Einstellungen für Raspberry Pi"
        cp /etc/dphys-swapfile /etc/dphys-swapfile.backup 2>/dev/null || true
        
        # Weniger häufige Swap-Nutzung
        if ! grep -q "CONF_SWAPPINESS" /etc/dphys-swapfile; then
            echo "CONF_SWAPPINESS=10" >> /etc/dphys-swapfile
        fi
        
        # Restart Swap-Service
        systemctl restart dphys-swapfile >/dev/null 2>&1 || true
    fi
    
    # GPU-Speicher für Headless-Betrieb optimieren
    if [[ -f /boot/config.txt ]]; then
        enhanced_log "INFO" "Konfiguriere GPU-Speicher für Headless-Betrieb"
        if ! grep -q "^gpu_mem=" /boot/config.txt; then
            echo "gpu_mem=16" >> /boot/config.txt
        fi
    elif [[ -f /boot/firmware/config.txt ]]; then
        # Neuere Raspberry Pi OS Versionen
        if ! grep -q "^gpu_mem=" /boot/firmware/config.txt; then
            echo "gpu_mem=16" >> /boot/firmware/config.txt
        fi
    fi
    
    enhanced_log "INFO" "Raspberry Pi-Optimierungen abgeschlossen"
    return 0
}

# Erweiterte Systemvalidierung
enhanced_validate_system() {
    log "Führe erweiterte Systemvalidierung durch"
    
    local errors=()
    local warnings=()
    
    # RAM prüfen
    local mem_kb mem_mb
    mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_mb=$((mem_kb / 1024))
    
    if [[ ${mem_mb} -lt ${MIN_RAM_MB} ]]; then
        errors+=("Zu wenig RAM: ${mem_mb}MB (Minimum: ${MIN_RAM_MB}MB)")
    elif [[ ${mem_mb} -lt 512 ]]; then
        warnings+=("Wenig RAM: ${mem_mb}MB - Performance könnte eingeschränkt sein")
    fi
    
    # Freien Speicherplatz prüfen (absolut und prozentual)
    local disk_available_kb disk_available_gb disk_usage_percent
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_available_gb=$(echo "scale=1; ${disk_available_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    disk_usage_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "100")
    
    if (( $(echo "${disk_available_gb} < ${MIN_FREE_SPACE_GB}" | bc -l 2>/dev/null || echo "1") )); then
        errors+=("Zu wenig freier Speicherplatz: ${disk_available_gb}GB (Minimum: ${MIN_FREE_SPACE_GB}GB)")
    elif [[ ${disk_usage_percent} -gt 85 ]]; then
        warnings+=("Festplatte zu ${disk_usage_percent}% voll (${disk_available_gb}GB frei)")
    fi
    
    # Ausgabe der Validierung
    if [[ ${#errors[@]} -gt 0 ]]; then
        enhanced_log "ERROR" "Kritische Systemanforderungen nicht erfüllt:"
        for error in "${errors[@]}"; do
            enhanced_log "ERROR" "  ${error}"
        done
        
        enhanced_notify "error" "Systemvalidierung" "Kritische Anforderungen nicht erfüllt:
$(printf '%s\n' "${errors[@]}")"
        
        return 1
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        enhanced_log "WARN" "Systemanforderungen-Warnungen:"
        for warning in "${warnings[@]}"; do
            enhanced_log "WARN" "  ${warning}"
        done
    fi
    
    log "Systemvalidierung erfolgreich (RAM: ${mem_mb}MB, Frei: ${disk_available_gb}GB)"
    return 0
}

# Intelligente Swap-Konfiguration
configure_smart_swap() {
    log "Prüfe und konfiguriere Swap-Speicher"
    
    # Aktuelle Swap-Nutzung prüfen
    local swap_total_kb swap_total_mb
    swap_total_kb=$(grep "SwapTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    swap_total_mb=$((swap_total_kb / 1024))
    
    if [[ ${swap_total_mb} -gt 0 ]]; then
        log "Swap bereits konfiguriert: ${swap_total_mb}MB"
        return 0
    fi
    
    # Gesamte Festplattengröße prüfen
    local disk_total_kb disk_total_gb
    disk_total_kb=$(df / | awk 'NR==2 {print $2}' || echo "0")
    disk_total_gb=$(echo "scale=1; ${disk_total_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    
    if (( $(echo "${disk_total_gb} < ${MIN_DISK_FOR_SWAP_GB}" | bc -l 2>/dev/null || echo "1") )); then
        log "Festplatte zu klein für Swap: ${disk_total_gb}GB (Minimum: ${MIN_DISK_FOR_SWAP_GB}GB)"
        return 0
    fi
    
    # RAM-Größe ermitteln
    local mem_kb mem_mb
    mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_mb=$((mem_kb / 1024))
    
    # Berechne benötigte Swap-Größe
    local target_total_mb swap_size_mb
    target_total_mb=$((SWAP_MIN_TOTAL_GB * 1024))
    
    if [[ ${mem_mb} -lt ${target_total_mb} ]]; then
        swap_size_mb=$((target_total_mb - mem_mb))
    else
        log "RAM (${mem_mb}MB) ist bereits ausreichend, kein Swap erforderlich"
        return 0
    fi
    
    # Begrenze Swap-Größe auf maximal 2GB
    if [[ ${swap_size_mb} -gt 2048 ]]; then
        swap_size_mb=2048
    fi
    
    log "Erstelle ${swap_size_mb}MB Swap-Datei"
    
    # Erstelle Swap-Datei
    local swap_file="/swapfile"
    
    if ! dd if=/dev/zero of="${swap_file}" bs=1M count="${swap_size_mb}" 2>/dev/null; then
        enhanced_log "ERROR" "Konnte Swap-Datei nicht erstellen"
        return 1
    fi
    
    chmod 600 "${swap_file}"
    
    if ! mkswap "${swap_file}" >/dev/null 2>&1; then
        enhanced_log "ERROR" "Konnte Swap-Datei nicht formatieren"
        rm -f "${swap_file}"
        return 1
    fi
    
    if ! swapon "${swap_file}"; then
        enhanced_log "ERROR" "Konnte Swap-Datei nicht aktivieren"
        rm -f "${swap_file}"
        return 1
    fi
    
    # Dauerhaft in /etc/fstab eintragen
    if ! grep -q "${swap_file}" /etc/fstab 2>/dev/null; then
        echo "${swap_file} none swap sw 0 0" >> /etc/fstab
    fi
    
    # Swap-Verhalten optimieren
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
    sysctl vm.swappiness=10 >/dev/null 2>&1 || true
    
    log "Swap erfolgreich konfiguriert: ${swap_size_mb}MB"
    return 0
}

# Prüfung auf kritische Updates und Reboot-Notwendigkeit (KORRIGIERT)
check_critical_updates() {
    log "Prüfe auf kritische Updates"
    
    local needs_reboot=false
    
    # Für Debian/Ubuntu
    if command -v apt-get >/dev/null 2>&1; then
        # Aktualisiere Paketlisten
        if ! timeout "${TIMEOUT_PACKAGE}" apt-get update >/dev/null 2>&1; then
            enhanced_log "WARN" "apt-get update fehlgeschlagen"
            return 0
        fi
        
        # Prüfe auf Kernel-Updates - KORRIGIERT
        local kernel_updates
        kernel_updates=$(apt list --upgradable 2>/dev/null | grep -c "linux-image\|linux-generic\|linux-headers" || echo "0")
        # Bereinige Output - entferne Newlines und Carriage Returns
        kernel_updates=$(echo "${kernel_updates}" | tr -d '\n\r' | awk '{print $1}')
        
        if [[ "${kernel_updates}" -gt 0 ]] 2>/dev/null; then
            log "Kernel-Updates gefunden: ${kernel_updates}"
            needs_reboot=true
        fi
        
        # Prüfe auf kritische System-Updates - KORRIGIERT
        local critical_updates
        critical_updates=$(apt list --upgradable 2>/dev/null | grep -c "systemd\|libc6\|openssh\|glibc" || echo "0")
        # Bereinige Output - entferne Newlines und Carriage Returns
        critical_updates=$(echo "${critical_updates}" | tr -d '\n\r' | awk '{print $1}')
        
        if [[ "${critical_updates}" -gt 0 ]] 2>/dev/null; then
            log "Kritische System-Updates gefunden: ${critical_updates}"
            needs_reboot=true
        fi
        
        # Führe Updates durch
        if [[ "${kernel_updates}" -gt 0 ]] 2>/dev/null || [[ "${critical_updates}" -gt 0 ]] 2>/dev/null; then
            log "Installiere kritische Updates..."
            if timeout "${TIMEOUT_PACKAGE}" apt-get upgrade -y >/dev/null 2>&1; then
                log "Updates erfolgreich installiert"
            else
                enhanced_log "ERROR" "Update-Installation fehlgeschlagen"
                return 1
            fi
        fi
        
    # Für RHEL/CentOS/Fedora
    elif command -v dnf >/dev/null 2>&1; then
        local kernel_updates
        kernel_updates=$(dnf check-update kernel* 2>/dev/null | grep -c "kernel" || echo "0")
        kernel_updates=$(echo "${kernel_updates}" | tr -d '\n\r' | awk '{print $1}')
        
        if [[ "${kernel_updates}" -gt 0 ]] 2>/dev/null; then
            log "Kernel-Updates gefunden, installiere..."
            if timeout "${TIMEOUT_PACKAGE}" dnf update -y kernel* >/dev/null 2>&1; then
                needs_reboot=true
            fi
        fi
        
        # Kritische Updates
        if timeout "${TIMEOUT_PACKAGE}" dnf update -y systemd glibc openssh* >/dev/null 2>&1; then
            log "Kritische Updates installiert"
            needs_reboot=true
        fi
        
    elif command -v yum >/dev/null 2>&1; then
        if timeout "${TIMEOUT_PACKAGE}" yum update -y kernel* systemd glibc openssh* >/dev/null 2>&1; then
            needs_reboot=true
        fi
    fi
    
    # Prüfe, ob /var/run/reboot-required existiert (Ubuntu)
    if [[ -f /var/run/reboot-required ]]; then
        needs_reboot=true
    fi
    
    if [[ "${needs_reboot}" == "true" ]]; then
        log "Reboot nach Updates erforderlich"
        REBOOT_REQUIRED="true"
        
        # Schedule Reboot mit Cleanup
        schedule_reboot_with_cleanup
    else
        log "Keine kritischen Updates oder Reboot erforderlich"
    fi
    
    return 0
}

# Plane Reboot mit nachfolgender Bereinigung
schedule_reboot_with_cleanup() {
    log "Plane Reboot mit automatischer Bereinigung"
    
    # Erstelle Post-Reboot-Skript
    local post_reboot_script="/usr/local/bin/post-reboot-cleanup"
    
    cat > "${post_reboot_script}" << 'EOF'
#!/bin/bash
# Post-Reboot Cleanup Script

LOG_FILE="/var/log/globalping-install.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [POST-REBOOT] $1" >> "${LOG_FILE}"
}

log "Starte Post-Reboot-Bereinigung"

# Warte bis System vollständig gestartet ist
sleep 30

# Führe Bereinigung durch
if [[ -x "/usr/local/bin/install_globalping.sh" ]]; then
    /usr/local/bin/install_globalping.sh --cleanup >> "${LOG_FILE}" 2>&1
    log "Post-Reboot-Bereinigung abgeschlossen"
else
    log "Cleanup-Skript nicht gefunden"
fi

# Entferne diesen Service nach Ausführung
systemctl disable post-reboot-cleanup.service 2>/dev/null || true
rm -f /etc/systemd/system/post-reboot-cleanup.service
rm -f /usr/local/bin/post-reboot-cleanup

log "Post-Reboot-Service entfernt"
EOF
    
    chmod +x "${post_reboot_script}"
    
    # Erstelle Systemd-Service für Post-Reboot
    cat > "/etc/systemd/system/post-reboot-cleanup.service" << EOF
[Unit]
Description=Post-Reboot Cleanup
After=multi-user.target
Wants=multi-user.target

[Service]
Type=oneshot
ExecStart=${post_reboot_script}
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable post-reboot-cleanup.service
    
    log "Post-Reboot-Service konfiguriert"
    
    # Plane Reboot in 2 Minuten
    log "System wird in 2 Minuten neu gestartet..."
    shutdown -r +2 "System-Reboot nach kritischen Updates" &
    
    enhanced_notify "error" "System-Reboot" "System wird nach kritischen Updates neu gestartet.
Post-Reboot-Bereinigung ist geplant."
}

# Verbesserte Globalping-Probe Installation mit restart=always
install_enhanced_globalping_probe() {
    log "Installiere erweiterte Globalping-Probe mit restart=always"
    
    # Validiere Voraussetzungen
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "ERROR" "Kein Adoption-Token angegeben"
        enhanced_notify "error" "Konfigurationsfehler" "Globalping-Probe: Kein Adoption-Token angegeben"
        return 1
    fi
    
    # Docker-Installation prüfen
    if ! command -v docker >/dev/null 2>&1; then
        log "Docker wird für Globalping-Probe benötigt"
        if ! install_docker; then
            enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
            enhanced_notify "error" "Docker-Installation" "Docker konnte nicht installiert werden"
            return 1
        fi
    fi
    
    # Prüfe bestehende Container
    local existing_container
    existing_container=$(docker ps -a --format "{{.Names}}" | grep -i globalping | head -1 || echo "")
    
    if [[ -n "${existing_container}" ]]; then
        log "Bestehender Globalping-Container gefunden: ${existing_container}"
        
        # Prüfe Token
        local current_token
        current_token=$(docker inspect "${existing_container}" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}' 2>/dev/null || echo "")
        
        if [[ "${current_token}" == "${ADOPTION_TOKEN}" ]]; then
            log "Container verwendet bereits den richtigen Token"
            
            # Update Container mit restart=always
            update_globalping_container_restart_policy "${existing_container}"
            return 0
        else
            log "Container verwendet falschen Token, entferne..."
            docker stop "${existing_container}" >/dev/null 2>&1 || true
            docker rm "${existing_container}" >/dev/null 2>&1 || true
        fi
    fi
    
    # Erstelle Arbeitsverzeichnis
    local globalping_dir="/opt/globalping"
    mkdir -p "${globalping_dir}"
    cd "${globalping_dir}" || return 1
    
    # Erweiterte Docker Compose-Konfiguration
    create_enhanced_globalping_compose "${globalping_dir}"
    
    # Starte Globalping-Probe
    if ! start_enhanced_globalping_probe "${globalping_dir}"; then
        enhanced_log "ERROR" "Globalping-Probe-Start fehlgeschlagen"
        enhanced_notify "error" "Globalping-Probe" "Container konnte nicht gestartet werden"
        return 1
    fi
    
    # Verifiziere Installation
    if ! verify_enhanced_globalping_probe; then
        enhanced_log "ERROR" "Globalping-Probe-Verifikation fehlgeschlagen"
        enhanced_notify "error" "Globalping-Probe" "Container-Verifikation fehlgeschlagen"
        return 1
    fi
    
    # Erstelle erweiterte Wartung
    create_enhanced_globalping_maintenance
    
    log "Erweiterte Globalping-Probe erfolgreich installiert"
    return 0
}

# Update bestehender Container Restart-Policy
update_globalping_container_restart_policy() {
    local container_name="$1"
    
    log "Aktualisiere Restart-Policy für ${container_name}"
    
    # Prüfe aktuelle Restart-Policy
    local current_policy
    current_policy=$(docker inspect "${container_name}" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null || echo "")
    
    if [[ "${current_policy}" == "always" ]]; then
        log "Restart-Policy bereits auf 'always' gesetzt"
        return 0
    fi
    
    # Update Container mit neuer Policy
    if docker update --restart=always "${container_name}" >/dev/null 2>&1; then
        log "Restart-Policy erfolgreich auf 'always' aktualisiert"
    else
        enhanced_log "WARN" "Konnte Restart-Policy nicht aktualisieren, starte Container neu"
        
        # Fallback: Container neu erstellen
        docker stop "${container_name}" >/dev/null 2>&1 || true
        docker rm "${container_name}" >/dev/null 2>&1 || true
        
        # Neu erstellen mit restart=always
        start_enhanced_globalping_probe "/opt/globalping"
    fi
}

# Erweiterte Docker Compose-Konfiguration
create_enhanced_globalping_compose() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Erstelle erweiterte Docker Compose-Konfiguration"
    
    cat > "${compose_file}" << EOF
version: '3.8'

services:
  globalping-probe:
    image: ghcr.io/jsdelivr/globalping-probe:latest
    container_name: globalping-probe
    restart: always
    environment:
      - ADOPTION_TOKEN=${ADOPTION_TOKEN}
      - NODE_ENV=production
    volumes:
      - probe-data:/home/node/.globalping
      - /etc/localtime:/etc/localtime:ro
    network_mode: host
    logging:
      driver: "json-file"
      options:
        max-size: "${MAX_LOG_SIZE_MB}m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "node", "healthcheck.js"]
      interval: 60s
      timeout: 30s
      retries: 3
      start_period: 120s
    security_opt:
      - no-new-privileges:true
    read_only: false
    tmpfs:
      - /tmp
    ulimits:
      nproc: 65535
      nofile:
        soft: 65535
        hard: 65535

volumes:
  probe-data:
    driver: local
EOF
    
    log "Erweiterte Docker Compose-Konfiguration erstellt"
    return 0
}

# Erweiterte Globalping-Probe-Start
start_enhanced_globalping_probe() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Starte erweiterte Globalping-Probe"
    
    cd "${globalping_dir}" || return 1
    
    # Ziehe neuestes Image mit Timeout
    log "Lade neuestes Globalping-Probe Image..."
    if ! docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        enhanced_log "WARN" "Konnte neuestes Image nicht laden, verwende lokales"
    fi
    
    # Starte mit Docker Compose
    if command -v docker-compose >/dev/null 2>&1; then
        if ! docker-compose -f "${compose_file}" up -d; then
            enhanced_log "ERROR" "Docker Compose-Start fehlgeschlagen"
            return 1
        fi
    elif docker compose version >/dev/null 2>&1; then
        if ! docker compose -f "${compose_file}" up -d; then
            enhanced_log "ERROR" "Docker Compose-Start fehlgeschlagen"
            return 1
        fi
    else
        # Fallback: docker run mit erweiterten Optionen
        enhanced_log "WARN" "Docker Compose nicht verfügbar, verwende docker run"
        
        # Entferne eventuell vorhandenen Container
        docker stop globalping-probe >/dev/null 2>&1 || true
        docker rm globalping-probe >/dev/null 2>&1 || true
        
        # Erstelle Volume
        docker volume create globalping-probe-data >/dev/null 2>&1 || true
        
        # Starte mit erweiterten Optionen
        if ! docker run -d \
            --name globalping-probe \
            --restart always \
            --network host \
            --log-driver json-file \
            --log-opt max-size="${MAX_LOG_SIZE_MB}m" \
            --log-opt max-file=3 \
            --security-opt no-new-privileges:true \
            --tmpfs /tmp \
            --ulimit nproc=65535 \
            --ulimit nofile=65535:65535 \
            -e "ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
            -e "NODE_ENV=production" \
            -v globalping-probe-data:/home/node/.globalping \
            -v /etc/localtime:/etc/localtime:ro \
            ghcr.io/jsdelivr/globalping-probe:latest; then
            enhanced_log "ERROR" "Container-Start mit docker run fehlgeschlagen"
            return 1
        fi
    fi
    
    log "Erweiterte Globalping-Probe erfolgreich gestartet"
    return 0
}

# Erweiterte Verifikation
verify_enhanced_globalping_probe() {
    log "Verifiziere erweiterte Globalping-Probe"
    
    # Warte auf Container-Start
    local wait_count=0
    local max_wait=60
    
    while [[ ${wait_count} -lt ${max_wait} ]]; do
        if docker ps --format "{{.Names}}" | grep -q "^globalping-probe$"; then
            break
        fi
        sleep 2
        ((wait_count++))
    done
    
    if [[ ${wait_count} -ge ${max_wait} ]]; then
        enhanced_log "ERROR" "Container nicht gestartet nach ${max_wait} Sekunden"
        return 1
    fi
    
    # Prüfe Container-Status
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' globalping-probe 2>/dev/null || echo "unknown")
    
    if [[ "${container_status}" != "running" ]]; then
        enhanced_log "ERROR" "Container-Status nicht 'running': ${container_status}"
        enhanced_log "ERROR" "Container-Logs:"
        docker logs globalping-probe 2>&1 | tail -10 | while IFS= read -r line; do
            enhanced_log "ERROR" "  ${line}"
        done
        return 1
    fi
    
    # Prüfe Restart-Policy
    local restart_policy
    restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' globalping-probe 2>/dev/null || echo "")
    
    if [[ "${restart_policy}" != "always" ]]; then
        enhanced_log "WARN" "Restart-Policy nicht 'always': ${restart_policy}"
    else
        log "Restart-Policy korrekt auf 'always' gesetzt"
    fi
    
    # Warte auf Probe-Initialisierung
    log "Warte auf Probe-Initialisierung..."
    sleep 20
    
    # Prüfe auf Connection-Logs
    local connection_check
    connection_check=$(docker logs globalping-probe 2>&1 | grep -c "Connection to API established\|Connected from" || echo "0")
    
    if [[ ${connection_check} -gt 0 ]]; then
        log "Globalping-Probe hat erfolgreich Verbindung zur API aufgebaut"
    else
        enhanced_log "WARN" "Keine API-Verbindung in den Logs erkannt"
    fi
    
    log "Erweiterte Globalping-Probe erfolgreich verifiziert"
    return 0
}

# Erweiterte Globalping-Wartung erstellen
create_enhanced_globalping_maintenance() {
    log "Erstelle erweiterte Globalping-Wartung"
    
    # Diese Funktion ist bereits durch die wöchentliche Wartung abgedeckt
    # und wird über den systemd-Timer ausgeführt
    log "Erweiterte Wartung wird über wöchentliche Auto-Update abgedeckt"
    
    return 0
}

# Wöchentlicher automatischer Modus
run_weekly_maintenance() {
    log "Starte wöchentliche automatische Wartung"
    
    WEEKLY_MODE="true"
    
    # Phase 1: Skript-Update
    log "Phase 1: Skript-Update"
    if ! perform_enhanced_auto_update; then
        enhanced_log "WARN" "Auto-Update fehlgeschlagen"
    fi
    
    # Phase 2: System-Updates
    log "Phase 2: System-Updates und Reboot-Check"
    if ! check_critical_updates; then
        enhanced_log "WARN" "System-Update-Check fehlgeschlagen"
    fi
    
    # Wenn Reboot geplant ist, beende hier
    if [[ "${REBOOT_REQUIRED}" == "true" ]]; then
        log "Reboot ist geplant, beende wöchentliche Wartung"
        return 0
    fi
    
    # Phase 3: Globalping-Wartung
    log "Phase 3: Globalping-Wartung"
    if ! perform_enhanced_globalping_maintenance; then
        enhanced_log "WARN" "Globalping-Wartung fehlgeschlagen"
    fi
    
    # Phase 4: Systemreinigung
    log "Phase 4: Systemreinigung"
    if ! perform_enhanced_system_cleanup; then
        enhanced_log "WARN" "Systemreinigung fehlgeschlagen"
    fi
    
    # Phase 5: Swap-Check
    log "Phase 5: Swap-Überprüfung"
    if ! configure_smart_swap; then
        enhanced_log "WARN" "Swap-Konfiguration fehlgeschlagen"
    fi
    
    # Phase 6: Log-Rotation
    log "Phase 6: Log-Rotation"
    perform_log_rotation
    
    log "Wöchentliche automatische Wartung abgeschlossen"
    return 0
}

# Erweiterte Globalping-Wartung
perform_enhanced_globalping_maintenance() {
    log "Führe erweiterte Globalping-Wartung durch"
    
    if ! command -v docker >/dev/null 2>&1; then
        enhanced_log "WARN" "Docker nicht verfügbar für Wartung"
        return 1
    fi
    
    local container_name="globalping-probe"
    
    # Prüfe, ob Container existiert
    if ! docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"; then
        enhanced_log "WARN" "Globalping-Container nicht gefunden"
        return 1
    fi
    
    # Container-Status prüfen
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    
    if [[ "${container_status}" != "running" ]]; then
        enhanced_log "WARN" "Globalping-Container nicht aktiv: ${container_status}"
        
        # Versuche Container zu starten
        if docker start "${container_name}" >/dev/null 2>&1; then
            log "Globalping-Container erfolgreich gestartet"
        else
            enhanced_log "ERROR" "Konnte Globalping-Container nicht starten"
            enhanced_notify "error" "Container-Problem" "Globalping-Container konnte nicht gestartet werden"
            return 1
        fi
    fi
    
    # Image-Update prüfen
    log "Prüfe auf Globalping-Image-Updates"
    local current_image_id latest_image_id
    current_image_id=$(docker inspect -f '{{.Image}}' "${container_name}" 2>/dev/null || echo "")
    
    if docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        latest_image_id=$(docker images --format "{{.ID}}" ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null | head -1 || echo "")
        
        if [[ -n "${current_image_id}" && -n "${latest_image_id}" && "${current_image_id}" != "${latest_image_id}" ]]; then
            log "Neues Globalping-Image verfügbar, aktualisiere Container"
            
            # Update mit Docker Compose falls verfügbar
            if [[ -f "/opt/globalping/docker-compose.yml" ]]; then
                cd /opt/globalping || return 1
                if command -v docker-compose >/dev/null 2>&1; then
                    docker-compose pull && docker-compose up -d
                elif docker compose version >/dev/null 2>&1; then
                    docker compose pull && docker compose up -d
                fi
            else
                # Manueller Container-Neustart
                docker stop "${container_name}" >/dev/null 2>&1 || true
                docker rm "${container_name}" >/dev/null 2>&1 || true
                start_enhanced_globalping_probe "/opt/globalping"
            fi
            
            log "Globalping-Container erfolgreich aktualisiert"
        else
            log "Globalping-Image ist bereits aktuell"
        fi
    else
        enhanced_log "WARN" "Konnte nicht auf Image-Updates prüfen"
    fi
    
    # Restart-Policy prüfen und korrigieren
    local restart_policy
    restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "${container_name}" 2>/dev/null || echo "")
    
    if [[ "${restart_policy}" != "always" ]]; then
        enhanced_log "WARN" "Restart-Policy nicht korrekt, korrigiere..."
        update_globalping_container_restart_policy "${container_name}"
    fi
    
    # Container-Gesundheit prüfen
    local health_status
    health_status=$(docker inspect -f '{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
    
    if [[ "${health_status}" == "unhealthy" ]]; then
        enhanced_log "WARN" "Container meldet unhealthy, starte neu"
        docker restart "${container_name}" >/dev/null 2>&1
        sleep 30
        
        # Prüfe erneut
        health_status=$(docker inspect -f '{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
        if [[ "${health_status}" == "unhealthy" ]]; then
            enhanced_notify "error" "Container-Gesundheit" "Globalping-Container meldet weiterhin 'unhealthy' nach Neustart"
        fi
    fi
    
    # Log-Größe prüfen und begrenzen
    local log_path
    log_path=$(docker inspect -f '{{.LogPath}}' "${container_name}" 2>/dev/null || echo "")
    
    if [[ -n "${log_path}" && -f "${log_path}" ]]; then
        local log_size_mb
        log_size_mb=$(stat -f%z "${log_path}" 2>/dev/null || stat -c%s "${log_path}" 2>/dev/null || echo "0")
        log_size_mb=$((log_size_mb / 1024 / 1024))
        
        if [[ ${log_size_mb} -gt ${MAX_LOG_SIZE_MB} ]]; then
            log "Container-Log zu groß (${log_size_mb}MB), kürze auf ${MAX_LOG_SIZE_MB}MB"
            tail -c $((MAX_LOG_SIZE_MB * 1024 * 1024)) "${log_path}" > "${log_path}.tmp" && mv "${log_path}.tmp" "${log_path}" 2>/dev/null || true
        fi
    fi
    
    log "Erweiterte Globalping-Wartung abgeschlossen"
    return 0
}

# Erweiterte Systemreinigung mit absoluten Schwellwerten
perform_enhanced_system_cleanup() {
    log "Starte erweiterte Systemreinigung"
    
    # Prüfe freien Speicherplatz
    local disk_available_kb disk_available_gb disk_usage_percent
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_available_gb=$(echo "scale=2; ${disk_available_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    disk_usage_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "100")
    
    log "Aktueller Speicherplatz: ${disk_available_gb}GB frei (${disk_usage_percent}% belegt)"
    
    # Prüfe, ob Bereinigung notwendig ist
    local cleanup_needed=false
    
    if (( $(echo "${disk_available_gb} < ${MIN_FREE_SPACE_GB}" | bc -l 2>/dev/null || echo "1") )); then
        log "Bereinigung wegen wenig freiem Speicher: ${disk_available_gb}GB < ${MIN_FREE_SPACE_GB}GB"
        cleanup_needed=true
    elif [[ ${disk_usage_percent} -gt 80 ]]; then
        log "Bereinigung wegen hoher Speichernutzung: ${disk_usage_percent}%"
        cleanup_needed=true
    fi
    
    if [[ "${cleanup_needed}" == "false" && "${WEEKLY_MODE}" == "false" ]]; then
        log "Keine Bereinigung erforderlich"
        return 0
    fi
    
    # Führe erweiterte Bereinigung durch
    log "Führe erweiterte Systemreinigung durch"
    
    # Docker-Bereinigung (schütze Globalping)
    if command -v docker >/dev/null 2>&1; then
        log "Bereinige Docker-Ressourcen (schütze Globalping)"
        
        # Entferne ungenutzte Images (außer Globalping)
        docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | \
            grep -v globalping | awk '{print $2}' | \
            xargs -r docker rmi >/dev/null 2>&1 || true
        
        # Entferne ungenutzte Volumes (außer Globalping)
        docker volume ls -q | grep -v globalping | \
            xargs -r docker volume rm >/dev/null 2>&1 || true
        
        # System-Prune (außer Globalping)
        docker system prune -f >/dev/null 2>&1 || true
    fi
    
    # Paketmanager-Cache bereinigen
    cleanup_package_cache_enhanced
    
    # Log-Rotation
    perform_log_rotation
    
    # Temporäre Dateien bereinigen
    cleanup_temp_files_enhanced
    
    # Prüfe Ergebnis
    local disk_available_after_kb disk_available_after_gb
    disk_available_after_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_available_after_gb=$(echo "scale=2; ${disk_available_after_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    
    local freed_space
    freed_space=$(echo "scale=2; ${disk_available_after_gb} - ${disk_available_gb}" | bc -l 2>/dev/null || echo "0")
    
    log "Bereinigung abgeschlossen: ${freed_space}GB freigegeben (${disk_available_after_gb}GB verfügbar)"
    
    # Warnung bei weiterhin kritischem Speicherplatz
    if (( $(echo "${disk_available_after_gb} < ${MIN_FREE_SPACE_GB}" | bc -l 2>/dev/null || echo "1") )); then
        enhanced_notify "error" "Kritischer Speicherplatz" "Nach Bereinigung nur ${disk_available_after_gb}GB frei (Minimum: ${MIN_FREE_SPACE_GB}GB)"
    fi
    
    return 0
}

# Erweiterte Paketmanager-Cache-Bereinigung
cleanup_package_cache_enhanced() {
    log "Bereinige Paketmanager-Cache erweitert"
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean >/dev/null 2>&1 || true
        apt-get autoclean >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
        
        # Entferne alte Archive
        rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true
        rm -rf /var/lib/apt/lists/* 2>/dev/null || true
        
    elif command -v dnf >/dev/null 2>&1; then
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/dnf/* 2>/dev/null || true
        
    elif command -v yum >/dev/null 2>&1; then
        yum clean all >/dev/null 2>&1 || true
        yum autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/yum/* 2>/dev/null || true
    fi
}

# Erweiterte temporäre Dateien-Bereinigung
cleanup_temp_files_enhanced() {
    log "Bereinige temporäre Dateien erweitert"
    
    # Temporäre Verzeichnisse
    find /tmp -type f -atime +1 -delete 2>/dev/null || true
    find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # Crash-Dumps
    find /var/crash -type f -mtime +1 -delete 2>/dev/null || true
    
    # Core-Dumps
    find / -xdev -name "core" -o -name "core.*" -type f -mtime +1 -delete 2>/dev/null || true
    
    # Browser-Caches
    find /home -path "*/.cache/*" -type f -atime +7 -delete 2>/dev/null || true
    find /root -path "*/.cache/*" -type f -atime +7 -delete 2>/dev/null || true
}

# Zentrale Log-Rotation
perform_log_rotation() {
    log "Führe zentrale Log-Rotation durch"
    
    # Systemd-Journal
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size="${MAX_LOG_SIZE_MB}M" --vacuum-time=7d >/dev/null 2>&1 || true
    fi
    
    # Rotiere große Log-Dateien
    find /var/log -type f -size +${MAX_LOG_SIZE_MB}M -not -path "*/globalping*" | while IFS= read -r log_file; do
        if [[ -n "${log_file}" ]]; then
            # Behalte nur die letzten 1000 Zeilen
            tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}" 2>/dev/null || true
            log "Log rotiert: ${log_file}"
        fi
    done
    
    # Entferne alte rotierte Logs
    find /var/log -name "*.1" -o -name "*.2" -o -name "*.old" -o -name "*.gz" -mtime +7 -delete 2>/dev/null || true
}

# Emergency Cleanup Funktion
perform_emergency_cleanup() {
    log "Führe Notfall-Bereinigung durch"
    
    # Stoppe alle nicht-essentiellen Services
    systemctl stop docker >/dev/null 2>&1 || true
    
    # Aggressive Docker-Bereinigung
    if command -v docker >/dev/null 2>&1; then
        # Stoppe alle Container außer wichtigen System-Containern
        docker ps -q | grep -v globalping | xargs -r docker stop >/dev/null 2>&1 || true
        
        # Entferne alle gestoppten Container
        docker container prune -f >/dev/null 2>&1 || true
        
        # Entferne alle ungenutzten Images
        docker image prune -a -f >/dev/null 2>&1 || true
        
        # Entferne alle ungenutzten Volumes
        docker volume prune -f >/dev/null 2>&1 || true
        
        # Entferne alle ungenutzten Netzwerke
        docker network prune -f >/dev/null 2>&1 || true
        
        # System-weite Bereinigung
        docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi
    
    # Aggressive Systemreinigung
    cleanup_package_cache_enhanced
    
    # Entferne große temporäre Dateien
    find /tmp -type f -size +10M -delete 2>/dev/null || true
    find /var/tmp -type f -size +10M -delete 2>/dev/null || true
    
    # Leere verschiedene Caches
    rm -rf /var/cache/*/* 2>/dev/null || true
    rm -rf /root/.cache/* 2>/dev/null || true
    
    # Journald-Logs aggressiv kürzen
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size=10M --vacuum-time=1d >/dev/null 2>&1 || true
    fi
    
    # Starte Docker wieder
    systemctl start docker >/dev/null 2>&1 || true
    
    log "Notfall-Bereinigung abgeschlossen"
    return 0
}

# Erweiterte Auto-Update-Einrichtung
setup_enhanced_auto_update() {
    log "Richte erweiterte automatische Updates ein"
    
    # Ermittle aktuellen Skriptpfad
    local current_script=""
    if command -v readlink >/dev/null 2>&1 && [[ -n "${0}" && "${0}" != "bash" && "${0}" != "-bash" ]]; then
        current_script=$(readlink -f "${0}" 2>/dev/null || echo "")
    fi
    
    if [[ -z "${current_script}" || ! -f "${current_script}" ]]; then
        local search_paths=("./install.sh" "$(pwd)/install.sh" "/root/install.sh")
        for path in "${search_paths[@]}"; do
            if [[ -f "${path}" && -r "${path}" ]]; then
                current_script=$(readlink -f "${path}" 2>/dev/null || echo "${path}")
                break
            fi
        done
    fi
    
    if [[ -z "${current_script}" || ! -f "${current_script}" ]]; then
        log "Lade Skript für Auto-Update herunter..."
        current_script="${TMP_DIR}/downloaded_install.sh"
        if ! curl -s -o "${current_script}" "${SCRIPT_URL}"; then
            enhanced_log "ERROR" "Konnte Skript nicht herunterladen"
            return 1
        fi
        chmod +x "${current_script}"
    fi
    
    # Installiere Skript
    mkdir -p "$(dirname "${SCRIPT_PATH}")" || return 1
    if [[ "${current_script}" != "${SCRIPT_PATH}" ]]; then
        cp "${current_script}" "${SCRIPT_PATH}" || return 1
        chmod +x "${SCRIPT_PATH}"
        log "Skript nach ${SCRIPT_PATH} installiert"
    fi
    
    # Entferne alte Update-Mechanismen
    remove_old_enhanced_schedulers
    
    # Richte wöchentliche systemd-Timer ein
    setup_enhanced_systemd_timers
    
    log "Erweiterte Auto-Update-Einrichtung abgeschlossen"
    return 0
}

# Erweiterte systemd-Timer einrichten
setup_enhanced_systemd_timers() {
    if ! check_systemd_available; then
        enhanced_log "WARN" "systemd nicht verfügbar, verwende crontab"
        setup_enhanced_crontab
        return $?
    fi
    
    log "Richte erweiterte systemd-Timer ein"
    
    # Auto-Update Service
    cat > "${SYSTEMD_SERVICE_PATH}" << EOF
[Unit]
Description=Globalping Installation Weekly Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} --auto-weekly
User=root
TimeoutStartSec=3600
Restart=no
Environment=WEEKLY_MODE=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Auto-Update Timer (Sonntag 03:00 mit Randomisierung)
    local random_delay=$((RANDOM % 3600))  # 0-60 Minuten
    cat > "${SYSTEMD_TIMER_PATH}" << EOF
[Unit]
Description=Weekly Globalping Installation Auto-Update and Maintenance
After=network-online.target

[Timer]
OnCalendar=Sun *-*-* 03:00:00
RandomizedDelaySec=${random_delay}
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Aktiviere Timer
    systemctl daemon-reload >/dev/null 2>&1 || return 1
    if systemctl enable globalping-update.timer >/dev/null 2>&1 && \
       systemctl start globalping-update.timer >/dev/null 2>&1; then
        log "Systemd-Timer erfolgreich eingerichtet: Sonntag 03:00 (+${random_delay}s)"
        return 0
    else
        enhanced_log "ERROR" "Konnte systemd-Timer nicht einrichten"
        return 1
    fi
}

# Erweiterte Crontab-Einrichtung als Fallback
setup_enhanced_crontab() {
    if ! check_crontab_available; then
        enhanced_log "ERROR" "Weder systemd noch crontab verfügbar"
        return 1
    fi
    
    log "Richte erweiterte Crontab ein"
    
    local random_hour=$((3 + RANDOM % 2))  # 3-4 Uhr
    local random_minute=$((RANDOM % 60))   # 0-59 Minuten
    
    local crontab_entry="${random_minute} ${random_hour} * * 0 ${SCRIPT_PATH} --auto-weekly >/dev/null 2>&1"
    
    local current_crontab="${TMP_DIR}/current_crontab"
    local new_crontab="${TMP_DIR}/new_crontab"
    
    crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
    grep -v "install_globalping.*--auto-weekly\|globalping.*--auto-update" "${current_crontab}" > "${new_crontab}"
    echo "${crontab_entry}" >> "${new_crontab}"
    
    if crontab "${new_crontab}" 2>/dev/null; then
        log "Crontab erfolgreich eingerichtet: Sonntag ${random_hour}:${random_minute}"
        return 0
    else
        enhanced_log "ERROR" "Konnte Crontab nicht aktualisieren"
        return 1
    fi
}

# Entferne alte Scheduler
remove_old_enhanced_schedulers() {
    log "Entferne alte Auto-Update-Mechanismen"
    
    # Entferne alte systemd-Timer
    if check_systemd_available; then
        systemctl stop globalping-update.timer >/dev/null 2>&1 || true
        systemctl disable globalping-update.timer >/dev/null 2>&1 || true
        systemctl stop globalping-maintenance.timer >/dev/null 2>&1 || true
        systemctl disable globalping-maintenance.timer >/dev/null 2>&1 || true
        
        rm -f "${SYSTEMD_TIMER_PATH}" 2>/dev/null || true
        rm -f "${SYSTEMD_SERVICE_PATH}" 2>/dev/null || true
        rm -f "/etc/systemd/system/globalping-maintenance.timer" 2>/dev/null || true
        rm -f "/etc/systemd/system/globalping-maintenance.service" 2>/dev/null || true
        
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    
    # Entferne alte Crontab-Einträge
    if check_crontab_available; then
        local current_crontab="${TMP_DIR}/current_crontab"
        local new_crontab="${TMP_DIR}/new_crontab"
        
        crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
        grep -v "globalping-maintenance\|install_globalping" "${current_crontab}" > "${new_crontab}"
        
        if ! cmp -s "${current_crontab}" "${new_crontab}"; then
            crontab "${new_crontab}" 2>/dev/null || true
        fi
    fi
    
    # Entferne alte Wartungsskripte
    rm -f "/usr/local/bin/globalping-maintenance" 2>/dev/null || true
    rm -f "/etc/cron.weekly/globalping-update" 2>/dev/null || true
}

# Erweiterte Auto-Update-Ausführung
perform_enhanced_auto_update() {
    log "Führe erweiterte automatische Aktualisierung durch"
    
    # Lock-File für Auto-Update
    local lock_file="/tmp/globalping_auto_update.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            log "Auto-Update bereits aktiv (PID: ${lock_pid})"
            return 0
        else
            rm -f "${lock_file}"
        fi
    fi
    
    echo "$$" > "${lock_file}"
    trap 'rm -f "${lock_file}"' EXIT
    
    # Download neue Version mit Retry-Logik
    local temp_script="${TMP_DIR}/update_script.sh"
    local download_attempts=0
    local max_attempts=3
    
    while [[ ${download_attempts} -lt ${max_attempts} ]]; do
        ((download_attempts++))
        
        if curl -sL --connect-timeout 10 \
           -o "${temp_script}" "${SCRIPT_URL}"; then
            log "Download erfolgreich (Versuch ${download_attempts})"
            break
        else
            enhanced_log "WARN" "Download fehlgeschlagen (Versuch ${download_attempts}/${max_attempts})"
            if [[ ${download_attempts} -eq ${max_attempts} ]]; then
                enhanced_notify "error" "Auto-Update" "Konnte aktuelle Version nicht herunterladen nach ${max_attempts} Versuchen"
                return 1
            fi
            sleep 10
        fi
    done
    
    # Validiere heruntergeladene Datei
    if [[ ! -f "${temp_script}" || ! -s "${temp_script}" ]]; then
        enhanced_notify "error" "Auto-Update" "Heruntergeladene Datei ist leer oder nicht vorhanden"
        return 1
    fi
    
    if ! head -1 "${temp_script}" | grep -q "^#!/bin/bash"; then
        enhanced_notify "error" "Auto-Update" "Heruntergeladene Datei ist kein gültiges Bash-Skript"
        return 1
    fi
    
    if ! timeout 10 bash -n "${temp_script}"; then
        enhanced_notify "error" "Auto-Update" "Syntax-Fehler in heruntergeladenem Skript"
        return 1
    fi
    
    # Versionsprüfung
    local current_version new_version
    current_version=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    new_version=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    
    log "Version-Check: ${current_version} -> ${new_version}"
    
    if [[ "${current_version}" == "${new_version}" && "${new_version}" != "unknown" ]]; then
        log "Bereits aktuellste Version installiert"
        return 0
    fi
    
    # Backup und Konfiguration sichern
    local backup_path="${SCRIPT_PATH}.backup.$(date +%s)"
    if [[ -f "${SCRIPT_PATH}" ]]; then
        cp "${SCRIPT_PATH}" "${backup_path}" || {
            enhanced_log "WARN" "Konnte Backup nicht erstellen"
        }
    fi
    
    local config_backup="${TMP_DIR}/config_backup"
    if [[ -f "${SCRIPT_PATH}" ]]; then
        grep -E "^(ADOPTION_TOKEN|TELEGRAM_TOKEN|TELEGRAM_CHAT|UBUNTU_PRO_TOKEN|SSH_KEY)=" "${SCRIPT_PATH}" > "${config_backup}" 2>/dev/null || true
    fi
    
    # Skript aktualisieren
    if ! cp "${temp_script}" "${SCRIPT_PATH}"; then
        enhanced_notify "error" "Auto-Update" "Konnte Skript nicht aktualisieren"
        return 1
    fi
    
    chmod +x "${SCRIPT_PATH}"
    
    # Konfiguration wiederherstellen
    if [[ -s "${config_backup}" ]]; then
        while IFS= read -r var_line; do
            if [[ -n "${var_line}" ]]; then
                local var_name
                var_name=$(echo "${var_line}" | cut -d'=' -f1)
                sed -i "s/^${var_name}=.*/${var_line}/" "${SCRIPT_PATH}" 2>/dev/null || true
            fi
        done < "${config_backup}"
    fi
    
    log "Skript erfolgreich auf Version ${new_version} aktualisiert"
    
    # Aufräumen
    rm -f "${temp_script}" "${config_backup}"
    
    return 0
}

# Erweiterte Hilfefunktion
show_enhanced_help() {
    cat << 'HELP_EOF'
==========================================
Globalping Server-Setup-Skript (Enhanced)
==========================================

BESCHREIBUNG:
    Erweiterte Automatisierung für Globalping-Probe Server mit
    intelligenter Wartung, erweiterten Benachrichtigungen und
    robusten Fehlerbehandlungen.

VERWENDUNG:
    ./install.sh [OPTIONEN]
    
    Das Skript muss mit Root-Rechten ausgeführt werden.

HAUPTOPTIONEN:
    -h, --help                      Zeigt diese Hilfe an
    --adoption-token TOKEN          Globalping Adoption-Token (erforderlich)
    --telegram-token TOKEN          Telegram-Bot-Token für Benachrichtigungen
    --telegram-chat ID              Telegram-Chat-ID für Benachrichtigungen
    --ubuntu-token TOKEN            Ubuntu Pro Token (nur für Ubuntu)
    --ssh-key "SCHLÜSSEL"           SSH Public Key für sicheren Zugang

WARTUNGS-OPTIONEN:
    --auto-weekly                   Wöchentliche automatische Wartung (intern)
    --cleanup                       Erweiterte Systemreinigung
    --emergency-cleanup             Aggressive Notfall-Bereinigung  
    --diagnose                      Vollständige Systemdiagnose
    --network-diagnose              Detaillierte Netzwerk-Diagnose

ERWEITERTE OPTIONEN:
    -d, --docker                    Installiert nur Docker
    -l, --log DATEI                 Alternative Log-Datei
    --debug                         Debug-Modus mit ausführlichem Logging
    --force                         Überspringt Sicherheitsabfragen
    --no-reboot                     Verhindert automatische Reboots

NEUE FEATURES:
    ✓ Intelligente Swap-Konfiguration (RAM + Swap ≥ 1GB)
    ✓ Automatische Reboots bei kritischen Updates
    ✓ Erweiterte Telegram-Benachrichtigungen (nur Fehler)
    ✓ Absolute Speicherplatz-Schwellwerte (1.5GB minimum)
    ✓ CPU-Hang-Schutz durch Timeouts
    ✓ restart=always für Globalping-Container
    ✓ Tägliche Log-Rotation (max 50MB)
    ✓ Wöchentliche automatische Wartung

SYSTEMANFORDERUNGEN:
    - Linux (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora)
    - Mindestens 256MB RAM
    - Mindestens 1.5GB freier Speicherplatz
    - Root-Rechte oder sudo-Zugang
    - Internetverbindung

AUTOMATISIERUNG:
    Nach der Installation läuft wöchentlich automatisch:
    ✓ Skript-Updates
    ✓ System-Updates mit Reboot-Check
    ✓ Globalping-Container-Wartung
    ✓ Systemreinigung
    ✓ Swap-Optimierung
    ✓ Log-Rotation

TELEGRAM-BENACHRICHTIGUNGEN:
    Das Skript sendet formatierte Nachrichten bei:
    ✓ Erfolgreicher Erstinstallation
    ✓ Kritischen Fehlern (keine Warnungen)
    
    Format:
    🌍 Country: DE
    🖥️ Hostname: hostname
    🌐 IP: 1.2.3.4
    📡 ASN: AS12345
    🏢 Provider: Provider Name
    🔧 Status/Fehlermeldung

BEISPIELE:
    # Vollständige Installation
    ./install.sh --adoption-token "token" \
                  --telegram-token "bot-token" \
                  --telegram-chat "chat-id"

    # Nur Diagnose
    ./install.sh --diagnose

    # Systemreinigung
    ./install.sh --cleanup

    # Debug-Modus
    ./install.sh --debug --adoption-token "token"

DATEIEN:
    - Setup-Log: /var/log/globalping-install.log
    - Globalping-Verzeichnis: /opt/globalping
    - Auto-Update-Skript: /usr/local/bin/install_globalping.sh
    - Systemd-Timer: /etc/systemd/system/globalping-update.timer

HELP_EOF
    exit 0
}

# Erweiterte Argumentverarbeitung
process_enhanced_args() {
    # Standardwerte
    local install_docker_only="false"
    local run_diagnostics_only="false"
    local run_network_diagnostics_only="false"
    local auto_weekly_mode="false"
    local cleanup_mode="false"
    local emergency_cleanup_mode="false"
    local force_mode="false"
    local no_reboot="false"
    
    # Keine Argumente = Hilfe
    if [[ $# -eq 0 ]]; then
        show_enhanced_help
    fi
    
    # Argumente verarbeiten
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_enhanced_help
                ;;
            -d|--docker)
                install_docker_only="true"
                shift
                ;;
            -l|--log)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    LOG_FILE="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--log benötigt einen Dateinamen"
                    exit 1
                fi
                ;;
            --debug)
                enable_enhanced_debug_mode
                shift
                ;;
            --force)
                force_mode="true"
                shift
                ;;
            --no-reboot)
                no_reboot="true"
                shift
                ;;
            --auto-weekly)
                auto_weekly_mode="true"
                WEEKLY_MODE="true"
                shift
                ;;
            --adoption-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    ADOPTION_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--adoption-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-chat)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_CHAT="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-chat benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ubuntu-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    UBUNTU_PRO_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ubuntu-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ssh-key)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    SSH_KEY="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ssh-key benötigt einen Wert"
                    exit 1
                fi
                ;;
            --cleanup)
                cleanup_mode="true"
                shift
                ;;
            --emergency-cleanup)
                emergency_cleanup_mode="true"
                shift
                ;;
            --diagnose)
                run_diagnostics_only="true"
                shift
                ;;
            --network-diagnose)
                run_network_diagnostics_only="true"
                shift
                ;;
            -*)
                enhanced_log "ERROR" "Unbekannte Option: $1"
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
            *)
                enhanced_log "ERROR" "Unerwartetes Argument: $1"
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
        esac
    done
    
    # Validiere und führe spezielle Modi aus
    execute_enhanced_special_modes \
        "${install_docker_only}" \
        "${run_diagnostics_only}" \
        "${run_network_diagnostics_only}" \
        "${auto_weekly_mode}" \
        "${cleanup_mode}" \
        "${emergency_cleanup_mode}" \
        "${force_mode}" \
        "${no_reboot}"
}

# Führe erweiterte spezielle Modi aus
execute_enhanced_special_modes() {
    local install_docker_only="$1"
    local run_diagnostics_only="$2"
    local run_network_diagnostics_only="$3"
    local auto_weekly_mode="$4"
    local cleanup_mode="$5"
    local emergency_cleanup_mode="$6"
    local force_mode="$7"
    local no_reboot="$8"
    
    # Zähle aktive Modi
    local active_modes=0
    [[ "${install_docker_only}" == "true" ]] && ((active_modes++))
    [[ "${run_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${run_network_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${auto_weekly_mode}" == "true" ]] && ((active_modes++))
    [[ "${cleanup_mode}" == "true" ]] && ((active_modes++))
    [[ "${emergency_cleanup_mode}" == "true" ]] && ((active_modes++))
    
    if [[ ${active_modes} -gt 1 ]]; then
        enhanced_log "ERROR" "Nur ein spezieller Modus kann gleichzeitig verwendet werden"
        exit 1
    fi
    
    # Root-Check für alle Modi
    check_root || {
        enhanced_log "ERROR" "Root-Rechte erforderlich"
        exit 1
    }
    
    # Temporäres Verzeichnis für alle Modi
    create_temp_dir || {
        enhanced_log "ERROR" "Konnte temporäres Verzeichnis nicht erstellen"
        exit 1
    }
    
    # No-Reboot-Flag global setzen
    if [[ "${no_reboot}" == "true" ]]; then
        export NO_REBOOT="true"
    fi
    
    # Führe speziellen Modus aus
    if [[ "${install_docker_only}" == "true" ]]; then
        execute_docker_only_mode
        exit $?
    elif [[ "${run_diagnostics_only}" == "true" ]]; then
        execute_diagnostics_mode
        exit $?
    elif [[ "${run_network_diagnostics_only}" == "true" ]]; then
        execute_network_diagnostics_mode
        exit $?
    elif [[ "${auto_weekly_mode}" == "true" ]]; then
        execute_weekly_mode
        exit $?
    elif [[ "${cleanup_mode}" == "true" ]]; then
        execute_cleanup_mode
        exit $?
    elif [[ "${emergency_cleanup_mode}" == "true" ]]; then
        execute_emergency_cleanup_mode "${force_mode}"
        exit $?
    fi
    
    # Normale Installation
    validate_installation_args
    return 0
}

# Validiere normale Installationsargumente
validate_installation_args() {
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "WARN" "Kein Adoption-Token - Globalping-Probe wird nicht installiert"
        echo "Warnung: Ohne --adoption-token wird keine Globalping-Probe installiert" >&2
    fi
    
    if [[ -n "${TELEGRAM_TOKEN}" && -z "${TELEGRAM_CHAT}" ]] || [[ -z "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]]; then
        enhanced_log "WARN" "Unvollständige Telegram-Konfiguration"
        echo "Für Telegram-Benachrichtigungen werden sowohl --telegram-token als auch --telegram-chat benötigt" >&2
    fi
}

# Spezielle Modi ausführen
execute_docker_only_mode() {
    log "Führe Docker-Installation durch"
    install_dependencies || enhanced_log "WARN" "Abhängigkeiten-Installation teilweise fehlgeschlagen"
    install_docker || {
        enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
        return 1
    }
    install_docker_compose || enhanced_log "WARN" "Docker Compose-Installation fehlgeschlagen"
    log "Docker-Installation abgeschlossen"
    return 0
}

execute_diagnostics_mode() {
    log "Führe vollständige Systemdiagnose durch"
    run_enhanced_diagnostics
    return $?
}

execute_network_diagnostics_mode() {
    log "Führe Netzwerk-Diagnose durch"
    run_enhanced_network_diagnosis
    return $?
}

execute_weekly_mode() {
    log "Führe wöchentliche automatische Wartung durch"
    get_enhanced_system_info
    run_weekly_maintenance
    return $?
}

execute_cleanup_mode() {
    log "Führe erweiterte Systemreinigung durch"
    perform_enhanced_system_cleanup
    return $?
}

execute_emergency_cleanup_mode() {
    local force_mode="$1"
    
    if [[ "${force_mode}" != "true" ]]; then
        echo "WARNUNG: Notfall-Bereinigung wird aggressive Maßnahmen ergreifen!"
        echo "Drücken Sie Ctrl+C innerhalb von 10 Sekunden zum Abbrechen..."
        sleep 10
    fi
    
    log "Führe Notfall-Bereinigung durch"
    perform_emergency_cleanup
    return $?
}

# Erweiterte Debug-Modus-Aktivierung
enable_enhanced_debug_mode() {
    enhanced_log "INFO" "Aktiviere erweiterten Debug-Modus"
    
    set -x
    
    local debug_log="/var/log/globalping-debug-$(date +%Y%m%d-%H%M%S).log"
    exec 19>"${debug_log}"
    BASH_XTRACEFD=19
    
    DEBUG_MODE="true"
    
    {
        echo "=== ENHANCED DEBUG SESSION ==="
        echo "Datum: $(date)"
        echo "Benutzer: $(whoami)"
        echo "Arbeitsverzeichnis: $(pwd)"
        echo "Skript-Pfad: ${0}"
        echo "Argumente: $*"
        echo "System: $(uname -a)"
        echo "Shell: ${SHELL} (${BASH_VERSION})"
        echo "Speicher: $(free -h | grep Mem)"
        echo "Festplatte: $(df -h / | grep /)"
        echo "=============================="
    } >&19
    
    enhanced_log "INFO" "Erweiterter Debug-Modus aktiviert: ${debug_log}"
    return 0
}

# Erweiterte Systemdiagnose mit Timeouts
run_enhanced_diagnostics() {
    log "Führe erweiterte Systemdiagnose durch"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== ERWEITERTE SYSTEMDIAGNOSE ==="
    echo "Zeitpunkt: $(date)"
    echo "Hostname: $(hostname 2>/dev/null || echo 'unbekannt')"
    echo "Skript-Version: ${SCRIPT_VERSION}"
    echo "=================================="
    
    # 1. HARDWARE-ANALYSE
    echo -e "\n[DIAGNOSE] Hardware-Analyse"
    analyze_hardware_enhanced issues warnings info_items
    
    # 2. SPEICHER-ANALYSE
    echo -e "\n[DIAGNOSE] Speicher-Analyse (erweitert)"
    analyze_memory_enhanced issues warnings info_items
    
    # 3. NETZWERK-GRUNDPRÜFUNG
    echo -e "\n[DIAGNOSE] Netzwerk-Analyse"
    analyze_network_enhanced issues warnings info_items
    
    # 4. DOCKER-SYSTEM
    if command -v docker >/dev/null 2>&1; then
        echo -e "\n[DIAGNOSE] Docker-System"
        analyze_docker_enhanced issues warnings info_items
    fi
    
    # 5. GLOBALPING-PROBE
    echo -e "\n[DIAGNOSE] Globalping-Probe"
    analyze_globalping_enhanced issues warnings info_items
    
    # 6. AUTO-UPDATE-SYSTEM
    echo -e "\n[DIAGNOSE] Auto-Update-System"
    analyze_autoupdate_enhanced issues warnings info_items
    
    # 7. SICHERHEIT
    echo -e "\n[DIAGNOSE] Sicherheits-Konfiguration"
    analyze_security_enhanced issues warnings info_items
    
    # 8. PERFORMANCE
    echo -e "\n[DIAGNOSE] Performance-Analyse"
    analyze_performance_enhanced issues warnings info_items
    
    # ERGEBNISSE
    echo -e "\n=== DIAGNOSE-ERGEBNISSE ==="
    echo "Kritische Probleme: ${#issues[@]}"
    echo "Warnungen: ${#warnings[@]}"
    echo "Informationen: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 KRITISCHE PROBLEME:"
        printf ' - %s\n' "${issues[@]}"
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo -e "\n🟡 WARNUNGEN:"
        printf ' - %s\n' "${warnings[@]}"
    fi
    
    if [[ ${#info_items[@]} -gt 0 ]]; then
        echo -e "\n🔵 SYSTEM-INFORMATIONEN:"
        printf ' - %s\n' "${info_items[@]}"
    fi
    
    echo "============================="
    
    # Bei kritischen Problemen Telegram-Benachrichtigung
    if [[ ${#issues[@]} -gt 0 ]]; then
        enhanced_notify "error" "Diagnose-Probleme" "$(printf '%s\n' "${issues[@]}" | head -5)"
        return 1
    fi
    
    return 0
}

# Hardware-Analyse
analyze_hardware_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Hardware..."
    
    # CPU-Information
    local cpu_cores cpu_model
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unbekannt")
    echo "CPU: ${cpu_model} (${cpu_cores} Kerne)"
    info_ref+=("CPU: ${cpu_cores} Kerne")
    
    # Architektur
    local arch
    arch=$(uname -m 2>/dev/null || echo "unknown")
    echo "Architektur: ${arch}"
    
    # Virtualisierung erkennen
    local virt_type="Bare Metal"
    if [[ -f /proc/cpuinfo ]] && grep -q "hypervisor" /proc/cpuinfo; then
        virt_type="Virtualisiert"
    elif [[ -d /proc/vz ]]; then
        virt_type="OpenVZ/Virtuozzo"
    elif [[ -f /proc/xen/capabilities ]]; then
        virt_type="Xen"
    elif systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "Virtualisiert")
    fi
    echo "Virtualisierung: ${virt_type}"
    info_ref+=("Virtualisierung: ${virt_type}")
}

# Erweiterte Speicher-Analyse
analyze_memory_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Speicher (erweitert)..."
    
    # RAM-Details
    local mem_total_kb mem_available_kb mem_total_mb mem_available_mb
    mem_total_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_available_kb=$(grep "MemAvailable" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_total_mb=$((mem_total_kb / 1024))
    mem_available_mb=$((mem_available_kb / 1024))
    
    echo "RAM: ${mem_available_mb}MB frei von ${mem_total_mb}MB"
    
    if [[ ${mem_total_mb} -lt ${MIN_RAM_MB} ]]; then
        issues_ref+=("Zu wenig RAM: ${mem_total_mb}MB (Minimum: ${MIN_RAM_MB}MB)")
    elif [[ ${mem_available_mb} -lt 100 ]]; then
        warnings_ref+=("Wenig freier RAM: ${mem_available_mb}MB")
    fi
    
    # Swap-Analyse
    local swap_total_kb swap_used_kb swap_total_mb swap_used_mb
    swap_total_kb=$(grep "SwapTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    swap_used_kb=$(grep "SwapUsed" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    swap_total_mb=$((swap_total_kb / 1024))
    swap_used_mb=$((swap_used_kb / 1024))
    
    if [[ ${swap_total_mb} -eq 0 ]]; then
        echo "Swap: Nicht konfiguriert"
        local combined_mb=$((mem_total_mb + swap_total_mb))
        if [[ ${combined_mb} -lt $((SWAP_MIN_TOTAL_GB * 1024)) ]]; then
            warnings_ref+=("RAM+Swap unter ${SWAP_MIN_TOTAL_GB}GB: ${combined_mb}MB")
        fi
    else
        echo "Swap: ${swap_used_mb}MB verwendet von ${swap_total_mb}MB"
        if [[ ${swap_used_mb} -gt $((swap_total_mb * 80 / 100)) ]]; then
            warnings_ref+=("Hohe Swap-Nutzung: ${swap_used_mb}MB/${swap_total_mb}MB")
        fi
    fi
    
    # Festplatten-Analyse
    local disk_total_kb disk_used_kb disk_available_kb disk_usage_percent
    disk_total_kb=$(df / | awk 'NR==2 {print $2}' || echo "0")
    disk_used_kb=$(df / | awk 'NR==2 {print $3}' || echo "0")
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_usage_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "100")
    
    local disk_total_gb disk_available_gb
    disk_total_gb=$(echo "scale=1; ${disk_total_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    disk_available_gb=$(echo "scale=1; ${disk_available_kb} / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    
    echo "Festplatte: ${disk_available_gb}GB frei von ${disk_total_gb}GB (${disk_usage_percent}% belegt)"
    
    if (( $(echo "${disk_available_gb} < ${MIN_FREE_SPACE_GB}" | bc -l 2>/dev/null || echo "1") )); then
        issues_ref+=("Kritisch wenig Speicherplatz: ${disk_available_gb}GB (Minimum: ${MIN_FREE_SPACE_GB}GB)")
    elif [[ ${disk_usage_percent} -gt 85 ]]; then
        warnings_ref+=("Festplatte zu ${disk_usage_percent}% voll")
    fi
    
    info_ref+=("Speicher: ${mem_available_mb}MB RAM, ${disk_available_gb}GB HDD frei")
}

# Erweiterte Netzwerk-Analyse
analyze_network_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Netzwerk (erweitert)..."
    
    # Interface-Analyse
    local active_interfaces
    active_interfaces=$(ip link show up 2>/dev/null | grep -c "state UP" || echo "0")
    echo "Aktive Interfaces: ${active_interfaces}"
    
    if [[ ${active_interfaces} -eq 0 ]]; then
        issues_ref+=("Keine aktiven Netzwerk-Interfaces")
        return 1
    fi
    
    # Öffentliche IP ermitteln
    local public_ip
    public_ip=$(curl -s https://api.ipify.org 2>/dev/null || echo "unbekannt")
    echo "Öffentliche IP: ${public_ip}"
    info_ref+=("Öffentliche IP: ${public_ip}")
    
    # DNS-Test
    local dns_test_passed=0
    local dns_targets=("google.com" "cloudflare.com")
    for target in "${dns_targets[@]}"; do
        if timeout 5 nslookup "${target}" >/dev/null 2>&1; then
            ((dns_test_passed++))
        fi
    done
    
    if [[ ${dns_test_passed} -eq 0 ]]; then
        issues_ref+=("DNS-Auflösung fehlgeschlagen")
    elif [[ ${dns_test_passed} -lt ${#dns_targets[@]} ]]; then
        warnings_ref+=("DNS-Auflösung teilweise fehlgeschlagen")
    else
        info_ref+=("DNS-Auflösung funktioniert")
    fi
    
    # Konnektivitäts-Test
    local connectivity_passed=0
    local ping_targets=("1.1.1.1" "8.8.8.8")
    for target in "${ping_targets[@]}"; do
        if timeout 5 ping -c 1 "${target}" >/dev/null 2>&1; then
            ((connectivity_passed++))
        fi
    done
    
    if [[ ${connectivity_passed} -eq 0 ]]; then
        issues_ref+=("Keine Internet-Konnektivität")
    else
        info_ref+=("Internet-Konnektivität verfügbar")
    fi
}

# Erweiterte Docker-Analyse
analyze_docker_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Docker-System (erweitert)..."
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        issues_ref+=("Docker-Dienst nicht aktiv")
        return 1
    fi
    
    local docker_version
    docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "unbekannt")
    echo "Docker-Version: ${docker_version}"
    
    # Container-Statistiken
    local total_containers running_containers
    total_containers=$(docker ps -a -q 2>/dev/null | wc -l || echo "0")
    running_containers=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    echo "Container: ${running_containers}/${total_containers} aktiv"
    
    # Speicherverbrauch
    if docker system df >/dev/null 2>&1; then
        local docker_size
        docker_size=$(docker system df --format "table {{.Type}}\t{{.Size}}" 2>/dev/null | grep "Images" | awk '{print $2}' || echo "0B")
        echo "Docker-Speicherverbrauch: ${docker_size}"
    fi
    
    # Unhealthy Container
    local unhealthy_count
    unhealthy_count=$(docker ps --filter health=unhealthy -q 2>/dev/null | wc -l || echo "0")
    if [[ ${unhealthy_count} -gt 0 ]]; then
        warnings_ref+=("${unhealthy_count} Container mit Status 'unhealthy'")
    fi
    
    info_ref+=("Docker: ${running_containers} Container aktiv")
}

# Erweiterte Globalping-Analyse
analyze_globalping_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Globalping-Probe (erweitert)..."
    
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker nicht verfügbar"
        return 0
    fi
    
    local container_name
    container_name=$(docker ps -a --format "{{.Names}}" | grep -i globalping | head -1 || echo "")
    
    if [[ -z "${container_name}" ]]; then
        warnings_ref+=("Globalping-Probe nicht installiert")
        return 0
    fi
    
    echo "Container: ${container_name}"
    
    # Status-Analyse
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    echo "Status: ${container_status}"
    
    case "${container_status}" in
        "running")
            # Restart-Policy prüfen
            local restart_policy
            restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "${container_name}" 2>/dev/null || echo "")
            echo "Restart-Policy: ${restart_policy}"
            
            if [[ "${restart_policy}" != "always" ]]; then
                warnings_ref+=("Globalping Restart-Policy nicht 'always': ${restart_policy}")
            fi
            
            # Uptime
            local started_at
            started_at=$(docker inspect -f '{{.State.StartedAt}}' "${container_name}" 2>/dev/null || echo "")
            if [[ -n "${started_at}" ]]; then
                local uptime_seconds
                uptime_seconds=$(( $(date +%s) - $(date -d "${started_at}" +%s 2>/dev/null || echo "0") ))
                local uptime_hours=$((uptime_seconds / 3600))
                echo "Laufzeit: ${uptime_hours} Stunden"
                
                if [[ ${uptime_seconds} -lt 300 ]]; then
                    warnings_ref+=("Globalping-Probe kürzlich neu gestartet")
                fi
            fi
            
            # API-Verbindung prüfen - KORRIGIERT
            local api_connection
            api_connection=$(docker logs --tail 50 "${container_name}" 2>&1 | grep -c "Connection to API established\|Connected from" || echo "0")
            # Bereinige Output
            api_connection=$(echo "${api_connection}" | tr -d '\n\r' | awk '{print $1}')
            
            if [[ "${api_connection}" -gt 0 ]] 2>/dev/null; then
                info_ref+=("Globalping-Probe: API-Verbindung aktiv")
            else
                warnings_ref+=("Globalping-Probe: Keine API-Verbindung erkannt")
            fi
            ;;
        *)
            issues_ref+=("Globalping-Probe nicht aktiv: ${container_status}")
            ;;
    esac
}

# Erweiterte Auto-Update-Analyse
analyze_autoupdate_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Auto-Update-System..."
    
    local update_mechanisms=()
    
    # Systemd-Timer
    if check_systemd_available && systemctl is-enabled globalping-update.timer >/dev/null 2>&1; then
        update_mechanisms+=("systemd-timer")
        
        if systemctl is-active globalping-update.timer >/dev/null 2>&1; then
            local next_run
            next_run=$(systemctl show globalping-update.timer --property=NextElapseUSecRealtime --value 2>/dev/null || echo "unknown")
            echo "Systemd-Timer: aktiv (nächster Lauf: ${next_run})"
        else
            warnings_ref+=("Systemd-Timer aktiviert aber nicht aktiv")
        fi
    fi
    
    # Crontab
    if check_crontab_available && crontab -l 2>/dev/null | grep -q "auto-weekly"; then
        update_mechanisms+=("crontab")
        echo "Crontab: konfiguriert"
    fi
    
    if [[ ${#update_mechanisms[@]} -eq 0 ]]; then
        warnings_ref+=("Kein Auto-Update-Mechanismus aktiv")
    else
        info_ref+=("Auto-Update aktiv: ${update_mechanisms[*]}")
    fi
    
    # Update-Skript prüfen
    if [[ -f "${SCRIPT_PATH}" && -x "${SCRIPT_PATH}" ]]; then
        local script_version
        script_version=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
        echo "Update-Skript: ${script_version}"
        info_ref+=("Update-Skript: Version ${script_version}")
    else
        warnings_ref+=("Update-Skript nicht gefunden: ${SCRIPT_PATH}")
    fi
}

# Performance-Analyse
analyze_performance_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere System-Performance..."
    
    # Load Average
    local load_1min load_5min
    if [[ -r /proc/loadavg ]]; then
        read -r load_1min load_5min _ _ _ < /proc/loadavg
        echo "Load Average: ${load_1min} (1min), ${load_5min} (5min)"
        
        local cpu_cores
        cpu_cores=$(nproc 2>/dev/null || echo "1")
        
        if (( $(echo "${load_1min} > ${cpu_cores} * 2" | bc -l 2>/dev/null || echo "0") )); then
            warnings_ref+=("Sehr hohe CPU-Last: ${load_1min} (Kerne: ${cpu_cores})")
        fi
    fi
    
    # I/O-Wait prüfen
    local iowait
    iowait=$(top -bn1 | grep "Cpu(s)" | awk '{print $10}' | tr -d '%' 2>/dev/null || echo "0")
    echo "I/O-Wait: ${iowait}%"
    
    if (( $(echo "${iowait} > 20" | bc -l 2>/dev/null || echo "0") )); then
        warnings_ref+=("Hohe I/O-Wait: ${iowait}%")
    fi
    
    # Offene Dateien
    local open_files
    open_files=$(lsof 2>/dev/null | wc -l || echo "0")
    echo "Offene Dateien: ${open_files}"
    
    info_ref+=("Performance: Load ${load_1min}, I/O-Wait ${iowait}%")
}

# Sicherheits-Analyse
analyze_security_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Sicherheits-Konfiguration..."
    
    # SSH-Konfiguration
    if [[ -f /etc/ssh/sshd_config ]]; then
        local root_login password_auth
        root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "default")
        password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "default")
        
        echo "SSH Root-Login: ${root_login}"
        echo "SSH Password-Auth: ${password_auth}"
        
        if [[ "${root_login}" == "yes" ]]; then
            warnings_ref+=("SSH Root-Login aktiviert")
        fi
    fi
    
    # Firewall-Status
    local firewall_status="nicht erkannt"
    if command -v ufw >/dev/null 2>&1; then
        firewall_status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            firewall_status="firewalld aktiv"
        else
            firewall_status="firewalld inaktiv"
        fi
    fi
    echo "Firewall: ${firewall_status}"
    
    # Fail2Ban
    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            info_ref+=("Fail2Ban: aktiv")
        else
            warnings_ref+=("Fail2Ban installiert aber inaktiv")
        fi
    fi
    
    info_ref+=("Sicherheit: SSH konfiguriert, Firewall ${firewall_status}")
}

# Erweiterte Netzwerk-Diagnose
run_enhanced_network_diagnosis() {
    log "Führe erweiterte Netzwerk-Diagnose durch"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== ERWEITERTE NETZWERK-DIAGNOSE ==="
    echo "Zeitpunkt: $(date)"
    echo "===================================="
    
    # Basis-Netzwerk-Tests mit Timeouts
    analyze_network_enhanced issues warnings info_items
    
    # Erweiterte Tests
    echo -e "\n[NETZWERK] Latenz-Tests"
    perform_latency_tests issues warnings info_items
    
    echo -e "\n[NETZWERK] Bandwidth-Schätzung"
    perform_bandwidth_test issues warnings info_items
    
    echo -e "\n[NETZWERK] IPv6-Tests"
    test_ipv6_connectivity issues warnings info_items
    
    # Ergebnisse anzeigen
    echo -e "\n=== NETZWERK-DIAGNOSE ERGEBNISSE ==="
    echo "Probleme: ${#issues[@]}, Warnungen: ${#warnings[@]}, Info: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 NETZWERK-PROBLEME:"
        printf ' - %s\n' "${issues[@]}"
        enhanced_notify "error" "Netzwerk-Probleme" "$(printf '%s\n' "${issues[@]}" | head -3)"
        return 1
    fi
    
    return 0
}

# Latenz-Tests
perform_latency_tests() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    local targets=("1.1.1.1" "8.8.8.8" "google.com")
    local high_latency_count=0
    
    for target in "${targets[@]}"; do
        local ping_result
        ping_result=$(timeout 10 ping -c 3 "${target}" 2>/dev/null | grep "avg" || echo "")
        
        if [[ -n "${ping_result}" ]]; then
            local avg_latency
            avg_latency=$(echo "${ping_result}" | cut -d'/' -f5 | cut -d'.' -f1 || echo "999")
            echo "Latenz ${target}: ${avg_latency}ms"
            
            if [[ ${avg_latency} -gt 500 ]]; then
                issues_ref+=("Sehr hohe Latenz ${target}: ${avg_latency}ms")
                ((high_latency_count++))
            elif [[ ${avg_latency} -gt 200 ]]; then
                warnings_ref+=("Hohe Latenz ${target}: ${avg_latency}ms")
                ((high_latency_count++))
            fi
        else
            warnings_ref+=("Latenz-Test ${target} fehlgeschlagen")
        fi
    done
    
    if [[ ${high_latency_count} -eq 0 ]]; then
        info_ref+=("Netzwerk-Latenz: Alle Tests unter 200ms")
    fi
}

# Bandwidth-Test
perform_bandwidth_test() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    local test_url="http://speedtest.tele2.net/1MB.zip"
    local start_time end_time
    
    echo "Führe Bandwidth-Test durch..."
    start_time=$(date +%s.%N 2>/dev/null || date +%s)
    
    if timeout 30 curl -s --connect-timeout 5 "${test_url}" -o /dev/null 2>/dev/null; then
        end_time=$(date +%s.%N 2>/dev/null || date +%s)
        local duration
        duration=$(echo "${end_time} - ${start_time}" | bc -l 2>/dev/null || echo "1")
        
        if (( $(echo "${duration} > 0" | bc -l 2>/dev/null || echo "1") )); then
            local speed_mbps
            speed_mbps=$(echo "scale=1; 8 / ${duration}" | bc -l 2>/dev/null || echo "1")
            echo "Download-Geschwindigkeit: ${speed_mbps} Mbps"
            
            if (( $(echo "${speed_mbps} < 1" | bc -l 2>/dev/null || echo "0") )); then
                warnings_ref+=("Sehr langsame Verbindung: ${speed_mbps} Mbps")
            else
                info_ref+=("Download-Geschwindigkeit: ${speed_mbps} Mbps")
            fi
        fi
    else
        warnings_ref+=("Bandwidth-Test fehlgeschlagen")
    fi
}

# IPv6-Tests
test_ipv6_connectivity() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    local ipv6_addresses
    ipv6_addresses=$(ip addr show 2>/dev/null | grep "inet6.*scope global" | wc -l || echo "0")
    
    echo "IPv6-Adressen: ${ipv6_addresses}"
    
    if [[ ${ipv6_addresses} -eq 0 ]]; then
        echo "IPv6 nicht konfiguriert"
        return 0
    fi
    
    local ipv6_targets=("2606:4700:4700::1111" "2001:4860:4860::8888")
    local successful_tests=0
    
    for target in "${ipv6_targets[@]}"; do
        if timeout 5 ping -6 -c 1 "${target}" >/dev/null 2>&1; then
            ((successful_tests++))
        fi
    done
    
    if [[ ${successful_tests} -eq 0 ]]; then
        warnings_ref+=("IPv6 konfiguriert aber keine Konnektivität")
    else
        info_ref+=("IPv6-Konnektivität: ${successful_tests}/${#ipv6_targets[@]} Tests erfolgreich")
    fi
}

# Docker Installation (falls fehlend)
install_docker() {
    enhanced_log "INFO" "Installiere Docker"
    
    # Prüfe, ob Docker bereits installiert und funktionsfähig ist
    if command -v docker >/dev/null 2>&1; then
        if docker --version >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
            enhanced_log "INFO" "Docker ist bereits installiert und aktiv"
            return 0
        else
            enhanced_log "INFO" "Docker ist installiert, aber nicht funktionsfähig - repariere Installation"
        fi
    fi
    
    # Erkenne Distribution sicher
    local distro_id=""
    local distro_version=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro_id="${ID,,}" # Kleinbuchstaben
        distro_version="${VERSION_ID}"
    else
        enhanced_log "ERROR" "Kann Distribution nicht ermitteln"
        return 1
    fi
    
    enhanced_log "INFO" "Erkannte Distribution: ${distro_id} ${distro_version}"
    
    # Installiere je nach Distribution
    case "${distro_id}" in
        ubuntu|debian)
            install_docker_debian_ubuntu "${distro_id}"
            ;;
        rhel|centos|rocky|almalinux|fedora)
            install_docker_rhel_family "${distro_id}"
            ;;
        *)
            enhanced_log "INFO" "Unbekannte Distribution, versuche universelle Installation"
            install_docker_universal
            ;;
    esac
    
    # Verifiziere Installation
    if ! verify_docker_installation; then
        enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
        return 1
    fi
    
    enhanced_log "INFO" "Docker erfolgreich installiert und konfiguriert"
    return 0
}

# Docker für Debian/Ubuntu
install_docker_debian_ubuntu() {
    local distro="$1"
    
    enhanced_log "INFO" "Installiere Docker für ${distro}"
    
    # Entferne alte Docker-Versionen
    apt-get remove -y docker docker-engine docker.io containerd runc >/dev/null 2>&1 || true
    
    # Installiere Abhängigkeiten
    apt-get update >/dev/null 2>&1 || {
        enhanced_log "WARN" "apt-get update fehlgeschlagen"
    }
    
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Konnte Abhängigkeiten nicht installieren"
        return 1
    }
    
    # Docker GPG-Schlüssel hinzufügen
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "${keyring_dir}"
    
    if ! curl -fsSL "https://download.docker.com/linux/${distro}/gpg" | \
         gpg --dearmor -o "${keyring_dir}/docker.gpg" 2>/dev/null; then
        enhanced_log "ERROR" "Konnte Docker GPG-Schlüssel nicht hinzufügen"
        return 1
    fi
    
    chmod a+r "${keyring_dir}/docker.gpg"
    
    # Docker-Repository hinzufügen
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    local codename
    codename=$(lsb_release -cs 2>/dev/null || echo "stable")
    
    echo "deb [arch=${arch} signed-by=${keyring_dir}/docker.gpg] https://download.docker.com/linux/${distro} ${codename} stable" | \
        tee /etc/apt/sources.list.d/docker.list >/dev/null
    
    # Docker installieren
    apt-get update >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Konnte Docker-Repository nicht aktualisieren"
        return 1
    }
    
    apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
        return 1
    }
    
    return 0
}

# Docker für RHEL-Familie
install_docker_rhel_family() {
    local distro="$1"
    
    enhanced_log "INFO" "Installiere Docker für ${distro}"
    
    # Entferne alte Docker-Versionen
    if command -v dnf >/dev/null 2>&1; then
        dnf remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine podman runc >/dev/null 2>&1 || true
        
        dnf install -y dnf-plugins-core >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Konnte DNF-Plugins nicht installieren"
            return 1
        }
        
        # Repository hinzufügen (Rocky/Alma verwenden CentOS-Repos)
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        dnf config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Konnte Docker-Repository nicht hinzufügen"
            return 1
        }
        
        dnf install -y docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
            return 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine >/dev/null 2>&1 || true
        
        yum install -y yum-utils >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Konnte YUM-Utils nicht installieren"
            return 1
        }
        
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        yum-config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Konnte Docker-Repository nicht hinzufügen"
            return 1
        }
        
        yum install -y docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
            return 1
        }
    else
        enhanced_log "ERROR" "Kein unterstützter Paketmanager gefunden"
        return 1
    fi
    
    return 0
}

# Universelle Docker-Installation (Fallback)
install_docker_universal() {
    enhanced_log "INFO" "Versuche universelle Docker-Installation"
    
    # Download und Ausführung des offiziellen Convenience-Skripts
    local install_script="${TMP_DIR}/get-docker.sh"
    
    if ! curl -fsSL https://get.docker.com -o "${install_script}"; then
        enhanced_log "ERROR" "Konnte Docker-Installationsskript nicht herunterladen"
        return 1
    fi
    
    # Skript-Validierung
    if ! grep -q "#!/bin/sh" "${install_script}"; then
        enhanced_log "ERROR" "Docker-Installationsskript ist ungültig"
        return 1
    fi
    
    chmod +x "${install_script}"
    
    # Ausführung mit Timeout
    if ! "${install_script}" >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker-Installationsskript fehlgeschlagen"
        return 1
    fi
    
    rm -f "${install_script}"
    return 0
}

# Docker-Installation verifizieren
verify_docker_installation() {
    enhanced_log "INFO" "Verifiziere Docker-Installation"
    
    # Prüfe, ob Docker-Befehl verfügbar ist
    if ! command -v docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker-Befehl nicht verfügbar"
        return 1
    fi
    
    # Starte und aktiviere Docker-Dienst
    if ! systemctl enable docker >/dev/null 2>&1; then
        enhanced_log "WARN" "Konnte Docker-Dienst nicht aktivieren"
    fi
    
    if ! systemctl start docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Konnte Docker-Dienst nicht starten"
        return 1
    fi
    
    # Warte auf Docker-Initialisierung
    local wait_count=0
    while [[ ${wait_count} -lt 30 ]]; do
        if systemctl is-active docker >/dev/null 2>&1; then
            break
        fi
        sleep 2
        ((wait_count++))
    done
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker-Dienst ist nicht aktiv"
        return 1
    fi
    
    # Teste Docker-Funktionalität
    if ! docker version >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker ist nicht funktionsfähig"
        return 1
    fi
    
    enhanced_log "INFO" "Docker-Installation erfolgreich verifiziert"
    return 0
}

# Docker Compose installieren (falls nicht über Plugin verfügbar)
install_docker_compose() {
    enhanced_log "INFO" "Prüfe Docker Compose Installation"
    
    # Prüfe Plugin-Version zuerst
    if docker compose version >/dev/null 2>&1; then
        enhanced_log "INFO" "Docker Compose Plugin ist bereits verfügbar"
        return 0
    fi
    
    # Prüfe eigenständige Version
    if command -v docker-compose >/dev/null 2>&1; then
        enhanced_log "INFO" "Docker Compose (eigenständig) ist bereits installiert"
        return 0
    fi
    
    enhanced_log "INFO" "Installiere Docker Compose"
    
    # Ermittle neueste Version
    local compose_version
    compose_version=$(curl -s "https://api.github.com/repos/docker/compose/releases/latest" | \
                     grep '"tag_name":' | cut -d'"' -f4 2>/dev/null || echo "")
    
    if [[ -z "${compose_version}" ]]; then
        compose_version="v2.21.0"  # Fallback-Version
        enhanced_log "INFO" "Verwende Fallback-Version: ${compose_version}"
    else
        enhanced_log "INFO" "Neueste Version gefunden: ${compose_version}"
    fi
    
    # Ermittle Architektur
    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        armv7l) arch="armv7" ;;
        *) 
            enhanced_log "ERROR" "Nicht unterstützte Architektur: ${arch}"
            return 1
            ;;
    esac
    
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    # Download Docker Compose
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-${os}-${arch}"
    local compose_path="/usr/local/bin/docker-compose"
    
    if ! curl -L "${compose_url}" -o "${compose_path}"; then
        enhanced_log "ERROR" "Konnte Docker Compose nicht herunterladen"
        return 1
    fi
    
    chmod +x "${compose_path}"
    
    # Verifiziere Installation
    if ! "${compose_path}" --version >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker Compose ist nicht funktionsfähig"
        rm -f "${compose_path}"
        return 1
    fi
    
    enhanced_log "INFO" "Docker Compose erfolgreich installiert"
    return 0
}

# Check-Funktionen
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        enhanced_log "ERROR" "Dieses Skript benötigt root-Rechte!"
        return 1
    fi
    enhanced_log "INFO" "Root-Check erfolgreich"
    return 0
}

check_internet() {
    enhanced_log "INFO" "Prüfe Internetverbindung..."
    
    # Mehrere Ziele testen mit Timeout
    local targets=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    local http_targets=("https://www.google.com" "https://www.cloudflare.com" "https://httpbin.org/ip")
    local connected=false
    
    # Erst ICMP-Pings versuchen
    for target in "${targets[@]}"; do
        if ping -c 1 -W 3 "${target}" >/dev/null 2>&1; then
            connected=true
            enhanced_log "INFO" "Internetverbindung via ICMP zu ${target} erfolgreich"
            break
        fi
    done
    
    # Wenn Ping fehlschlägt, versuche HTTP-Anfragen
    if [[ "${connected}" == "false" ]]; then
        for target in "${http_targets[@]}"; do
            if curl -s --connect-timeout 5 --max-time 10 "${target}" >/dev/null 2>&1; then
                connected=true
                enhanced_log "INFO" "Internetverbindung via HTTP zu ${target} erfolgreich"
                break
            fi
        done
    fi
    
    if [[ "${connected}" == "false" ]]; then
        enhanced_log "ERROR" "Keine Internetverbindung verfügbar"
        enhanced_notify "error" "Netzwerk-Problem" "Keine Internetverbindung verfügbar"
        return 1
    fi
    
    enhanced_log "INFO" "Internetverbindung erfolgreich verifiziert"
    return 0
}

check_systemd_available() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]] && systemctl --version >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

check_crontab_available() {
    if command -v crontab >/dev/null 2>&1; then
        # Prüfe, ob crontab schreibbar ist
        if crontab -l >/dev/null 2>&1 || [[ $? -eq 1 ]]; then
            return 0
        fi
    fi
    return 1
}

# Sicheres temporäres Verzeichnis
create_temp_dir() {
    # Entferne altes temporäres Verzeichnis falls vorhanden
    [[ -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"
    
    mkdir -p "${TMP_DIR}" || {
        enhanced_log "WARN" "Konnte temporäres Verzeichnis nicht erstellen, verwende /tmp"
        TMP_DIR="/tmp/globalping_install_$$"
        mkdir -p "${TMP_DIR}" || {
            enhanced_log "ERROR" "Konnte kein temporäres Verzeichnis erstellen"
            return 1
        }
    }
    
    chmod 700 "${TMP_DIR}"
    enhanced_log "INFO" "Temporäres Verzeichnis angelegt: ${TMP_DIR}"
    
    # Cleanup-Trap für temporäres Verzeichnis
    trap 'rm -rf "${TMP_DIR}" 2>/dev/null || true' EXIT
    
    return 0
}

# Erweiterte Hauptfunktion
enhanced_main() {
    local start_time
    start_time=$(date +%s)
    
    enhanced_log "INFO" "=== STARTE ERWEITERTES SERVER-SETUP ==="
    enhanced_log "INFO" "Version: ${SCRIPT_VERSION}"
    enhanced_log "INFO" "Modus: ${WEEKLY_MODE:+Wöchentlich}${WEEKLY_MODE:-Normal}"
    enhanced_log "INFO" "Startzeit: $(date)"
    enhanced_log "INFO" "========================================="
    
    # Sammle Systeminformationen früh
    get_enhanced_system_info
    
    # PHASE 1: Erweiterte Systemvalidierung
    enhanced_log "INFO" "Phase 1: Erweiterte Systemvalidierung"
    if ! enhanced_validate_system; then
        enhanced_notify "error" "Systemvalidierung" "Kritische Systemanforderungen nicht erfüllt. Setup kann nicht fortgesetzt werden."
        return 1
    fi
    
    # PHASE 2: Grundlegende Systemvorbereitung
    enhanced_log "INFO" "Phase 2: Systemvorbereitung"
    
    install_sudo || enhanced_log "WARN" "sudo-Installation fehlgeschlagen"
    
    if ! install_dependencies; then
        enhanced_log "WARN" "Abhängigkeiten-Installation teilweise fehlgeschlagen"
    fi
    
    if ! update_system; then
        enhanced_log "WARN" "Systemaktualisierung fehlgeschlagen"
    fi
    
    # PHASE 3: Swap-Konfiguration
    enhanced_log "INFO" "Phase 3: Intelligente Swap-Konfiguration"
    if ! configure_smart_swap; then
        enhanced_log "WARN" "Swap-Konfiguration fehlgeschlagen"
    fi
    
    # PHASE 4: Systemkonfiguration
    enhanced_log "INFO" "Phase 4: Systemkonfiguration"
    
    if ! configure_hostname; then
        enhanced_log "WARN" "Hostname-Konfiguration fehlgeschlagen"
    fi
    
    if [[ -n "${SSH_KEY}" ]]; then
        if ! setup_ssh_key; then
            enhanced_log "WARN" "SSH-Schlüssel-Setup fehlgeschlagen"
        fi
    fi
    
    # PHASE 5: Ubuntu Pro
    enhanced_log "INFO" "Phase 5: Ubuntu Pro Aktivierung"
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        if ! ubuntu_pro_attach; then
            enhanced_log "WARN" "Ubuntu Pro Aktivierung fehlgeschlagen"
        fi
    fi
    
    # PHASE 6: Docker-Installation
    enhanced_log "INFO" "Phase 6: Docker-System"
    
    if [[ -n "${ADOPTION_TOKEN}" ]] || ! command -v docker >/dev/null 2>&1; then
        if ! install_docker; then
            enhanced_log "ERROR" "Docker-Installation fehlgeschlagen"
            enhanced_notify "error" "Docker-Installation" "Docker konnte nicht installiert werden. Globalping-Probe nicht verfügbar."
        else
            if ! install_docker_compose; then
                enhanced_log "WARN" "Docker Compose-Installation fehlgeschlagen"
            fi
        fi
    fi
    
    # PHASE 7: Globalping-Probe
    enhanced_log "INFO" "Phase 7: Erweiterte Globalping-Probe"
    if [[ -n "${ADOPTION_TOKEN}" ]]; then
        if ! install_enhanced_globalping_probe; then
            enhanced_log "ERROR" "Globalping-Probe-Installation fehlgeschlagen"
            enhanced_notify "error" "Globalping-Probe" "Installation der Globalping-Probe fehlgeschlagen"
        fi
    else
        enhanced_log "INFO" "Kein Adoption-Token - überspringe Globalping-Probe"
    fi
    
    # PHASE 8: Auto-Update-Konfiguration
    enhanced_log "INFO" "Phase 8: Erweiterte Auto-Update-Konfiguration"
    if ! setup_enhanced_auto_update; then
        enhanced_log "WARN" "Auto-Update-Einrichtung fehlgeschlagen"
    fi
    
    # PHASE 9: Kritische Updates
    enhanced_log "INFO" "Phase 9: Kritische Updates und Reboot-Check"
    if [[ "${NO_REBOOT:-}" != "true" ]]; then
        if ! check_critical_updates; then
            enhanced_log "WARN" "Update-Check fehlgeschlagen"
        fi
        
        # Wenn Reboot geplant ist, beende hier
        if [[ "${REBOOT_REQUIRED}" == "true" ]]; then
            enhanced_log "INFO" "Reboot geplant - Setup wird nach Neustart fortgesetzt"
            enhanced_notify "error" "System-Reboot" "System wird nach Updates neu gestartet. Setup wird automatisch fortgesetzt."
            return 0
        fi
    else
        enhanced_log "INFO" "Reboot-Check übersprungen (--no-reboot)"
    fi
    
    # PHASE 10: Systemoptimierung
    enhanced_log "INFO" "Phase 10: Erweiterte Systemoptimierung"
    if ! perform_enhanced_system_cleanup; then
        enhanced_log "WARN" "Systemreinigung fehlgeschlagen"
    fi
    
    # PHASE 11: Abschlussdiagnose
    enhanced_log "INFO" "Phase 11: Abschlussdiagnose"
    if ! run_enhanced_diagnostics; then
        enhanced_log "WARN" "Abschlussdiagnose ergab Probleme"
    fi
    
    # PHASE 12: Zusammenfassung
    enhanced_log "INFO" "Phase 12: Abschluss und Zusammenfassung"
    create_enhanced_summary
    
    # Berechne Ausführungszeit
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    enhanced_log "INFO" "=== ERWEITERTES SERVER-SETUP ABGESCHLOSSEN ==="
    enhanced_log "INFO" "Ausführungszeit: ${duration} Sekunden"
    enhanced_log "INFO" "Abschlusszeit: $(date)"
    enhanced_log "INFO" "=============================================="
    
    # Erfolgreiche Installation-Benachrichtigung
    if [[ "${WEEKLY_MODE}" != "true" ]]; then
        enhanced_notify "install_success" "Installation abgeschlossen" "Server erfolgreich eingerichtet in ${duration} Sekunden.

Konfigurierte Features:
${ADOPTION_TOKEN:+✓ Globalping-Probe}
${TELEGRAM_TOKEN:+✓ Telegram-Benachrichtigungen}
${SSH_KEY:+✓ SSH-Zugang}
✓ Automatische Wartung
✓ Intelligente Swap-Konfiguration"
    fi
    
    return 0
}

# Erweiterte Zusammenfassung (vereinfacht für Platz)
create_enhanced_summary() {
    local summary_file="/root/enhanced_setup_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    enhanced_log "INFO" "Erstelle erweiterte Zusammenfassung: ${summary_file}"
    
    {
        echo "=========================================="
        echo "    ERWEITERTE SERVER SETUP ZUSAMMENFASSUNG"
        echo "=========================================="
        echo "Datum: $(date)"
        echo "Skript-Version: ${SCRIPT_VERSION}"
        echo "Hostname: $(hostname 2>/dev/null || echo 'unbekannt')"
        echo "Land: ${COUNTRY}, IP: ${PUBLIC_IP}"
        echo "Globalping-Probe: ${ADOPTION_TOKEN:+Installiert}${ADOPTION_TOKEN:-Nicht installiert}"
        echo "Telegram: ${TELEGRAM_TOKEN:+Konfiguriert}${TELEGRAM_TOKEN:-Nicht konfiguriert}"
        echo "Auto-Update: Wöchentlich aktiv"
        echo "=========================================="
    } > "${summary_file}"
    
    echo "=== SETUP ERFOLGREICH ABGESCHLOSSEN ==="
    echo "Details: ${summary_file}"
    echo "Automatische Wartung: Wöchentlich geplant"
    echo "========================================"
    
    return 0
}

# Erweiterte Initialisierung
initialize_enhanced_script() {
    # Sichere Umgebung
    umask 022
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    
    # Log-System initialisieren
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    # Script-Lock für Instanz-Kontrolle
    local lock_file="/var/lock/globalping-install-enhanced.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            enhanced_log "ERROR" "Script läuft bereits (PID: ${lock_pid})"
            exit 1
        else
            rm -f "${lock_file}"
        fi
    fi
    
    echo "$$" > "${lock_file}"
    
    # Cleanup-Trap (nur einmal setzen)
    trap 'enhanced_cleanup_and_exit $?' EXIT
    
    enhanced_log "INFO" "Erweiterte Script-Initialisierung abgeschlossen (PID: $$)"
}

# Erweiterte Cleanup-Funktion
enhanced_cleanup_and_exit() {
    local exit_code="$1"
    
    # Entferne Lock-Files
    rm -f "/var/lock/globalping-install-enhanced.lock" 2>/dev/null || true
    rm -f "/tmp/globalping_auto_update.lock" 2>/dev/null || true
    
    # Temporäre Dateien aufräumen
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    
    # Debug-Modus beenden
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        set +x
        [[ -n "${BASH_XTRACEFD}" ]] && exec 19>&- 2>/dev/null || true
    fi
    
    # Abschluss-Log
    if [[ ${exit_code} -eq 0 ]]; then
        enhanced_log "INFO" "Script erfolgreich beendet"
    else
        enhanced_log "ERROR" "Script mit Fehler beendet (Exit-Code: ${exit_code})"
    fi
    
    exit "${exit_code}"
}

# Script-Haupt-Eingang (Enhanced)
enhanced_script_main() {
    # Globale Start-Zeit für Performance-Tracking
    local start_time
    start_time=$(date +%s)
    export start_time
    
    # Erweiterte Initialisierung
    initialize_enhanced_script
    
    # Erweiterte Error-Handler
    trap 'enhanced_error_handler ${LINENO} $?' ERR
    
    # Validiere Systemvoraussetzungen
    if ! check_root; then
        enhanced_log "ERROR" "Root-Rechte erforderlich"
        exit 1
    fi
    
    if ! check_internet; then
        enhanced_log "ERROR" "Internetverbindung erforderlich"
        exit 1
    fi
    
    # Temporäres Verzeichnis erstellen
    if ! create_temp_dir; then
        enhanced_log "ERROR" "Konnte temporäres Verzeichnis nicht erstellen"
        exit 1
    fi
    
    # Verarbeite erweiterte Argumente
    process_enhanced_args "$@"
    
    # Führe erweiterte Hauptfunktion aus
    enhanced_main
}

# Umgebungsvariablen-Support (Backward Compatibility)
load_environment_variables() {
    # Übernehme Umgebungsvariablen falls gesetzt (nur wenn noch nicht durch Argumente gesetzt)
    [[ -z "${ADOPTION_TOKEN}" && -n "${ADOPTION_TOKEN:-}" ]] && ADOPTION_TOKEN="${ADOPTION_TOKEN}"
    [[ -z "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_TOKEN:-}" ]] && TELEGRAM_TOKEN="${TELEGRAM_TOKEN}"
    [[ -z "${TELEGRAM_CHAT}" && -n "${TELEGRAM_CHAT:-}" ]] && TELEGRAM_CHAT="${TELEGRAM_CHAT}"
    [[ -z "${UBUNTU_PRO_TOKEN}" && -n "${UBUNTU_PRO_TOKEN:-}" ]] && UBUNTU_PRO_TOKEN="${UBUNTU_PRO_TOKEN}"
    [[ -z "${SSH_KEY}" && -n "${SSH_KEY:-}" ]] && SSH_KEY="${SSH_KEY}"
    
    if [[ -n "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "INFO" "Adoption-Token aus Umgebungsvariable geladen"
    fi
    if [[ -n "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]]; then
        enhanced_log "INFO" "Telegram-Konfiguration aus Umgebungsvariablen geladen"
    fi
}

# ===========================================
# SCRIPT EXECUTION START (ENHANCED)
# ===========================================

# Prüfe, ob Script direkt ausgeführt wird (Enhanced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script wird direkt ausgeführt
    
    # Lade Umgebungsvariablen für Backward Compatibility
    load_environment_variables
    
    # Starte erweiterte Hauptfunktion
    enhanced_script_main "$@"
else
    # Script wird gesourced - nur Funktionen laden
    enhanced_log "INFO" "Erweiterte Script-Funktionen geladen (gesourced)"
fi

# ===========================================
# END OF ENHANCED SCRIPT
# ===========================================

# Erweiterte Version-Info
# Version: 2025.06.07-enhanced
# Features: Erweiterte Automatisierung, intelligente Swap-Konfiguration,
#           robuste Fehlerbehandlung, erweiterte Telegram-Benachrichtigungen,
#           CPU-Hang-Schutz, automatische Reboots, absolute Speicherplatz-Schwellwerte
# Kompatibilität: Ubuntu 18.04+, Debian 9+, RHEL/CentOS 7+, Rocky/Alma 8+, Fedora 30+