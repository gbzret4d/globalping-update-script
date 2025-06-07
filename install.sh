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
readonly CRON_JOB="0 0 * * 0 /usr/local/bin/globalping-maintenance"
readonly AUTO_UPDATE_CRON="0 0 * * 0 /usr/local/bin/install_globalping.sh --auto-update"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"
readonly SCRIPT_VERSION="2025.06.07"

# Initialisiere Variablen
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""
DEBUG_MODE="false"
# =============================================
# FUNKTIONEN
# =============================================

# Error Handling
error_handler() {
    local line_number="$1"
    local error_code="${2:-1}"
    log "KRITISCHER FEHLER in Zeile ${line_number}, Exit-Code: ${error_code}"
    notify error "❌ Installation fehlgeschlagen in Zeile ${line_number}"
    
    # Cleanup bei Fehler
    cleanup_on_error
    exit "${error_code}"
}

# Cleanup-Funktion für Fehlerbehandlung
cleanup_on_error() {
    if [[ -d "${TMP_DIR:-}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
    
    # Stoppe laufende Operationen
    if pgrep -f "docker pull" >/dev/null 2>&1; then
        pkill -f "docker pull" || true
    fi
}

# Verbessertes Logging-System
log() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Stelle sicher, dass Log-Verzeichnis existiert
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    echo "[${timestamp}] ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || {
        echo "[${timestamp}] ${message}" >&2
    }
}

# Robuste Telegram-Benachrichtigung
notify() {
    local level="$1"
    local message="$2"
    local emoji=""
    local title=""

    case "${level}" in
        info) emoji="📄"; title="Benachrichtigung" ;;
        warn) emoji="⚠️"; title="Warnung" ;;
        error) emoji="❌"; title="Fehler" ;;
        success) emoji="✅"; title="Erfolg" ;;
        *) emoji="ℹ️"; title="Info" ;;
    esac

    if [[ -n "${TELEGRAM_TOKEN:-}" && -n "${TELEGRAM_CHAT:-}" ]]; then
        # Escape-Sonderzeichen für Telegram
        local escaped_message
        escaped_message=$(printf '%s' "${message}" | sed 's/[_*\[\]()~`>#+=|{}.!-]/\\&/g')
        
        # Verwende timeout für curl
        timeout 10 curl -s -X POST "${TELEGRAM_API_URL}${TELEGRAM_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT}" \
            -d "text=${emoji} [${title}] ${escaped_message}" \
            -d "parse_mode=MarkdownV2" \
            --max-time 5 \
            --retry 2 >/dev/null 2>&1 || {
            log "Warnung: Telegram-Benachrichtigung fehlgeschlagen"
        }
    fi
}
# Verbesserte Sudo-Installation
install_sudo() {
    log "Prüfe, ob sudo installiert ist..."
    
    # Prüfe, ob sudo installiert ist
    if command -v sudo >/dev/null 2>&1; then
        log "sudo ist bereits installiert"
        return 0
    fi
    
    log "sudo ist nicht installiert. Installiere..."
    
    # Installiere sudo je nach Distribution
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        apt-get update >/dev/null 2>&1 || {
            log "Warnung: apt-get update fehlgeschlagen"
        }
        apt-get install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/Neuere RHEL-basierte Systeme
        dnf install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS/Rocky/Alma
        yum install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    else
        log "Kein unterstützter Paketmanager gefunden. Kann sudo nicht installieren."
        return 1
    fi
    
    # Prüfe, ob sudo jetzt installiert ist
    if command -v sudo >/dev/null 2>&1; then
        log "sudo erfolgreich installiert"
        return 0
    else
        log "Fehler: sudo konnte nicht installiert werden"
        return 1
    fi
}

# Robuste Root-Prüfung
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log "FEHLER: Dieses Skript benötigt root-Rechte!"
        log "Führen Sie das Skript mit 'sudo' oder als root-Benutzer aus."
        return 1
    fi
    log "Root-Check erfolgreich"
    return 0
}

# Verbesserte Internetverbindungsprüfung
check_internet() {
    log "Prüfe Internetverbindung..."
    
    # Mehrere Ziele testen mit Timeout
    local targets=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    local http_targets=("https://www.google.com" "https://www.cloudflare.com" "https://httpbin.org/ip")
    local connected=false
    
    # Erst ICMP-Pings versuchen
    for target in "${targets[@]}"; do
        if timeout 5 ping -c 1 -W 3 "${target}" >/dev/null 2>&1; then
            connected=true
            log "Internetverbindung via ICMP zu ${target} erfolgreich"
            break
        fi
    done
    
    # Wenn Ping fehlschlägt, versuche HTTP-Anfragen
    if [[ "${connected}" == "false" ]]; then
        for target in "${http_targets[@]}"; do
            if timeout 10 curl -s --connect-timeout 5 --max-time 10 "${target}" >/dev/null 2>&1; then
                connected=true
                log "Internetverbindung via HTTP zu ${target} erfolgreich"
                break
            fi
        done
    fi
    
    if [[ "${connected}" == "false" ]]; then
        log "FEHLER: Keine Internetverbindung verfügbar"
        log "Überprüfen Sie Ihre Netzwerkeinstellungen und versuchen Sie es erneut."
        notify error "❌ Keine Internetverbindung verfügbar"
        return 1
    fi
    
    log "Internetverbindung erfolgreich verifiziert"
    return 0
}

# Sicheres temporäres Verzeichnis
create_temp_dir() {
    # Entferne altes temporäres Verzeichnis falls vorhanden
    [[ -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"
    
    mkdir -p "${TMP_DIR}" || {
        log "Warnung: Konnte temporäres Verzeichnis nicht erstellen, verwende /tmp"
        TMP_DIR="/tmp/globalping_install_$$"
        mkdir -p "${TMP_DIR}" || {
            log "Fehler: Konnte kein temporäres Verzeichnis erstellen"
            return 1
        }
    }
    
    chmod 700 "${TMP_DIR}"
    log "Temporäres Verzeichnis angelegt: ${TMP_DIR}"
    
    # Cleanup-Trap für temporäres Verzeichnis
    trap 'rm -rf "${TMP_DIR}" 2>/dev/null || true' EXIT
    
    return 0
}
# Verbesserte Hostname-Konfiguration
configure_hostname() {
    log "Konfiguriere Hostname im Format: Land-ISP-ASN-globalping-IPOktett"
    
    # Hole IP-Adresse mit mehreren Fallback-Optionen
    local ip_address=""
    local ip_services=("https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com" "https://ipecho.net/plain")
    
    for service in "${ip_services[@]}"; do
        ip_address=$(timeout 10 curl -s -4 --connect-timeout 5 "${service}" 2>/dev/null | tr -d '\n\r' | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || echo "")
        if [[ -n "${ip_address}" && "${ip_address}" != "0.0.0.0" ]]; then
            log "IP-Adresse erfolgreich ermittelt: ${ip_address}"
            break
        fi
    done
    
    if [[ -z "${ip_address}" || "${ip_address}" == "0.0.0.0" ]]; then
        log "Warnung: Konnte öffentliche IP nicht ermitteln, verwende Fallback"
        ip_address="127.0.0.1"
    fi
    
    local ip_first_octet
    ip_first_octet=$(echo "${ip_address}" | cut -d '.' -f1)
    
    # Sammle Geo-Informationen mit verbesserter Fehlerbehandlung
    local country="XX"
    local asn="0"
    local isp="unknown"
    
    # Primäre Methode: ipinfo.io
    log "Versuche Geo-Daten von ipinfo.io zu holen..."
    local ipinfo_response
    ipinfo_response=$(timeout 15 curl -s --connect-timeout 5 "https://ipinfo.io/json" 2>/dev/null || echo "")
    
    if [[ -n "${ipinfo_response}" ]] && echo "${ipinfo_response}" | grep -q '"country"'; then
        country=$(echo "${ipinfo_response}" | grep -o '"country": *"[^"]*"' | cut -d'"' -f4 | head -1)
        local asn_raw
        asn_raw=$(echo "${ipinfo_response}" | grep -o '"org": *"[^"]*"' | cut -d'"' -f4 | head -1)
        
        if [[ -n "${asn_raw}" ]]; then
            asn=$(echo "${asn_raw}" | grep -o "AS[0-9]*" | sed 's/AS//' | head -1)
            isp=$(echo "${asn_raw}" | sed 's/^AS[0-9]* //' | tr ' ' '-' | tr -cd '[:alnum:]-' | cut -c1-20)
        fi
        
        log "ipinfo.io: Land=${country}, ASN=${asn}, ISP=${isp}"
    else
        # Fallback: ip-api.com
        log "ipinfo.io fehlgeschlagen, versuche ip-api.com..."
        local ip_api_response
        ip_api_response=$(timeout 15 curl -s --connect-timeout 5 "http://ip-api.com/json/${ip_address}" 2>/dev/null || echo "")
        
        if [[ -n "${ip_api_response}" ]] && echo "${ip_api_response}" | grep -q '"status":"success"'; then
            country=$(echo "${ip_api_response}" | grep -o '"countryCode": *"[^"]*"' | cut -d'"' -f4 | head -1)
            asn=$(echo "${ip_api_response}" | grep -o '"as": *"[^"]*"' | cut -d'"' -f4 | grep -o "AS[0-9]*" | sed 's/AS//' | head -1)
            isp=$(echo "${ip_api_response}" | grep -o '"isp": *"[^"]*"' | cut -d'"' -f4 | tr ' ' '-' | tr -cd '[:alnum:]-' | cut -c1-20)
            
            log "ip-api.com: Land=${country}, ASN=${asn}, ISP=${isp}"
        else
            log "Beide API-Anfragen fehlgeschlagen, verwende Standardwerte"
        fi
    fi
    
    # Validierung und Bereinigung
    [[ -z "${country}" || "${country}" == "null" ]] && country="XX"
    [[ -z "${asn}" || "${asn}" == "null" ]] && asn="0"
    [[ -z "${isp}" || "${isp}" == "null" ]] && isp="unknown"
    
    # ISP-Name validieren und kürzen
    isp=$(echo "${isp}" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]-' | cut -c1-15)
    [[ -z "${isp}" ]] && isp="unknown"
    
    # Hostname generieren
    local new_hostname="${country}-${isp}-${asn}-globalping-${ip_first_octet}"
    
    # Hostname-Länge auf DNS-Limit (63 Zeichen) beschränken
    if [[ ${#new_hostname} -gt 63 ]]; then
        # Kürze ISP-Teil dynamisch
        local max_isp_length=$((63 - ${#country} - ${#asn} - 13 - ${#ip_first_octet}))
        if [[ ${max_isp_length} -gt 0 ]]; then
            isp="${isp:0:${max_isp_length}}"
            new_hostname="${country}-${isp}-${asn}-globalping-${ip_first_octet}"
        else
            # Fallback: nur Land und IP
            new_hostname="${country}-globalping-${ip_first_octet}"
        fi
        log "Hostname gekürzt auf: ${new_hostname}"
    fi
    
    # Hostname setzen
    log "Setze Hostname: ${new_hostname}"
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "${new_hostname}" || {
            log "hostnamectl fehlgeschlagen, versuche alternative Methode"
            hostname "${new_hostname}"
            echo "${new_hostname}" > /etc/hostname
        }
    else
        hostname "${new_hostname}"
        echo "${new_hostname}" > /etc/hostname
    fi
    
    # Hostname in /etc/hosts eintragen
    if [[ -f /etc/hosts ]]; then
        # Entferne alte 127.0.1.1 Einträge
        sed -i '/^127\.0\.1\.1/d' /etc/hosts
        echo "127.0.1.1 ${new_hostname}" >> /etc/hosts
        log "Hostname in /etc/hosts eingetragen"
    fi
    
    # Verifikation
    local current_hostname
    current_hostname=$(hostname 2>/dev/null || echo "unknown")
    if [[ "${current_hostname}" == "${new_hostname}" ]]; then
        log "Hostname erfolgreich konfiguriert: ${new_hostname}"
        notify info "🏷️ Hostname konfiguriert: ${new_hostname}"
        return 0
    else
        log "Warnung: Hostname-Verifikation fehlgeschlagen"
        return 1
    fi
}
# Zufälliges Zeitoffset für verteilte Updates
generate_random_offset() {
    # Generiere zufällige Stunde (0-23) und Minute (0-59)
    local random_hour=$((RANDOM % 24))
    local random_minute=$((RANDOM % 60))
    
    printf "%02d:%02d" "${random_hour}" "${random_minute}"
}

# Verbesserte Crontab-Prüfung
check_crontab_available() {
    if command -v crontab >/dev/null 2>&1; then
        # Teste, ob crontab funktioniert
        if crontab -l >/dev/null 2>&1 || [[ $? -eq 1 ]]; then
            return 0
        fi
    fi
    return 1
}

# Verbesserte systemd-Prüfung  
check_systemd_available() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]] && systemctl --version >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Robuste Auto-Update-Einrichtung
setup_auto_update() {
    log "Richte automatische Skript-Updates ein"
    
    # Ermittle aktuellen Skriptpfad sicher
    local current_script=""
    
    # Methode 1: Verwende readlink auf $0
    if command -v readlink >/dev/null 2>&1 && [[ -n "${0}" && "${0}" != "bash" && "${0}" != "-bash" ]]; then
        current_script=$(readlink -f "${0}" 2>/dev/null || echo "")
    fi
    
    # Methode 2: Suche nach install.sh im aktuellen Verzeichnis
    if [[ -z "${current_script}" || ! -f "${current_script}" ]]; then
        local search_paths=("./install.sh" "$(pwd)/install.sh" "/root/install.sh")
        for path in "${search_paths[@]}"; do
            if [[ -f "${path}" && -r "${path}" ]]; then
                current_script=$(readlink -f "${path}" 2>/dev/null || echo "${path}")
                break
            fi
        done
    fi
    
    # Methode 3: Download als letzter Ausweg
    if [[ -z "${current_script}" || ! -f "${current_script}" ]]; then
        log "Kann aktuelles Skript nicht finden, lade es herunter..."
        current_script="${TMP_DIR}/downloaded_install.sh"
        if ! timeout 30 curl -s -o "${current_script}" "${SCRIPT_URL}"; then
            log "Fehler: Konnte Skript nicht herunterladen"
            return 1
        fi
        chmod +x "${current_script}"
    fi
    
    # Validiere gefundenes Skript
    if [[ ! -f "${current_script}" || ! -r "${current_script}" ]]; then
        log "Fehler: Konnte kein gültiges Skript für Auto-Update finden"
        return 1
    fi
    
    log "Verwende Skript: ${current_script}"
    
    # Erstelle Zielverzeichnis
    mkdir -p "$(dirname "${SCRIPT_PATH}")" || {
        log "Fehler: Konnte Verzeichnis für Skript nicht erstellen"
        return 1
    }
    
    # Installiere Skript
    if [[ "${current_script}" != "${SCRIPT_PATH}" ]]; then
        cp "${current_script}" "${SCRIPT_PATH}" || {
            log "Fehler: Konnte Skript nicht nach ${SCRIPT_PATH} kopieren"
            return 1
        }
        chmod +x "${SCRIPT_PATH}"
        log "Skript nach ${SCRIPT_PATH} installiert"
    fi
    
    # Zufälliges Zeitoffset generieren
    local time_offset
    time_offset=$(generate_random_offset)
    log "Zufälliges Zeitoffset für Updates: ${time_offset}"
    
    # Entferne alte Update-Mechanismen
    remove_old_update_schedulers
    
    # Versuche verschiedene Scheduling-Methoden
    local update_scheduled=false
    
    # Option 1: systemd timer (bevorzugt)
    if [[ "${update_scheduled}" == "false" ]] && check_systemd_available; then
        if setup_systemd_timer "${time_offset}"; then
            log "Auto-Update via systemd timer eingerichtet"
            update_scheduled=true
        fi
    fi
    
    # Option 2: crontab
    if [[ "${update_scheduled}" == "false" ]] && check_crontab_available; then
        if setup_crontab_update "${time_offset}"; then
            log "Auto-Update via crontab eingerichtet"
            update_scheduled=true
        fi
    fi
    
    # Option 3: anacron (cron.weekly)
    if [[ "${update_scheduled}" == "false" ]] && check_anacron_available; then
        if setup_anacron_update; then
            log "Auto-Update via anacron eingerichtet"
            update_scheduled=true
        fi
    fi
    
    if [[ "${update_scheduled}" == "true" ]]; then
        notify info "🔄 Automatische Updates aktiviert (${time_offset})"
    else
        log "Warnung: Konnte keinen Auto-Update-Mechanismus einrichten"
        notify warn "⚠️ Auto-Update konnte nicht eingerichtet werden"
        return 1
    fi
    
    return 0
}

# Robuste systemd-Timer-Einrichtung
setup_systemd_timer() {
    local time_offset="$1"
    local hour minute
    
    # Parse Zeitoffset
    if [[ "${time_offset}" =~ ^([0-9]{2}):([0-9]{2})$ ]]; then
        hour="${BASH_REMATCH[1]}"
        minute="${BASH_REMATCH[2]}"
    else
        hour="00"
        minute="00"
    fi
    
    # Erstelle Service-Datei
    cat > "${SYSTEMD_SERVICE_PATH}" << EOF
[Unit]
Description=Globalping Installation Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} --auto-update
User=root
TimeoutStartSec=1800
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    
    # Erstelle Timer-Datei
    cat > "${SYSTEMD_TIMER_PATH}" << EOF
[Unit]
Description=Weekly Globalping Installation Auto-Update
After=network-online.target

[Timer]
OnCalendar=Sun *-*-* ${hour}:${minute}:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Aktiviere Timer
    systemctl daemon-reload >/dev/null 2>&1 || {
        log "Fehler: systemctl daemon-reload fehlgeschlagen"
        return 1
    }
    
    if systemctl enable "${SYSTEMD_TIMER_PATH##*/}" >/dev/null 2>&1 && \
       systemctl start "${SYSTEMD_TIMER_PATH##*/}" >/dev/null 2>&1; then
        log "Systemd-Timer erfolgreich eingerichtet: Sonntag ${hour}:${minute}"
        return 0
    else
        log "Fehler: Konnte systemd-Timer nicht einrichten"
        # Aufräumen bei Fehler
        rm -f "${SYSTEMD_TIMER_PATH}" "${SYSTEMD_SERVICE_PATH}"
        return 1
    fi
}

# Sichere Crontab-Update-Einrichtung
setup_crontab_update() {
    local time_offset="$1"
    local hour minute
    
    # Parse Zeitoffset
    if [[ "${time_offset}" =~ ^([0-9]{2}):([0-9]{2})$ ]]; then
        hour="${BASH_REMATCH[1]}"
        minute="${BASH_REMATCH[2]}"
    else
        hour="0"
        minute="0"
    fi
    
    # Entferne führende Nullen für cron
    hour=$((10#${hour}))
    minute=$((10#${minute}))
    
    local crontab_entry="${minute} ${hour} * * 0 ${SCRIPT_PATH} --auto-update >/dev/null 2>&1"
    
    # Sichere aktuelle crontab
    local current_crontab="${TMP_DIR}/current_crontab"
    crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
    
    # Entferne alte Update-Einträge, behalte andere
    local new_crontab="${TMP_DIR}/new_crontab"
    grep -v "install_globalping.*--auto-update" "${current_crontab}" > "${new_crontab}"
    
    # Füge neuen Eintrag hinzu
    echo "${crontab_entry}" >> "${new_crontab}"
    
    # Installiere neue crontab
    if crontab "${new_crontab}" 2>/dev/null; then
        log "Crontab-Update eingerichtet: Sonntag ${hour}:${minute}"
        return 0
    else
        log "Fehler: Konnte crontab nicht aktualisieren"
        return 1
    fi
}
# Sichere Auto-Update-Ausführung
perform_auto_update() {
    log "Führe automatisches Skript-Update durch"
    
    # Prüfe, ob bereits ein Update läuft
    local lock_file="/tmp/globalping_update.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            log "Update bereits in Bearbeitung (PID: ${lock_pid}), überspringe"
            return 0
        else
            rm -f "${lock_file}"
        fi
    fi
    
    # Erstelle Lock-Datei
    echo "$$" > "${lock_file}"
    trap 'rm -f "${lock_file}"' EXIT
    
    # Temporäre Datei für neue Version
    local temp_script="${TMP_DIR}/update_script.sh"
    
    # Aktuelle Version herunterladen mit Retry-Logik
    log "Lade neueste Version von ${SCRIPT_URL} herunter"
    local download_attempts=0
    local max_attempts=3
    
    while [[ ${download_attempts} -lt ${max_attempts} ]]; do
        ((download_attempts++))
        
        if timeout 60 curl -sL --connect-timeout 10 --max-time 60 \
           -o "${temp_script}" "${SCRIPT_URL}"; then
            log "Download erfolgreich (Versuch ${download_attempts})"
            break
        else
            log "Download fehlgeschlagen (Versuch ${download_attempts}/${max_attempts})"
            if [[ ${download_attempts} -eq ${max_attempts} ]]; then
                log "Fehler: Konnte aktuelle Version nicht herunterladen"
                notify error "❌ Auto-Update fehlgeschlagen: Download-Fehler"
                return 1
            fi
            sleep 5
        fi
    done
    
    # Validiere heruntergeladene Datei
    if [[ ! -f "${temp_script}" || ! -s "${temp_script}" ]]; then
        log "Fehler: Heruntergeladene Datei ist leer oder existiert nicht"
        notify error "❌ Auto-Update fehlgeschlagen: Leere Datei"
        return 1
    fi
    
    # Prüfe Shebang
    if ! head -1 "${temp_script}" | grep -q "^#!/bin/bash"; then
        log "Fehler: Heruntergeladene Datei ist kein gültiges Bash-Skript"
        notify error "❌ Auto-Update fehlgeschlagen: Ungültiges Skript"
        return 1
    fi
    
    # Syntax-Check
    if ! bash -n "${temp_script}"; then
        log "Fehler: Syntax-Fehler in heruntergeladenem Skript"
        notify error "❌ Auto-Update fehlgeschlagen: Syntax-Fehler"
        return 1
    fi
    
    # Versionsprüfung
    local current_version=""
    local new_version=""
    
    if [[ -f "${SCRIPT_PATH}" ]]; then
        current_version=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    fi
    new_version=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    
    log "Aktuelle Version: ${current_version}"
    log "Verfügbare Version: ${new_version}"
    
    # Prüfe, ob Update notwendig ist
    if [[ "${current_version}" == "${new_version}" && "${new_version}" != "unknown" ]]; then
        log "Bereits aktuellste Version installiert, überspringe Update"
        return 0
    fi
    
    # Backup der aktuellen Version
    if [[ -f "${SCRIPT_PATH}" ]]; then
        local backup_path="${SCRIPT_PATH}.backup.$(date +%s)"
        cp "${SCRIPT_PATH}" "${backup_path}" || {
            log "Warnung: Konnte Backup nicht erstellen"
        }
        log "Backup erstellt: ${backup_path}"
    fi
    
    # Sichere wichtige Konfigurationsvariablen
    local config_backup="${TMP_DIR}/config_backup"
    if [[ -f "${SCRIPT_PATH}" ]]; then
        grep -E "^(ADOPTION_TOKEN|TELEGRAM_TOKEN|TELEGRAM_CHAT|UBUNTU_PRO_TOKEN|SSH_KEY)=" "${SCRIPT_PATH}" > "${config_backup}" 2>/dev/null || true
    fi
    
    # Skript aktualisieren
    cp "${temp_script}" "${SCRIPT_PATH}" || {
        log "Fehler: Konnte Skript nicht aktualisieren"
        notify error "❌ Auto-Update fehlgeschlagen: Kopier-Fehler"
        return 1
    }
    
    chmod +x "${SCRIPT_PATH}"
    
    # Konfiguration wiederherstellen
    if [[ -s "${config_backup}" ]]; then
        log "Stelle Konfigurationsvariablen wieder her"
        while IFS= read -r var_line; do
            if [[ -n "${var_line}" ]]; then
                local var_name
                var_name=$(echo "${var_line}" | cut -d'=' -f1)
                # Ersetze Variable im aktualisierten Skript
                sed -i "s/^${var_name}=.*/${var_line}/" "${SCRIPT_PATH}"
            fi
        done < "${config_backup}"
    fi
    
    log "Skript erfolgreich auf Version ${new_version} aktualisiert"
    notify success "✅ Auto-Update auf Version ${new_version} abgeschlossen"
    
    # Aufräumen
    rm -f "${temp_script}" "${config_backup}"
    
    return 0
}

# Alte Update-Scheduler sicher entfernen
remove_old_update_schedulers() {
    log "Entferne alte Auto-Update-Mechanismen..."
    
    # Entferne crontab-Einträge
    if check_crontab_available; then
        local current_crontab="${TMP_DIR}/current_crontab"
        local new_crontab="${TMP_DIR}/new_crontab"
        
        crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
        grep -v "install_globalping.*--auto-update" "${current_crontab}" > "${new_crontab}"
        
        if ! cmp -s "${current_crontab}" "${new_crontab}"; then
            crontab "${new_crontab}" 2>/dev/null && log "Alte crontab-Einträge bereinigt"
        fi
    fi
    
    # Entferne systemd timer und service
    if check_systemd_available; then
        if [[ -f "${SYSTEMD_TIMER_PATH}" ]]; then
            systemctl stop "$(basename "${SYSTEMD_TIMER_PATH}")" >/dev/null 2>&1 || true
            systemctl disable "$(basename "${SYSTEMD_TIMER_PATH}")" >/dev/null 2>&1 || true
            rm -f "${SYSTEMD_TIMER_PATH}"
            log "Alter systemd timer entfernt"
        fi
        
        if [[ -f "${SYSTEMD_SERVICE_PATH}" ]]; then
            systemctl stop "$(basename "${SYSTEMD_SERVICE_PATH}")" >/dev/null 2>&1 || true
            systemctl disable "$(basename "${SYSTEMD_SERVICE_PATH}")" >/dev/null 2>&1 || true
            rm -f "${SYSTEMD_SERVICE_PATH}"
            log "Alter systemd service entfernt"
        fi
        
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    
    # Entferne anacron-Skript
    if [[ -f "/etc/cron.weekly/globalping-update" ]]; then
        rm -f "/etc/cron.weekly/globalping-update"
        log "Altes anacron-Skript entfernt"
    fi
}
# Robuste Docker-Installation
install_docker() {
    log "Installiere Docker"
    
    # Prüfe, ob Docker bereits installiert und funktionsfähig ist
    if command -v docker >/dev/null 2>&1; then
        if docker --version >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
            log "Docker ist bereits installiert und aktiv"
            return 0
        else
            log "Docker ist installiert, aber nicht funktionsfähig - repariere Installation"
        fi
    fi
    
    # Erkenne Distribution sicher
    local distro_id=""
    local distro_version=""
    local distro_codename=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro_id="${ID,,}" # Kleinbuchstaben
        distro_version="${VERSION_ID}"
        distro_codename="${VERSION_CODENAME:-}"
    else
        log "Fehler: Kann Distribution nicht ermitteln"
        return 1
    fi
    
    log "Erkannte Distribution: ${distro_id} ${distro_version}"
    
    # Installiere je nach Distribution
    case "${distro_id}" in
        ubuntu|debian)
            install_docker_debian_ubuntu "${distro_id}" "${distro_codename}"
            ;;
        rhel|centos|rocky|almalinux|fedora)
            install_docker_rhel_family "${distro_id}" "${distro_version}"
            ;;
        *)
            log "Unbekannte Distribution, versuche universelle Installation"
            install_docker_universal
            ;;
    esac
    
    # Verifiziere Installation
    if ! verify_docker_installation; then
        log "Fehler: Docker-Installation fehlgeschlagen"
        return 1
    fi
    
    log "Docker erfolgreich installiert und konfiguriert"
    return 0
}

# Docker für Debian/Ubuntu
install_docker_debian_ubuntu() {
    local distro="$1"
    local codename="$2"
    
    log "Installiere Docker für ${distro}"
    
    # Entferne alte Docker-Versionen
    apt-get remove -y docker docker-engine docker.io containerd runc >/dev/null 2>&1 || true
    
    # Installiere Abhängigkeiten
    apt-get update >/dev/null 2>&1 || {
        log "Warnung: apt-get update fehlgeschlagen"
    }
    
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release >/dev/null 2>&1 || {
        log "Fehler: Konnte Abhängigkeiten nicht installieren"
        return 1
    }
    
    # Docker GPG-Schlüssel hinzufügen
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "${keyring_dir}"
    
    if ! curl -fsSL "https://download.docker.com/linux/${distro}/gpg" | \
         gpg --dearmor -o "${keyring_dir}/docker.gpg" 2>/dev/null; then
        log "Fehler: Konnte Docker GPG-Schlüssel nicht hinzufügen"
        return 1
    fi
    
    chmod a+r "${keyring_dir}/docker.gpg"
    
    # Docker-Repository hinzufügen
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    
    # Verwende Codename falls verfügbar, sonst lsb_release
    if [[ -z "${codename}" ]]; then
        codename=$(lsb_release -cs 2>/dev/null || echo "stable")
    fi
    
    echo "deb [arch=${arch} signed-by=${keyring_dir}/docker.gpg] https://download.docker.com/linux/${distro} ${codename} stable" | \
        tee /etc/apt/sources.list.d/docker.list >/dev/null
    
    # Docker installieren
    apt-get update >/dev/null 2>&1 || {
        log "Fehler: Konnte Docker-Repository nicht aktualisieren"
        return 1
    }
    
    apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin >/dev/null 2>&1 || {
        log "Fehler: Docker-Installation fehlgeschlagen"
        return 1
    }
    
    return 0
}

# Docker für RHEL-Familie
install_docker_rhel_family() {
    local distro="$1"
    local version="$2"
    
    log "Installiere Docker für ${distro} ${version}"
    
    # Entferne alte Docker-Versionen
    if command -v dnf >/dev/null 2>&1; then
        dnf remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine podman runc >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine >/dev/null 2>&1 || true
    fi
    
    # Installiere Abhängigkeiten
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y dnf-plugins-core >/dev/null 2>&1 || {
            log "Fehler: Konnte DNF-Plugins nicht installieren"
            return 1
        }
        
        # Repository hinzufügen (Rocky/Alma verwenden CentOS-Repos)
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        dnf config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            log "Fehler: Konnte Docker-Repository nicht hinzufügen"
            return 1
        }
        
        dnf install -y docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            log "Fehler: Docker-Installation fehlgeschlagen"
            return 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y yum-utils >/dev/null 2>&1 || {
            log "Fehler: Konnte YUM-Utils nicht installieren"
            return 1
        }
        
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        yum-config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            log "Fehler: Konnte Docker-Repository nicht hinzufügen"
            return 1
        }
        
        yum install -y docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            log "Fehler: Docker-Installation fehlgeschlagen"
            return 1
        }
    else
        log "Fehler: Kein unterstützter Paketmanager gefunden"
        return 1
    fi
    
    return 0
}

# Universelle Docker-Installation (Fallback)
install_docker_universal() {
    log "Versuche universelle Docker-Installation"
    
    # Download und Ausführung des offiziellen Convenience-Skripts
    local install_script="${TMP_DIR}/get-docker.sh"
    
    if ! timeout 60 curl -fsSL https://get.docker.com -o "${install_script}"; then
        log "Fehler: Konnte Docker-Installationsskript nicht herunterladen"
        return 1
    fi
    
    # Skript-Validierung
    if ! grep -q "#!/bin/sh" "${install_script}"; then
        log "Fehler: Docker-Installationsskript ist ungültig"
        return 1
    fi
    
    chmod +x "${install_script}"
    
    # Ausführung mit Timeout
    if ! timeout 600 "${install_script}" >/dev/null 2>&1; then
        log "Fehler: Docker-Installationsskript fehlgeschlagen"
        return 1
    fi
    
    rm -f "${install_script}"
    return 0
}

# Docker-Installation verifizieren
verify_docker_installation() {
    log "Verifiziere Docker-Installation"
    
    # Prüfe, ob Docker-Befehl verfügbar ist
    if ! command -v docker >/dev/null 2>&1; then
        log "Fehler: Docker-Befehl nicht verfügbar"
        return 1
    fi
    
    # Starte und aktiviere Docker-Dienst
    if ! systemctl enable docker >/dev/null 2>&1; then
        log "Warnung: Konnte Docker-Dienst nicht aktivieren"
    fi
    
    if ! systemctl start docker >/dev/null 2>&1; then
        log "Fehler: Konnte Docker-Dienst nicht starten"
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
        log "Fehler: Docker-Dienst ist nicht aktiv"
        return 1
    fi
    
    # Teste Docker-Funktionalität
    if ! timeout 30 docker version >/dev/null 2>&1; then
        log "Fehler: Docker ist nicht funktionsfähig"
        return 1
    fi
    
    # Teste Container-Ausführung
    if ! timeout 60 docker run --rm hello-world >/dev/null 2>&1; then
        log "Warnung: Docker-Container-Test fehlgeschlagen"
        # Nicht kritisch, da Netzwerkprobleme die Ursache sein können
    fi
    
    log "Docker-Installation erfolgreich verifiziert"
    return 0
}

# Docker Compose installieren (falls nicht über Plugin verfügbar)
install_docker_compose() {
    log "Prüfe Docker Compose Installation"
    
    # Prüfe Plugin-Version zuerst
    if docker compose version >/dev/null 2>&1; then
        log "Docker Compose Plugin ist bereits verfügbar"
        return 0
    fi
    
    # Prüfe eigenständige Version
    if command -v docker-compose >/dev/null 2>&1; then
        log "Docker Compose (eigenständig) ist bereits installiert"
        return 0
    fi
    
    log "Installiere Docker Compose"
    
    # Ermittle neueste Version
    local compose_version
    compose_version=$(timeout 10 curl -s "https://api.github.com/repos/docker/compose/releases/latest" | \
                     grep '"tag_name":' | cut -d'"' -f4 2>/dev/null || echo "")
    
    if [[ -z "${compose_version}" ]]; then
        compose_version="v2.21.0"  # Fallback-Version
        log "Verwende Fallback-Version: ${compose_version}"
    else
        log "Neueste Version gefunden: ${compose_version}"
    fi
    
    # Ermittle Architektur
    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        armv7l) arch="armv7" ;;
        *) 
            log "Fehler: Nicht unterstützte Architektur: ${arch}"
            return 1
            ;;
    esac
    
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    # Download Docker Compose
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-${os}-${arch}"
    local compose_path="/usr/local/bin/docker-compose"
    
    if ! timeout 120 curl -L "${compose_url}" -o "${compose_path}"; then
        log "Fehler: Konnte Docker Compose nicht herunterladen"
        return 1
    fi
    
    chmod +x "${compose_path}"
    
    # Verifiziere Installation
    if ! "${compose_path}" --version >/dev/null 2>&1; then
        log "Fehler: Docker Compose ist nicht funktionsfähig"
        rm -f "${compose_path}"
        return 1
    fi
    
    log "Docker Compose erfolgreich installiert"
    return 0
}
# Robuste Globalping-Probe Installation
install_globalping_probe() {
    log "Installiere und konfiguriere Globalping-Probe"
    
    # Validiere Voraussetzungen
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        log "Fehler: Kein Adoption-Token angegeben"
        notify error "❌ Globalping-Probe: Kein Adoption-Token angegeben"
        return 1
    fi
    
    # Validiere Token-Format (sollte alphanumerisch sein)
    if ! [[ "${ADOPTION_TOKEN}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log "Warnung: Adoption-Token hat unerwartetes Format"
    fi
    
    # Docker-Installation prüfen
    if ! command -v docker >/dev/null 2>&1; then
        log "Docker wird für Globalping-Probe benötigt, installiere..."
        if ! install_docker; then
            log "Fehler: Docker-Installation fehlgeschlagen"
            notify error "❌ Globalping-Probe: Docker-Installation fehlgeschlagen"
            return 1
        fi
    fi
    
    # Docker Compose prüfen
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
        log "Docker Compose wird benötigt, installiere..."
        if ! install_docker_compose; then
            log "Warnung: Docker Compose-Installation fehlgeschlagen, verwende docker run"
        fi
    fi
    
    # Prüfe bestehende Globalping-Container
    check_existing_globalping_containers
    
    # Erstelle Arbeitsverzeichnis
    local globalping_dir="/opt/globalping"
    if ! mkdir -p "${globalping_dir}"; then
        log "Fehler: Konnte Verzeichnis ${globalping_dir} nicht erstellen"
        return 1
    fi
    
    chmod 755 "${globalping_dir}"
    cd "${globalping_dir}" || {
        log "Fehler: Konnte nicht in ${globalping_dir} wechseln"
        return 1
    }
    
    # Erstelle Docker Compose-Konfiguration
    create_globalping_compose_config "${globalping_dir}"
    
    # Starte Globalping-Probe
    if ! start_globalping_probe "${globalping_dir}"; then
        log "Fehler: Konnte Globalping-Probe nicht starten"
        notify error "❌ Globalping-Probe-Start fehlgeschlagen"
        return 1
    fi
    
    # Warte und verifiziere
    if ! verify_globalping_probe; then
        log "Fehler: Globalping-Probe-Verifikation fehlgeschlagen"
        notify error "❌ Globalping-Probe-Verifikation fehlgeschlagen"
        return 1
    fi
    
    # Erstelle Wartungsskript
    create_globalping_maintenance
    
    log "Globalping-Probe erfolgreich installiert und gestartet"
    notify success "✅ Globalping-Probe erfolgreich eingerichtet"
    
    return 0
}

# Prüfe bestehende Globalping-Container
check_existing_globalping_containers() {
    log "Prüfe bestehende Globalping-Container"
    
    # Finde alle Container mit "globalping" im Namen
    local existing_containers
    existing_containers=$(docker ps -a --format "{{.Names}}" | grep -i globalping || true)
    
    if [[ -n "${existing_containers}" ]]; then
        log "Gefundene Globalping-Container: ${existing_containers}"
        
        # Prüfe, ob Container mit richtigem Token läuft
        while IFS= read -r container_name; do
            if [[ -n "${container_name}" ]]; then
                local current_token
                current_token=$(docker inspect "${container_name}" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}' 2>/dev/null || echo "")
                
                if [[ "${current_token}" == "${ADOPTION_TOKEN}" ]]; then
                    log "Container ${container_name} verwendet bereits den richtigen Token"
                    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
                        log "Container ${container_name} läuft bereits, aktualisiere..."
                        update_existing_globalping_container "${container_name}"
                        return 0
                    fi
                else
                    log "Container ${container_name} verwendet anderen Token, entferne..."
                    docker stop "${container_name}" >/dev/null 2>&1 || true
                    docker rm "${container_name}" >/dev/null 2>&1 || true
                fi
            fi
        done <<< "${existing_containers}"
    fi
    
    log "Keine kompatiblen Container gefunden, führe Neuinstallation durch"
}

# Aktualisiere bestehenden Container
update_existing_globalping_container() {
    local container_name="$1"
    
    log "Aktualisiere bestehenden Container: ${container_name}"
    
    # Stoppe Container
    docker stop "${container_name}" >/dev/null 2>&1 || true
    
    # Entferne Container (behalte Volume)
    docker rm "${container_name}" >/dev/null 2>&1 || true
    
    # Aktualisiere Image
    if ! docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        log "Warnung: Konnte neuestes Image nicht ziehen"
    fi
    
    log "Container wird mit neuer Konfiguration neu erstellt"
}

# Erstelle Docker Compose-Konfiguration
create_globalping_compose_config() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Erstelle Docker Compose-Konfiguration"
    
    # Erstelle Compose-Datei mit erweiterten Optionen
    cat > "${compose_file}" << EOF
version: '3.8'

services:
  globalping-probe:
    image: ghcr.io/jsdelivr/globalping-probe:latest
    container_name: globalping-probe
    restart: unless-stopped
    environment:
      - ADOPTION_TOKEN=${ADOPTION_TOKEN}
    volumes:
      - probe-data:/home/node/.globalping
    network_mode: host
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "node", "healthcheck.js"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

volumes:
  probe-data:
    driver: local
EOF
    
    # Validiere Compose-Datei
    if command -v docker-compose >/dev/null 2>&1; then
        if ! docker-compose -f "${compose_file}" config >/dev/null 2>&1; then
            log "Fehler: Docker Compose-Konfiguration ist ungültig"
            return 1
        fi
    elif docker compose version >/dev/null 2>&1; then
        if ! docker compose -f "${compose_file}" config >/dev/null 2>&1; then
            log "Fehler: Docker Compose-Konfiguration ist ungültig"
            return 1
        fi
    fi
    
    log "Docker Compose-Konfiguration erstellt: ${compose_file}"
    return 0
}

# Starte Globalping-Probe
start_globalping_probe() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Starte Globalping-Probe"
    
    cd "${globalping_dir}" || return 1
    
    # Ziehe neuestes Image
    log "Lade neuestes Globalping-Probe Image..."
    if ! timeout 300 docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        log "Warnung: Konnte neuestes Image nicht laden, verwende lokales Image"
    fi
    
    # Starte mit Docker Compose (bevorzugt) oder docker run
    if command -v docker-compose >/dev/null 2>&1; then
        if ! docker-compose -f "${compose_file}" up -d; then
            log "Fehler: Docker Compose-Start fehlgeschlagen"
            return 1
        fi
    elif docker compose version >/dev/null 2>&1; then
        if ! docker compose -f "${compose_file}" up -d; then
            log "Fehler: Docker Compose-Start fehlgeschlagen"
            return 1
        fi
    else
        # Fallback: docker run
        log "Docker Compose nicht verfügbar, verwende docker run"
        if ! start_globalping_with_docker_run; then
            return 1
        fi
    fi
    
    log "Globalping-Probe-Container gestartet"
    return 0
}

# Fallback: Starte mit docker run
start_globalping_with_docker_run() {
    log "Starte Globalping-Probe mit docker run"
    
    # Entferne eventuell vorhandenen Container
    docker stop globalping-probe >/dev/null 2>&1 || true
    docker rm globalping-probe >/dev/null 2>&1 || true
    
    # Erstelle Volume falls nicht vorhanden
    docker volume create globalping-probe-data >/dev/null 2>&1 || true
    
    # Starte Container
    if ! docker run -d \
        --name globalping-probe \
        --restart unless-stopped \
        --network host \
        --log-driver json-file \
        --log-opt max-size=10m \
        --log-opt max-file=3 \
        -e "ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
        -v globalping-probe-data:/home/node/.globalping \
        ghcr.io/jsdelivr/globalping-probe:latest; then
        log "Fehler: Konnte Container nicht mit docker run starten"
        return 1
    fi
    
    return 0
}

# Verifiziere Globalping-Probe
verify_globalping_probe() {
    log "Verifiziere Globalping-Probe"
    
    # Warte auf Container-Start
    local wait_count=0
    local max_wait=60
    
    while [[ ${wait_count} -lt ${max_wait} ]]; do
        if docker ps --format "{{.Names}}" | grep -q "^globalping-probe$"; then
            log "Container ist gestartet"
            break
        fi
        sleep 2
        ((wait_count++))
    done
    
    if [[ ${wait_count} -ge ${max_wait} ]]; then
        log "Fehler: Container wurde nicht innerhalb von ${max_wait} Sekunden gestartet"
        return 1
    fi
    
    # Prüfe Container-Status
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' globalping-probe 2>/dev/null || echo "unknown")
    
    if [[ "${container_status}" != "running" ]]; then
        log "Fehler: Container-Status ist nicht 'running': ${container_status}"
        log "Container-Logs:"
        docker logs globalping-probe 2>&1 | tail -20 | while IFS= read -r line; do
            log "  ${line}"
        done
        return 1
    fi
    
    # Warte auf Probe-Initialisierung
    log "Warte auf Probe-Initialisierung..."
    sleep 15
    
    # Prüfe Logs auf Fehler
    local error_lines
    error_lines=$(docker logs globalping-probe 2>&1 | grep -i error | wc -l || echo "0")
    
    if [[ ${error_lines} -gt 5 ]]; then
        log "Warnung: ${error_lines} Fehler in den Container-Logs gefunden"
        docker logs globalping-probe 2>&1 | grep -i error | tail -5 | while IFS= read -r line; do
            log "  ERROR: ${line}"
        done
    fi
    
    # Prüfe, ob Container gesund ist (falls Healthcheck verfügbar)
    local health_status
    health_status=$(docker inspect -f '{{.State.Health.Status}}' globalping-probe 2>/dev/null || echo "none")
    
    if [[ "${health_status}" == "unhealthy" ]]; then
        log "Warnung: Container-Healthcheck meldet 'unhealthy'"
    elif [[ "${health_status}" == "healthy" ]]; then
        log "Container-Healthcheck: healthy"
    fi
    
    log "Globalping-Probe erfolgreich verifiziert"
    return 0
}
# Erstelle verbessertes Wartungsskript
create_globalping_maintenance() {
    log "Erstelle Globalping-Wartungsskript"
    
    local maintenance_script="/usr/local/bin/globalping-maintenance"
    
    cat > "${maintenance_script}" << 'MAINTENANCE_EOF'
#!/bin/bash
set -euo pipefail

readonly LOG_FILE="/var/log/globalping-maintenance.log"
readonly GLOBALPING_DIR="/opt/globalping"
readonly CONTAINER_NAME="globalping-probe"

# Logging-Funktion
log() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] ${message}" | tee -a "${LOG_FILE}"
}

# Sicherstellen, dass Log-Verzeichnis existiert
mkdir -p "$(dirname "${LOG_FILE}")"

log "=== Starte Globalping-Wartung ==="

# Prüfe, ob Container existiert
if ! docker ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    log "FEHLER: Globalping-Container nicht gefunden"
    exit 1
fi

# Container-Status prüfen
container_status=$(docker inspect -f '{{.State.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "unknown")
log "Aktueller Container-Status: ${container_status}"

# Speicher-Verbrauch prüfen
if docker stats --no-stream "${CONTAINER_NAME}" >/dev/null 2>&1; then
    memory_usage=$(docker stats --no-stream --format "{{.MemUsage}}" "${CONTAINER_NAME}" 2>/dev/null || echo "unknown")
    log "Speicher-Verbrauch: ${memory_usage}"
fi

# Image-Update durchführen
log "Prüfe auf Image-Updates..."
if docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
    current_image_id=$(docker inspect -f '{{.Image}}' "${CONTAINER_NAME}" 2>/dev/null || echo "")
    latest_image_id=$(docker images --format "{{.ID}}" ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null | head -1 || echo "")
    
    if [[ -n "${current_image_id}" && -n "${latest_image_id}" && "${current_image_id}" != "${latest_image_id}" ]]; then
        log "Neues Image verfügbar, aktualisiere Container..."
        
        # Neustart mit Docker Compose falls verfügbar
        if [[ -f "${GLOBALPING_DIR}/docker-compose.yml" ]]; then
            cd "${GLOBALPING_DIR}" || exit 1
            if command -v docker-compose >/dev/null 2>&1; then
                docker-compose pull && docker-compose up -d
            elif docker compose version >/dev/null 2>&1; then
                docker compose pull && docker compose up -d
            fi
        else
            # Manueller Neustart
            docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
            docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
            
            # Container neu starten (vereinfacht)
            docker run -d \
                --name "${CONTAINER_NAME}" \
                --restart unless-stopped \
                --network host \
                -e "ADOPTION_TOKEN=${ADOPTION_TOKEN:-}" \
                -v globalping-probe-data:/home/node/.globalping \
                ghcr.io/jsdelivr/globalping-probe:latest
        fi
        
        log "Container erfolgreich aktualisiert"
    else
        log "Bereits neuestes Image verwendet"
    fi
else
    log "Warnung: Konnte nicht auf Updates prüfen"
fi

# Container-Logs bereinigen
log "Bereinige Container-Logs..."
docker logs "${CONTAINER_NAME}" 2>&1 | tail -1000 > "/tmp/${CONTAINER_NAME}.log" || true

# Alte Docker-Images bereinigen
log "Bereinige alte Docker-Images..."
docker image prune -af --filter "until=72h" >/dev/null 2>&1 || true

# Systemressourcen bereinigen
log "Bereinige ungenutzte Docker-Ressourcen..."
docker system prune -f --volumes --filter "until=72h" >/dev/null 2>&1 || true

# Wartungslogs rotieren
if [[ -f "${LOG_FILE}" ]] && [[ $(stat -f%z "${LOG_FILE}" 2>/dev/null || stat -c%s "${LOG_FILE}" 2>/dev/null || echo "0") -gt 10485760 ]]; then
    log "Rotiere Wartungs-Logs"
    mv "${LOG_FILE}" "${LOG_FILE}.old"
    touch "${LOG_FILE}"
fi

log "=== Globalping-Wartung abgeschlossen ==="
MAINTENANCE_EOF
    
    chmod +x "${maintenance_script}"
    
    # Teste das Wartungsskript
    if ! bash -n "${maintenance_script}"; then
        log "Fehler: Wartungsskript hat Syntax-Fehler"
        return 1
    fi
    
    # Richte Cron-Job oder systemd-Timer ein
    setup_maintenance_scheduler
    
    log "Globalping-Wartungsskript erstellt: ${maintenance_script}"
    return 0
}

# Richte Wartungsplaner ein
setup_maintenance_scheduler() {
    log "Richte Wartungsplaner ein"
    
    # Entferne alte Wartungsplaner
    remove_old_maintenance_schedulers
    
    # Bevorzuge systemd-Timer
    if check_systemd_available; then
        setup_maintenance_systemd_timer
    elif check_crontab_available; then
        setup_maintenance_crontab
    elif check_anacron_available; then
        setup_maintenance_anacron
    else
        log "Warnung: Konnte keinen Wartungsplaner einrichten"
        return 1
    fi
    
    return 0
}

# Systemd-Timer für Wartung
setup_maintenance_systemd_timer() {
    local service_file="/etc/systemd/system/globalping-maintenance.service"
    local timer_file="/etc/systemd/system/globalping-maintenance.timer"
    
    cat > "${service_file}" << EOF
[Unit]
Description=Globalping Probe Maintenance
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/globalping-maintenance
User=root
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF

    cat > "${timer_file}" << EOF
[Unit]
Description=Weekly Globalping Probe Maintenance
After=network-online.target

[Timer]
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    if systemctl enable globalping-maintenance.timer >/dev/null 2>&1 && \
       systemctl start globalping-maintenance.timer >/dev/null 2>&1; then
        log "Systemd-Timer für Wartung eingerichtet"
        return 0
    else
        log "Fehler: Konnte Systemd-Timer nicht einrichten"
        return 1
    fi
}

# Crontab für Wartung
setup_maintenance_crontab() {
    local cron_entry="0 2 * * 0 /usr/local/bin/globalping-maintenance >/dev/null 2>&1"
    
    local current_crontab="${TMP_DIR}/current_maintenance_crontab"
    local new_crontab="${TMP_DIR}/new_maintenance_crontab"
    
    crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
    grep -v "globalping-maintenance" "${current_crontab}" > "${new_crontab}"
    echo "${cron_entry}" >> "${new_crontab}"
    
    if crontab "${new_crontab}" 2>/dev/null; then
        log "Crontab für Wartung eingerichtet"
        return 0
    else
        log "Fehler: Konnte Crontab nicht einrichten"
        return 1
    fi
}

# Entferne alte Wartungsplaner
remove_old_maintenance_schedulers() {
    # Entferne Crontab-Einträge
    if check_crontab_available; then
        local current_crontab="${TMP_DIR}/current_maintenance_crontab"
        local new_crontab="${TMP_DIR}/new_maintenance_crontab"
        
        crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
        if grep -v "globalping-maintenance" "${current_crontab}" > "${new_crontab}"; then
            if ! cmp -s "${current_crontab}" "${new_crontab}"; then
                crontab "${new_crontab}" 2>/dev/null
            fi
        fi
    fi
    
    # Entferne systemd-Timer
    if check_systemd_available; then
        systemctl stop globalping-maintenance.timer >/dev/null 2>&1 || true
        systemctl disable globalping-maintenance.timer >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/globalping-maintenance.timer
        rm -f /etc/systemd/system/globalping-maintenance.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    
    # Entferne anacron
    rm -f /etc/cron.weekly/globalping-maintenance
}
# Verbesserte umfassende Systemreinigung
perform_system_cleanup() {
    log "Starte umfassende Systemreinigung"
    
    # Überprüfe Root-Rechte
    if [[ "${EUID}" -ne 0 ]]; then
        log "Fehler: Systemreinigung muss als Root ausgeführt werden"
        return 1
    fi
    
    # Erstelle Cleanup-Report
    local cleanup_report="${TMP_DIR}/cleanup_report_$(date +%Y%m%d_%H%M%S).txt"
    local permanent_report="/var/log/globalping-cleanup-$(date +%Y%m%d-%H%M%S).log"
    
    {
        echo "==== UMFASSENDE SYSTEMREINIGUNG - START $(date) ===="
        echo "Hostname: $(hostname)"
        echo "Benutzer: $(whoami)"
        echo "System: $(uname -a)"
    } > "${cleanup_report}"
    
    # PHASE 1: DIAGNOSE vor Bereinigung
    log "PHASE 1: Systemdiagnose vor Bereinigung"
    perform_pre_cleanup_diagnosis >> "${cleanup_report}"
    
    # Prüfe kritische Speichersituation
    local root_usage
    root_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    
    if [[ ${root_usage} -ge 90 ]]; then
        log "WARNUNG: Kritische Speichersituation erkannt (${root_usage}% belegt)"
        {
            echo -e "\n[NOTFALL] Kritische Speichersituation erkannt"
            perform_emergency_cleanup
        } >> "${cleanup_report}"
    fi
    
    # PHASE 2: DOCKER BEREINIGUNG
    log "PHASE 2: Docker-Ressourcen bereinigen"
    cleanup_docker_resources >> "${cleanup_report}"
    
    # PHASE 3: PAKETMANAGER BEREINIGEN
    log "PHASE 3: Paketmanager Cache bereinigen"
    cleanup_package_managers >> "${cleanup_report}"
    
    # PHASE 4: LOG-DATEIEN BEREINIGEN
    log "PHASE 4: Log-Dateien bereinigen"
    cleanup_log_files >> "${cleanup_report}"
    
    # PHASE 5: TEMPORÄRE DATEIEN BEREINIGEN
    log "PHASE 5: Temporäre Dateien bereinigen"
    cleanup_temporary_files >> "${cleanup_report}"
    
    # PHASE 6: BOOT-PARTITION BEREINIGEN
    log "PHASE 6: Boot-Partition bereinigen"
    cleanup_boot_partition >> "${cleanup_report}"
    
    # PHASE 7: SYSTEM-CACHE LEEREN
    log "PHASE 7: System-Cache leeren"
    cleanup_system_cache >> "${cleanup_report}"
    
    # PHASE 8: ERGEBNIS DOKUMENTIEREN
    log "PHASE 8: Ergebnisse dokumentieren"
    perform_post_cleanup_diagnosis >> "${cleanup_report}"
    
    # Abschlussbericht
    {
        echo -e "\n==== UMFASSENDE SYSTEMREINIGUNG - ENDE $(date) ===="
        echo "Cleanup-Report gespeichert in: ${permanent_report}"
    } >> "${cleanup_report}"
    
    # Zeige und speichere Bericht
    cat "${cleanup_report}"
    cp "${cleanup_report}" "${permanent_report}"
    
    # Benachrichtigung senden
    local final_usage
    final_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    notify success "✅ Systemreinigung abgeschlossen. Speicherverbrauch: ${final_usage}%"
    
    log "Bereinigungsbericht gespeichert in: ${permanent_report}"
    return 0
}

# Diagnose vor Bereinigung
perform_pre_cleanup_diagnosis() {
    echo -e "\n[DIAGNOSE] Speicherplatz vor Bereinigung:"
    df -h 2>/dev/null || echo "df-Befehl fehlgeschlagen"
    
    echo -e "\n[DIAGNOSE] Inode-Nutzung:"
    df -i 2>/dev/null || echo "df -i fehlgeschlagen"
    
    echo -e "\n[DIAGNOSE] Größte Verzeichnisse (Top 10):"
    timeout 30 du -hx --max-depth=2 / 2>/dev/null | sort -rh | head -10 || echo "du-Analyse fehlgeschlagen"
    
    echo -e "\n[DIAGNOSE] Größte Dateien (>100MB):"
    timeout 60 find / -xdev -type f -size +100M -exec ls -lh {} \; 2>/dev/null | \
        sort -k5,5rh | head -10 || echo "Große-Dateien-Suche fehlgeschlagen"
    
    echo -e "\n[DIAGNOSE] Speicherverbrauch:"
    free -h 2>/dev/null || echo "free-Befehl fehlgeschlagen"
    
    echo -e "\n[DIAGNOSE] Aktive Prozesse (CPU):"
    ps aux --sort=-%cpu | head -10 2>/dev/null || echo "ps-Befehl fehlgeschlagen"
}

# Docker-Ressourcen bereinigen
cleanup_docker_resources() {
    echo -e "\n[BEREINIGUNG] Docker Ressourcen..."
    
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker nicht installiert, überspringe Docker-Bereinigung"
        return 0
    fi
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        echo "Docker-Service nicht aktiv, versuche Start..."
        systemctl start docker >/dev/null 2>&1 || {
            echo "Kann Docker nicht starten, überspringe Docker-Bereinigung"
            return 0
        }
    fi
    
    echo "Docker Status vor Bereinigung:"
    docker system df 2>/dev/null || echo "docker system df fehlgeschlagen"
    
    # Sichere Globalping-Container vor Bereinigung
    local globalping_containers
    globalping_containers=$(docker ps -a --format "{{.Names}}" | grep -i globalping || true)
    
    if [[ -n "${globalping_containers}" ]]; then
        echo "Geschützte Globalping-Container: ${globalping_containers}"
    fi
    
    # Stoppe Container mit hohem Ressourcenverbrauch (außer Globalping)
    echo "Analysiere Container-Ressourcenverbrauch..."
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | \
        tail -n +2 | while IFS=$'\t' read -r container cpu_perc mem_usage; do
        if [[ -n "${container}" ]] && ! echo "${container}" | grep -qi globalping; then
            # Extrahiere CPU-Prozent (entferne %-Zeichen)
            local cpu_num
            cpu_num=$(echo "${cpu_perc}" | tr -d '%' | cut -d'.' -f1 || echo "0")
            if [[ ${cpu_num} -gt 80 ]]; then
                echo "Stoppe ressourcenintensiven Container: ${container} (CPU: ${cpu_perc})"
                docker stop "${container}" >/dev/null 2>&1 || true
            fi
        fi
    done
    
    # Bereinige ungenutzte Ressourcen (schütze Globalping)
    echo "Bereinige ungenutzte Docker-Ressourcen..."
    
    # Entferne gestoppte Container (außer Globalping)
    docker ps -a --format "{{.Names}}" | grep -v -i globalping | \
        xargs -r docker rm >/dev/null 2>&1 || true
    
    # Entferne ungenutzte Images (behalte Globalping-Images)
    docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | \
        grep -v globalping | awk '{print $2}' | \
        xargs -r docker rmi >/dev/null 2>&1 || true
    
    # Entferne ungenutzte Volumes (vorsichtig)
    docker volume ls -qf dangling=true | grep -v globalping | \
        xargs -r docker volume rm >/dev/null 2>&1 || true
    
    # Entferne Build-Cache
    docker builder prune -af >/dev/null 2>&1 || true
    
    # Bereinige Container-Logs (begrenzt)
    echo "Begrenze Container-Log-Größen..."
    docker ps -q | while IFS= read -r container_id; do
        if [[ -n "${container_id}" ]]; then
            local container_name
            container_name=$(docker inspect --format '{{.Name}}' "${container_id}" 2>/dev/null | sed 's/^.//' || echo "unknown")
            if ! echo "${container_name}" | grep -qi globalping; then
                local log_path
                log_path=$(docker inspect --format '{{.LogPath}}' "${container_id}" 2>/dev/null || echo "")
                if [[ -n "${log_path}" && -f "${log_path}" ]]; then
                    # Begrenze Log auf 1MB
                    tail -c 1048576 "${log_path}" > "${log_path}.tmp" && mv "${log_path}.tmp" "${log_path}" 2>/dev/null || true
                fi
            fi
        fi
    done
    
    echo "Docker Status nach Bereinigung:"
    docker system df 2>/dev/null || echo "docker system df fehlgeschlagen"
}

# Paketmanager bereinigen
cleanup_package_managers() {
    echo -e "\n[BEREINIGUNG] Paketmanager Cache..."
    
    # Erkenne Distribution
    local distro_id=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro_id="${ID,,}"
    fi
    
    case "${distro_id}" in
        ubuntu|debian)
            cleanup_apt_cache
            ;;
        rhel|centos|rocky|almalinux)
            cleanup_rhel_cache
            ;;
        fedora)
            cleanup_fedora_cache
            ;;
        *)
            echo "Unbekannte Distribution: ${distro_id}, versuche universelle Bereinigung"
            cleanup_universal_cache
            ;;
    esac
}

# APT Cache bereinigen (Debian/Ubuntu)
cleanup_apt_cache() {
    echo "Debian/Ubuntu: Bereinige APT-Cache"
    
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get nicht verfügbar"
        return 0
    fi
    
    # Standard-Bereinigung
    apt-get clean -y >/dev/null 2>&1 || echo "apt-get clean fehlgeschlagen"
    apt-get autoclean -y >/dev/null 2>&1 || echo "apt-get autoclean fehlgeschlagen"
    apt-get autoremove -y >/dev/null 2>&1 || echo "apt-get autoremove fehlgeschlagen"
    
    # Entferne Paket-Archive
    rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true
    
    # Sichere Kernel-Bereinigung
    cleanup_old_kernels_debian
    
    echo "APT-Cache bereinigt"
}

# Sichere Kernel-Bereinigung für Debian/Ubuntu
cleanup_old_kernels_debian() {
    local current_kernel
    current_kernel=$(uname -r)
    echo "Aktueller Kernel: ${current_kernel}"
    
    # Finde installierte Kernel (außer dem aktuellen)
    local old_kernels
    old_kernels=$(dpkg -l 'linux-image*' 2>/dev/null | grep '^ii' | awk '{print $2}' | \
                 grep -v "${current_kernel}" | grep -v "linux-image-generic" | head -n -1 || true)
    
    if [[ -n "${old_kernels}" ]]; then
        echo "Entferne alte Kernel: ${old_kernels}"
        # shellcheck disable=SC2086
        apt-get purge -y ${old_kernels} >/dev/null 2>&1 || echo "Kernel-Entfernung teilweise fehlgeschlagen"
    else
        echo "Keine alten Kernel zum Entfernen gefunden"
    fi
    
    # Entferne auch alte Header
    local old_headers
    old_headers=$(dpkg -l 'linux-headers*' 2>/dev/null | grep '^ii' | awk '{print $2}' | \
                 grep -v "${current_kernel}" | grep -v "linux-headers-generic" | head -n -1 || true)
    
    if [[ -n "${old_headers}" ]]; then
        echo "Entferne alte Kernel-Header: ${old_headers}"
        # shellcheck disable=SC2086
        apt-get purge -y ${old_headers} >/dev/null 2>&1 || echo "Header-Entfernung teilweise fehlgeschlagen"
    fi
}

# RHEL/CentOS Cache bereinigen
cleanup_rhel_cache() {
    echo "RHEL/CentOS: Bereinige YUM/DNF-Cache"
    
    if command -v dnf >/dev/null 2>&1; then
        dnf clean all >/dev/null 2>&1 || echo "dnf clean fehlgeschlagen"
        dnf autoremove -y >/dev/null 2>&1 || echo "dnf autoremove fehlgeschlagen"
        rm -rf /var/cache/dnf/* 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
        yum clean all >/dev/null 2>&1 || echo "yum clean fehlgeschlagen"
        yum autoremove -y >/dev/null 2>&1 || echo "yum autoremove fehlgeschlagen"
        rm -rf /var/cache/yum/* 2>/dev/null || true
    fi
    
    # Sichere Kernel-Bereinigung für RHEL
    cleanup_old_kernels_rhel
}

# Sichere Kernel-Bereinigung für RHEL/CentOS
cleanup_old_kernels_rhel() {
    local current_kernel
    current_kernel=$(uname -r)
    echo "Aktueller Kernel: ${current_kernel}"
    
    # Verwende package-cleanup falls verfügbar
    if command -v package-cleanup >/dev/null 2>&1; then
        package-cleanup --oldkernels --count=1 -y >/dev/null 2>&1 || echo "package-cleanup fehlgeschlagen"
    else
        # Manuelle Bereinigung
        local old_kernels
        old_kernels=$(rpm -q kernel 2>/dev/null | grep -v "${current_kernel}" | head -n -1 || true)
        
        if [[ -n "${old_kernels}" ]]; then
            echo "Entferne alte Kernel: ${old_kernels}"
            # shellcheck disable=SC2086
            rpm -e --nodeps ${old_kernels} >/dev/null 2>&1 || echo "Kernel-Entfernung fehlgeschlagen"
        fi
    fi
}

# Log-Dateien bereinigen
cleanup_log_files() {
    echo -e "\n[BEREINIGUNG] Log-Dateien..."
    
    # Sichere wichtige Logs vor Bereinigung
    local protected_logs=("globalping" "docker" "ssh")
    
    echo "Entferne alte Log-Archive..."
    find /var/log -type f \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.zip" \) \
         -mtime +7 -delete 2>/dev/null || true
    
    echo "Entferne rotierte Logs..."
    find /var/log -type f -regex ".*\.[0-9]+" -mtime +3 -delete 2>/dev/null || true
    
    echo "Kürze große Log-Dateien..."
    find /var/log -type f -size +100M -not -path "*/globalping*" | while IFS= read -r log_file; do
        if [[ -n "${log_file}" ]]; then
            # Prüfe, ob es ein geschütztes Log ist
            local is_protected=false
            for protected in "${protected_logs[@]}"; do
                if [[ "${log_file}" == *"${protected}"* ]]; then
                    is_protected=true
                    break
                fi
            done
            
            if [[ "${is_protected}" == "false" ]]; then
                echo "Kürze: ${log_file}"
                tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}" 2>/dev/null || true
            fi
        fi
    done
    
    # Crash-Dumps entfernen
    echo "Entferne Crash-Dumps..."
    find /var/crash /var/dump -type f -mtime +1 -delete 2>/dev/null || true
    
    # Systemd-Journal bereinigen (vorsichtig)
    if command -v journalctl >/dev/null 2>&1; then
        echo "Bereinige Systemd-Journal..."
        journalctl --vacuum-time=14d --vacuum-size=500M >/dev/null 2>&1 || echo "Journal-Bereinigung fehlgeschlagen"
    fi
    
    echo "Log-Dateien bereinigt"
}

# Temporäre Dateien bereinigen
cleanup_temporary_files() {
    echo -e "\n[BEREINIGUNG] Temporäre Dateien..."
    
    # Sichere Bereinigung temporärer Verzeichnisse
    echo "Bereinige /tmp und /var/tmp..."
    find /tmp -type f -atime +3 -delete 2>/dev/null || true
    find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # Entferne leere Verzeichnisse
    find /tmp /var/tmp -type d -empty -delete 2>/dev/null || true
    
    # Vim-Swap und Backup-Dateien
    echo "Entferne Editor-Artefakte..."
    find /home /root -name "*.sw[po]" -o -name ".*.sw[po]" -o -name "*~" -delete 2>/dev/null || true
    
    # Browser-Caches (vorsichtig)
    echo "Bereinige Browser-Caches..."
    find /home /root -path "*/\.cache/chromium*" -type f -atime +7 -delete 2>/dev/null || true
    find /home /root -path "*/\.cache/mozilla*" -type f -atime +7 -delete 2>/dev/null || true
    
    # Thumbnail-Caches
    find /home -name ".thumbnails" -type d -exec rm -rf {}/* \; 2>/dev/null || true
    
    # Core-Dumps
    echo "Entferne Core-Dumps..."
    find / -xdev -name "core" -o -name "core.[0-9]*" -type f -delete 2>/dev/null || true
    
    echo "Temporäre Dateien bereinigt"
}
# Boot-Partition bereinigen
cleanup_boot_partition() {
    echo -e "\n[BEREINIGUNG] Boot-Partition..."
    
    if [[ ! -d /boot ]]; then
        echo "Kein separates /boot-Verzeichnis gefunden"
        return 0
    fi
    
    local boot_usage
    boot_usage=$(df /boot 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    
    echo "/boot Verzeichnis verwendet ${boot_usage}% des verfügbaren Platzes"
    
    if [[ ${boot_usage} -lt 70 ]]; then
        echo "/boot hat ausreichend Speicherplatz"
        return 0
    fi
    
    echo "/boot ist zu ${boot_usage}% voll, bereinige..."
    
    local current_kernel
    current_kernel=$(uname -r)
    echo "Aktueller Kernel: ${current_kernel}"
    
    # Sichere Bereinigung alter Kernel-Dateien
    cleanup_boot_kernel_files "${current_kernel}"
    
    # Bei kritischem Speichermangel zusätzliche Maßnahmen
    if [[ ${boot_usage} -gt 85 ]]; then
        echo "Kritischer Speichermangel in /boot, aggressive Bereinigung..."
        cleanup_boot_emergency
    fi
    
    # Neue Belegung prüfen
    local new_boot_usage
    new_boot_usage=$(df /boot 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    echo "/boot Speicherplatz nach Bereinigung: ${new_boot_usage}%"
}

# Kernel-Dateien in /boot bereinigen
cleanup_boot_kernel_files() {
    local current_kernel="$1"
    
    echo "Bereinige Kernel-Dateien in /boot..."
    
    # Sichere Entfernung alter initramfs-Dateien
    if ls /boot/initramfs-*.img >/dev/null 2>&1; then
        ls -t /boot/initramfs-*.img | grep -v "${current_kernel}" | tail -n +3 | while IFS= read -r file; do
            if [[ -n "${file}" && -f "${file}" ]]; then
                echo "Entferne: ${file}"
                rm -f "${file}"
            fi
        done
    fi
    
    # Sichere Entfernung alter vmlinuz-Dateien
    if ls /boot/vmlinuz-* >/dev/null 2>&1; then
        ls -t /boot/vmlinuz-* | grep -v "${current_kernel}" | tail -n +3 | while IFS= read -r file; do
            if [[ -n "${file}" && -f "${file}" ]]; then
                echo "Entferne: ${file}"
                rm -f "${file}"
            fi
        done
    fi
    
    # System.map Dateien
    if ls /boot/System.map-* >/dev/null 2>&1; then
        ls -t /boot/System.map-* | grep -v "${current_kernel}" | tail -n +3 | while IFS= read -r file; do
            if [[ -n "${file}" && -f "${file}" ]]; then
                echo "Entferne: ${file}"
                rm -f "${file}"
            fi
        done
    fi
    
    # config-Dateien
    if ls /boot/config-* >/dev/null 2>&1; then
        ls -t /boot/config-* | grep -v "${current_kernel}" | tail -n +3 | while IFS= read -r file; do
            if [[ -n "${file}" && -f "${file}" ]]; then
                echo "Entferne: ${file}"
                rm -f "${file}"
            fi
        done
    fi
}

# Notfall-Bereinigung für /boot
cleanup_boot_emergency() {
    echo "Führe Notfall-Bereinigung in /boot durch..."
    
    # Entferne Rescue-Kernel falls vorhanden
    rm -f /boot/*rescue* 2>/dev/null || true
    
    # Entferne alte GRUB-Konfigurationen
    find /boot -name "*.old" -delete 2>/dev/null || true
    
    # Entferne temporäre Dateien
    find /boot -name "*.tmp" -delete 2>/dev/null || true
    
    # Komprimiere große Kernel-Images falls möglich
    find /boot -name "vmlinuz-*" -size +10M | while IFS= read -r kernel_file; do
        if [[ -n "${kernel_file}" && -f "${kernel_file}" ]] && command -v gzip >/dev/null 2>&1; then
            if [[ ! "${kernel_file}" == *"$(uname -r)"* ]]; then
                echo "Komprimiere: ${kernel_file}"
                gzip "${kernel_file}" 2>/dev/null || true
            fi
        fi
    done
    
    echo "Notfall-Bereinigung in /boot abgeschlossen"
}

# System-Cache leeren
cleanup_system_cache() {
    echo -e "\n[BEREINIGUNG] System-Cache..."
    
    # Synchronisiere Dateisystem
    echo "Synchronisiere Dateisystem..."
    sync
    
    # Font-Cache bereinigen
    if command -v fc-cache >/dev/null 2>&1; then
        echo "Bereinige Font-Cache..."
        fc-cache -f >/dev/null 2>&1 || true
    fi
    
    # Leere verschiedene System-Caches
    echo "Leere System-Caches..."
    
    # Page Cache, Dentries und Inodes (vorsichtig)
    echo "Leere Memory-Caches..."
    if [[ -w /proc/sys/vm/drop_caches ]]; then
        echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 2
        echo 2 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 2
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi
    
    # Swap optimieren falls vorhanden
    optimize_swap_usage
    
    # Locate-Datenbank aktualisieren
    if command -v updatedb >/dev/null 2>&1; then
        echo "Aktualisiere Locate-Datenbank..."
        updatedb >/dev/null 2>&1 || true
    fi
    
    # Man-Page-Cache aktualisieren
    if command -v mandb >/dev/null 2>&1; then
        echo "Aktualisiere Man-Page-Cache..."
        mandb >/dev/null 2>&1 || true
    fi
    
    echo "System-Cache bereinigt"
}

# Swap-Nutzung optimieren
optimize_swap_usage() {
    if ! grep -q "SwapTotal" /proc/meminfo; then
        echo "Kein Swap konfiguriert"
        return 0
    fi
    
    local swap_total
    swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    
    if [[ ${swap_total} -eq 0 ]]; then
        echo "Swap ist nicht aktiviert"
        return 0
    fi
    
    local swap_used
    swap_used=$(grep "SwapUsed" /proc/meminfo | awk '{print $2}' || echo "0")
    
    echo "Swap-Nutzung: ${swap_used}KB von ${swap_total}KB"
    
    if [[ ${swap_used} -gt 0 ]]; then
        echo "Optimiere Swap-Nutzung..."
        # Nur wenn genügend RAM verfügbar ist
        local mem_available
        mem_available=$(grep "MemAvailable" /proc/meminfo | awk '{print $2}' || echo "0")
        
        if [[ ${mem_available} -gt $((swap_used * 2)) ]]; then
            echo "Leere Swap (ausreichend RAM verfügbar)..."
            swapoff -a 2>/dev/null && swapon -a 2>/dev/null || {
                echo "Swap-Optimierung fehlgeschlagen"
            }
        else
            echo "Nicht genügend RAM für Swap-Optimierung verfügbar"
        fi
    fi
}

# Diagnose nach Bereinigung
perform_post_cleanup_diagnosis() {
    echo -e "\n[ERGEBNIS] Speicherplatz nach Bereinigung:"
    df -h 2>/dev/null || echo "df-Befehl fehlgeschlagen"
    
    echo -e "\n[ERGEBNIS] Inode-Nutzung nach Bereinigung:"
    df -i 2>/dev/null || echo "df -i fehlgeschlagen"
    
    echo -e "\n[ERGEBNIS] Speicherverbrauch nach Bereinigung:"
    free -h 2>/dev/null || echo "free-Befehl fehlgeschlagen"
    
    echo -e "\n[ERGEBNIS] Docker-Status nach Bereinigung:"
    if command -v docker >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
        docker system df 2>/dev/null || echo "docker system df fehlgeschlagen"
    else
        echo "Docker nicht verfügbar"
    fi
    
    # Berechne gesparten Speicherplatz
    local space_before space_after space_saved
    space_before=$(grep "vor Bereinigung:" -A 20 "${cleanup_report}" | grep "/$" | awk '{print $3}' | tr -d 'G' || echo "0")
    space_after=$(df / | awk 'NR==2 {print $3}' | numfmt --to=iec --suffix=B || echo "0")
    
    echo -e "\n[ZUSAMMENFASSUNG] Bereinigung abgeschlossen"
    echo "Verfügbarer Speicherplatz wurde optimiert"
}
# Verbesserte Notfall-Bereinigung für kritische Speichersituationen
perform_emergency_cleanup() {
    echo -e "\n[NOTFALL] Kritische Speichersituation erkannt, starte aggressive Reinigung..."
    
    # Warnung ausgeben
    log "WARNUNG: Starte Notfall-Bereinigung - aggressive Maßnahmen"
    
    # 1. SOFORTIGE LOG-BEREINIGUNG
    echo "1. Aggressive Log-Bereinigung..."
    emergency_cleanup_logs
    
    # 2. DOCKER NOTFALL-BEREINIGUNG  
    echo "2. Docker Notfall-Bereinigung..."
    emergency_cleanup_docker
    
    # 3. CACHE-VERZEICHNISSE LEEREN
    echo "3. Leere alle Cache-Verzeichnisse..."
    emergency_cleanup_caches
    
    # 4. TEMPORÄRE DATEIEN AGGRESSIV ENTFERNEN
    echo "4. Aggressive temporäre Datei-Bereinigung..."
    emergency_cleanup_temp_files
    
    # 5. PAKET-CACHES KOMPLETT LEEREN
    echo "5. Leere alle Paket-Caches..."
    emergency_cleanup_package_caches
    
    # 6. KERNEL-BEREINIGUNG (AGGRESSIV)
    echo "6. Aggressive Kernel-Bereinigung..."
    emergency_cleanup_kernels
    
    # 7. SPEICHER FORCIERT FREIGEBEN
    echo "7. Forciere Speicher-Freigabe..."
    emergency_memory_cleanup
    
    echo "[NOTFALL] Aggressive Reinigung abgeschlossen"
}

# Notfall-Log-Bereinigung
emergency_cleanup_logs() {
    # Kürze ALLE Log-Dateien auf minimal notwendige Größe
    find /var/log -type f -name "*.log" -not -path "*/globalping*" | while IFS= read -r log_file; do
        if [[ -n "${log_file}" && -f "${log_file}" ]]; then
            # Behalte nur die letzten 100 Zeilen
            tail -n 100 "${log_file}" > "${log_file}.emergency" 2>/dev/null && mv "${log_file}.emergency" "${log_file}" 2>/dev/null || true
        fi
    done
    
    # Entferne alle rotierten Logs sofort
    find /var/log -type f \( -name "*.1" -o -name "*.2" -o -name "*.3" -o -name "*.old" -o -name "*.gz" -o -name "*.bz2" \) -delete 2>/dev/null || true
    
    # Journal drastisch kürzen
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size=50M --vacuum-time=1d >/dev/null 2>&1 || true
    fi
    
    # Syslog kürzen
    if [[ -f /var/log/syslog ]]; then
        tail -n 500 /var/log/syslog > /var/log/syslog.emergency && mv /var/log/syslog.emergency /var/log/syslog || true
    fi
    
    echo "  Log-Dateien aggressiv gekürzt"
}

# Docker Notfall-Bereinigung
emergency_cleanup_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "  Docker nicht installiert"
        return 0
    fi
    
    # Stoppe alle Container außer Globalping
    docker ps --format "{{.Names}}" | grep -v -i globalping | xargs -r docker stop >/dev/null 2>&1 || true
    
    # Entferne alle gestoppten Container außer Globalping
    docker ps -a --format "{{.Names}}" | grep -v -i globalping | xargs -r docker rm >/dev/null 2>&1 || true
    
    # Entferne alle Images außer Globalping (aggressive)
    docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | grep -v globalping | awk '{print $2}' | xargs -r docker rmi -f >/dev/null 2>&1 || true
    
    # Entferne alle Volumes außer Globalping
    docker volume ls -q | grep -v globalping | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    
    # Entferne alle Networks außer Standard und Globalping
    docker network ls --format "{{.Name}}" | grep -v -E "^(bridge|host|none)$" | grep -v globalping | xargs -r docker network rm >/dev/null 2>&1 || true
    
    # Komplette System-Bereinigung
    docker system prune -af --volumes >/dev/null 2>&1 || true
    
    # Container-Log-Dateien direkt bereinigen
    if [[ -d /var/lib/docker/containers ]]; then
        find /var/lib/docker/containers -name "*-json.log" -exec truncate -s 1M {} \; 2>/dev/null || true
    fi
    
    echo "  Docker aggressiv bereinigt"
}

# Cache-Verzeichnisse Notfall-Bereinigung
emergency_cleanup_caches() {
    # Alle Benutzer-Cache-Verzeichnisse leeren
    find /home -type d -name ".cache" -exec rm -rf {}/* \; 2>/dev/null || true
    find /root -type d -name ".cache" -exec rm -rf {}/* \; 2>/dev/null || true
    
    # System-Cache-Verzeichnisse
    rm -rf /var/cache/* 2>/dev/null || true
    rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
    
    # Thumbnail-Caches
    find /home -name ".thumbnails" -type d -exec rm -rf {} \; 2>/dev/null || true
    
    # Browser-Caches komplett entfernen
    find /home -path "*/.mozilla/firefox/*/Cache*" -exec rm -rf {} \; 2>/dev/null || true
    find /home -path "*/.cache/chromium*" -exec rm -rf {} \; 2>/dev/null || true
    find /home -path "*/.cache/google-chrome*" -exec rm -rf {} \; 2>/dev/null || true
    
    echo "  Alle Cache-Verzeichnisse geleert"
}

# Temporäre Dateien Notfall-Bereinigung
emergency_cleanup_temp_files() {
    # Alle temporären Dateien ohne Alterscheck entfernen
    find /tmp -type f -delete 2>/dev/null || true
    find /var/tmp -type f -delete 2>/dev/null || true
    
    # Leere Verzeichnisse entfernen
    find /tmp /var/tmp -type d -empty -delete 2>/dev/null || true
    
    # Core-Dumps und Crash-Dateien
    find / -xdev -name "core" -o -name "core.*" -o -name "*.crash" -delete 2>/dev/null || true
    
    # Swap-Dateien von Editoren
    find /home /root -name "*.swp" -o -name "*.swo" -o -name "*~" -delete 2>/dev/null || true
    
    # Backup-Dateien
    find /home /root -name "*.bak" -o -name "*.backup" -o -name "#*#" -delete 2>/dev/null || true
    
    echo "  Temporäre Dateien aggressiv entfernt"
}

# Paket-Caches Notfall-Bereinigung
emergency_cleanup_package_caches() {
    # APT (Debian/Ubuntu)
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean >/dev/null 2>&1 || true
        apt-get autoclean >/dev/null 2>&1 || true
        apt-get autoremove --purge -y >/dev/null 2>&1 || true
        rm -rf /var/cache/apt/* 2>/dev/null || true
        rm -rf /var/lib/apt/lists/* 2>/dev/null || true
    fi
    
    # DNF/YUM (RedHat-Familie)
    if command -v dnf >/dev/null 2>&1; then
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/dnf/* 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
        yum clean all >/dev/null 2>&1 || true
        yum autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/yum/* 2>/dev/null || true
    fi
    
    # ZYPPER (SUSE)
    if command -v zypper >/dev/null 2>&1; then
        zypper clean --all >/dev/null 2>&1 || true
        rm -rf /var/cache/zypp/* 2>/dev/null || true
    fi
    
    # PACMAN (Arch)
    if command -v pacman >/dev/null 2>&1; then
        pacman -Scc --noconfirm >/dev/null 2>&1 || true
        rm -rf /var/cache/pacman/* 2>/dev/null || true
    fi
    
    echo "  Alle Paket-Caches geleert"
}

# Aggressive Kernel-Bereinigung
emergency_cleanup_kernels() {
    local current_kernel
    current_kernel=$(uname -r)
    echo "  Aktueller Kernel: ${current_kernel}"
    
    # Debian/Ubuntu
    if command -v dpkg >/dev/null 2>&1; then
        # Entferne ALLE alten Kernel außer dem aktuellen
        dpkg -l 'linux-image*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "${current_kernel}" | xargs -r apt-get purge -y >/dev/null 2>&1 || true
        dpkg -l 'linux-headers*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "${current_kernel}" | xargs -r apt-get purge -y >/dev/null 2>&1 || true
        dpkg -l 'linux-modules*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "${current_kernel}" | xargs -r apt-get purge -y >/dev/null 2>&1 || true
    fi
    
    # RHEL/CentOS
    if command -v rpm >/dev/null 2>&1; then
        # Entferne alle Kernel außer dem aktuellen
        rpm -q kernel 2>/dev/null | grep -v "${current_kernel}" | xargs -r rpm -e --nodeps >/dev/null 2>&1 || true
        rpm -q kernel-devel 2>/dev/null | grep -v "${current_kernel}" | xargs -r rpm -e --nodeps >/dev/null 2>&1 || true
    fi
    
    # Bereinige /boot aggressiv
    if [[ -d /boot ]]; then
        find /boot -name "*" -not -name "*${current_kernel}*" -not -name "grub*" -not -name "efi*" -type f -delete 2>/dev/null || true
    fi
    
    echo "  Alte Kernel aggressiv entfernt"
}

# Speicher forciert freigeben
emergency_memory_cleanup() {
    # Synchronisiere alle Dateisystem-Operationen
    sync
    sync
    sync
    
    # Leere alle Caches aggressiv
    if [[ -w /proc/sys/vm/drop_caches ]]; then
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 3
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi
    
    # Swap komplett leeren falls vorhanden und genügend RAM
    local mem_total swap_used
    mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}' || echo "0")
    swap_used=$(grep "SwapUsed" /proc/meminfo | awk '{print $2}' || echo "0")
    
    if [[ ${swap_used} -gt 0 && ${mem_total} -gt $((swap_used * 3)) ]]; then
        echo "  Leere Swap komplett..."
        swapoff -a 2>/dev/null || true
        sleep 2
        swapon -a 2>/dev/null || true
    fi
    
    # Kompaktierung der Speicher-Fragmente
    if [[ -w /proc/sys/vm/compact_memory ]]; then
        echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
    fi
    
    echo "  Speicher forciert freigegeben"
}
# Verbesserte Selbstdiagnose
run_self_diagnosis() {
    log "Führe umfassende Selbstdiagnose durch"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    # Erstelle Diagnose-Header
    echo "=== SYSTEMDIAGNOSE GESTARTET ==="
    echo "Zeitpunkt: $(date)"
    echo "Hostname: $(hostname 2>/dev/null || echo 'unbekannt')"
    echo "Benutzer: $(whoami 2>/dev/null || echo 'unbekannt')"
    echo "====================================="
    
    # 1. SPEICHERPLATZ-ANALYSE
    echo -e "\n[DIAGNOSE] Speicherplatz-Analyse"
    analyze_disk_space issues warnings info_items
    
    # 2. SPEICHER-ANALYSE
    echo -e "\n[DIAGNOSE] Arbeitsspeicher-Analyse"
    analyze_memory_usage issues warnings info_items
    
    # 3. CPU-ANALYSE
    echo -e "\n[DIAGNOSE] CPU-Auslastung"
    analyze_cpu_usage issues warnings info_items
    
    # 4. NETZWERK-GRUNDPRÜFUNG
    echo -e "\n[DIAGNOSE] Netzwerk-Grundprüfung"
    analyze_network_basics issues warnings info_items
    
    # 5. SYSTEMDIENSTE
    echo -e "\n[DIAGNOSE] Kritische Systemdienste"
    analyze_system_services issues warnings info_items
    
    # 6. DOCKER-STATUS (falls installiert)
    if command -v docker >/dev/null 2>&1; then
        echo -e "\n[DIAGNOSE] Docker-System"
        analyze_docker_status issues warnings info_items
    fi
    
    # 7. GLOBALPING-PROBE (falls installiert)
    echo -e "\n[DIAGNOSE] Globalping-Probe"
    analyze_globalping_status issues warnings info_items
    
    # 8. AUTO-UPDATE-MECHANISMUS
    echo -e "\n[DIAGNOSE] Auto-Update-Konfiguration"
    analyze_autoupdate_config issues warnings info_items
    
    # 9. SICHERHEIT-GRUNDPRÜFUNG
    echo -e "\n[DIAGNOSE] Sicherheits-Grundprüfung"
    analyze_security_basics issues warnings info_items
    
    # ERGEBNISSE ZUSAMMENFASSEN
    echo -e "\n=== DIAGNOSE-ERGEBNISSE ==="
    echo "Gefundene Probleme: ${#issues[@]}"
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
        echo -e "\n🔵 INFORMATIONEN:"
        printf ' - %s\n' "${info_items[@]}"
    fi
    
    echo "================================"
    
    # Rückgabewert basierend auf gefundenen Problemen
    if [[ ${#issues[@]} -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Speicherplatz analysieren
analyze_disk_space() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Speicherplatz..."
    
    # Root-Partition prüfen
    if ! df / >/dev/null 2>&1; then
        issues_ref+=("Kann Speicherplatz nicht ermitteln")
        return 1
    fi
    
    local root_usage
    root_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    echo "Root-Partition: ${root_usage}% belegt"
    
    if [[ ${root_usage} -ge 95 ]]; then
        issues_ref+=("Kritischer Speicherplatz: ${root_usage}% (Root)")
    elif [[ ${root_usage} -ge 85 ]]; then
        warnings_ref+=("Wenig Speicherplatz: ${root_usage}% (Root)")
    else
        info_ref+=("Speicherplatz Root: ${root_usage}% - OK")
    fi
    
    # Boot-Partition prüfen (falls vorhanden)
    if [[ -d /boot ]] && df /boot >/dev/null 2>&1; then
        local boot_usage
        boot_usage=$(df /boot | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
        echo "Boot-Partition: ${boot_usage}% belegt"
        
        if [[ ${boot_usage} -ge 90 ]]; then
            issues_ref+=("Boot-Partition kritisch voll: ${boot_usage}%")
        elif [[ ${boot_usage} -ge 75 ]]; then
            warnings_ref+=("Boot-Partition wird voll: ${boot_usage}%")
        fi
    fi
    
    # Inode-Nutzung prüfen
    local inode_usage
    inode_usage=$(df -i / | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
    echo "Inode-Nutzung: ${inode_usage}%"
    
    if [[ ${inode_usage} -ge 90 ]]; then
        issues_ref+=("Kritische Inode-Nutzung: ${inode_usage}%")
    elif [[ ${inode_usage} -ge 80 ]]; then
        warnings_ref+=("Hohe Inode-Nutzung: ${inode_usage}%")
    fi
    
    # Große Dateien suchen (>1GB)
    echo "Suche große Dateien..."
    local large_files
    large_files=$(timeout 30 find / -xdev -type f -size +1G 2>/dev/null | wc -l || echo "0")
    if [[ ${large_files} -gt 10 ]]; then
        warnings_ref+=("Viele große Dateien gefunden: ${large_files} Dateien >1GB")
    fi
}

# Arbeitsspeicher analysieren
analyze_memory_usage() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Arbeitsspeicher..."
    
    if ! free >/dev/null 2>&1; then
        issues_ref+=("Kann Speicherinformationen nicht abrufen")
        return 1
    fi
    
    local mem_total mem_available mem_usage_percent
    mem_total=$(free -m | awk '/^Mem:/ {print $2}' || echo "0")
    mem_available=$(free -m | awk '/^Mem:/ {print $7}' || echo "0")
    
    if [[ ${mem_total} -gt 0 ]]; then
        mem_usage_percent=$(( (mem_total - mem_available) * 100 / mem_total ))
    else
        mem_usage_percent=0
    fi
    
    echo "RAM: ${mem_available}MB frei von ${mem_total}MB (${mem_usage_percent}% belegt)"
    
    if [[ ${mem_available} -lt 100 ]]; then
        issues_ref+=("Kritisch wenig RAM: Nur ${mem_available}MB frei")
    elif [[ ${mem_available} -lt 500 ]]; then
        warnings_ref+=("Wenig RAM verfügbar: ${mem_available}MB frei")
    else
        info_ref+=("RAM-Nutzung: ${mem_usage_percent}% - OK")
    fi
    
    # Swap-Nutzung prüfen
    local swap_total swap_used
    swap_total=$(free -m | awk '/^Swap:/ {print $2}' || echo "0")
    swap_used=$(free -m | awk '/^Swap:/ {print $3}' || echo "0")
    
    if [[ ${swap_total} -gt 0 ]]; then
        local swap_usage_percent=$((swap_used * 100 / swap_total))
        echo "Swap: ${swap_used}MB verwendet von ${swap_total}MB (${swap_usage_percent}%)"
        
        if [[ ${swap_usage_percent} -gt 80 ]]; then
            warnings_ref+=("Hohe Swap-Nutzung: ${swap_usage_percent}%")
        fi
    else
        echo "Swap: Nicht konfiguriert"
        if [[ ${mem_total} -lt 2048 ]]; then
            warnings_ref+=("Kein Swap bei wenig RAM (${mem_total}MB)")
        fi
    fi
}

# CPU-Auslastung analysieren
analyze_cpu_usage() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere CPU-Auslastung..."
    
    local cpu_cores
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    echo "CPU-Kerne: ${cpu_cores}"
    
    # Load Average prüfen
    local load_1min load_5min load_15min
    if [[ -r /proc/loadavg ]]; then
        read -r load_1min load_5min load_15min _ _ < /proc/loadavg
        echo "Load Average: ${load_1min} (1min), ${load_5min} (5min), ${load_15min} (15min)"
        
        # Prüfe 1-Minuten-Load
        if (( $(echo "${load_1min} > ${cpu_cores} * 2" | bc -l 2>/dev/null || echo "0") )); then
            issues_ref+=("Sehr hohe CPU-Last: ${load_1min} (Kerne: ${cpu_cores})")
        elif (( $(echo "${load_1min} > ${cpu_cores}" | bc -l 2>/dev/null || echo "0") )); then
            warnings_ref+=("Hohe CPU-Last: ${load_1min} (Kerne: ${cpu_cores})")
        else
            info_ref+=("CPU-Last: ${load_1min} - OK")
        fi
    else
        warnings_ref+=("Kann Load Average nicht ermitteln")
    fi
    
    # Top-Prozesse anzeigen
    echo "Top CPU-Prozesse:"
    if command -v ps >/dev/null 2>&1; then
        ps aux --sort=-%cpu | head -6 | tail -n +2 | while IFS= read -r line; do
            echo "  ${line}"
        done
    fi
}

# Netzwerk-Grundlagen analysieren
analyze_network_basics() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Netzwerk..."
    
    # Aktive Interfaces prüfen
    local active_interfaces
    active_interfaces=$(ip link show up 2>/dev/null | grep -c "state UP" || echo "0")
    echo "Aktive Netzwerk-Interfaces: ${active_interfaces}"
    
    if [[ ${active_interfaces} -eq 0 ]]; then
        issues_ref+=("Keine aktiven Netzwerk-Interfaces")
        return 1
    fi
    
    # Default Route prüfen
    if ! ip route show default >/dev/null 2>&1; then
        issues_ref+=("Keine Standard-Route konfiguriert")
    else
        local default_gw
        default_gw=$(ip route show default | awk '{print $3}' | head -1 || echo "unbekannt")
        echo "Standard-Gateway: ${default_gw}"
        info_ref+=("Standard-Gateway konfiguriert: ${default_gw}")
    fi
    
    # DNS-Auflösung testen
    echo "Teste DNS-Auflösung..."
    if timeout 5 nslookup google.com >/dev/null 2>&1 || timeout 5 host google.com >/dev/null 2>&1; then
        info_ref+=("DNS-Auflösung funktioniert")
    else
        issues_ref+=("DNS-Auflösung fehlgeschlagen")
    fi
    
    # Internet-Konnektivität testen
    echo "Teste Internet-Konnektivität..."
    if timeout 5 ping -c 1 1.1.1.1 >/dev/null 2>&1; then
        info_ref+=("Internet-Konnektivität verfügbar")
    else
        warnings_ref+=("Internet-Konnektivität über ICMP nicht verfügbar")
    fi
}

# Systemdienste analysieren
analyze_system_services() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Systemdienste..."
    
    if ! command -v systemctl >/dev/null 2>&1; then
        warnings_ref+=("systemctl nicht verfügbar - kann Dienste nicht prüfen")
        return 0
    fi
    
    local critical_services=("systemd-journald" "systemd-logind" "dbus" "systemd-networkd" "systemd-resolved")
    local optional_services=("cron" "ssh" "sshd" "rsyslog")
    
    # Kritische Dienste prüfen
    for service in "${critical_services[@]}"; do
        if systemctl is-active "${service}" >/dev/null 2>&1; then
            echo "✓ ${service}: aktiv"
        elif systemctl list-unit-files "${service}*" >/dev/null 2>&1; then
            issues_ref+=("Kritischer Dienst nicht aktiv: ${service}")
        fi
    done
    
    # Optionale Dienste prüfen
    for service in "${optional_services[@]}"; do
        if systemctl is-active "${service}" >/dev/null 2>&1; then
            echo "✓ ${service}: aktiv"
            info_ref+=("${service} läuft")
        elif systemctl list-unit-files "${service}*" >/dev/null 2>&1; then
            echo "- ${service}: inaktiv"
        fi
    done
    
    # Failed Services prüfen
    local failed_services
    failed_services=$(systemctl --failed --no-legend 2>/dev/null | wc -l || echo "0")
    if [[ ${failed_services} -gt 0 ]]; then
        warnings_ref+=("${failed_services} Dienste im failed-Zustand")
        echo "Failed Services:"
        systemctl --failed --no-legend 2>/dev/null | head -5 | while IFS= read -r line; do
            echo "  ${line}"
        done
    fi
}

# Docker-Status analysieren
analyze_docker_status() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Docker-System..."
    
    # Docker-Dienst prüfen
    if ! systemctl is-active docker >/dev/null 2>&1; then
        issues_ref+=("Docker-Dienst ist nicht aktiv")
        return 1
    fi
    
    echo "✓ Docker-Dienst: aktiv"
    
    # Docker-Version
    local docker_version
    docker_version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',' || echo "unbekannt")
    echo "Docker-Version: ${docker_version}"
    
    # Container-Status
    local total_containers running_containers stopped_containers
    total_containers=$(docker ps -a -q 2>/dev/null | wc -l || echo "0")
    running_containers=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    stopped_containers=$((total_containers - running_containers))
    
    echo "Container: ${running_containers} laufend, ${stopped_containers} gestoppt"
    
    if [[ ${total_containers} -eq 0 ]]; then
        warnings_ref+=("Keine Docker-Container gefunden")
    else
        info_ref+=("Docker: ${running_containers}/${total_containers} Container aktiv")
    fi
    
    # Unhealthy Container prüfen
    local unhealthy_containers
    unhealthy_containers=$(docker ps --filter health=unhealthy -q 2>/dev/null | wc -l || echo "0")
    if [[ ${unhealthy_containers} -gt 0 ]]; then
        issues_ref+=("${unhealthy_containers} Container mit Status 'unhealthy'")
    fi
    
    # Docker-Speicherverbrauch
    if docker system df >/dev/null 2>&1; then
        echo "Docker Speicherverbrauch:"
        docker system df 2>/dev/null | while IFS= read -r line; do
            echo "  ${line}"
        done
    fi
}

# Globalping-Status analysieren
analyze_globalping_status() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Globalping-Probe..."
    
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker nicht verfügbar - überspringe Globalping-Prüfung"
        return 0
    fi
    
    # Prüfe, ob Globalping-Container existiert
    if ! docker ps -a --format "{{.Names}}" | grep -qi globalping; then
        warnings_ref+=("Globalping-Probe nicht installiert")
        return 0
    fi
    
    local container_name
    container_name=$(docker ps -a --format "{{.Names}}" | grep -i globalping | head -1)
    echo "Gefundener Container: ${container_name}"
    
    # Container-Status prüfen
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    echo "Container-Status: ${container_status}"
    
    case "${container_status}" in
        "running")
            info_ref+=("Globalping-Probe läuft")
            
            # Uptime prüfen
            local started_at uptime_seconds uptime_days uptime_hours
            started_at=$(docker inspect -f '{{.State.StartedAt}}' "${container_name}" 2>/dev/null || echo "")
            if [[ -n "${started_at}" ]]; then
                local started_timestamp
                started_timestamp=$(date -d "${started_at}" +%s 2>/dev/null || echo "0")
                local now_timestamp
                now_timestamp=$(date +%s)
                uptime_seconds=$((now_timestamp - started_timestamp))
                uptime_days=$((uptime_seconds / 86400))
                uptime_hours=$(( (uptime_seconds % 86400) / 3600 ))
                echo "Laufzeit: ${uptime_days} Tage, ${uptime_hours} Stunden"
                
                if [[ ${uptime_seconds} -lt 300 ]]; then
                    warnings_ref+=("Globalping-Probe kürzlich neu gestartet")
                fi
            fi
            
            # Logs auf Fehler prüfen
            local error_count
            error_count=$(docker logs --tail 100 "${container_name}" 2>&1 | grep -ci error || echo "0")
            if [[ ${error_count} -gt 5 ]]; then
                warnings_ref+=("Globalping-Probe: ${error_count} Fehler in den letzten Logs")
            fi
            ;;
        "exited"|"stopped")
            issues_ref+=("Globalping-Probe ist gestoppt")
            ;;
        "restarting")
            warnings_ref+=("Globalping-Probe wird neugestartet")
            ;;
        *)
            issues_ref+=("Globalping-Probe in unbekanntem Zustand: ${container_status}")
            ;;
    esac
    
    # Health-Check prüfen
    local health_status
    health_status=$(docker inspect -f '{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
    if [[ "${health_status}" != "none" ]]; then
        echo "Health-Status: ${health_status}"
        if [[ "${health_status}" == "unhealthy" ]]; then
            issues_ref+=("Globalping-Probe meldet 'unhealthy'")
        fi
    fi
}

# Auto-Update-Konfiguration analysieren
analyze_autoupdate_config() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Auto-Update-Konfiguration..."
    
    local update_mechanism_found=false
    local mechanisms=()
    
    # Crontab prüfen
    if check_crontab_available && crontab -l 2>/dev/null | grep -q "install_globalping.*--auto-update"; then
        update_mechanism_found=true
        mechanisms+=("crontab")
        echo "✓ Crontab Auto-Update: konfiguriert"
    fi
    
    # systemd Timer prüfen
    if check_systemd_available && systemctl is-enabled globalping-update.timer >/dev/null 2>&1; then
        update_mechanism_found=true
        mechanisms+=("systemd-timer")
        echo "✓ Systemd Timer Auto-Update: aktiv"
        
        # Timer-Status prüfen
        if systemctl is-active globalping-update.timer >/dev/null 2>&1; then
            echo "✓ Timer ist aktiv"
        else
            warnings_ref+=("Systemd Timer ist aktiviert aber nicht aktiv")
        fi
    fi
    
    # anacron prüfen
    if [[ -x "/etc/cron.weekly/globalping-update" ]]; then
        update_mechanism_found=true
        mechanisms+=("anacron")
        echo "✓ Anacron Auto-Update: konfiguriert"
    fi
    
    if [[ "${update_mechanism_found}" == "true" ]]; then
        info_ref+=("Auto-Update aktiv via: ${mechanisms[*]}")
    else
        warnings_ref+=("Kein Auto-Update-Mechanismus gefunden")
    fi
    
    # Skript-Installation prüfen
    if [[ -f "${SCRIPT_PATH}" && -x "${SCRIPT_PATH}" ]]; then
        echo "✓ Update-Skript installiert: ${SCRIPT_PATH}"
        info_ref+=("Update-Skript verfügbar")
    else
        warnings_ref+=("Update-Skript nicht gefunden: ${SCRIPT_PATH}")
    fi
}

# Sicherheits-Grundlagen analysieren
analyze_security_basics() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Sicherheits-Grundlagen..."
    
    # SSH-Konfiguration prüfen
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo "SSH-Konfiguration gefunden"
        
        # Root-Login prüfen
        if grep -q "^PermitRootLogin.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            warnings_ref+=("SSH Root-Login ist aktiviert")
        fi
        
        # Password-Authentication prüfen
        if grep -q "^PasswordAuthentication.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            warnings_ref+=("SSH Password-Authentication ist aktiviert")
        fi
        
        info_ref+=("SSH-Konfiguration vorhanden")
    fi
    
    # Firewall-Status prüfen
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 || echo "unknown")
        echo "UFW Status: ${ufw_status}"
        
        if [[ "${ufw_status}" == *"inactive"* ]]; then
            warnings_ref+=("UFW Firewall ist deaktiviert")
        else
            info_ref+=("UFW Firewall ist aktiv")
        fi
    elif command -v iptables >/dev/null 2>&1; then
        local iptables_rules
        iptables_rules=$(iptables -L 2>/dev/null | wc -l || echo "0")
        if [[ ${iptables_rules} -lt 10 ]]; then
            warnings_ref+=("Keine/wenige iptables-Regeln konfiguriert")
        fi
    fi
    
    # Automatische Updates prüfen
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        if grep -q "1" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
            info_ref+=("Automatische Sicherheitsupdates aktiviert")
        fi
    elif command -v dnf >/dev/null 2>&1; then
        if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
            info_ref+=("DNF automatische Updates aktiviert")
        fi
    fi
    
    # Fail2ban prüfen
    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            info_ref+=("Fail2ban ist aktiv")
        else
            warnings_ref+=("Fail2ban installiert aber nicht aktiv")
        fi
    fi
}
# Verbesserte Netzwerk-Diagnose
run_network_diagnosis() {
    log "Führe detaillierte Netzwerk-Diagnose durch"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== NETZWERK-DIAGNOSE GESTARTET ==="
    echo "Zeitpunkt: $(date)"
    echo "====================================="
    
    # 1. INTERFACE-ANALYSE
    echo -e "\n[NETZWERK] Interface-Analyse"
    analyze_network_interfaces issues warnings info_items
    
    # 2. ROUTING-ANALYSE
    echo -e "\n[NETZWERK] Routing-Analyse"
    analyze_routing issues warnings info_items
    
    # 3. DNS-ANALYSE
    echo -e "\n[NETZWERK] DNS-Analyse"
    analyze_dns_resolution issues warnings info_items
    
    # 4. KONNEKTIVITÄTS-TESTS
    echo -e "\n[NETZWERK] Konnektivitäts-Tests"
    analyze_connectivity issues warnings info_items
    
    # 5. LATENZ-ANALYSE
    echo -e "\n[NETZWERK] Latenz-Analyse"
    analyze_network_latency issues warnings info_items
    
    # 6. BANDWIDTH-EINSCHÄTZUNG
    echo -e "\n[NETZWERK] Bandwidth-Einschätzung"
    estimate_bandwidth issues warnings info_items
    
    # 7. IPv6-KONNEKTIVITÄT
    echo -e "\n[NETZWERK] IPv6-Konnektivität"
    analyze_ipv6_connectivity issues warnings info_items
    
    # 8. OFFENE PORTS
    echo -e "\n[NETZWERK] Port-Analyse"
    analyze_open_ports issues warnings info_items
    
    # ERGEBNISSE ZUSAMMENFASSEN
    echo -e "\n=== NETZWERK-DIAGNOSE ERGEBNISSE ==="
    echo "Gefundene Probleme: ${#issues[@]}"
    echo "Warnungen: ${#warnings[@]}"
    echo "Informationen: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 NETZWERK-PROBLEME:"
        printf ' - %s\n' "${issues[@]}"
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo -e "\n🟡 NETZWERK-WARNUNGEN:"
        printf ' - %s\n' "${warnings[@]}"
    fi
    
    if [[ ${#info_items[@]} -gt 0 ]]; then
        echo -e "\n🔵 NETZWERK-INFORMATIONEN:"
        printf ' - %s\n' "${info_items[@]}"
    fi
    
    echo "========================================="
    
    # Rückgabewert basierend auf gefundenen Problemen
    if [[ ${#issues[@]} -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Netzwerk-Interfaces analysieren
analyze_network_interfaces() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Netzwerk-Interfaces..."
    
    if ! command -v ip >/dev/null 2>&1; then
        issues_ref+=("ip-Befehl nicht verfügbar")
        return 1
    fi
    
    # Alle Interfaces auflisten
    echo "Verfügbare Interfaces:"
    ip link show 2>/dev/null | grep -E "^[0-9]+:" | while IFS= read -r line; do
        echo "  ${line}"
    done
    
    # Aktive Interfaces zählen
    local active_interfaces
    active_interfaces=$(ip link show up 2>/dev/null | grep -c "state UP" || echo "0")
    echo "Aktive Interfaces: ${active_interfaces}"
    
    if [[ ${active_interfaces} -eq 0 ]]; then
        issues_ref+=("Keine aktiven Netzwerk-Interfaces")
        return 1
    elif [[ ${active_interfaces} -eq 1 ]]; then
        warnings_ref+=("Nur ein aktives Interface (keine Redundanz)")
    else
        info_ref+=("${active_interfaces} aktive Interfaces verfügbar")
    fi
    
    # IP-Adressen der aktiven Interfaces
    echo "IP-Adressen:"
    ip addr show up 2>/dev/null | grep -E "inet " | while IFS= read -r line; do
        echo "  ${line}"
    done
    
    # MTU-Größen prüfen
    echo "MTU-Größen:"
    ip link show 2>/dev/null | grep -E "mtu [0-9]+" | while IFS= read -r line; do
        local interface mtu
        interface=$(echo "${line}" | cut -d: -f2 | awk '{print $1}')
        mtu=$(echo "${line}" | grep -o "mtu [0-9]*" | awk '{print $2}')
        echo "  ${interface}: ${mtu}"
        
        if [[ -n "${mtu}" && ${mtu} -lt 1400 ]]; then
            warnings_ref+=("Ungewöhnlich niedrige MTU: ${interface} (${mtu})")
        fi
    done
}

# Routing analysieren
analyze_routing() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Routing..."
    
    # Default Route prüfen
    local default_routes
    default_routes=$(ip route show default 2>/dev/null | wc -l || echo "0")
    
    if [[ ${default_routes} -eq 0 ]]; then
        issues_ref+=("Keine Standard-Route konfiguriert")
    elif [[ ${default_routes} -gt 1 ]]; then
        warnings_ref+=("Mehrere Standard-Routen konfiguriert (${default_routes})")
    else
        local gateway
        gateway=$(ip route show default | awk '{print $3}' | head -1)
        echo "Standard-Gateway: ${gateway}"
        info_ref+=("Standard-Gateway: ${gateway}")
        
        # Gateway-Erreichbarkeit testen
        if timeout 3 ping -c 1 "${gateway}" >/dev/null 2>&1; then
            info_ref+=("Gateway ist erreichbar")
        else
            issues_ref+=("Gateway nicht erreichbar: ${gateway}")
        fi
    fi
    
    # Routing-Tabelle anzeigen
    echo "Routing-Tabelle:"
    ip route show 2>/dev/null | head -10 | while IFS= read -r line; do
        echo "  ${line}"
    done
    
    # Prüfe auf ungewöhnliche Routen
    local route_count
    route_count=$(ip route show 2>/dev/null | wc -l || echo "0")
    if [[ ${route_count} -gt 50 ]]; then
        warnings_ref+=("Sehr viele Routen konfiguriert: ${route_count}")
    fi
}

# DNS-Auflösung analysieren
analyze_dns_resolution() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere DNS-Auflösung..."
    
    # DNS-Server aus /etc/resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        echo "Konfigurierte DNS-Server:"
        grep "^nameserver" /etc/resolv.conf 2>/dev/null | while IFS= read -r line; do
            echo "  ${line}"
        done
        
        local dns_count
        dns_count=$(grep -c "^nameserver" /etc/resolv.conf 2>/dev/null || echo "0")
        if [[ ${dns_count} -eq 0 ]]; then
            issues_ref+=("Keine DNS-Server in /etc/resolv.conf")
        elif [[ ${dns_count} -eq 1 ]]; then
            warnings_ref+=("Nur ein DNS-Server konfiguriert (keine Redundanz)")
        fi
    else
        warnings_ref+=("/etc/resolv.conf nicht gefunden")
    fi
    
    # DNS-Auflösung testen
    local test_domains=("google.com" "cloudflare.com" "github.com")
    local successful_resolutions=0
    
    for domain in "${test_domains[@]}"; do
        echo "Teste DNS-Auflösung für ${domain}..."
        if timeout 5 nslookup "${domain}" >/dev/null 2>&1 || timeout 5 host "${domain}" >/dev/null 2>&1; then
            echo "  ✓ ${domain}: OK"
            ((successful_resolutions++))
        else
            echo "  ✗ ${domain}: Fehlgeschlagen"
        fi
    done
    
    if [[ ${successful_resolutions} -eq 0 ]]; then
        issues_ref+=("DNS-Auflösung komplett fehlgeschlagen")
    elif [[ ${successful_resolutions} -lt ${#test_domains[@]} ]]; then
        warnings_ref+=("DNS-Auflösung teilweise fehlgeschlagen (${successful_resolutions}/${#test_domains[@]})")
    else
        info_ref+=("DNS-Auflösung funktioniert korrekt")
    fi
    
    # DNS-Response-Zeit messen
    local dns_response_time
    dns_response_time=$(timeout 5 time -p nslookup google.com 2>&1 | grep "^real" | awk '{print $2}' || echo "0")
    if [[ -n "${dns_response_time}" ]] && (( $(echo "${dns_response_time} > 2" | bc -l 2>/dev/null || echo "0") )); then
        warnings_ref+=("Langsame DNS-Antwortzeit: ${dns_response_time}s")
    fi
}

# Konnektivität analysieren
analyze_connectivity() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Internet-Konnektivität..."
    
    local test_targets=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    local successful_pings=0
    
    # ICMP-Tests
    for target in "${test_targets[@]}"; do
        echo "Teste ICMP zu ${target}..."
        if timeout 5 ping -c 3 "${target}" >/dev/null 2>&1; then
            echo "  ✓ ${target}: Erreichbar"
            ((successful_pings++))
        else
            echo "  ✗ ${target}: Nicht erreichbar"
        fi
    done
    
    if [[ ${successful_pings} -eq 0 ]]; then
        issues_ref+=("Keine ICMP-Konnektivität zu externen Hosts")
    elif [[ ${successful_pings} -lt ${#test_targets[@]} ]]; then
        warnings_ref+=("ICMP-Konnektivität teilweise verfügbar (${successful_pings}/${#test_targets[@]})")
    else
        info_ref+=("ICMP-Konnektivität vollständig verfügbar")
    fi
    
    # HTTP/HTTPS-Tests
    local http_targets=("http://httpbin.org/ip" "https://www.google.com" "https://www.cloudflare.com")
    local successful_http=0
    
    for target in "${http_targets[@]}"; do
        echo "Teste HTTP(S) zu ${target}..."
        if timeout 10 curl -s --connect-timeout 5 "${target}" >/dev/null 2>&1; then
            echo "  ✓ ${target}: Erreichbar"
            ((successful_http++))
        else
            echo "  ✗ ${target}: Nicht erreichbar"
        fi
    done
    
    if [[ ${successful_http} -eq 0 ]]; then
        issues_ref+=("Keine HTTP(S)-Konnektivität verfügbar")
    elif [[ ${successful_http} -lt ${#http_targets[@]} ]]; then
        warnings_ref+=("HTTP(S)-Konnektivität teilweise verfügbar (${successful_http}/${#http_targets[@]})")
    else
        info_ref+=("HTTP(S)-Konnektivität vollständig verfügbar")
    fi
}

# Netzwerk-Latenz analysieren
analyze_network_latency() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere Netzwerk-Latenz..."
    
    local targets=("1.1.1.1" "8.8.8.8" "google.com")
    local high_latency_count=0
    
    for target in "${targets[@]}"; do
        echo "Messe Latenz zu ${target}..."
        local ping_result
        ping_result=$(timeout 10 ping -c 5 "${target}" 2>/dev/null | grep "avg" || echo "")
        
        if [[ -n "${ping_result}" ]]; then
            local avg_latency
            avg_latency=$(echo "${ping_result}" | cut -d'/' -f5 | cut -d'.' -f1 || echo "999")
            echo "  Durchschnittliche Latenz: ${avg_latency}ms"
            
            if [[ ${avg_latency} -gt 500 ]]; then
                issues_ref+=("Sehr hohe Latenz zu ${target}: ${avg_latency}ms")
                ((high_latency_count++))
            elif [[ ${avg_latency} -gt 200 ]]; then
                warnings_ref+=("Hohe Latenz zu ${target}: ${avg_latency}ms")
                ((high_latency_count++))
            fi
        else
            echo "  Latenz-Messung fehlgeschlagen"
            warnings_ref+=("Latenz-Messung zu ${target} fehlgeschlagen")
        fi
    done
    
    if [[ ${high_latency_count} -eq 0 ]]; then
        info_ref+=("Netzwerk-Latenz ist akzeptabel")
    fi
}

# Bandwidth schätzen
estimate_bandwidth() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Schätze verfügbare Bandwidth..."
    
    # Einfacher Download-Test
    local test_url="http://speedtest.tele2.net/1MB.zip"
    local start_time end_time duration
    
    echo "Führe kurzen Download-Test durch..."
    start_time=$(date +%s.%N 2>/dev/null || date +%s)
    
    if timeout 30 curl -s --connect-timeout 5 --max-time 30 "${test_url}" -o /dev/null 2>/dev/null; then
        end_time=$(date +%s.%N 2>/dev/null || date +%s)
        duration=$(echo "${end_time} - ${start_time}" | bc -l 2>/dev/null || echo "1")
        
        if (( $(echo "${duration} > 0" | bc -l 2>/dev/null || echo "1") )); then
            local speed_mbps
            speed_mbps=$(echo "scale=2; 8 / ${duration}" | bc -l 2>/dev/null || echo "1")
            echo "Geschätzte Download-Geschwindigkeit: ${speed_mbps} Mbps"
            
            if (( $(echo "${speed_mbps} < 1" | bc -l 2>/dev/null || echo "0") )); then
                warnings_ref+=("Sehr langsame Internet-Verbindung: ${speed_mbps} Mbps")
            elif (( $(echo "${speed_mbps} < 10" | bc -l 2>/dev/null || echo "0") )); then
                warnings_ref+=("Langsame Internet-Verbindung: ${speed_mbps} Mbps")
            else
                info_ref+=("Internet-Geschwindigkeit: ${speed_mbps} Mbps")
            fi
        fi
    else
        warnings_ref+=("Bandwidth-Test fehlgeschlagen")
    fi
}

# IPv6-Konnektivität analysieren
analyze_ipv6_connectivity() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere IPv6-Konnektivität..."
    
    # IPv6-Adressen prüfen
    local ipv6_addresses
    ipv6_addresses=$(ip addr show 2>/dev/null | grep "inet6.*scope global" | wc -l || echo "0")
    
    if [[ ${ipv6_addresses} -eq 0 ]]; then
        echo "Keine globalen IPv6-Adressen konfiguriert"
        warnings_ref+=("IPv6 nicht konfiguriert")
        return 0
    fi
    
    echo "IPv6-Adressen gefunden: ${ipv6_addresses}"
    ip addr show 2>/dev/null | grep "inet6.*scope global" | while IFS= read -r line; do
        echo "  ${line}"
    done
    
    # IPv6-Konnektivität testen
    local ipv6_targets=("2606:4700:4700::1111" "2001:4860:4860::8888")
    local successful_ipv6=0
    
    for target in "${ipv6_targets[@]}"; do
        echo "Teste IPv6-Konnektivität zu ${target}..."
        if timeout 5 ping -6 -c 2 "${target}" >/dev/null 2>&1; then
            echo "  ✓ ${target}: Erreichbar"
            ((successful_ipv6++))
        else
            echo "  ✗ ${target}: Nicht erreichbar"
        fi
    done
    
    if [[ ${successful_ipv6} -eq 0 ]]; then
        warnings_ref+=("IPv6 konfiguriert aber keine Konnektivität")
    else
        info_ref+=("IPv6-Konnektivität verfügbar")
    fi
}

# Offene Ports analysieren
analyze_open_ports() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analysiere offene Ports..."
    
    # Listening Ports
    if command -v ss >/dev/null 2>&1; then
        echo "Listening Ports (ss):"
        ss -tulpn 2>/dev/null | grep LISTEN | head -10 | while IFS= read -r line; do
            echo "  ${line}"
        done
        
        local open_ports
        open_ports=$(ss -tulpn 2>/dev/null | grep LISTEN | wc -l || echo "0")
        echo "Anzahl offener Ports: ${open_ports}"
        
        if [[ ${open_ports} -gt 20 ]]; then
            warnings_ref+=("Viele offene Ports: ${open_ports}")
        fi
        
    elif command -v netstat >/dev/null 2>&1; then
        echo "Listening Ports (netstat):"
        netstat -tulpn 2>/dev/null | grep LISTEN | head -10 | while IFS= read -r line; do
            echo "  ${line}"
        done
        
        local open_ports
        open_ports=$(netstat -tulpn 2>/dev/null | grep LISTEN | wc -l || echo "0")
        echo "Anzahl offener Ports: ${open_ports}"
        
        if [[ ${open_ports} -gt 20 ]]; then
            warnings_ref+=("Viele offene Ports: ${open_ports}")
        fi
    else
        warnings_ref+=("Keine Tools für Port-Analyse verfügbar (ss/netstat)")
    fi
    
    info_ref+=("Port-Analyse abgeschlossen")
}
# Verbesserte Hilfefunktion
show_help() {
    cat << 'HELP_EOF'
==========================================
Server-Setup-Skript für Globalping-Probe
==========================================

BESCHREIBUNG:
    Dieses Skript automatisiert die komplette Einrichtung eines Linux-Servers
    mit Globalping-Probe, inklusive Docker-Installation, Systemoptimierung,
    Auto-Updates und umfassender Wartung.

VERWENDUNG:
    ./install.sh [OPTIONEN]
    
    Das Skript muss mit Root-Rechten ausgeführt werden.

HAUPTOPTIONEN:
    -h, --help                      Zeigt diese Hilfe an
    --adoption-token TOKEN          Globalping Adoption-Token (erforderlich für Probe)
    --telegram-token TOKEN          Telegram-Bot-Token für Benachrichtigungen
    --telegram-chat ID              Telegram-Chat-ID für Benachrichtigungen
    --ubuntu-token TOKEN            Ubuntu Pro Token (nur für Ubuntu)
    --ssh-key "SCHLÜSSEL"           SSH Public Key für sicheren Zugang

ZUSÄTZLICHE OPTIONEN:
    -d, --docker                    Installiert nur Docker und Docker Compose
    -l, --log DATEI                 Alternative Log-Datei (Standard: /var/log/globalping-install.log)
    --debug                         Aktiviert ausführliches Debug-Logging
    --auto-update                   Führt automatisches Skript-Update durch (intern)

WARTUNGS-OPTIONEN:
    --cleanup                       Führt umfassende Systemreinigung durch
    --emergency-cleanup             Führt aggressive Notfall-Bereinigung durch
    --diagnose                      Führt vollständige Systemdiagnose durch
    --network-diagnose              Führt detaillierte Netzwerk-Diagnose durch

BEISPIELE:
    # Vollständige Globalping-Probe Installation
    ./install.sh --adoption-token "your-token-here" \
                  --telegram-token "bot-token" \
                  --telegram-chat "chat-id" \
                  --ssh-key "ssh-rsa AAAA..."

    # Nur Docker installieren
    ./install.sh --docker

    # Systemdiagnose durchführen
    ./install.sh --diagnose

    # Notfall-Bereinigung bei Speicherproblemen
    ./install.sh --emergency-cleanup

    # Debug-Modus für Problemanalyse
    ./install.sh --debug --adoption-token "token"

SYSTEMANFORDERUNGEN:
    - Linux-Distribution (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora)
    - Root-Rechte oder sudo-Zugang
    - Internetverbindung
    - Mindestens 1GB RAM
    - Mindestens 5GB freier Speicherplatz

UNTERSTÜTZTE DISTRIBUTIONEN:
    ✓ Ubuntu 18.04+          ✓ Debian 9+
    ✓ CentOS 7+              ✓ RHEL 7+
    ✓ Rocky Linux 8+         ✓ AlmaLinux 8+
    ✓ Fedora 30+             ✓ Amazon Linux 2

FEATURES:
    ✓ Automatische Systemerkennung und -optimierung
    ✓ Docker und Docker Compose Installation
    ✓ Globalping-Probe mit Auto-Updates
    ✓ Hostname-Optimierung basierend auf Geolocation
    ✓ Telegram-Benachrichtigungen
    ✓ Umfassende Systemreinigung
    ✓ Diagnose und Monitoring
    ✓ Sicherheitsoptimierungen
    ✓ Raspberry Pi Unterstützung

WEITERE INFORMATIONEN:
    - Log-Datei: /var/log/globalping-install.log
    - Globalping-Verzeichnis: /opt/globalping
    - Auto-Update-Skript: /usr/local/bin/install_globalping.sh
    - Wartungs-Skript: /usr/local/bin/globalping-maintenance

Bei Problemen oder Fragen konsultieren Sie die Log-Datei oder führen Sie
eine Diagnose durch: ./install.sh --diagnose

HELP_EOF
    exit 0
}

# Verbesserte Argumentverarbeitung
process_args() {
    # Standardwerte setzen
    local install_docker_only="false"
    local run_diagnostics_only="false"
    local run_network_diagnostics_only="false"
    local auto_update_mode="false"
    local cleanup_mode="false"
    local emergency_cleanup_mode="false"
    
    # Keine Argumente = Hilfe anzeigen
    if [[ $# -eq 0 ]]; then
        log "Keine Argumente übergeben, zeige Hilfe"
        show_help
    fi
    
    # Argumente verarbeiten
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -d|--docker)
                install_docker_only="true"
                log "Modus: Nur Docker-Installation"
                shift
                ;;
            -l|--log)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    readonly LOG_FILE="$2"
                    log "Alternative Log-Datei: ${LOG_FILE}"
                    shift 2
                else
                    log "Fehler: --log benötigt einen Dateinamen"
                    echo "Fehler: --log benötigt einen Dateinamen" >&2
                    exit 1
                fi
                ;;
            --debug)
                enable_debug_mode
                log "Debug-Modus aktiviert"
                shift
                ;;
            --auto-update)
                auto_update_mode="true"
                log "Modus: Automatisches Update"
                shift
                ;;
            --adoption-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    ADOPTION_TOKEN="$2"
                    log "Adoption-Token gesetzt (${#ADOPTION_TOKEN} Zeichen)"
                    shift 2
                else
                    log "Fehler: --adoption-token benötigt einen Wert"
                    echo "Fehler: --adoption-token benötigt einen Wert" >&2
                    exit 1
                fi
                ;;
            --telegram-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_TOKEN="$2"
                    log "Telegram-Token gesetzt"
                    shift 2
                else
                    log "Fehler: --telegram-token benötigt einen Wert"
                    echo "Fehler: --telegram-token benötigt einen Wert" >&2
                    exit 1
                fi
                ;;
            --telegram-chat)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_CHAT="$2"
                    log "Telegram-Chat-ID gesetzt: ${TELEGRAM_CHAT}"
                    shift 2
                else
                    log "Fehler: --telegram-chat benötigt einen Wert"
                    echo "Fehler: --telegram-chat benötigt einen Wert" >&2
                    exit 1
                fi
                ;;
            --ubuntu-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    UBUNTU_PRO_TOKEN="$2"
                    log "Ubuntu Pro Token gesetzt"
                    shift 2
                else
                    log "Fehler: --ubuntu-token benötigt einen Wert"
                    echo "Fehler: --ubuntu-token benötigt einen Wert" >&2
                    exit 1
                fi
                ;;
            --ssh-key)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    SSH_KEY="$2"
                    log "SSH-Schlüssel gesetzt"
                    shift 2
                else
                    log "Fehler: --ssh-key benötigt einen Wert"
                    echo "Fehler: --ssh-key benötigt einen Wert" >&2
                    exit 1
                fi
                ;;
            --cleanup)
                cleanup_mode="true"
                log "Modus: Systemreinigung"
                shift
                ;;
            --emergency-cleanup)
                emergency_cleanup_mode="true"
                log "Modus: Notfall-Bereinigung"
                shift
                ;;
            --diagnose)
                run_diagnostics_only="true"
                log "Modus: Systemdiagnose"
                shift
                ;;
            --network-diagnose)
                run_network_diagnostics_only="true"
                log "Modus: Netzwerk-Diagnose"
                shift
                ;;
            -*)
                log "Fehler: Unbekannte Option: $1"
                echo "Fehler: Unbekannte Option: $1" >&2
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
            *)
                log "Fehler: Unerwartetes Argument: $1"
                echo "Fehler: Unerwartetes Argument: $1" >&2
                echo "Verwenden Sie --help für Hilfe" >&2
                exit 1
                ;;
        esac
    done
    
    # Validiere Argument-Kombinationen
    validate_argument_combinations \
        "${install_docker_only}" \
        "${run_diagnostics_only}" \
        "${run_network_diagnostics_only}" \
        "${auto_update_mode}" \
        "${cleanup_mode}" \
        "${emergency_cleanup_mode}"
    
    # Führe spezielle Modi aus
    execute_special_modes \
        "${install_docker_only}" \
        "${run_diagnostics_only}" \
        "${run_network_diagnostics_only}" \
        "${auto_update_mode}" \
        "${cleanup_mode}" \
        "${emergency_cleanup_mode}"
}

# Validiere Argument-Kombinationen
validate_argument_combinations() {
    local install_docker_only="$1"
    local run_diagnostics_only="$2"
    local run_network_diagnostics_only="$3"
    local auto_update_mode="$4"
    local cleanup_mode="$5"
    local emergency_cleanup_mode="$6"
    
    # Zähle aktive Modi
    local active_modes=0
    [[ "${install_docker_only}" == "true" ]] && ((active_modes++))
    [[ "${run_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${run_network_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${auto_update_mode}" == "true" ]] && ((active_modes++))
    [[ "${cleanup_mode}" == "true" ]] && ((active_modes++))
    [[ "${emergency_cleanup_mode}" == "true" ]] && ((active_modes++))
    
    # Mehr als ein spezieller Modus = Fehler
    if [[ ${active_modes} -gt 1 ]]; then
        log "Fehler: Nur ein spezieller Modus kann gleichzeitig verwendet werden"
        echo "Fehler: Nur ein spezieller Modus kann gleichzeitig verwendet werden" >&2
        exit 1
    fi
    
    # Validiere Token für normale Installation
    if [[ ${active_modes} -eq 0 && -z "${ADOPTION_TOKEN}" ]]; then
        log "Warnung: Kein Adoption-Token angegeben - Globalping-Probe wird nicht installiert"
        echo "Warnung: Ohne Adoption-Token wird keine Globalping-Probe installiert" >&2
        echo "Verwenden Sie --adoption-token TOKEN für eine vollständige Installation" >&2
    fi
    
    # Validiere Telegram-Konfiguration
    if [[ -n "${TELEGRAM_TOKEN}" && -z "${TELEGRAM_CHAT}" ]] || [[ -z "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]]; then
        log "Warnung: Unvollständige Telegram-Konfiguration"
        echo "Warnung: Für Telegram-Benachrichtigungen werden sowohl --telegram-token als auch --telegram-chat benötigt" >&2
    fi
}

# Führe spezielle Modi aus
execute_special_modes() {
    local install_docker_only="$1"
    local run_diagnostics_only="$2"
    local run_network_diagnostics_only="$3"
    local auto_update_mode="$4"
    local cleanup_mode="$5"
    local emergency_cleanup_mode="$6"
    
    # Root-Check für alle Modi außer Hilfe
    check_root || {
        log "Root-Check fehlgeschlagen"
        exit 1
    }
    
    # Erstelle temporäres Verzeichnis für alle Modi
    create_temp_dir || {
        log "Konnte temporäres Verzeichnis nicht erstellen"
        exit 1
    }
    
    # Führe speziellen Modus aus
    if [[ "${install_docker_only}" == "true" ]]; then
        log "Führe Docker-Installation durch"
        install_dependencies || log "Warnung: Abhängigkeiten-Installation fehlgeschlagen"
        install_docker || {
            log "Docker-Installation fehlgeschlagen"
            exit 1
        }
        install_docker_compose || log "Warnung: Docker Compose-Installation fehlgeschlagen"
        log "Docker-Installation abgeschlossen"
        exit 0
        
    elif [[ "${run_diagnostics_only}" == "true" ]]; then
        log "Führe vollständige Systemdiagnose durch"
        run_diagnostics
        exit $?
        
    elif [[ "${run_network_diagnostics_only}" == "true" ]]; then
        log "Führe Netzwerk-Diagnose durch"
        run_network_diagnosis
        exit $?
        
    elif [[ "${auto_update_mode}" == "true" ]]; then
        log "Führe automatisches Update durch"
        perform_auto_update
        exit $?
        
    elif [[ "${cleanup_mode}" == "true" ]]; then
        log "Führe Systemreinigung durch"
        perform_system_cleanup
        exit $?
        
    elif [[ "${emergency_cleanup_mode}" == "true" ]]; then
        log "Führe Notfall-Bereinigung durch"
        echo "WARNUNG: Notfall-Bereinigung wird aggressive Maßnahmen ergreifen!"
        echo "Drücken Sie Ctrl+C innerhalb von 10 Sekunden zum Abbrechen..."
        sleep 10
        perform_emergency_cleanup
        exit $?
    fi
    
    # Kein spezieller Modus = normale Installation
    return 0
}

# Debug-Modus aktivieren
enable_debug_mode() {
    log "Aktiviere Debug-Modus"
    
    # Bash-Debug aktivieren
    set -x
    
    # Debug-Log-Datei erstellen
    local debug_log="/var/log/globalping-debug-$(date +%Y%m%d-%H%M%S).log"
    exec 19>"${debug_log}"
    BASH_XTRACEFD=19
    
    DEBUG_MODE="true"
    
    # Debug-Informationen sammeln
    {
        echo "=== DEBUG SESSION STARTED ==="
        echo "Datum: $(date)"
        echo "Benutzer: $(whoami)"
        echo "Arbeitsverzeichnis: $(pwd)"
        echo "Skript-Pfad: ${0}"
        echo "Argumente: $*"
        echo "System: $(uname -a)"
        echo "Shell: ${SHELL} (${BASH_VERSION})"
        echo "============================="
    } >&19
    
    log "Debug-Modus aktiviert, ausführliches Logging in: ${debug_log}"
    
    return 0
}
# Verbesserte Hauptfunktion
main() {
    local start_time
    start_time=$(date +%s)
    
    log "=== STARTE SERVER-SETUP-SKRIPT ==="
    log "Version: ${SCRIPT_VERSION}"
    log "Startzeit: $(date)"
    log "======================================"
    
    # Initialisierung
    log "Phase 1: Initialisierung und Validierung"
    
    # Erstelle temporäres Verzeichnis
    create_temp_dir || {
        log "KRITISCH: Konnte temporäres Verzeichnis nicht erstellen"
        exit 1
    }
    
    # Grundlegende Systemprüfungen
    check_internet || {
        log "KRITISCH: Keine Internetverbindung verfügbar"
        notify error "❌ Setup fehlgeschlagen: Keine Internetverbindung"
        exit 1
    }
    
    # Sudo installieren falls erforderlich
    install_sudo || {
        log "Warnung: sudo-Installation fehlgeschlagen, fahre trotzdem fort"
    }
    
    log "Phase 2: Systemanalyse"
    
    # Systemarchitektur erkennen
    detect_architecture || {
        log "Warnung: Architektur-Erkennung fehlgeschlagen"
    }
    
    # Systeminformationen sammeln
    get_system_info || {
        log "Warnung: Systeminformationen-Sammlung fehlgeschlagen"
    }
    
    log "Phase 3: Systemvorbereitung"
    
    # Abhängigkeiten installieren
    install_dependencies || {
        log "Warnung: Installation der Abhängigkeiten teilweise fehlgeschlagen"
    }
    
    # System aktualisieren
    update_system || {
        log "Warnung: Systemaktualisierung fehlgeschlagen"
    }
    
    log "Phase 4: Systemkonfiguration"
    
    # Hostname konfigurieren
    configure_hostname || {
        log "Warnung: Hostname-Konfiguration fehlgeschlagen"
    }
    
    # SSH-Schlüssel einrichten
    if [[ -n "${SSH_KEY}" ]]; then
        setup_ssh_key || {
            log "Warnung: SSH-Schlüssel-Setup fehlgeschlagen"
        }
    else
        log "Kein SSH-Schlüssel angegeben, überspringe SSH-Setup"
    fi
    
    log "Phase 5: Ubuntu Pro (falls anwendbar)"
    
    # Ubuntu Pro aktivieren (nur auf Ubuntu)
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        ubuntu_pro_attach || {
            log "Warnung: Ubuntu Pro Aktivierung fehlgeschlagen"
        }
    else
        log "Ubuntu Pro nicht anwendbar oder kein Token angegeben"
    fi
    
    log "Phase 6: Docker-Installation"
    
    # Docker installieren (falls noch nicht vorhanden oder Globalping-Token angegeben)
    if [[ -n "${ADOPTION_TOKEN}" ]] || ! command -v docker >/dev/null 2>&1; then
        install_docker || {
            log "Fehler: Docker-Installation fehlgeschlagen"
            notify error "❌ Docker-Installation fehlgeschlagen"
            # Nicht kritisch genug für Exit, da eventuell andere Tasks erfolgreich waren
        }
        
        install_docker_compose || {
            log "Warnung: Docker Compose-Installation fehlgeschlagen"
        }
    else
        log "Docker bereits installiert und kein Adoption-Token - überspringe Docker-Installation"
    fi
    
    log "Phase 7: Globalping-Probe"
    
    # Globalping-Probe installieren falls Token angegeben
    if [[ -n "${ADOPTION_TOKEN}" ]]; then
        install_globalping_probe || {
            log "Fehler: Globalping-Probe-Installation fehlgeschlagen"
            notify error "❌ Globalping-Probe-Installation fehlgeschlagen"
        }
    else
        log "Kein Adoption-Token angegeben, überspringe Globalping-Probe-Installation"
    fi
    
    log "Phase 8: Auto-Update-Konfiguration"
    
    # Auto-Update einrichten
    setup_auto_update || {
        log "Warnung: Auto-Update-Einrichtung fehlgeschlagen"
    }
    
    log "Phase 9: Systemoptimierung"
    
    # Systemreinigung durchführen
    perform_system_cleanup || {
        log "Warnung: Systemreinigung fehlgeschlagen"
    }
    
    log "Phase 10: Abschlussdiagnose"
    
    # Diagnose durchführen
    run_diagnostics || {
        log "Warnung: Abschlussdiagnose ergab Probleme"
    }
    
    log "Phase 11: Zusammenfassung"
    
    # Zusammenfassung erstellen
    create_summary
    
    # Berechne Ausführungszeit
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    log "=== SERVER-SETUP ABGESCHLOSSEN ==="
    log "Ausführungszeit: ${duration} Sekunden"
    log "Abschlusszeit: $(date)"
    log "=================================="
    
    # Erfolgs-Benachrichtigung
    notify success "✅ Server-Setup abgeschlossen (${duration}s)"
    
    return 0
}

# Verbesserte Zusammenfassungsfunktion
create_summary() {
    local summary_file="/root/server_setup_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    log "Erstelle Setup-Zusammenfassung in: ${summary_file}"
    
    {
        echo "=========================================="
        echo "       SERVER SETUP ZUSAMMENFASSUNG"
        echo "=========================================="
        echo "Datum: $(date)"
        echo "Skript-Version: ${SCRIPT_VERSION}"
        echo "Hostname: $(hostname 2>/dev/null || echo 'unbekannt')"
        echo "=========================================="
        
        echo -e "\n--- SYSTEM-INFORMATION ---"
        echo "Betriebssystem: $(get_os_info)"
        echo "Kernel: $(uname -r 2>/dev/null || echo 'unbekannt')"
        echo "Architektur: $(uname -m 2>/dev/null || echo 'unbekannt')"
        echo "CPU-Kerne: $(nproc 2>/dev/null || echo 'unbekannt')"
        echo "RAM gesamt: $(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo 'unbekannt')"
        echo "Festplatte (Root): $(df -h / 2>/dev/null | awk 'NR==2 {print $2}' || echo 'unbekannt')"
        echo "Verfügbarer Speicher: $(df -h / 2>/dev/null | awk 'NR==2 {print $4}' || echo 'unbekannt')"
        
        echo -e "\n--- NETZWERK-INFORMATION ---"
        echo "Öffentliche IP: $(get_public_ip)"
        echo "Lokale IPs:"
        ip addr show 2>/dev/null | grep -E "inet " | grep -v "127.0.0.1" | awk '{print "  " $2}' || echo "  Nicht verfügbar"
        echo "Standard-Gateway: $(ip route show default 2>/dev/null | awk '{print $3}' | head -1 || echo 'unbekannt')"
        echo "DNS-Server:"
        grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print "  " $2}' || echo "  Nicht verfügbar"
        
        echo -e "\n--- INSTALLIERTE KOMPONENTEN ---"
        echo "sudo: $(get_component_status sudo)"
        echo "Docker: $(get_component_status docker)"
        echo "Docker Compose: $(get_docker_compose_status)"
        echo "Globalping-Probe: $(get_globalping_status)"
        
        echo -e "\n--- DIENSTE-STATUS ---"
        if command -v systemctl >/dev/null 2>&1; then
            echo "SSH: $(get_service_status ssh sshd)"
            echo "Docker: $(get_service_status docker)"
            echo "Cron: $(get_service_status cron crond)"
        else
            echo "systemctl nicht verfügbar - kann Dienste-Status nicht prüfen"
        fi
        
        echo -e "\n--- AUTO-UPDATE KONFIGURATION ---"
        echo "$(get_autoupdate_status)"
        
        echo -e "\n--- SICHERHEIT ---"
        echo "Firewall: $(get_firewall_status)"
        echo "SSH Root-Login: $(get_ssh_root_status)"
        echo "Automatische Updates: $(get_auto_security_updates_status)"
        
        echo -e "\n--- KONFIGURIERTE FEATURES ---"
        [[ -n "${ADOPTION_TOKEN}" ]] && echo "✓ Globalping-Probe konfiguriert"
        [[ -n "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]] && echo "✓ Telegram-Benachrichtigungen aktiviert"
        [[ -n "${SSH_KEY}" ]] && echo "✓ SSH-Schlüssel konfiguriert"
        [[ -n "${UBUNTU_PRO_TOKEN}" ]] && echo "✓ Ubuntu Pro aktiviert"
        
        echo -e "\n--- WICHTIGE DATEIEN ---"
        echo "Setup-Log: ${LOG_FILE}"
        echo "Globalping-Verzeichnis: /opt/globalping"
        echo "Auto-Update-Skript: ${SCRIPT_PATH}"
        echo "Wartungs-Skript: /usr/local/bin/globalping-maintenance"
        
        echo -e "\n--- NÄCHSTE SCHRITTE ---"
        if [[ -n "${ADOPTION_TOKEN}" ]]; then
            echo "1. Prüfen Sie den Globalping-Probe Status:"
            echo "   docker ps | grep globalping"
            echo "   docker logs globalping-probe"
        fi
        echo "2. Überwachen Sie die Auto-Updates:"
        if check_systemd_available && systemctl is-enabled globalping-update.timer >/dev/null 2>&1; then
            echo "   systemctl status globalping-update.timer"
        elif check_crontab_available; then
            echo "   crontab -l | grep globalping"
        fi
        echo "3. Regelmäßige Diagnose durchführen:"
        echo "   ${SCRIPT_PATH} --diagnose"
        echo "4. Bei Problemen Logs prüfen:"
        echo "   tail -f ${LOG_FILE}"
        
        echo -e "\n=========================================="
        echo "Setup-Zusammenfassung erstellt: $(date)"
        echo "=========================================="
        
    } > "${summary_file}"
    
    # Zeige Zusammenfassung auch in der Konsole
    cat "${summary_file}"
    
    log "Zusammenfassung gespeichert in: ${summary_file}"
    
    return 0
}

# Hilfsfunktionen für Zusammenfassung
get_os_info() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${PRETTY_NAME:-${NAME} ${VERSION_ID}}"
    else
        echo "Unbekannt"
    fi
}

get_public_ip() {
    local ip
    ip=$(timeout 5 curl -s https://api.ipify.org 2>/dev/null || 
         timeout 5 curl -s https://ifconfig.me/ip 2>/dev/null || 
         echo "Nicht verfügbar")
    echo "${ip}"
}

get_component_status() {
    local component="$1"
    if command -v "${component}" >/dev/null 2>&1; then
        local version
        case "${component}" in
            sudo) version=$(sudo --version 2>/dev/null | head -1 | awk '{print $3}' || echo "") ;;
            docker) version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "") ;;
            *) version="" ;;
        esac
        echo "Installiert${version:+ (${version})}"
    else
        echo "Nicht installiert"
    fi
}

get_docker_compose_status() {
    if docker compose version >/dev/null 2>&1; then
        local version
        version=$(docker compose version 2>/dev/null | awk '{print $4}' || echo "")
        echo "Plugin installiert${version:+ (${version})}"
    elif command -v docker-compose >/dev/null 2>&1; then
        local version
        version=$(docker-compose --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "")
        echo "Standalone installiert${version:+ (${version})}"
    else
        echo "Nicht installiert"
    fi
}

get_globalping_status() {
    if command -v docker >/dev/null 2>&1 && docker ps --format "{{.Names}}" | grep -qi globalping; then
        echo "Installiert und läuft"
    elif command -v docker >/dev/null 2>&1 && docker ps -a --format "{{.Names}}" | grep -qi globalping; then
        echo "Installiert aber gestoppt"
    else
        echo "Nicht installiert"
    fi
}

get_service_status() {
    local services=("$@")
    for service in "${services[@]}"; do
        if systemctl is-active "${service}" >/dev/null 2>&1; then
            echo "Aktiv"
            return 0
        fi
    done
    echo "Inaktiv"
}

get_autoupdate_status() {
    local mechanisms=()
    
    if check_crontab_available && crontab -l 2>/dev/null | grep -q "install_globalping.*--auto-update"; then
        mechanisms+=("Crontab")
    fi
    
    if check_systemd_available && systemctl is-enabled globalping-update.timer >/dev/null 2>&1; then
        mechanisms+=("Systemd-Timer")
    fi
    
    if [[ -x "/etc/cron.weekly/globalping-update" ]]; then
        mechanisms+=("Anacron")
    fi
    
    if [[ ${#mechanisms[@]} -gt 0 ]]; then
        echo "Aktiv (${mechanisms[*]})"
    else
        echo "Nicht konfiguriert"
    fi
}

get_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        local status
        status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
        echo "UFW: ${status}"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            echo "firewalld: aktiv"
        else
            echo "firewalld: inaktiv"
        fi
    else
        echo "Nicht erkannt"
    fi
}

get_ssh_root_status() {
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "^PermitRootLogin.*no" /etc/ssh/sshd_config 2>/dev/null; then
            echo "Deaktiviert"
        elif grep -q "^PermitRootLogin.*yes" /etc/ssh/sshd_config 2>/dev/null; then
            echo "Aktiviert"
        else
            echo "Standard (meist aktiviert)"
        fi
    else
        echo "SSH nicht konfiguriert"
    fi
}

get_auto_security_updates_status() {
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && grep -q "1" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
        echo "APT: Aktiviert"
    elif command -v dnf >/dev/null 2>&1 && systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
        echo "DNF: Aktiviert"
    else
        echo "Nicht konfiguriert"
    fi
}
# Globale Initialisierung
initialize_script() {
    # Setze sichere umask
    umask 022
    
    # Exportiere wichtige Variablen
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    
    # Setze sichere PATH
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    
    # Initialisiere Log-System
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    # Erstelle Lock-File für Script-Instanz
    local lock_file="/var/lock/globalping-install.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            echo "Fehler: Script läuft bereits (PID: ${lock_pid})" >&2
            exit 1
        else
            rm -f "${lock_file}"
        fi
    fi
    
    echo "$$" > "${lock_file}"
    
    # Cleanup bei Script-Ende
    trap 'cleanup_and_exit $?' EXIT
    trap 'emergency_exit' INT TERM
    
    log "Script-Initialisierung abgeschlossen (PID: $$)"
}

# Cleanup bei normalem Exit
cleanup_and_exit() {
    local exit_code="$1"
    
    # Entferne Lock-File
    rm -f "/var/lock/globalping-install.lock" 2>/dev/null || true
    
    # Temporäre Dateien aufräumen
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    
    # Debug-Modus beenden
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        set +x
        [[ -n "${BASH_XTRACEFD}" ]] && exec 19>&-
    fi
    
    # Abschluss-Log
    if [[ ${exit_code} -eq 0 ]]; then
        log "Script erfolgreich beendet"
    else
        log "Script mit Fehler beendet (Exit-Code: ${exit_code})"
    fi
    
    exit "${exit_code}"
}

# Notfall-Exit bei Unterbrechung
emergency_exit() {
    local signal="${1:-UNKNOWN}"
    
    log "Script durch Signal unterbrochen: ${signal}"
    notify error "❌ Setup durch Benutzer unterbrochen"
    
    # Stoppe laufende Operationen
    if command -v docker >/dev/null 2>&1; then
        docker stop $(docker ps -q) >/dev/null 2>&1 || true
    fi
    
    # Cleanup
    cleanup_and_exit 130
}

# Erweiterte Error-Handler-Installation
install_error_handlers() {
    # Error-Handler für unbehandelte Fehler
    trap 'error_handler ${LINENO} $?' ERR
    
    # Signal-Handler
    trap 'emergency_exit INT' INT
    trap 'emergency_exit TERM' TERM
    trap 'emergency_exit HUP' HUP
    
    # Exit-Handler
    trap 'cleanup_and_exit $?' EXIT
}

# Validiere Systemvoraussetzungen
validate_system_requirements() {
    log "Validiere Systemvoraussetzungen"
    
    local errors=()
    local warnings=()
    
    # Minimum RAM prüfen (512MB)
    local mem_kb
    mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    local mem_mb=$((mem_kb / 1024))
    
    if [[ ${mem_mb} -lt 512 ]]; then
        errors+=("Nicht genügend RAM: ${mem_mb}MB (Minimum: 512MB)")
    elif [[ ${mem_mb} -lt 1024 ]]; then
        warnings+=("Wenig RAM verfügbar: ${mem_mb}MB (Empfohlen: 1GB+)")
    fi
    
    # Minimum Speicherplatz prüfen (2GB)
    local disk_available_kb
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    local disk_available_mb=$((disk_available_kb / 1024))
    
    if [[ ${disk_available_mb} -lt 2048 ]]; then
        errors+=("Nicht genügend Speicherplatz: ${disk_available_mb}MB (Minimum: 2GB)")
    elif [[ ${disk_available_mb} -lt 5120 ]]; then
        warnings+=("Wenig Speicherplatz: ${disk_available_mb}MB (Empfohlen: 5GB+)")
    fi
    
    # Kernel-Version prüfen (3.10+)
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    if [[ -n "${kernel_version}" ]] && (( $(echo "${kernel_version} < 3.10" | bc -l 2>/dev/null || echo "0") )); then
        warnings+=("Alter Kernel: ${kernel_version} (Docker benötigt 3.10+)")
    fi
    
    # Ausgabe der Validierungsergebnisse
    if [[ ${#errors[@]} -gt 0 ]]; then
        log "KRITISCHE SYSTEMANFORDERUNGEN NICHT ERFÜLLT:"
        printf '%s\n' "${errors[@]}" | while IFS= read -r error; do
            log "  ❌ ${error}"
        done
        return 1
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        log "SYSTEMANFORDERUNGEN-WARNUNGEN:"
        printf '%s\n' "${warnings[@]}" | while IFS= read -r warning; do
            log "  ⚠️  ${warning}"
        done
    fi
    
    log "Systemvoraussetzungen erfüllt"
    return 0
}

# Script-Eingang (Main Entry Point)
script_main() {
    # Initialisierung
    initialize_script
    install_error_handlers
    
    # Validiere System
    validate_system_requirements || {
        log "Systemvalidierung fehlgeschlagen"
        exit 1
    }
    
    # Verarbeite Argumente
    process_args "$@"
    
    # Führe Hauptfunktion aus
    main
}

# ===========================================
# SCRIPT EXECUTION START
# ===========================================

# Prüfe, ob Script direkt ausgeführt wird
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script wird direkt ausgeführt
    script_main "$@"
else
    # Script wird gesourced - nur Funktionen laden
    log "Script wurde gesourced - Funktionen geladen"
fi

# Ende des Scripts