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
    notify error "âŒ Installation fehlgeschlagen in Zeile $line"
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
        info) emoji="ðŸ””"; title="Benachrichtigung" ;;
        warn) emoji="âš ï¸"; title="Warnung" ;;
        error) emoji="âŒ"; title="Fehler" ;;
        success) emoji="âœ…"; title="Erfolg" ;;
        *) emoji="â„¹ï¸"; title="Info" ;;
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
    
    log "Konfiguriere Hostname: $current_hostname"
    
    # Backup der originalen hosts-Datei
    mkdir -p "$TMP_DIR"
    cp /etc/hosts "$TMP_DIR/hosts.backup.$(date +%s)" || {
        log "Warnung: Konnte keine Sicherung von /etc/hosts erstellen"
    }

    # PrÃ¼fe, ob die Datei beschreibbar ist
    if [ ! -w "/etc/hosts" ]; then
        log "Warnung: /etc/hosts ist nicht beschreibbar, versuche Berechtigungen zu Ã¤ndern"
        chmod u+w /etc/hosts || {
            log "Fehler: Konnte Berechtigungen fÃ¼r /etc/hosts nicht Ã¤ndern"
            notify warn "âš ï¸ Hostname-Konfiguration fehlgeschlagen"
            return 1
        }
    }
        fi

    # Versuche, die Datei zu bearbeiten
    {
        # Alte EintrÃ¤ge bereinigen (fÃ¼r IPv4 und IPv6)
        sed -i "/^127\.0\.0\.1.*$short_hostname/d" /etc/hosts
        sed -i "/^::1.*$short_hostname/d" /etc/hosts

        # Neue EintrÃ¤ge hinzufÃ¼gen
        if ! grep -q "127.0.0.1.*$current_hostname" /etc/hosts; then
            sed -i "/^127.0.0.1/s/$/ $current_hostname/" /etc/hosts || \
            echo "127.0.0.1 localhost $current_hostname" >> /etc/hosts
        fi

                if ! grep -q "::1.*$current_hostname" /etc/hosts; then
            sed -i "/^::1/s/$/ $current_hostname/" /etc/hosts || \
            echo "::1 localhost $current_hostname" >> /etc/hosts
        fi

    } || {
        log "Fehler: Konnte /etc/hosts nicht aktualisieren"
        notify warn "âš ï¸ Hostname-Konfiguration fehlgeschlagen"
        return 1
    }

    log "Hostname aktualisiert: $current_hostname (Kurzname: $short_hostname)"
    return 0
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
# TemporÃ¤res Verzeichnis erstellen
create_temp_dir() {
    mkdir -p "$TMP_DIR" || {
        log "Warnung: Konnte temporÃ¤res Verzeichnis nicht erstellen, verwende /tmp"
        TMP_DIR="/tmp"
    }
    chmod 700 "$TMP_DIR"
    log "TemporÃ¤res Verzeichnis angelegt: $TMP_DIR"
}

# Root-Check
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "FEHLER: Dieses Skript benÃ¶tigt root-Rechte!"
        return 1
    fi
    log "Root-Check erfolgreich"
    return 0
}

# Internetverbindung testen
check_internet() {
    log "PrÃ¼fe Internetverbindung..."
    
    # Mehrere Ziele testen mit Timeout
    local targets=("google.com" "cloudflare.com" "1.1.1.1" "8.8.8.8")
    local connected=false
    
    for target in "${targets[@]}"; do
        if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
            connected=true
            break
        fi
    done
    
    # Wenn Ping fehlschlÃ¤gt, versuche HTTP-Anfrage
    if [ "$connected" = false ]; then
        if curl -s --connect-timeout 5 --max-time 10 "https://www.google.com" >/dev/null 2>&1 || \
           curl -s --connect-timeout 5 --max-time 10 "https://www.cloudflare.com" >/dev/null 2>&1 || \
           curl -s --connect-timeout 5 --max-time 10 "https://1.1.1.1" >/dev/null 2>&1; then
            connected=true
        fi
    fi
    
    if [ "$connected" = false ]; then
        log "KEINE INTERNETVERBINDUNG - Installation kann nicht fortgesetzt werden"
        notify error "âŒ Keine Internetverbindung verfÃ¼gbar"
        return 1
    fi
    
    log "Internetverbindung verfÃ¼gbar"
    return 0
}

# AbhÃ¤ngigkeiten installieren
install_dependencies() {
    log "Installiere SystemabhÃ¤ngigkeiten"
    
    if command -v apt-get >/dev/null; then
        apt-get update >/dev/null 2>&1 || {
            log "Warnung: apt-get update fehlgeschlagen, versuche trotzdem Installation"
        }
        apt-get install -y \
            curl wget awk sed grep coreutils \
            lsb-release iproute2 systemd >/dev/null 2>&1 || {
            log "Fehler: Konnte AbhÃ¤ngigkeiten nicht installieren"
            return 1
        }
    elif command -v yum >/dev/null; then
        yum install -y \
            curl wget awk sed grep coreutils \
            redhat-lsb-systemd iproute >/dev/null 2>&1 || {
            log "Fehler: Konnte AbhÃ¤ngigkeiten nicht installieren"
            return 1
        }
    elif command -v dnf >/dev/null; then
        dnf install -y \
            curl wget awk sed grep coreutils \
            redhat-lsb-systemd iproute >/dev/null 2>&1 || {
            log "Fehler: Konnte AbhÃ¤ngigkeiten nicht installieren"
            return 1
        }
    else
        log "Kein unterstÃ¼tzter Paketmanager gefunden!"
        log "Versuche minimale AbhÃ¤ngigkeiten zu prÃ¼fen..."
        
        # PrÃ¼fe minimale AbhÃ¤ngigkeiten
        for cmd in curl wget grep sed; do
            if ! command -v $cmd >/dev/null; then
                log "Kritische AbhÃ¤ngigkeit fehlt: $cmd"
                return 1
            fi
        done
        
        log "Minimale AbhÃ¤ngigkeiten vorhanden, fahre fort"
    fi
    
    log "SystemabhÃ¤ngigkeiten erfolgreich installiert oder bereits vorhanden"
    return 0
}

# SSH-SchlÃ¼ssel einrichten
setup_ssh_key() {
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR" || {
            log "Fehler: Konnte SSH-Verzeichnis nicht erstellen"
            return 1
        }
        chmod 700 "$SSH_DIR"
    fi
    
    if [ -n "$SSH_KEY" ]; then
        # PrÃ¼fe, ob der SchlÃ¼ssel bereits existiert
        if [ -f "$SSH_DIR/authorized_keys" ] && grep -q "$SSH_KEY" "$SSH_DIR/authorized_keys"; then
            log "SSH-SchlÃ¼ssel bereits vorhanden"
            return 0
        fi
        
        # FÃ¼ge SchlÃ¼ssel hinzu
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys" || {
            log "Fehler: Konnte SSH-SchlÃ¼ssel nicht hinzufÃ¼gen"
            return 1
        }
        chmod 600 "$SSH_DIR/authorized_keys"
        log "SSH-SchlÃ¼ssel erfolgreich hinzugefÃ¼gt"
        notify info "SSH-Zugang eingerichtet"
    else
        log "Kein SSH-SchlÃ¼ssel angegeben, Ã¼berspringe"
    fi
    
    return 0
}
# Systemaktualisierung
update_system() {
    log "FÃ¼hre Systemaktualisierung durch"
    
    if command -v apt-get >/dev/null; then
        apt-get update >/dev/null 2>&1 || {
            log "Warnung: apt-get update fehlgeschlagen"
        }
        apt-get upgrade -y >/dev/null 2>&1 || {
            log "Warnung: apt-get upgrade fehlgeschlagen"
        }
    elif command -v yum >/dev/null; then
        yum update -y >/dev/null 2>&1 || {
            log "Warnung: yum update fehlgeschlagen"
        }
    elif command -v dnf >/dev/null; then
        dnf update -y >/dev/null 2>&1 || {
            log "Warnung: dnf update fehlgeschlagen"
        }
    else
        log "Kein unterstÃ¼tzter Paketmanager gefunden, Ã¼berspringe Systemaktualisierung"
    fi
    
    log "Systemaktualisierung abgeschlossen"
    return 0
}

# Docker installieren
install_docker() {
    log "Installiere Docker"
    
    # PrÃ¼fe, ob Docker bereits installiert ist
    if command -v docker >/dev/null; then
        log "Docker ist bereits installiert"
        return 0
    fi
    
    # Installiere Docker je nach Distribution
    if command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update >/dev/null 2>&1
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release >/dev/null 2>&1
        
        # FÃ¼ge Docker-Repository hinzu
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg >/dev/null 2>&1
        
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null
        
        apt-get update >/dev/null 2>&1
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    elif command -v yum >/dev/null; then
        # RHEL/CentOS
        yum install -y yum-utils >/dev/null 2>&1
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
        yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    elif command -v dnf >/dev/null; then
        # Fedora
        dnf -y install dnf-plugins-core >/dev/null 2>&1
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo >/dev/null 2>&1
        dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    else
        # Fallback: Convenience-Skript
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh >/dev/null 2>&1
        rm get-docker.sh
    fi
    
    # Starte und aktiviere Docker
    systemctl enable --now docker >/dev/null 2>&1
    
    # PrÃ¼fe, ob Docker erfolgreich installiert wurde
    if ! command -v docker >/dev/null; then
        log "Fehler: Docker-Installation fehlgeschlagen"
        return 1
    fi
    
    log "Docker erfolgreich installiert"
    return 0
}

# Docker Compose installieren
install_docker_compose() {
    log "Installiere Docker Compose"
    
    # PrÃ¼fe, ob Docker Compose bereits installiert ist
    if command -v docker-compose >/dev/null; then
        log "Docker Compose ist bereits installiert"
        return 0
    fi
    
    # Installiere Docker Compose
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    
    if [ -z "$COMPOSE_VERSION" ]; then
        COMPOSE_VERSION="v2.20.3"  # Fallback-Version
    fi
    
    mkdir -p /usr/local/bin
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose >/dev/null 2>&1
    chmod +x /usr/local/bin/docker-compose
    
    # PrÃ¼fe, ob Docker Compose erfolgreich installiert wurde
    if ! command -v docker-compose >/dev/null; then
        log "Fehler: Docker Compose-Installation fehlgeschlagen"
        return 1
    fi
    
    log "Docker Compose erfolgreich installiert"
    return 0
}
# Erstelle Hauptfunktion
main() {
    log "Starte Server-Setup-Skript"
    
    # PrÃ¼fe Root-Rechte
    if [ "$(id -u)" -ne 0 ]; then
        log "Fehler: Dieses Skript muss als Root ausgefÃ¼hrt werden"
        exit 1
    fi
    
    # Erstelle temporÃ¤res Verzeichnis
    mkdir -p "$TMP_DIR"
    
    # FÃ¼hre Funktionen aus
    check_root || { log "Root-Check fehlgeschlagen"; exit 1; }
    check_internet || { log "Internetverbindung nicht verfÃ¼gbar"; exit 1; }
    create_temp_dir
    install_dependencies || log "Warnung: Installation der AbhÃ¤ngigkeiten fehlgeschlagen"
    update_system || log "Warnung: Systemaktualisierung fehlgeschlagen"
    get_system_info
    manage_hostname || log "Warnung: Hostname-Konfiguration fehlgeschlagen"
    setup_ssh_key || log "Warnung: SSH-SchlÃ¼ssel-Setup fehlgeschlagen"
    ubuntu_pro_attach || log "Warnung: Ubuntu Pro Aktivierung fehlgeschlagen"
    
    # Installiere Docker und Docker Compose, falls gewÃ¼nscht
    if [ "$INSTALL_DOCKER" = "true" ]; then
        install_docker || log "Warnung: Docker-Installation fehlgeschlagen"
        install_docker_compose || log "Warnung: Docker Compose-Installation fehlgeschlagen"
    fi
    
    # Erstelle Zusammenfassung
    create_summary
    
    # Bereinige temporÃ¤res Verzeichnis
    rm -rf "$TMP_DIR"
    
    log "Server-Setup abgeschlossen"
    return 0
}

# Erstelle Zusammenfassung
create_summary() {
    SUMMARY_FILE="/root/server_setup_summary.txt"
    
    {
        echo "=== SERVER SETUP ZUSAMMENFASSUNG ==="
        echo "Datum: $(date)"
        echo "Hostname: $(hostname)"
        echo "IP-Adressen:"
        ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | sort
        
        echo -e "\n--- SYSTEMINFO ---"
        echo "Betriebssystem: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
        echo "Kernel: $(uname -r)"
        echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')"
        echo "RAM: $(free -h | grep Mem | awk '{print $2}')"
        echo "Festplatte: $(df -h / | awk 'NR==2 {print $2}')"
        
        echo -e "\n--- INSTALLIERTE DIENSTE ---"
        echo "Docker: $(if command -v docker >/dev/null; then echo "Ja ($(docker --version))"; else echo "Nein"; fi)"
        echo "Docker Compose: $(if command -v docker-compose >/dev/null; then echo "Ja ($(docker-compose --version))"; else echo "Nein"; fi)"
        
        echo -e "\n--- OFFENE PORTS ---"
        if command -v netstat >/dev/null; then
            netstat -tulpn | grep LISTEN
        elif command -v ss >/dev/null; then
            ss -tulpn | grep LISTEN
        fi
        
        echo -e "\n=== SETUP ABGESCHLOSSEN ==="
        echo "Weitere Informationen finden Sie im Log: $LOG_FILE"
    } > "$SUMMARY_FILE"
    
    log "Zusammenfassung erstellt: $SUMMARY_FILE"
    
    # Zeige Zusammenfassung an
    cat "$SUMMARY_FILE"
}

# Hilfefunktion
show_help() {
    cat << EOF
Server-Setup-Skript

Dieses Skript automatisiert die Einrichtung eines Linux-Servers mit
grundlegenden Verwaltungsfunktionen.

Verwendung: $0 [OPTIONEN]

Optionen:
  -h, --help              Zeigt diese Hilfe an
  -d, --docker            Installiert Docker und Docker Compose
  -l, --log DATEI         Gibt eine alternative Log-Datei an

Beispiele:
  $0                      FÃ¼hrt Basiseinrichtung aus
  $0 -d                   Installiert Docker und Docker Compose
  $0 --log /var/log/server-setup.log

EOF
    exit 0
}
# Verarbeite Kommandozeilenargumente
process_args() {
    # Standardwerte
    INSTALL_DOCKER="false"
    
    # Argumente verarbeiten
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -d|--docker)
                INSTALL_DOCKER="true"
                shift
                ;;
            -l|--log)
                if [ -n "$2" ]; then
                    LOG_FILE="$2"
                    shift 2
                else
                    log "Fehler: --log benÃ¶tigt einen Dateinamen"
                    exit 1
                fi
                ;;
            --auto-update)
                # Automatisches Update-Flag
                AUTO_UPDATE="true"
                shift
                ;;
            *)
                log "Unbekannte Option: $1"
                show_help
                ;;
        esac
    done
}

# Trap fÃ¼r Error-Handling
trap 'error_handler $LINENO' ERR

# Verarbeite Kommandozeilenargumente
process_args "$@"

# FÃ¼hre Hauptfunktion aus
main

# Erfolgreich beendet
exit 0
