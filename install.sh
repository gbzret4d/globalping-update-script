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
SCRIPT_VERSION="2023.10.21"

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
        info) emoji="📄"; title="Benachrichtigung" ;;
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

# Sudo installieren
install_sudo() {
    log "Prüfe, ob sudo installiert ist..."
    
    # Prüfe, ob sudo installiert ist
    if command -v sudo >/dev/null; then
        log "sudo ist bereits installiert"
        return 0
    fi
    
    log "sudo ist nicht installiert. Installiere..."
    
    # Installiere sudo je nach Distribution
    if command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update >/dev/null 2>&1 || log "Warnung: apt-get update fehlgeschlagen"
        apt-get install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    elif command -v yum >/dev/null; then
        # RHEL/CentOS/Rocky/Alma
        yum install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    elif command -v dnf >/dev/null; then
        # Fedora/Neuere RHEL-basierte Systeme
        dnf install -y sudo >/dev/null 2>&1 || {
            log "Fehler: Konnte sudo nicht installieren"
            return 1
        }
    else
        log "Kein unterstützter Paketmanager gefunden. Kann sudo nicht installieren."
        return 1
    fi
    
    # Prüfe, ob sudo jetzt installiert ist
    if command -v sudo >/dev/null; then
        log "sudo erfolgreich installiert"
        return 0
    else
        log "Fehler: sudo konnte nicht installiert werden"
        return 1
    fi
}
# Direkte Hostname-Konfiguration ohne Zufallszahlen
configure_hostname() {
    log "Konfiguriere Hostname im Format: Land-ISP-ASN-globalping-IPOktett"
    
    # Hole IP-Adresse mit Fallback-Optionen
    IP_ADDRESS=$(curl -s -4 --connect-timeout 5 https://api.ipify.org || 
                 curl -s -4 --connect-timeout 5 https://ifconfig.me || 
                 curl -s -4 --connect-timeout 5 https://icanhazip.com || 
                 echo "0.0.0.0")
    IP_FIRST_OCTET=$(echo "$IP_ADDRESS" | cut -d '.' -f1)
    
    # Debug-Ausgabe
    log "Öffentliche IP erkannt: $IP_ADDRESS (Erstes Oktett: $IP_FIRST_OCTET)"
    
    # Primäre Methode: ipinfo.io
    log "Versuche Daten von ipinfo.io zu holen..."
    ipinfo_response=$(curl -s --connect-timeout 5 "https://ipinfo.io/json")
    
    if [ -n "$ipinfo_response" ] && ! echo "$ipinfo_response" | grep -q "error"; then
        COUNTRY=$(echo "$ipinfo_response" | grep -o '"country": "[^"]*' | cut -d'"' -f4)
        ASN_RAW=$(echo "$ipinfo_response" | grep -o '"org": "[^"]*' | cut -d'"' -f4)
        ASN=$(echo "$ASN_RAW" | grep -o "^AS[0-9]*" | sed 's/AS//')
        ISP=$(echo "$ASN_RAW" | sed 's/^AS[0-9]* //' | tr ' ' '-' | tr -cd '[:alnum:]-')
        
        log "ipinfo.io Daten erfolgreich abgerufen"
        log "Land: $COUNTRY, ASN: $ASN, ISP: $ISP"
    else
        # Fallback: ip-api.com
        log "ipinfo.io fehlgeschlagen, versuche ip-api.com..."
        ip_api_response=$(curl -s --connect-timeout 5 "http://ip-api.com/json")
        
        if [ -n "$ip_api_response" ] && echo "$ip_api_response" | grep -q '"status":"success"'; then
            COUNTRY=$(echo "$ip_api_response" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4)
            ASN=$(echo "$ip_api_response" | grep -o '"as":"[^"]*' | cut -d'"' -f4 | grep -o "AS[0-9]*" | sed 's/AS//')
            ISP=$(echo "$ip_api_response" | grep -o '"isp":"[^"]*' | cut -d'"' -f4 | tr ' ' '-' | tr -cd '[:alnum:]-')
            
            log "ip-api.com Daten erfolgreich abgerufen"
            log "Land: $COUNTRY, ASN: $ASN, ISP: $ISP"
        else
            # Notfall-Fallback
            log "Beide API-Anfragen fehlgeschlagen, verwende Standardwerte"
            COUNTRY="XX"
            ASN="0"
            ISP="unknown"
        fi
    fi
    
    # Sicherstellen, dass alle Variablen Werte haben
    [ -z "$COUNTRY" ] && COUNTRY="XX"
    [ -z "$ASN" ] && ASN="0"
    [ -z "$ISP" ] && ISP="unknown"
    
    # ISP-Name validieren und kürzen
    ISP=$(echo "$ISP" | tr -cd '[:alnum:]-')
    
    # Hostname generieren
    NEW_HOSTNAME="${COUNTRY}-${ISP}-${ASN}-globalping-${IP_FIRST_OCTET}"
    
    # Hostname-Länge auf DNS-Limit (63 Zeichen) beschränken
    if [ ${#NEW_HOSTNAME} -gt 63 ]; then
        # Maximale ISP-Länge berechnen
        max_isp_length=$((63 - ${#COUNTRY} - ${#ASN} - 13 - ${#IP_FIRST_OCTET}))
        ISP="${ISP:0:$max_isp_length}"
        NEW_HOSTNAME="${COUNTRY}-${ISP}-${ASN}-globalping-${IP_FIRST_OCTET}"
        log "Hostname gekürzt: $NEW_HOSTNAME"
    fi
    
    log "Setze Hostname: $NEW_HOSTNAME"
    hostnamectl set-hostname "$NEW_HOSTNAME" || {
        log "hostnamectl fehlgeschlagen, versuche hostname-Befehl"
        hostname "$NEW_HOSTNAME"
        echo "$NEW_HOSTNAME" > /etc/hostname
    }
    
    # Hostname in /etc/hosts eintragen
    if [ -f /etc/hosts ]; then
        sed -i '/^127\.0\.1\.1/d' /etc/hosts
        echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts
    fi
    
    log "Hostname erfolgreich konfiguriert: $NEW_HOSTNAME"
    return 0
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

    # Erkenne Distribution
    DISTRO="Unbekannt"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID $VERSION_ID"
    fi
    
    log "Systeminfo: $DISTRO | $OS_INFO | $CPU_CORES Cores | $MEMORY MB RAM | $DISK_SPACE frei"
}
# Temporäres Verzeichnis erstellen
create_temp_dir() {
    mkdir -p "$TMP_DIR" || {
        log "Warnung: Konnte temporäres Verzeichnis nicht erstellen, verwende /tmp"
        TMP_DIR="/tmp"
    }
    chmod 700 "$TMP_DIR"
    log "Temporäres Verzeichnis angelegt: $TMP_DIR"
}

# Root-Check
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "FEHLER: Dieses Skript benötigt root-Rechte!"
        return 1
    fi
    log "Root-Check erfolgreich"
    return 0
}

# Internetverbindung testen
check_internet() {
    log "Prüfe Internetverbindung..."
    
    # Mehrere Ziele testen mit Timeout
    local targets=("google.com" "cloudflare.com" "1.1.1.1" "8.8.8.8")
    local connected=false
    
    for target in "${targets[@]}"; do
        if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
            connected=true
            break
        fi
    done
    
    # Wenn Ping fehlschlägt, versuche HTTP-Anfrage
    if [ "$connected" = false ]; then
        if curl -s --connect-timeout 5 --max-time 10 "https://www.google.com" >/dev/null 2>&1 || \
           curl -s --connect-timeout 5 --max-time 10 "https://www.cloudflare.com" >/dev/null 2>&1 || \
           curl -s --connect-timeout 5 --max-time 10 "https://1.1.1.1" >/dev/null 2>&1; then
            connected=true
        fi
    fi
    
    if [ "$connected" = false ]; then
        log "KEINE INTERNETVERBINDUNG - Installation kann nicht fortgesetzt werden"
        notify error "❌ Keine Internetverbindung verfügbar"
        return 1
    fi
    
    log "Internetverbindung verfügbar"
    return 0
}
# Abhängigkeiten installieren
install_dependencies() {
    log "Prüfe Systemabhängigkeiten"
    
    # Erkenne Distribution
    local is_debian_based=false
    local is_rhel_based=false
    
    if [ -f /etc/debian_version ] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    # Liste der zu prüfenden Befehle
    local required_cmds=("curl" "wget" "grep" "sed" "awk")
    local missing_cmds=()
    
    # Prüfe, welche Befehle fehlen
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    # Wenn alle Befehle vorhanden sind, überspringe Installation
    if [ ${#missing_cmds[@]} -eq 0 ]; then
        log "Alle benötigten Abhängigkeiten sind bereits installiert"
        return 0
    fi
    
    log "Folgende Abhängigkeiten fehlen: ${missing_cmds[*]}"
    
    if [ "$is_debian_based" = "true" ] && command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update >/dev/null 2>&1 || {
            log "Warnung: apt-get update fehlgeschlagen, versuche trotzdem Installation"
        }
        apt-get install -y \
            curl wget awk sed grep coreutils \
            lsb-release iproute2 systemd >/dev/null 2>&1 || {
            # Überprüfe ob die Pakete trotzdem installiert wurden
            for cmd in "${missing_cmds[@]}"; do
                if ! command -v "$cmd" >/dev/null; then
                    log "Fehler: Konnte Abhängigkeit $cmd nicht installieren"
                    return 1
                fi
            done
            # Wenn wir hier ankommen, wurden alle fehlenden Befehle installiert
            log "Alle benötigten Abhängigkeiten sind jetzt verfügbar"
            return 0
        }
    elif [ "$is_rhel_based" = "true" ]; then
        if command -v dnf >/dev/null; then
            # Neuere RHEL-basierte Systeme (Rocky, Alma, Fedora)
            dnf install -y \
                curl wget gawk sed grep coreutils \
                redhat-lsb-core iproute >/dev/null 2>&1 || {
                # Überprüfe nach Installation
                for cmd in "${missing_cmds[@]}"; do
                    if ! command -v "$cmd" >/dev/null; then
                        log "Fehler: Konnte Abhängigkeit $cmd nicht installieren"
                        return 1
                    fi
                done
                log "Alle benötigten Abhängigkeiten sind jetzt verfügbar"
                return 0
            }
        elif command -v yum >/dev/null; then
            # Ältere RHEL-basierte Systeme
            yum install -y \
                curl wget gawk sed grep coreutils \
                redhat-lsb-core iproute >/dev/null 2>&1 || {
                # Überprüfe nach Installation
                for cmd in "${missing_cmds[@]}"; do
                    if ! command -v "$cmd" >/dev/null; then
                        log "Fehler: Konnte Abhängigkeit $cmd nicht installieren"
                        return 1
                    fi
                done
                log "Alle benötigten Abhängigkeiten sind jetzt verfügbar"
                return 0
            }
        else
            log "Kein unterstützter Paketmanager auf RHEL-basiertem System gefunden"
            return 1
        fi
    else
        log "Kein unterstützter Paketmanager gefunden!"
        log "Versuche minimale Abhängigkeiten zu prüfen..."
        
        # Prüfe minimale Abhängigkeiten
        for cmd in curl wget grep sed; do
            if ! command -v $cmd >/dev/null; then
                log "Kritische Abhängigkeit fehlt: $cmd"
                return 1
            fi
        done
        
        log "Minimale Abhängigkeiten vorhanden, fahre fort"
    fi
    
    log "Systemabhängigkeiten erfolgreich installiert oder bereits vorhanden"
    return 0
}

# SSH-Schlüssel einrichten
setup_ssh_key() {
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR" || {
            log "Fehler: Konnte SSH-Verzeichnis nicht erstellen"
            return 1
        }
        chmod 700 "$SSH_DIR"
    fi
    
    if [ -n "$SSH_KEY" ]; then
        # Prüfe, ob der Schlüssel bereits existiert
        if [ -f "$SSH_DIR/authorized_keys" ] && grep -q "$SSH_KEY" "$SSH_DIR/authorized_keys"; then
            log "SSH-Schlüssel bereits vorhanden"
            return 0
        fi
        
        # Füge Schlüssel hinzu
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys" || {
            log "Fehler: Konnte SSH-Schlüssel nicht hinzufügen"
            return 1
        }
        chmod 600 "$SSH_DIR/authorized_keys"
        log "SSH-Schlüssel erfolgreich hinzugefügt"
        notify info "SSH-Zugang eingerichtet"
    else
        log "Kein SSH-Schlüssel angegeben, überspringe"
    fi
    
    return 0
}
# Systemaktualisierung
update_system() {
    log "Führe Systemaktualisierung durch"
    
    # Erkenne Distribution
    local is_debian_based=false
    local is_rhel_based=false
    
    if [ -f /etc/debian_version ] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    if [ "$is_debian_based" = "true" ] && command -v apt-get >/dev/null; then
        apt-get update >/dev/null 2>&1 || {
            log "Warnung: apt-get update fehlgeschlagen"
        }
        apt-get upgrade -y >/dev/null 2>&1 || {
            log "Warnung: apt-get upgrade fehlgeschlagen"
        }
    elif [ "$is_rhel_based" = "true" ]; then
        if command -v dnf >/dev/null; then
            dnf update -y >/dev/null 2>&1 || {
                log "Warnung: dnf update fehlgeschlagen"
            }
        elif command -v yum >/dev/null; then
            yum update -y >/dev/null 2>&1 || {
                log "Warnung: yum update fehlgeschlagen"
            }
        else
            log "Kein unterstützter Paketmanager auf RHEL-basiertem System gefunden"
        fi
    else
        log "Kein unterstützter Paketmanager gefunden, überspringe Systemaktualisierung"
    fi
    
    log "Systemaktualisierung abgeschlossen"
    return 0
}

# Docker installieren
install_docker() {
    log "Installiere Docker"
    
    # Prüfe, ob Docker bereits installiert ist
    if command -v docker >/dev/null; then
        log "Docker ist bereits installiert"
        return 0
    fi
    
    # Erkenne Distribution
    local is_debian_based=false
    local is_rhel_based=false
    local distro_id=""
    local distro_version=""
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro_id="$ID"
        distro_version="$VERSION_ID"
    fi
    
    if [ -f /etc/debian_version ] || [[ "$distro_id" =~ ^(debian|ubuntu)$ ]]; then
        is_debian_based=true
    elif [[ "$distro_id" =~ ^(rhel|centos|fedora|rocky|almalinux)$ ]]; then
        is_rhel_based=true
    fi
    
    # Installiere Docker je nach Distribution
    if [ "$is_debian_based" = "true" ] && command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update >/dev/null 2>&1
        apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release >/dev/null 2>&1
        
        # Füge Docker-Repository hinzu
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg >/dev/null 2>&1
        
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null
        
        apt-get update >/dev/null 2>&1
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
    elif [ "$is_rhel_based" = "true" ]; then
        # RHEL-basierte Systeme (RHEL, CentOS, Rocky, Alma)
        if command -v dnf >/dev/null; then
            # Neuere RHEL-basierte Systeme
            dnf -y install dnf-plugins-core >/dev/null 2>&1
            
            # Rocky und AlmaLinux verwenden CentOS-Repos
            if [[ "$distro_id" =~ ^(rocky|almalinux)$ ]]; then
                dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
            else
                dnf config-manager --add-repo https://download.docker.com/linux/$(echo "$distro_id" | tr '[:upper:]' '[:lower:]')/docker-ce.repo >/dev/null 2>&1
            fi
            
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
        elif command -v yum >/dev/null; then
            # Ältere RHEL-basierte Systeme
            yum install -y yum-utils >/dev/null 2>&1
            
            # Rocky und AlmaLinux verwenden CentOS-Repos
            if [[ "$distro_id" =~ ^(rocky|almalinux)$ ]]; then
                yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
            else
                yum-config-manager --add-repo https://download.docker.com/linux/$(echo "$distro_id" | tr '[:upper:]' '[:lower:]')/docker-ce.repo >/dev/null 2>&1
            fi
            
            yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
        else
            log "Kein unterstützter Paketmanager auf RHEL-basiertem System gefunden"
            return 1
        fi
    else
        # Fallback: Convenience-Skript
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh >/dev/null 2>&1
        rm get-docker.sh
    fi
    
    # Starte und aktiviere Docker
    systemctl enable --now docker >/dev/null 2>&1
    
    # Prüfe, ob Docker erfolgreich installiert wurde
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
    
    # Prüfe, ob Docker Compose bereits installiert ist
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
    
    # Prüfe, ob Docker Compose erfolgreich installiert wurde
    if ! command -v docker-compose >/dev/null; then
        log "Fehler: Docker Compose-Installation fehlgeschlagen"
        return 1
    fi
    
    log "Docker Compose erfolgreich installiert"
    return 0
}
# Globalping-Probe installieren und konfigurieren
install_globalping_probe() {
    log "Prüfe Globalping-Probe Status"
    
    # Voraussetzungen prüfen
    if [ -z "$ADOPTION_TOKEN" ]; then
        log "Fehler: Kein Adoption-Token angegeben. Probe-Installation nicht möglich."
        notify error "❌ Globalping-Probe konnte nicht installiert werden: Kein Adoption-Token"
        return 1
    fi
    
    # Docker-Installation prüfen und ggf. installieren
    if ! command -v docker >/dev/null; then
        log "Docker wird für Globalping-Probe benötigt, installiere..."
        install_docker || {
            log "Fehler: Docker-Installation fehlgeschlagen, Probe kann nicht installiert werden"
            notify error "❌ Globalping-Probe-Installation fehlgeschlagen: Docker nicht verfügbar"
            return 1
        }
    fi
    
    # Docker Compose prüfen und ggf. installieren
    if ! command -v docker-compose >/dev/null; then
        log "Docker Compose wird benötigt, installiere..."
        install_docker_compose || {
            log "Fehler: Docker Compose-Installation fehlgeschlagen"
            notify error "❌ Globalping-Probe-Installation fehlgeschlagen: Docker Compose nicht verfügbar"
            return 1
        }
    fi
    
    # Prüfen, ob bereits ein Globalping-Container existiert
    if docker ps -a | grep -q globalping-probe; then
        log "Globalping-Probe Container existiert bereits"
        
        # Prüfen, ob der Container mit dem richtigen Token läuft
        local current_token=$(docker inspect -f '{{range .Config.Env}}{{if eq (index (split . "=") 0) "ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}' globalping-probe 2>/dev/null || echo "")
        
        if [ "$current_token" = "$ADOPTION_TOKEN" ]; then
            log "Globalping-Probe ist bereits mit dem richtigen Token konfiguriert"
            
            # Prüfen ob ein Update verfügbar ist
            log "Prüfe auf Updates für Globalping-Probe..."
            
            # Container stoppen, Image aktualisieren und neu starten
            log "Aktualisiere Globalping-Probe..."
            
            docker stop globalping-probe >/dev/null 2>&1
            docker rm globalping-probe >/dev/null 2>&1
            docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1
            
            log "Alte Globalping-Probe entfernt, starte neue Version"
        else
            log "Globalping-Probe mit unterschiedlichem Token gefunden, aktualisiere..."
            
            # Container stoppen und entfernen
            docker stop globalping-probe >/dev/null 2>&1
            docker rm globalping-probe >/dev/null 2>&1
            
            log "Alte Globalping-Probe entfernt, setze mit neuem Token fort"
        fi
    else
        log "Keine vorhandene Globalping-Probe gefunden, führe Neuinstallation durch"
    fi
    
    # Verzeichnis erstellen
    mkdir -p /opt/globalping || {
        log "Fehler: Konnte Verzeichnis /opt/globalping nicht erstellen"
        return 1
    }
    
    # Docker Compose-Datei erstellen
    cat > /opt/globalping/docker-compose.yml << EOF
version: '3'
services:
  probe:
    image: ghcr.io/jsdelivr/globalping-probe:latest
    container_name: globalping-probe
    restart: always
    environment:
      - ADOPTION_TOKEN=${ADOPTION_TOKEN}
    volumes:
      - ./probe-data:/home/node/.globalping
    network_mode: host
EOF
    
    # Probe starten
    cd /opt/globalping && docker-compose up -d || {
        log "Fehler: Konnte Globalping-Probe nicht starten"
        notify error "❌ Globalping-Probe-Start fehlgeschlagen"
        return 1
    }
    
    # Warten auf Probe-Initialisierung
    log "Warte auf Initialisierung der Globalping-Probe..."
    sleep 10
    
    # Prüfen, ob Container läuft
    if docker ps | grep -q globalping-probe; then
        log "Globalping-Probe erfolgreich gestartet"
        notify success "✅ Globalping-Probe erfolgreich installiert und gestartet"
    else
        log "Fehler: Globalping-Probe-Container nicht gefunden nach Start"
        notify error "❌ Globalping-Probe-Start fehlgeschlagen: Container nicht aktiv"
        return 1
    fi
    
    # Maintenance-Skript erstellen
    create_globalping_maintenance
    
    return 0
}
# Erstelle Wartungsskript für Globalping
create_globalping_maintenance() {
    log "Erstelle Globalping-Wartungsskript"
    
    cat > /usr/local/bin/globalping-maintenance << 'EOF'
#!/bin/bash
set -eo pipefail

LOG_FILE="/var/log/globalping-maintenance.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Sicherstellen, dass das Log-Verzeichnis existiert
mkdir -p "$(dirname "$LOG_FILE")"

log "Starte Globalping-Wartung"

# Probe-Update durchführen
log "Aktualisiere Globalping-Probe..."
cd /opt/globalping && docker-compose pull && docker-compose up -d

# Alte Images aufräumen
log "Bereinige alte Docker-Images..."
docker image prune -af --filter "until=24h"

# Logs rotieren
log "Rotiere Logs..."
find /opt/globalping -name "*.log" -type f -size +100M -exec truncate -s 0 {} \;

log "Globalping-Wartung abgeschlossen"
EOF
    
    chmod +x /usr/local/bin/globalping-maintenance
    
    # Cron-Job einrichten
    if ! crontab -l | grep -q "globalping-maintenance"; then
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        log "Cron-Job für Globalping-Wartung eingerichtet"
    fi
    
    log "Globalping-Wartungsskript erstellt und eingerichtet"
}

# Globalping-Probe Status prüfen
check_globalping_status() {
    log "Prüfe Status der Globalping-Probe"
    
    if ! docker ps -a | grep -q globalping-probe; then
        log "Globalping-Probe ist nicht installiert"
        return 1
    fi
    
    local container_status=$(docker inspect -f '{{.State.Status}}' globalping-probe 2>/dev/null || echo "error")
    
    if [ "$container_status" = "running" ]; then
        log "Globalping-Probe ist aktiv und läuft"
        
        # Uptime prüfen
        local uptime=$(docker inspect -f '{{.State.StartedAt}}' globalping-probe | xargs -I{} date -d {} '+%s')
        local now=$(date '+%s')
        local uptime_seconds=$((now - uptime))
        local uptime_days=$((uptime_seconds / 86400))
        local uptime_hours=$(( (uptime_seconds % 86400) / 3600 ))
        
        log "Probe läuft seit $uptime_days Tagen und $uptime_hours Stunden"
        
        # Logs auf Fehler prüfen
        local error_count=$(docker logs --tail 100 globalping-probe 2>&1 | grep -c -i "error" || true)
        if [ "$error_count" -gt 5 ]; then
            log "Warnung: $error_count Fehler in den letzten 100 Log-Einträgen gefunden"
            notify warn "⚠️ Globalping-Probe zeigt $error_count Fehler in den Logs"
        fi
        
        return 0
    else
        log "Globalping-Probe ist nicht aktiv (Status: $container_status)"
        notify error "❌ Globalping-Probe ist nicht aktiv (Status: $container_status)"
        
        # Versuche Container zu starten, wenn er existiert aber nicht läuft
        if [ "$container_status" != "error" ]; then
            log "Versuche Globalping-Probe neu zu starten..."
            docker start globalping-probe && {
                log "Globalping-Probe erfolgreich neu gestartet"
                notify success "✅ Globalping-Probe erfolgreich neu gestartet"
                return 0
            } || {
                log "Fehler: Konnte Globalping-Probe nicht neu starten"
                return 1
            }
        fi
        
        return 1
    fi
}
# Architektur erkennen und anpassen
detect_architecture() {
    log "Erkenne System-Architektur"
    
    ARCH=$(uname -m)
    IS_ARM=false
    
    case "$ARCH" in
        arm*|aarch*)
            IS_ARM=true
            log "ARM-Architektur erkannt: $ARCH"
            ;;
        x86_64|amd64)
            log "x86_64-Architektur erkannt"
            ;;
        *)
            log "Unbekannte Architektur: $ARCH"
            ;;
    esac
    
    # Für Raspberry Pi spezifische Erkennung
    if [ "$IS_ARM" = "true" ] && [ -f /proc/device-tree/model ] && grep -q "Raspberry Pi" /proc/device-tree/model; then
        IS_RASPBERRY_PI=true
        PI_MODEL=$(tr -d '\0' < /proc/device-tree/model)
        log "Raspberry Pi erkannt: $PI_MODEL"
        
        # Optimierungen für Raspberry Pi
        optimize_for_raspberry_pi
    fi
    
    return 0
}

# Raspberry Pi-spezifische Optimierungen
optimize_for_raspberry_pi() {
    log "Führe Raspberry Pi-spezifische Optimierungen durch"
    
    # Swap-Optimierung für bessere SD-Karten-Lebensdauer
    if [ -f /etc/dphys-swapfile ]; then
        log "Optimiere Swap-Einstellungen"
        # Sichern der ursprünglichen Datei
        cp /etc/dphys-swapfile /etc/dphys-swapfile.backup
        
        # Weniger häufige Swap-Nutzung
        echo "CONF_SWAPPINESS=10" >> /etc/dphys-swapfile
        
        # Angemessene Swap-Größe setzen (basierend auf RAM)
        TOTAL_MEM=$(free -m | grep Mem | awk '{print $2}')
        if [ "$TOTAL_MEM" -lt 1024 ]; then
            # Wenig RAM, mehr Swap
            echo "CONF_SWAPSIZE=1024" >> /etc/dphys-swapfile
        else
            # Mehr RAM, weniger Swap
            echo "CONF_SWAPSIZE=512" >> /etc/dphys-swapfile
        fi
        
        # Swap-Dienst neu starten
        /etc/init.d/dphys-swapfile restart
    fi
    
    # Überprüfen und Einstellen des GPU-Speichers (minimal für Headless-Betrieb)
    if [ -f /boot/config.txt ]; then
        log "Konfiguriere GPU-Speicher für Headless-Betrieb"
        
        if ! grep -q "^gpu_mem=" /boot/config.txt; then
            echo "gpu_mem=16" >> /boot/config.txt
            log "GPU-Speicher auf 16MB eingestellt (Headless-Optimierung)"
        fi
    fi
    
    # Temperaturüberwachung einrichten
    if command -v vcgencmd >/dev/null; then
        log "Richte Temperaturüberwachung ein"
        
        # Erstelle Skript zur Temperaturüberwachung
        cat > /usr/local/bin/check-pi-temp << 'EOF'
#!/bin/bash
TEMP=$(vcgencmd measure_temp | cut -d= -f2 | cut -d\' -f1)
echo "Raspberry Pi Temperatur: $TEMP°C"
if (( $(echo "$TEMP > 75" | bc -l) )); then
    echo "WARNUNG: Temperatur über 75°C!" >&2
    exit 1
fi
exit 0
EOF
        chmod +x /usr/local/bin/check-pi-temp
        
        # Cron-Job für stündliche Temperaturprüfung
        if ! crontab -l | grep -q "check-pi-temp"; then
            (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/check-pi-temp | logger -t pi-temp") | crontab -
            log "Cron-Job für Temperaturüberwachung eingerichtet"
        fi
    fi
    
    log "Raspberry Pi-Optimierungen abgeschlossen"
    return 0
}

# Selbstdiagnose durchführen
run_self_diagnosis() {
    log "Führe Selbstdiagnose durch"
    
    # Ergebnis-Array
    local issues=()
    
    # 1. Speicherplatz prüfen
    log "Prüfe Speicherplatz..."
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        issues+=("Kritischer Speicherplatz: $disk_usage% belegt")
    fi
    
    # 2. RAM-Nutzung prüfen
    log "Prüfe RAM-Nutzung..."
    local free_memory=$(free -m | awk '/Mem:/ {print $4}')
    if [ "$free_memory" -lt 100 ]; then
        issues+=("Wenig freier RAM: Nur $free_memory MB verfügbar")
    fi
    
    # 3. CPU-Auslastung prüfen
    log "Prüfe CPU-Auslastung..."
    local load=$(cat /proc/loadavg | cut -d' ' -f1)
    local cores=$(nproc)
    if (( $(echo "$load > $cores" | bc -l) )); then
        issues+=("Hohe CPU-Last: $load (Kerne: $cores)")
    fi
    
    # 4. Systemdienste prüfen
    log "Prüfe kritische Systemdienste..."
    local critical_services=("systemd-journald" "systemd-logind" "cron" "sshd")
    for service in "${critical_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            :  # Dienst läuft
        else
            issues+=("Kritischer Dienst nicht aktiv: $service")
        fi
    done
    
    # 5. Netzwerk-Interface prüfen
    log "Prüfe Netzwerk-Interfaces..."
    if ! ip link | grep -q "UP"; then
        issues+=("Kein aktives Netzwerk-Interface gefunden")
    fi
    
    # 6. Docker-Status prüfen (falls vorhanden)
    if command -v docker >/dev/null; then
        log "Prüfe Docker-Status..."
        if ! systemctl is-active docker >/dev/null 2>&1; then
            issues+=("Docker-Dienst ist nicht aktiv")
        fi
        
        # Unhealthy Container finden
        local unhealthy_containers=$(docker ps --filter health=unhealthy -q | wc -l)
        if [ "$unhealthy_containers" -gt 0 ]; then
            issues+=("$unhealthy_containers Container mit Status 'unhealthy'")
        fi
    fi
    
    # 7. Globalping-Probe prüfen (falls installiert)
    if docker ps -a | grep -q globalping-probe; then
        log "Prüfe Globalping-Probe..."
        if ! docker ps | grep -q globalping-probe; then
            issues+=("Globalping-Probe ist nicht aktiv")
        fi
    fi
    
    # Ergebnisse anzeigen
    if [ ${#issues[@]} -eq 0 ]; then
        log "Selbstdiagnose abgeschlossen: Keine Probleme gefunden"
        return 0
    else
        log "Selbstdiagnose abgeschlossen: ${#issues[@]} Probleme gefunden"
        for issue in "${issues[@]}"; do
            log "PROBLEM: $issue"
        done
        
        # Kritische Probleme an Telegram senden
        notify warn "⚠️ Selbstdiagnose: ${#issues[@]} Probleme gefunden"
        return 1
    fi
}
# Netzwerk-Diagnose durchführen
run_network_diagnosis() {
    log "Führe Netzwerk-Diagnose durch"
    
    local issues=()
    
    # 1. DNS-Auflösung testen
    log "Teste DNS-Auflösung..."
    if ! host -W 2 google.com >/dev/null 2>&1 && ! host -W 2 cloudflare.com >/dev/null 2>&1; then
        issues+=("DNS-Auflösung fehlgeschlagen")
    fi
    
    # 2. Paketverlustraten messen
    log "Messe Paketverlustrate..."
    local packet_loss=$(ping -c 10 -q 1.1.1.1 2>/dev/null | grep -oP '\d+(?=% packet loss)' || echo "100")
    if [ "$packet_loss" -gt 5 ]; then
        issues+=("Hohe Paketverlustrate: $packet_loss%")
    fi
    
    # 3. Latenzen zu verschiedenen Zielen messen
    log "Messe Netzwerklatenz..."
    local targets=("1.1.1.1" "8.8.8.8" "google.com")
    local high_latency=false
    
    for target in "${targets[@]}"; do
        local latency=$(ping -c 3 -q "$target" 2>/dev/null | grep -oP 'avg=\K[0-9\.]+' || echo "999")
        log "Latenz zu $target: ${latency}ms"
        
        if (( $(echo "$latency > 200" | bc -l) )); then
            high_latency=true
            issues+=("Hohe Latenz zu $target: ${latency}ms")
        fi
    done
    
    # 4. MTU-Größe testen
    log "Prüfe MTU-Größe..."
    local default_interface=$(ip route | grep default | head -1 | awk '{print $5}')
    if [ -n "$default_interface" ]; then
        local current_mtu=$(ip link show "$default_interface" | grep -oP 'mtu \K\d+')
        log "Aktuelle MTU auf $default_interface: $current_mtu"
        
        if [ "$current_mtu" -lt 1400 ]; then
            issues+=("Ungewöhnlich niedrige MTU: $current_mtu auf $default_interface")
        fi
    else
        issues+=("Kein Standard-Gateway gefunden")
    fi
    
    # 5. Routing-Tabelle prüfen
    log "Prüfe Routing-Tabelle..."
    if ! ip route | grep -q "^default"; then
        issues+=("Keine Standard-Route gefunden")
    fi
    
    # 6. IPv6-Konnektivität prüfen
    log "Prüfe IPv6-Konnektivität..."
    if ip -6 addr | grep -q "scope global"; then
        if ! ping -6 -c 1 -W 3 2606:4700:4700::1111 >/dev/null 2>&1; then
            issues+=("IPv6 konfiguriert, aber keine Konnektivität")
        else
            log "IPv6-Konnektivität verfügbar"
        fi
    else
        log "Keine globale IPv6-Adresse konfiguriert"
    fi
    
    # Ergebnisse anzeigen
    if [ ${#issues[@]} -eq 0 ]; then
        log "Netzwerk-Diagnose abgeschlossen: Keine Probleme gefunden"
        return 0
    else
        log "Netzwerk-Diagnose abgeschlossen: ${#issues[@]} Probleme gefunden"
        for issue in "${issues[@]}"; do
            log "NETZWERK-PROBLEM: $issue"
        done
        
        # Probleme an Telegram senden
        notify warn "⚠️ Netzwerk-Diagnose: ${#issues[@]} Probleme gefunden"
        return 1
    fi
}

# Debug-Modus (detailliertes Logging)
enable_debug_mode() {
    log "Aktiviere Debug-Modus"
    
    # Erweitere das Logging
    set -x
    
    # Speichere Debug-Log in separater Datei
    exec 19> "/var/log/globalping-debug-$(date +%s).log"
    BASH_XTRACEFD=19
    
    DEBUG_MODE=true
    log "Debug-Modus aktiviert, ausführliches Logging in Datei"
    
    return 0
}

# Haupt-Diagnosefunktion
run_diagnostics() {
    log "Starte umfassende Systemdiagnose"
    
    # Erstelle Diagnose-Verzeichnis
    local diag_dir="/var/log/globalping-diagnostics/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$diag_dir"
    
    # Speichere Systeminfos
    log "Sammle Systeminformationen..."
    uname -a > "$diag_dir/uname.txt"
    cat /etc/os-release > "$diag_dir/os-release.txt"
    free -h > "$diag_dir/memory.txt"
    df -h > "$diag_dir/disk.txt"
    lscpu > "$diag_dir/cpu.txt"
    
    # Führe Diagnosetests durch
    log "Führe Selbstdiagnose durch..."
    run_self_diagnosis > "$diag_dir/self-diagnosis.txt" 2>&1
    
    log "Führe Netzwerk-Diagnose durch..."
    run_network_diagnosis > "$diag_dir/network-diagnosis.txt" 2>&1
    
    # Speichere Docker-Status, falls vorhanden
    if command -v docker >/dev/null; then
        log "Sammle Docker-Informationen..."
        docker info > "$diag_dir/docker-info.txt" 2>&1
        docker ps -a > "$diag_dir/docker-ps.txt" 2>&1
        docker stats --no-stream > "$diag_dir/docker-stats.txt" 2>&1
        
        # Probe-Logs, falls vorhanden
        if docker ps -a | grep -q globalping-probe; then
            docker logs globalping-probe > "$diag_dir/globalping-logs.txt" 2>&1
            docker inspect globalping-probe > "$diag_dir/globalping-inspect.txt" 2>&1
        fi
    fi
    
    # System-Logs sammeln
    log "Sammle System-Logs..."
    journalctl -n 1000 > "$diag_dir/journalctl.txt" 2>&1
    dmesg > "$diag_dir/dmesg.txt" 2>&1
    
    if [ -f "/var/log/syslog" ]; then
        tail -n 1000 /var/log/syslog > "$diag_dir/syslog.txt"
    fi
    
    # Ergebnis-Archiv erstellen
    local archive_file="/root/globalping-diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$archive_file" -C "$(dirname "$diag_dir")" "$(basename "$diag_dir")"
    
    log "Diagnose abgeschlossen. Ergebnisse in: $archive_file"
    notify success "✅ Systemdiagnose abgeschlossen. Ergebnisse gespeichert."
    
    # Aufräumen
    rm -rf "$diag_dir"
    
    return 0
}
# Erstelle Hauptfunktion
main() {
    log "Starte Server-Setup-Skript"
    
    # Prüfe Root-Rechte
    if [ "$(id -u)" -ne 0 ]; then
        log "Fehler: Dieses Skript muss als Root ausgeführt werden"
        exit 1
    fi
    
    # Erstelle temporäres Verzeichnis
    mkdir -p "$TMP_DIR"
    
    # Führe Funktionen aus
    check_root || { log "Root-Check fehlgeschlagen"; exit 1; }
    check_internet || { log "Internetverbindung nicht verfügbar"; exit 1; }
    create_temp_dir
    
    # Installiere sudo, falls nicht vorhanden
    install_sudo || log "Warnung: sudo-Installation fehlgeschlagen"
    
    # Erkenne Architektur
    detect_architecture
    
    install_dependencies || log "Warnung: Installation der Abhängigkeiten fehlgeschlagen"
    update_system || log "Warnung: Systemaktualisierung fehlgeschlagen"
    get_system_info
    
    # Verwende die neue Hostname-Konfiguration
    configure_hostname || log "Warnung: Hostname-Konfiguration fehlgeschlagen"
    
    setup_ssh_key || log "Warnung: SSH-Schlüssel-Setup fehlgeschlagen"
    
    # Aktiviere Ubuntu Pro nur auf Ubuntu-Systemen
    if grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        ubuntu_pro_attach || log "Warnung: Ubuntu Pro Aktivierung fehlgeschlagen"
    else
        log "Kein Ubuntu-System erkannt, überspringe Ubuntu Pro Aktivierung"
    fi
    
    # Globalping-Probe installieren, wenn Adoption-Token angegeben
    if [ -n "$ADOPTION_TOKEN" ]; then
        install_globalping_probe || log "Warnung: Globalping-Probe-Installation fehlgeschlagen"
    else
        log "Kein Adoption-Token angegeben, überspringe Globalping-Probe-Installation"
    fi
    
    # Führe Diagnose durch
    run_diagnostics
    
    # Erstelle Zusammenfassung
    create_summary
    
    # Bereinige temporäres Verzeichnis
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
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "Distribution: $NAME $VERSION_ID"
        else
            echo "Distribution: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'Unbekannt')"
        fi
        echo "Kernel: $(uname -r)"
        echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')"
        echo "RAM: $(free -h | grep Mem | awk '{print $2}')"
        echo "Festplatte: $(df -h / | awk 'NR==2 {print $2}')"
        
        echo -e "\n--- INSTALLIERTE DIENSTE ---"
        echo "sudo: $(if command -v sudo >/dev/null; then echo "Ja ($(sudo --version | head -1))"; else echo "Nein"; fi)"
        echo "Docker: $(if command -v docker >/dev/null; then echo "Ja ($(docker --version))"; else echo "Nein"; fi)"
        echo "Docker Compose: $(if command -v docker-compose >/dev/null; then echo "Ja ($(docker-compose --version))"; else echo "Nein"; fi)"
        echo "Globalping-Probe: $(if docker ps | grep -q globalping-probe; then echo "Ja (Aktiv)"; elif docker ps -a | grep -q globalping-probe; then echo "Ja (Inaktiv)"; else echo "Nein"; fi)"
        
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
Server-Setup-Skript v$SCRIPT_VERSION

Dieses Skript automatisiert die Einrichtung eines Linux-Servers mit
Globalping-Probe und grundlegenden Verwaltungsfunktionen.

Verwendung: $0 [OPTIONEN]

Optionen:
  -h, --help                  Zeigt diese Hilfe an
  -d, --docker                Installiert Docker und Docker Compose
  -l, --log DATEI             Gibt eine alternative Log-Datei an
  --adoption-token TOKEN      Setzt den Globalping Adoption-Token
  --telegram-token TOKEN      Setzt den Telegram-Bot-Token
  --telegram-chat ID          Setzt die Telegram-Chat-ID
  --ubuntu-token TOKEN        Setzt den Ubuntu Pro Token
  --ssh-key SCHLÜSSEL         Fügt einen SSH-Schlüssel hinzu
  --diagnose                  Führt umfassende Systemdiagnose durch
  --debug                     Aktiviert ausführliches Logging
  --auto-update               Führt automatisches Update durch

Beispiele:
  $0 --adoption-token "xxx"   Richtet einen Globalping-Probe-Server ein
  $0 --diagnose               Führt Diagnose auf bestehendem Server durch
  $0 --help                   Zeigt diese Hilfe an

EOF
    exit 0
}

# Verarbeite Kommandozeilenargumente
process_args() {
    # Standardwerte
    INSTALL_DOCKER="false"
    RUN_DIAGNOSTICS_ONLY="false"
    
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
                    log "Fehler: --log benötigt einen Dateinamen"
                    exit 1
                fi
                ;;
            --auto-update)
                # Automatisches Update-Flag
                AUTO_UPDATE="true"
                shift
                ;;
            --adoption-token)
                if [ -n "$2" ]; then
                    ADOPTION_TOKEN="$2"
                    shift 2
                else
                    log "Fehler: --adoption-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-token)
                if [ -n "$2" ]; then
                    TELEGRAM_TOKEN="$2"
                    shift 2
                else
                    log "Fehler: --telegram-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --telegram-chat)
                if [ -n "$2" ]; then
                    TELEGRAM_CHAT="$2"
                    shift 2
                else
                    log "Fehler: --telegram-chat benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ubuntu-token)
                if [ -n "$2" ]; then
                    UBUNTU_PRO_TOKEN="$2"
                    shift 2
                else
                    log "Fehler: --ubuntu-token benötigt einen Wert"
                    exit 1
                fi
                ;;
            --ssh-key)
                if [ -n "$2" ]; then
                    SSH_KEY="$2"
                    shift 2
                else
                    log "Fehler: --ssh-key benötigt einen Wert"
                    exit 1
                fi
                ;;
            --diagnose)
                RUN_DIAGNOSTICS_ONLY="true"
                shift
                ;;
            --debug)
                enable_debug_mode
                shift
                ;;
            *)
                log "Unbekannte Option: $1"
                show_help
                ;;
        esac
    done
    
    # Wenn nur Diagnose ausgeführt werden soll
    if [ "$RUN_DIAGNOSTICS_ONLY" = "true" ]; then
        check_root || { log "Root-Check fehlgeschlagen"; exit 1; }
        run_diagnostics
        exit 0
    fi
}

# Trap für Error-Handling
trap 'error_handler $LINENO' ERR

# Verarbeite Kommandozeilenargumente
process_args "$@"

# Führe Hauptfunktion aus
main

# Erfolgreich beendet
exit 0