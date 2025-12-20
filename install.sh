#!/bin/bash
set -euo pipefail

# =============================================
# GLOBAL VARIABLES & COMPATIBILITY LAYER
# =============================================
# ACHTUNG: Diese leeren Variablen MÜSSEN hier stehen bleiben.
# Alte Versionen des Skripts nutzen 'sed', um hier Werte einzutragen.
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# CONSTANTS & CONFIGURATION
# =============================================
readonly SCRIPT_VERSION="2025.12.21-v2.9"
readonly CONFIG_FILE="/etc/globalping/config.env"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"

# Resource Limits (Defaults) - Override in config.env
GP_CPU_LIMIT="0.90"   # 90% of one core
GP_MEM_LIMIT=""       # Empty = Docker default

# System Requirements
readonly MIN_FREE_SPACE_GB="1.5"
readonly MIN_RAM_MB="256"
readonly MAX_LOG_SIZE_MB="50"

# Timeouts
readonly TIMEOUT_NETWORK="15"

# Runtime State
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"
FORCE_RECREATE="false"

# System Info Placeholders
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""

# =============================================
# 1. CONFIGURATION MIGRATION SYSTEM
# =============================================

load_and_migrate_config() {
    # Ensure config directory exists
    if [[ ! -d "$(dirname "${CONFIG_FILE}")" ]]; then
        mkdir -p "$(dirname "${CONFIG_FILE}")"
        chmod 700 "$(dirname "${CONFIG_FILE}")"
    fi

    # 1. Load existing config
    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi

    # 2. MIGRATION: Check if variables were injected by old update script
    local save_needed=false

    migrate_var() {
        local var_name="$1"
        local var_value="$2"
        if [[ -n "${var_value}" ]] && ! grep -q "${var_name}=" "${CONFIG_FILE}" 2>/dev/null; then
            echo "${var_name}=\"${var_value}\"" >> "${CONFIG_FILE}"
            save_needed=true
        fi
    }

    migrate_var "ADOPTION_TOKEN" "${ADOPTION_TOKEN}"
    migrate_var "TELEGRAM_TOKEN" "${TELEGRAM_TOKEN}"
    migrate_var "TELEGRAM_CHAT" "${TELEGRAM_CHAT}"
    migrate_var "SSH_KEY" "${SSH_KEY}"
    migrate_var "UBUNTU_PRO_TOKEN" "${UBUNTU_PRO_TOKEN}"

    # 3. Save Defaults if missing
    if ! grep -q "GP_CPU_LIMIT=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "GP_CPU_LIMIT=\"${GP_CPU_LIMIT}\"" >> "${CONFIG_FILE}"
    fi

    if [[ "${save_needed}" == "true" ]]; then
        chmod 600 "${CONFIG_FILE}"
        # Reload to ensure consistency
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        echo "[INFO] Configuration successfully migrated to ${CONFIG_FILE}" >> "${LOG_FILE}"
    fi
}

save_config_var() {
    local key="$1"
    local value="$2"
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    touch "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
    
    if grep -q "^${key}=" "${CONFIG_FILE}"; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "${CONFIG_FILE}"
    else
        echo "${key}=\"${value}\"" >> "${CONFIG_FILE}"
    fi
}

# =============================================
# 2. HELPER FUNCTIONS & LOGGING
# =============================================

setup_colors() {
    if [ -t 1 ]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        NC='\033[0m' # No Color
    else
        RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""
    fi
}

enhanced_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local prefix
    local color
    
    case "${level}" in
        "ERROR") prefix="❌ [ERROR]"; color="${RED}" ;;
        "WARN")  prefix="⚠️  [WARN]";  color="${YELLOW}" ;;
        "INFO")  prefix="ℹ️  [INFO]";  color="${GREEN}" ;;
        "DEBUG") prefix="🔍 [DEBUG]"; color="${BLUE}" ;;
        *)       prefix="📝 [${level}]"; color="${NC}" ;;
    esac
    
    # Log to file (plain text)
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    echo "[${timestamp}] ${prefix} ${message}" >> "${LOG_FILE}"
    
    # Log to screen (colored)
    echo -e "${color}[${timestamp}] ${prefix} ${message}${NC}"
}

log() { enhanced_log "INFO" "$1"; }
warn() { enhanced_log "WARN" "$1"; }
err() { enhanced_log "ERROR" "$1"; }

retry_command() {
    local retries=3
    local count=0
    local delay=5
    local cmd="$*"

    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [ $count -lt $retries ]; then
            warn "Command failed (Attempt $count/$retries): $cmd"
            sleep $delay
        else
            err "Command failed after $retries attempts: $cmd"
            return $exit_code
        fi
    done
    return 0
}

wait_for_apt_locks() {
    local max_retries=60
    local i=0
    
    # Only check on Debian/Ubuntu systems
    if [ -f /etc/debian_version ]; then
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
              fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
              fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
            
            if [ $i -ge $max_retries ]; then
                warn "Timeout waiting for APT locks. Attempting to proceed..."
                break
            fi
            if [ $i -eq 0 ]; then log "Waiting for APT locks (another update is running)..."; fi
            sleep 2
            ((i++))
        done
    fi
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "This script requires root privileges. Please use sudo."
        return 1
    fi
    return 0
}

# =============================================
# 3. SYSTEM INFORMATION & TELEGRAM
# =============================================

get_enhanced_system_info() {
    log "Collecting extended system information..."
    
    PUBLIC_IP=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "unknown")
    local ipinfo
    ipinfo=$(curl -s --connect-timeout 5 "https://ipinfo.io/json" 2>/dev/null || echo "")
    
    if [[ -n "$ipinfo" ]]; then
        COUNTRY=$(echo "$ipinfo" | grep -o '"country": *"[^"]*"' | cut -d'"' -f4 | head -1)
        local asn_raw
        asn_raw=$(echo "$ipinfo" | grep -o '"org": *"[^"]*"' | cut -d'"' -f4 | head -1)
        if [[ -n "$asn_raw" ]]; then
            ASN=$(echo "$asn_raw" | grep -o "AS[0-9]*" | head -1)
            PROVIDER=$(echo "$asn_raw" | sed 's/^AS[0-9]* //' | tr ' ' '-' | tr -cd '[:alnum:] -')
        fi
    fi
    
    # Fallbacks
    [[ -z "${COUNTRY}" ]] && COUNTRY="XX"
    [[ -z "${ASN}" ]] && ASN="unknown"
    [[ -z "${PROVIDER}" ]] && PROVIDER="unknown"

    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        # Intelligent Hostname Generation
        HOSTNAME_NEW="${COUNTRY,,}-${PROVIDER,,}-${ASN}-globalping-$(echo "${PUBLIC_IP}" | tr '.' '-')"
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-node")
    fi
    
    log "System Identification: IP=${PUBLIC_IP}, Host=${HOSTNAME_NEW}, ISP=${PROVIDER}, ASN=${ASN}"
}

enhanced_notify() {
    local level="$1"
    local title="$2"
    local message="$3"

    # Avoid duplicate success messages
    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then return 0; fi
    # Only send Errors and Install Success
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then return 0; fi
    # Check config
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then return 0; fi

    # Ensure we have data
    if [[ -z "${COUNTRY}" ]]; then get_enhanced_system_info; fi

    local icon emoji
    if [[ "${level}" == "install_success" ]]; then
        icon="✅"; emoji="SUCCESS"; TELEGRAM_SENT="true"
    else
        icon="❌"; emoji="CRITICAL ERROR"
    fi

    # --- RESTORED DETAILED STATS ---
    local ram_info disk_info load_info virt_type
    ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "?")
    disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5")"}' || echo "?")
    load_info=$(uptime | awk -F'load average:' '{print $2}' | xargs || echo "?")
    virt_type=$(systemd-detect-virt 2>/dev/null || echo "Bare Metal")
    
    local docker_stat="Not Installed"
    if command -v docker >/dev/null 2>&1; then docker_stat="Installed"; fi
    
    local fail2ban_stat="Not Installed"
    if command -v fail2ban-client >/dev/null 2>&1; then fail2ban_stat="Active"; fi

    local extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP: [${PUBLIC_IP}](https://ipinfo.io/${PUBLIC_IP})
├─ ISP: ${PROVIDER}
├─ ASN: [${ASN}](https://bgp.he.net/${ASN})
└─ Virt: ${virt_type}

💾 SYSTEM STATUS:
├─ RAM: ${ram_info}
├─ Disk: ${disk_info}
└─ Load: ${load_info}

🔧 SERVICES:
├─ Docker: ${docker_stat}
├─ Fail2Ban: ${fail2ban_stat}
├─ SSH Key: ${SSH_KEY:+Configured}${SSH_KEY:-Not set}
└─ Ubuntu Pro: ${UBUNTU_PRO_TOKEN:+Active}${UBUNTU_PRO_TOKEN:-Not used}

📋 ${title}:
${message}

🔗 LINKS:
├─ [Geo Map](https://db-ip.com/${PUBLIC_IP})
└─ [BGP Routing](https://bgp.he.net/${ASN})

📊 Logs: /var/log/globalping-install.log"

    # Send with simplified curl but keep full message
    if ! curl -s -X POST --connect-timeout 10 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        -d "parse_mode=Markdown" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" >/dev/null 2>&1; then
            warn "Failed to send Telegram notification (Network/Token issue)."
    fi
}

# =============================================
# 4. INSTALLATION & OPTIMIZATION
# =============================================

install_dependencies() {
    log "Checking and installing dependencies..."
    
    local missing_cmds=()
    for cmd in curl wget unzip tar gzip bc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then missing_cmds+=("$cmd"); fi
    done
    
    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        log "All base dependencies are already installed."
        return 0
    fi
    
    log "Installing missing dependencies: ${missing_cmds[*]}"
    if command -v apt-get >/dev/null 2>&1; then 
        wait_for_apt_locks
        retry_command apt-get update >/dev/null 2>&1
        retry_command apt-get install -y curl wget unzip docker.io bc tar gzip >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        retry_command dnf install -y curl wget unzip docker bc tar gzip >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        retry_command yum install -y curl wget unzip docker bc tar gzip >/dev/null 2>&1 || true
    fi
}

update_system_packages() {
    log "Updating system packages (Security)..."
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        # Check for phased updates
        if apt list --upgradable 2>/dev/null | grep -q "phased"; then
             log "Phased updates detected. Skipping full upgrade to avoid reboot loops."
             retry_command apt-get upgrade -y >/dev/null 2>&1 || true
        else
             retry_command apt-get upgrade -y >/dev/null 2>&1 || true
        fi
        retry_command apt-get autoremove -y >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        retry_command dnf update -y --refresh >/dev/null 2>&1 || true
        retry_command dnf autoremove -y >/dev/null 2>&1 || true
    fi
    log "System update completed."
}

configure_hostname() {
    log "Verifying hostname configuration..."
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current
        current=$(hostname)
        if [[ "$current" != "$HOSTNAME_NEW" ]]; then
            log "Updating hostname: $current -> $HOSTNAME_NEW"
            hostname "$HOSTNAME_NEW"
            echo "$HOSTNAME_NEW" > /etc/hostname
            sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
        else
            log "Hostname is already correct."
        fi
    fi
}

install_docker() {
    log "Checking Docker status..."
    
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active docker >/dev/null 2>&1; then
            log "Docker is already installed and active."
            return 0
        fi
        log "Docker installed but not running. Starting..."
        systemctl start docker && return 0
    fi
    
    log "Installing Docker via get.docker.com..."
    if ! retry_command curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        err "Failed to download Docker install script."
        return 1
    fi
    
    if ! sh /tmp/get-docker.sh >/dev/null 2>&1; then
        err "Docker installation script returned error."
        return 1
    fi
    
    systemctl enable docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
    log "Docker installed successfully."
    return 0
}

configure_smart_swap() {
    log "Checking Swap configuration..."
    
    local swap_total
    swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    
    if [[ "${swap_total}" -gt 0 ]]; then
        log "Swap is already configured (${swap_total} kB)."
        return 0
    fi
    
    local swap_file="/swapfile"
    local mem_total
    mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    
    # Only if RAM < 1GB
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "Low RAM detected (<1GB). Creating 1GB Swap file..."
        touch "${swap_file}"
        if command -v chattr >/dev/null 2>&1; then chattr +C "${swap_file}" 2>/dev/null || true; fi
        
        if dd if=/dev/zero of="${swap_file}" bs=1M count=1024 status=none; then
            chmod 600 "${swap_file}"
            mkswap "${swap_file}" >/dev/null 2>&1
            swapon "${swap_file}"
            echo "${swap_file} none swap sw 0 0" >> /etc/fstab
            log "Swap created successfully."
        else
            err "Failed to create swap file."
            return 1
        fi
    else
        log "Sufficient RAM available. No swap needed."
    fi
    return 0
}

enable_tcp_bbr() {
    log "Checking TCP BBR Congestion Control..."
    if grep -q "bbr" /etc/sysctl.conf; then
        log "TCP BBR is already enabled."
        return 0
    fi
    
    log "Enabling TCP BBR..."
    if ! echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf; then
        warn "Could not write to sysctl.conf"
        return 1
    fi
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    
    if sysctl -p >/dev/null 2>&1; then
        log "TCP BBR successfully enabled."
    else
        warn "Could not apply sysctl settings."
    fi
}

install_fail2ban() {
    if command -v fail2ban-client >/dev/null 2>&1; then 
        log "Fail2Ban is already installed."
        return 0
    fi
    
    log "Installing Fail2Ban..."
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        retry_command apt-get install -y fail2ban >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        retry_command dnf install -y fail2ban >/dev/null 2>&1
    fi
    
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        log "Configuring Fail2Ban SSH jail..."
        cat > "/etc/fail2ban/jail.local" << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 5
bantime = 1h
EOF
        systemctl restart fail2ban >/dev/null 2>&1 || true
    fi
    
    systemctl enable fail2ban >/dev/null 2>&1 || true
    log "Fail2Ban installed and active."
}

# =============================================
# 5. CONTAINER LOGIC (SMART & VERBOSE)
# =============================================

install_enhanced_globalping_probe() {
    log "Installing Globalping Probe (v2.9)..."
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        err "Adoption Token is missing. Please provide it via --adoption-token or config."
        return 1
    fi
    
    install_docker || return 1
    
    # 1. Pull Image
    log "Pulling latest Docker Image..."
    if ! retry_command docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        err "Failed to pull Globalping image."
        enhanced_notify "error" "Docker Error" "Failed to pull image."
        return 1
    fi

    # 2. Smart Check Logic
    local container_name="globalping-probe"
    local recreate_needed=false
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
        log "Container '${container_name}' found. Checking status..."
        
        # Check running state
        local state
        state=$(docker inspect -f '{{.State.Status}}' "${container_name}")
        
        # Check Token
        local current_token
        current_token=$(docker inspect "${container_name}" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "GP_ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}')
        
        # Check Image
        local current_image
        current_image=$(docker inspect "${container_name}" --format '{{.Image}}')
        local latest_image
        latest_image=$(docker inspect ghcr.io/jsdelivr/globalping-probe:latest --format '{{.Id}}')

        if [[ "$current_token" != "$ADOPTION_TOKEN" ]]; then
            log "Reason for update: Token has changed."
            recreate_needed=true
        elif [[ "$current_image" != "$latest_image" ]]; then
            log "Reason for update: New image version detected."
            recreate_needed=true
        elif [[ "$state" != "running" ]]; then
            log "Reason for update: Container is not running."
            recreate_needed=true
        elif [[ "${FORCE_RECREATE}" == "true" ]]; then
            log "Reason for update: Force flag used."
            recreate_needed=true
        else
            log "Container is up-to-date and running correctly. No action needed."
            return 0
        fi
    else
        log "Container does not exist. Creating new..."
        recreate_needed=true
    fi

    # 3. Recreate if needed
    if [[ "${recreate_needed}" == "true" ]]; then
        log "Stopping and removing old container (Force)..."
        docker rm -f "${container_name}" >/dev/null 2>&1 || true
        
        # Prepare Limits
        local limit_args=""
        [[ -n "${GP_CPU_LIMIT}" ]] && limit_args+=" --cpus=${GP_CPU_LIMIT}"
        [[ -n "${GP_MEM_LIMIT}" ]] && limit_args+=" --memory=${GP_MEM_LIMIT}"
        
        log "Starting container (Limits: CPU=${GP_CPU_LIMIT:-Default}, MEM=${GP_MEM_LIMIT:-Default})..."
        
        # Run and capture output
        local run_output
        if ! run_output=$(docker run -d \
            --name "${container_name}" \
            --restart always \
            --network host \
            --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
            ${limit_args} \
            -e "GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
            -e "NODE_ENV=production" \
            -v globalping-data:/home/node/.globalping \
            ghcr.io/jsdelivr/globalping-probe:latest 2>&1); then
                err "Failed to start container. Docker Error:"
                err "$run_output"
                enhanced_notify "error" "Installation Failed" "Docker Error: $run_output"
                return 1
        fi
        
        log "Globalping Probe started successfully."
    fi
    return 0
}

perform_enhanced_auto_update() {
    log "Checking for script updates..."
    local temp_script="${TMP_DIR}/update_script.sh"
    
    if retry_command curl -sL --connect-timeout 10 -o "${temp_script}" "${SCRIPT_URL}"; then
        
        # 1. Integrity Check
        if ! grep -q "END OF SCRIPT" "${temp_script}"; then
            enhanced_notify "error" "Auto-Update" "Download incomplete/corrupt."
            return 1
        fi
        
        # 2. Syntax Check
        if ! bash -n "${temp_script}"; then
            enhanced_notify "error" "Auto-Update" "New script has SYNTAX ERRORS."
            return 1
        fi
        
        # 3. Version Check
        local current_ver
        local new_ver
        current_ver=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        new_ver=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        
        if [[ "${current_ver}" != "${new_ver}" ]]; then
            log "New version found: ${current_ver} -> ${new_ver}"
            cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.backup"
            cp "${temp_script}" "${SCRIPT_PATH}"
            chmod +x "${SCRIPT_PATH}"
            log "Update successful."
            return 0
        else
            log "Script is already up to date."
        fi
    fi
    return 0
}

perform_aggressive_cleanup() {
    log "🧹 Starting aggressive cleanup..."
    if command -v docker >/dev/null 2>&1; then
        log "Pruning Docker (unused images/volumes)..."
        docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        log "Cleaning Apt cache..."
        apt-get autoremove -y >/dev/null 2>&1 || true
        apt-get clean >/dev/null 2>&1 || true
    fi
    log "Truncating old logs..."
    find /var/log -type f -size +50M -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
    local disk_free
    disk_free=$(df -h / | awk 'NR==2 {print $4}')
    log "Cleanup finished. Free space: ${disk_free}"
}

# =============================================
# 6. DIAGNOSTICS & MENU
# =============================================

run_enhanced_diagnostics() {
    echo "=== SYSTEM DIAGNOSTICS (v2.9) ==="
    echo "Time: $(date)"
    echo "Host: ${HOSTNAME_NEW} (${PUBLIC_IP})"
    
    echo -e "\n[Hardware]"
    local cpu_model
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
    echo "CPU: ${cpu_model} ($(nproc) Cores)"
    echo "RAM: $(free -h | grep Mem | awk '{print $4}' ) free"
    
    echo -e "\n[Network]"
    echo "IPv4: ${PUBLIC_IP}"
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' | cut -d/ -f1)
    if [[ -n "${ipv6_addr}" ]]; then
        echo "IPv6: ${ipv6_addr} (Detected)"
        if ping6 -c 1 -W 2 google.com >/dev/null 2>&1; then echo "IPv6 Connectivity: OK"; else echo "IPv6 Connectivity: FAIL"; fi
    else
        echo "IPv6: Not detected"
    fi
    
    echo -e "\n[Docker]"
    if command -v docker >/dev/null 2>&1; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    else
        echo "Docker: Not installed."
    fi
    
    echo -e "\n[Security]"
    if command -v fail2ban-client >/dev/null 2>&1; then echo "Fail2Ban: Installed"; else echo "Fail2Ban: Not installed"; fi
    local ssh_keys
    ssh_keys=$(wc -l < "${SSH_DIR}/authorized_keys" 2>/dev/null || echo "0")
    echo "SSH Keys: ${ssh_keys} authorized"
    
    echo "================================="
}

show_interactive_menu() {
    clear
    echo "======================================================="
    echo "   Globalping Probe Installer & Manager (v${SCRIPT_VERSION##*-})"
    echo "======================================================="
    echo ""
    echo "1. Install / Update Globalping Probe"
    echo "2. Configure Settings (Tokens, Telegram)"
    echo "3. Run Full System Diagnostics"
    echo "4. Run System Cleanup"
    echo "5. Uninstall Globalping"
    echo "6. Exit"
    echo ""
    read -p "Select option [1-6]: " choice

    case "${choice}" in
        1) process_enhanced_args --force ;;
        2)
            read -p "Enter Adoption Token [Current: ${ADOPTION_TOKEN:0:5}...]: " t_adopt
            [[ -n "$t_adopt" ]] && save_config_var "ADOPTION_TOKEN" "$t_adopt"
            read -p "Enter Telegram Bot Token: " t_bot
            [[ -n "$t_bot" ]] && save_config_var "TELEGRAM_TOKEN" "$t_bot"
            read -p "Enter Telegram Chat ID: " t_chat
            [[ -n "$t_chat" ]] && save_config_var "TELEGRAM_CHAT" "$t_chat"
            echo "Settings saved."
            sleep 1
            load_and_migrate_config
            show_interactive_menu
            ;;
        3) process_enhanced_args --diagnose ;;
        4) process_enhanced_args --cleanup ;;
        5) process_enhanced_args --uninstall ;;
        6) exit 0 ;;
        *) show_interactive_menu ;;
    esac
}

# =============================================
# 7. CLEANUP & MAIN
# =============================================

perform_uninstall() {
    local force="$1"
    if [[ "${force}" != "true" ]]; then
        echo "⚠️  WARNING: You are about to UNINSTALL Globalping Probe."
        echo -n "Are you sure? [y/N] "
        read -r response
        if [[ ! "${response}" =~ ^[yY]$ ]]; then exit 0; fi
    fi
    
    log "Starting uninstallation..."
    if command -v docker >/dev/null 2>&1; then
        docker stop globalping-probe 2>/dev/null || true
        docker rm globalping-probe 2>/dev/null || true
        docker rmi ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null || true
        docker volume rm globalping-data 2>/dev/null || true
    fi
    systemctl stop globalping-update.timer 2>/dev/null || true
    systemctl disable globalping-update.timer 2>/dev/null || true
    rm -f "${SYSTEMD_TIMER_PATH}" "${SYSTEMD_SERVICE_PATH}" "${SCRIPT_PATH}" "${CONFIG_FILE}"
    systemctl daemon-reload
    echo "✅ Uninstallation completed."
    exit 0
}

process_enhanced_args() {
    local uninstall="false"
    local diagnose="false"
    local force="false"
    local auto_weekly="false"
    local cleanup="false"
    local fail2ban="false"
    local telegram_test="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall) uninstall="true"; shift ;;
            --diagnose) diagnose="true"; shift ;;
            --cleanup) cleanup="true"; shift ;;
            --force) force="true"; FORCE_RECREATE="true"; shift ;;
            --auto-weekly) auto_weekly="true"; WEEKLY_MODE="true"; shift ;;
            --install-fail2ban) fail2ban="true"; shift ;;
            --test-telegram) telegram_test="true"; shift ;;
            --adoption-token) save_config_var "ADOPTION_TOKEN" "$2"; ADOPTION_TOKEN="$2"; shift 2 ;;
            --telegram-token) save_config_var "TELEGRAM_TOKEN" "$2"; TELEGRAM_TOKEN="$2"; shift 2 ;;
            --telegram-chat) save_config_var "TELEGRAM_CHAT" "$2"; TELEGRAM_CHAT="$2"; shift 2 ;;
            --ssh-key) save_config_var "SSH_KEY" "$2"; SSH_KEY="$2"; shift 2 ;;
            --ubuntu-token) save_config_var "UBUNTU_PRO_TOKEN" "$2"; UBUNTU_PRO_TOKEN="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ "$uninstall" == "true" ]]; then perform_uninstall "${force}"; exit 0; fi
    if [[ "$diagnose" == "true" ]]; then run_enhanced_diagnostics; exit 0; fi
    if [[ "$cleanup" == "true" ]]; then perform_aggressive_cleanup; exit 0; fi
    if [[ "$telegram_test" == "true" ]]; then test_telegram_config; exit 0; fi

    if [[ "$auto_weekly" == "true" ]]; then
        perform_enhanced_auto_update
        enable_tcp_bbr
        # Weekly logic
        if command -v docker >/dev/null 2>&1; then docker system prune -f >/dev/null 2>&1; fi
        install_enhanced_globalping_probe
        exit 0
    fi

    # Default Install
    check_root
    setup_colors
    get_enhanced_system_info
    install_dependencies
    update_system_packages
    configure_hostname
    setup_ssh_key
    configure_smart_swap
    enable_tcp_bbr
    if [[ "$fail2ban" == "true" ]]; then install_fail2ban; fi

    install_enhanced_globalping_probe
    
    # Auto-Update Setup
    cp "$0" "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"
    cat > "${SYSTEMD_SERVICE_PATH}" << EOF
[Unit]
Description=Globalping Auto-Update
After=network.target
[Service]
ExecStart=${SCRIPT_PATH} --auto-weekly
[Install]
WantedBy=multi-user.target
EOF
    cat > "${SYSTEMD_TIMER_PATH}" << EOF
[Unit]
Description=Weekly Globalping Update
[Timer]
OnCalendar=Sun 03:00:00
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload; systemctl enable globalping-update.timer; systemctl start globalping-update.timer

    enhanced_notify "install_success" "Installation Complete" "Setup finished successfully (v2.9)."
    echo "✅ Installation successfully completed."
}

# =============================================
# ENTRY POINT
# =============================================
load_and_migrate_config
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then show_interactive_menu; else process_enhanced_args "$@"; fi
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================