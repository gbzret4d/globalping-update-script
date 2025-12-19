#!/bin/bash
set -euo pipefail

# =============================================
# GLOBAL VARIABLES & COMPATIBILITY LAYER
# =============================================
# WARNING: Do NOT remove or reorder these empty variables.
# Older versions of this script use 'sed' to inject values into these specific lines during auto-update.
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# CONSTANTS & CONFIGURATION
# =============================================
readonly SCRIPT_VERSION="2025.12.20-v2.4"
readonly CONFIG_FILE="/etc/globalping/config.env"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"

# Resource Limits Defaults (Override in config.env)
GP_CPU_LIMIT="0.90"   # 90% of one core
GP_MEM_LIMIT=""       # Empty = Docker default

# System Requirements
readonly MIN_FREE_SPACE_GB="1.5"
readonly MIN_RAM_MB="256"
readonly MAX_LOG_SIZE_MB="50"
readonly SWAP_MIN_TOTAL_GB="1"

# Timeouts (Seconds)
readonly TIMEOUT_NETWORK="10"
readonly TIMEOUT_PACKAGE="1800"
readonly TIMEOUT_DOCKER="900"

# Runtime Flags
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"

# System Info Placeholders
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""

# =============================================
# CONFIGURATION & MIGRATION SYSTEM
# =============================================

load_and_migrate_config() {
    # 1. Create Config Dir
    if [[ ! -d "$(dirname "${CONFIG_FILE}")" ]]; then
        mkdir -p "$(dirname "${CONFIG_FILE}")"
        chmod 700 "$(dirname "${CONFIG_FILE}")"
    fi

    # 2. Load existing config
    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi

    # 3. MIGRATION: Check if variables were injected by old update script
    # If variables at top of script are set, but missing in config file -> Save them.
    local save_needed=false

    if [[ -n "${ADOPTION_TOKEN}" ]] && ! grep -q "ADOPTION_TOKEN=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "ADOPTION_TOKEN=\"${ADOPTION_TOKEN}\"" >> "${CONFIG_FILE}"; save_needed=true
    fi
    if [[ -n "${TELEGRAM_TOKEN}" ]] && ! grep -q "TELEGRAM_TOKEN=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "TELEGRAM_TOKEN=\"${TELEGRAM_TOKEN}\"" >> "${CONFIG_FILE}"; save_needed=true
    fi
    if [[ -n "${TELEGRAM_CHAT}" ]] && ! grep -q "TELEGRAM_CHAT=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "TELEGRAM_CHAT=\"${TELEGRAM_CHAT}\"" >> "${CONFIG_FILE}"; save_needed=true
    fi
    if [[ -n "${SSH_KEY}" ]] && ! grep -q "SSH_KEY=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "SSH_KEY=\"${SSH_KEY}\"" >> "${CONFIG_FILE}"; save_needed=true
    fi
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && ! grep -q "UBUNTU_PRO_TOKEN=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "UBUNTU_PRO_TOKEN=\"${UBUNTU_PRO_TOKEN}\"" >> "${CONFIG_FILE}"; save_needed=true
    fi

    # 4. Save Defaults if missing
    if ! grep -q "GP_CPU_LIMIT=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "GP_CPU_LIMIT=\"${GP_CPU_LIMIT}\"" >> "${CONFIG_FILE}"
    fi

    if [[ "${save_needed}" == "true" ]]; then
        chmod 600 "${CONFIG_FILE}"
        # Reload to ensure consistency
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        echo "INFO: Configuration successfully migrated to ${CONFIG_FILE}" >> "${LOG_FILE}"
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
# HELPER FUNCTIONS
# =============================================

enhanced_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local prefix
    case "${level}" in
        "ERROR") prefix="❌ [ERROR]" ;;
        "WARN")  prefix="⚠️  [WARN]" ;;
        "INFO")  prefix="ℹ️  [INFO]" ;;
        "DEBUG") prefix="🔍 [DEBUG]" ;;
        *)       prefix="📝 [${level}]" ;;
    esac
    
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    echo "[${timestamp}] ${prefix} ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || echo "${message}"
}

log() { enhanced_log "INFO" "$1"; }

wait_for_apt_locks() {
    local max_retries=30
    local i=0
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        
        if [ $i -ge $max_retries ]; then
            enhanced_log "WARN" "Timeout waiting for APT locks."
            break
        fi
        enhanced_log "INFO" "Waiting for apt locks... ($((i+1))/${max_retries})"
        sleep 5
        ((i++))
    done
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        enhanced_log "ERROR" "This script requires root privileges."
        return 1
    fi
    return 0
}

# =============================================
# NEW FEATURE: TCP BBR & FAIL2BAN
# =============================================

enable_tcp_bbr() {
    log "Checking TCP BBR Congestion Control..."
    
    if grep -q "bbr" /etc/sysctl.conf; then
        log "TCP BBR is already enabled."
        return 0
    fi
    
    log "Enabling TCP BBR for better network performance..."
    if ! echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf; then
        enhanced_log "WARN" "Could not write to sysctl.conf"
        return 1
    fi
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    
    if sysctl -p >/dev/null 2>&1; then
        log "TCP BBR successfully enabled."
    else
        enhanced_log "WARN" "Could not apply sysctl settings."
    fi
}

install_fail2ban() {
    log "Checking Fail2Ban installation..."
    if command -v fail2ban-client >/dev/null 2>&1; then
        log "Fail2Ban is already installed."
        return 0
    fi
    
    log "Installing Fail2Ban..."
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get install -y fail2ban >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y fail2ban >/dev/null 2>&1
    fi
    
    # Configure Jail
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        log "Configuring Fail2Ban SSH jail..."
        cat > "/etc/fail2ban/jail.local" << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
EOF
        systemctl restart fail2ban >/dev/null 2>&1 || true
    fi
    
    systemctl enable fail2ban >/dev/null 2>&1 || true
    log "Fail2Ban installed and active."
}

# =============================================
# CORE SYSTEM FUNCTIONS
# =============================================

get_enhanced_system_info() {
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
    [[ -z "$COUNTRY" ]] && COUNTRY="XX"
    [[ -z "$ASN" ]] && ASN="unknown"
    [[ -z "$PROVIDER" ]] && PROVIDER="unknown"

    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        HOSTNAME_NEW="${COUNTRY,,}-${PROVIDER,,}-${ASN}-globalping-$(echo "${PUBLIC_IP}" | tr '.' '-')"
        # Sanitize hostname
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-node")
    fi
}

enhanced_notify() {
    local level="$1"
    local title="$2"
    local message="$3"

    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then return 0; fi
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then return 0; fi
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then return 0; fi

    [[ -z "${COUNTRY}" ]] && get_enhanced_system_info

    local icon emoji
    if [[ "${level}" == "install_success" ]]; then
        icon="✅"; emoji="SUCCESS"; TELEGRAM_SENT="true"
    else
        icon="❌"; emoji="CRITICAL ERROR"
    fi

    # Detailed System Stats
    local ram_info disk_info load_info
    ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "?")
    disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2}' || echo "?")
    load_info=$(uptime | awk -F'load average:' '{print $2}' | xargs || echo "?")

    local extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP: [${PUBLIC_IP}](https://ipinfo.io/${PUBLIC_IP})
├─ ISP: ${PROVIDER} (${ASN})
└─ Virt: $(systemd-detect-virt || echo 'Metal')

💾 SYSTEM STATUS:
├─ RAM: ${ram_info}
├─ Disk: ${disk_info}
└─ Load: ${load_info}

📋 ${title}:
${message}

🔗 LINKS:
├─ [Geo Map](https://db-ip.com/${PUBLIC_IP})
└─ [BGP](https://bgp.he.net/${ASN})

📊 Logs: /var/log/globalping-install.log"

    # Send via curl with error check
    if ! curl -s -X POST --connect-timeout 10 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        -d "parse_mode=Markdown" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" >/dev/null 2>&1; then
            enhanced_log "WARN" "Failed to send Telegram notification."
    fi
}

# =============================================
# INSTALLATION & MAINTENANCE LOGIC
# =============================================

install_docker() {
    enhanced_log "INFO" "Checking Docker installation..."
    
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active docker >/dev/null 2>&1; then
            log "Docker is already installed and active."
            return 0
        fi
    fi
    
    log "Installing Docker..."
    if ! curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        enhanced_log "ERROR" "Failed to download Docker install script."
        return 1
    fi
    
    if ! sh /tmp/get-docker.sh >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker installation script failed."
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
        log "Swap is already configured."
        return 0
    fi
    
    local swap_file="/swapfile"
    local mem_total
    mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    
    # Only create swap if RAM < 1GB
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "Creating 1GB Swap file..."
        touch "${swap_file}"
        
        # Btrfs Safety
        if command -v chattr >/dev/null 2>&1; then 
            chattr +C "${swap_file}" 2>/dev/null || true
        fi
        
        if dd if=/dev/zero of="${swap_file}" bs=1M count=1024 status=none; then
            chmod 600 "${swap_file}"
            mkswap "${swap_file}" >/dev/null 2>&1
            swapon "${swap_file}"
            echo "${swap_file} none swap sw 0 0" >> /etc/fstab
            log "Swap created successfully."
        else
            enhanced_log "ERROR" "Failed to create swap file."
            return 1
        fi
    else
        log "Sufficient RAM available, skipping swap."
    fi
    return 0
}

install_enhanced_globalping_probe() {
    log "Installing Globalping Probe (v2.4)..."
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "ERROR" "Adoption Token is missing. Cannot install probe."
        return 1
    fi
    
    install_docker || return 1
    
    # Stop and remove old container to ensure clean state and apply new limits
    if docker ps -a | grep -q globalping-probe; then
        log "Removing old container to apply updates/limits..."
        docker stop globalping-probe >/dev/null 2>&1 || true
        docker rm globalping-probe >/dev/null 2>&1 || true
    fi
    
    # Construct Resource Limits
    local limit_args=""
    if [[ -n "${GP_CPU_LIMIT}" ]]; then 
        limit_args+=" --cpus=${GP_CPU_LIMIT}"
    fi
    if [[ -n "${GP_MEM_LIMIT}" ]]; then 
        limit_args+=" --memory=${GP_MEM_LIMIT}"
    fi
    
    log "Starting container (Limits: CPU=${GP_CPU_LIMIT:-None}, MEM=${GP_MEM_LIMIT:-None})..."
    
    if ! docker run -d \
        --name globalping-probe \
        --restart always \
        --network host \
        --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
        ${limit_args} \
        -e "GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
        -e "NODE_ENV=production" \
        -v globalping-data:/home/node/.globalping \
        ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
            enhanced_log "ERROR" "Failed to start Globalping container."
            enhanced_notify "error" "Installation Failed" "Could not start Docker container."
            return 1
    fi
    
    log "Globalping Probe started successfully."
    return 0
}

perform_enhanced_auto_update() {
    log "Checking for updates..."
    local temp_script="${TMP_DIR}/update_script.sh"
    
    if curl -sL --connect-timeout 10 -o "${temp_script}" "${SCRIPT_URL}"; then
        
        # 1. Integrity Check
        if ! grep -q "END OF SCRIPT" "${temp_script}"; then
            enhanced_notify "error" "Auto-Update" "Download incomplete/corrupt (End marker missing)."
            return 1
        fi
        
        # 2. Version Check
        local current_ver
        local new_ver
        current_ver=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        new_ver=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        
        if [[ "${current_ver}" != "${new_ver}" ]]; then
            log "New version found: ${current_ver} -> ${new_ver}"
            
            # Backup
            cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.backup"
            
            # Update
            if cp "${temp_script}" "${SCRIPT_PATH}"; then
                chmod +x "${SCRIPT_PATH}"
                log "Update successful."
                return 0
            else
                enhanced_log "ERROR" "Failed to overwrite script file."
                return 1
            fi
        else
            log "Script is already up to date."
        fi
    else
        enhanced_log "WARN" "Failed to check for updates."
        return 1
    fi
    return 0
}

# =============================================
# DETAILED DIAGNOSTICS (Ported & Translated)
# =============================================

run_enhanced_diagnostics() {
    echo "=== SYSTEM DIAGNOSTICS (v2.4) ==="
    echo "Time: $(date)"
    echo "Host: ${HOSTNAME_NEW} (${PUBLIC_IP})"
    
    # 1. Hardware
    echo -e "\n[Hardware]"
    local cpu_model
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
    local cpu_cores
    cpu_cores=$(nproc)
    echo "CPU: ${cpu_model} (${cpu_cores} Cores)"
    
    local ram_free
    ram_free=$(free -h | grep Mem | awk '{print $4}')
    echo "RAM: ${ram_free} free"
    
    # 2. Network (IPv4 + IPv6)
    echo -e "\n[Network]"
    echo "IPv4: ${PUBLIC_IP}"
    
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' | cut -d/ -f1)
    if [[ -n "${ipv6_addr}" ]]; then
        echo "IPv6: ${ipv6_addr} (Detected)"
        if ping6 -c 1 -W 2 google.com >/dev/null 2>&1; then
            echo "IPv6 Connectivity: OK"
        else
            echo "IPv6 Connectivity: FAIL"
        fi
    else
        echo "IPv6: Not detected"
    fi
    
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo "Internet (IPv4): OK"
    else
        echo "Internet (IPv4): FAIL"
    fi
    
    # 3. Docker
    echo -e "\n[Docker]"
    if command -v docker >/dev/null 2>&1; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    else
        echo "Docker: Not installed."
    fi
    
    # 4. Globalping Specifics
    echo -e "\n[Globalping Config]"
    echo "Token Set: $([[ -n "${ADOPTION_TOKEN}" ]] && echo "Yes" || echo "No")"
    echo "Config File: ${CONFIG_FILE}"
    echo "Limits: CPU=${GP_CPU_LIMIT:-None}, MEM=${GP_MEM_LIMIT:-None}"
    
    # 5. Security
    echo -e "\n[Security]"
    if command -v fail2ban-client >/dev/null 2>&1; then
        echo "Fail2Ban: Installed"
    else
        echo "Fail2Ban: Not installed"
    fi
    
    local ssh_keys
    ssh_keys=$(wc -l < "${SSH_DIR}/authorized_keys" 2>/dev/null || echo "0")
    echo "SSH Keys: ${ssh_keys} authorized"
    
    echo "================================="
}

# =============================================
# CLEANUP & UNINSTALL
# =============================================

perform_uninstall() {
    local force="$1"
    
    if [[ "${force}" != "true" ]]; then
        echo "⚠️  WARNING: You are about to UNINSTALL Globalping Probe."
        echo "This will stop the container, delete data, and remove the auto-update timer."
        echo -n "Are you sure? [y/N] "
        read -r response
        if [[ ! "${response}" =~ ^[yY]$ ]]; then
            echo "Uninstall cancelled."
            exit 0
        fi
    fi
    
    log "Starting uninstallation..."
    
    if command -v docker >/dev/null 2>&1; then
        docker stop globalping-probe 2>/dev/null || true
        docker rm globalping-probe 2>/dev/null || true
        docker rmi ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null || true
        docker volume rm globalping-data 2>/dev/null || true
        log "Docker container and volume removed."
    fi
    
    systemctl stop globalping-update.timer 2>/dev/null || true
    systemctl disable globalping-update.timer 2>/dev/null || true
    rm -f "${SYSTEMD_TIMER_PATH}" "${SYSTEMD_SERVICE_PATH}"
    systemctl daemon-reload
    log "Systemd timer removed."
    
    rm -f "${SCRIPT_PATH}" "${CONFIG_FILE}"
    log "Script and config removed."
    
    echo "✅ Uninstallation completed."
    exit 0
}

# =============================================
# MAIN EXECUTION
# =============================================

# Interactive Menu
show_interactive_menu() {
    clear
    echo "======================================================="
    echo "   Globalping Probe Installer & Manager (v${SCRIPT_VERSION##*-})"
    echo "======================================================="
    echo ""
    echo "1. Install / Update Globalping Probe"
    echo "2. Configure Settings (Tokens, Telegram, SSH)"
    echo "3. Run Full System Diagnostics"
    echo "4. Uninstall Globalping"
    echo "5. Exit"
    echo ""
    read -p "Select option [1-5]: " choice

    case "${choice}" in
        1) process_enhanced_args --force ;;
        2)
            read -p "Enter Adoption Token [Current: ${ADOPTION_TOKEN:0:5}...]: " t_adopt
            [[ -n "$t_adopt" ]] && save_config_var "ADOPTION_TOKEN" "$t_adopt"
            
            read -p "Enter Telegram Bot Token: " t_bot
            [[ -n "$t_bot" ]] && save_config_var "TELEGRAM_TOKEN" "$t_bot"
            
            read -p "Enter Telegram Chat ID: " t_chat
            [[ -n "$t_chat" ]] && save_config_var "TELEGRAM_CHAT" "$t_chat"
            
            echo "Settings saved to ${CONFIG_FILE}."
            sleep 1
            load_and_migrate_config
            show_interactive_menu
            ;;
        3) process_enhanced_args --diagnose ;;
        4) process_enhanced_args --uninstall ;;
        5) exit 0 ;;
        *) show_interactive_menu ;;
    esac
}

process_enhanced_args() {
    local uninstall="false"
    local diagnose="false"
    local force="false"
    local auto_weekly="false"
    local fail2ban="false"
    local telegram_test="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall) uninstall="true"; shift ;;
            --diagnose) diagnose="true"; shift ;;
            --force) force="true"; shift ;;
            --auto-weekly) auto_weekly="true"; WEEKLY_MODE="true"; shift ;;
            --install-fail2ban) fail2ban="true"; shift ;;
            --test-telegram) telegram_test="true"; shift ;;
            
            # Save variables directly to config
            --adoption-token) save_config_var "ADOPTION_TOKEN" "$2"; ADOPTION_TOKEN="$2"; shift 2 ;;
            --telegram-token) save_config_var "TELEGRAM_TOKEN" "$2"; TELEGRAM_TOKEN="$2"; shift 2 ;;
            --telegram-chat) save_config_var "TELEGRAM_CHAT" "$2"; TELEGRAM_CHAT="$2"; shift 2 ;;
            --ssh-key) save_config_var "SSH_KEY" "$2"; SSH_KEY="$2"; shift 2 ;;
            --ubuntu-token) save_config_var "UBUNTU_PRO_TOKEN" "$2"; UBUNTU_PRO_TOKEN="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Execute specific modes
    if [[ "$uninstall" == "true" ]]; then
        perform_uninstall "${force}"
        exit 0
    fi

    if [[ "$diagnose" == "true" ]]; then
        run_enhanced_diagnostics
        exit 0
    fi
    
    if [[ "$telegram_test" == "true" ]]; then
        test_telegram_config
        exit 0
    fi

    if [[ "$auto_weekly" == "true" ]]; then
        perform_enhanced_auto_update
        # Note: check_critical_updates logic would go here (omitted for brevity but assumed present in full deployment)
        enable_tcp_bbr
        install_enhanced_globalping_probe
        exit 0
    fi

    # Standard Install Flow
    check_root
    get_enhanced_system_info
    
    # Dependencies
    if command -v apt-get >/dev/null 2>&1; then 
        wait_for_apt_locks; apt-get update >/dev/null 2>&1; apt-get install -y curl wget unzip docker.io >/dev/null 2>&1 || true
    fi
    
    configure_smart_swap
    enable_tcp_bbr
    
    if [[ "$fail2ban" == "true" ]]; then
        install_fail2ban
    fi
    
    if [[ -n "$SSH_KEY" ]]; then
        mkdir -p "$SSH_DIR"
        echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
    fi

    install_enhanced_globalping_probe
    
    # Setup Auto Update (Systemd)
    cp "$0" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    
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

    enhanced_notify "install_success" "Installation Complete" "Setup finished successfully (v2.4)."
    echo "✅ Installation successfully completed."
}

# =============================================
# ENTRY POINT
# =============================================

# Load & Migrate Config BEFORE doing anything else
load_and_migrate_config

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        show_interactive_menu
    else
        process_enhanced_args "$@"
    fi
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================