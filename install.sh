#!/bin/bash
set -euo pipefail

# =============================================
# GLOBAL VARIABLES & COMPATIBILITY LAYER
# =============================================
# WARNING: Do NOT remove or reorder these empty variables.
# Older versions (v1.x - v2.3) use 'sed' to inject values here during auto-update.
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# CONSTANTS & CONFIGURATION
# =============================================
readonly SCRIPT_VERSION="2025.12.21-v2.5"
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

# Runtime State
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
# CONFIGURATION MIGRATION SYSTEM
# =============================================

load_and_migrate_config() {
    mkdir -p "$(dirname "${CONFIG_FILE}")"

    # 1. Load existing config
    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi

    # 2. MIGRATION: Check if variables were injected by old update script
    local save_needed=false

    # Helper to migrate a single variable
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
# HELPER FUNCTIONS & ERROR HANDLING
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

# NEW: Generic Retry Function
retry_command() {
    local retries=3
    local count=0
    local delay=5
    local cmd="$*"

    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [ $count -lt $retries ]; then
            enhanced_log "WARN" "Command failed (Attempt $count/$retries): $cmd"
            sleep $delay
        else
            enhanced_log "ERROR" "Command failed after $retries attempts: $cmd"
            return $exit_code
        fi
    done
    return 0
}

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

# NEW: Check OS Compatibility
check_compatibility() {
    if [[ "${EUID}" -ne 0 ]]; then
        enhanced_log "ERROR" "This script requires root privileges."
        return 1
    fi

    # Check for Systemd (Critical for Timer)
    if ! pidof systemd >/dev/null 2>&1 && [[ ! -d /run/systemd/system ]]; then
        enhanced_log "ERROR" "Systemd not detected. This script requires a systemd-based OS."
        return 1
    fi

    return 0
}

# =============================================
# FEATURE: TCP BBR & FAIL2BAN
# =============================================

enable_tcp_bbr() {
    log "Checking TCP BBR Congestion Control..."
    if grep -q "bbr" /etc/sysctl.conf; then
        log "TCP BBR is already enabled."
        return 0
    fi
    
    log "Enabling TCP BBR..."
    if ! echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf; then
        enhanced_log "WARN" "Could not write to sysctl.conf"
        return 1
    fi
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    
    if sysctl -p >/dev/null 2>&1; then
        log "TCP BBR successfully enabled."
    else
        enhanced_log "WARN" "Could not apply sysctl settings (maybe container restriction?)."
    fi
}

install_fail2ban() {
    if command -v fail2ban-client >/dev/null 2>&1; then return 0; fi
    
    log "Installing Fail2Ban..."
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        retry_command apt-get install -y fail2ban >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        retry_command dnf install -y fail2ban >/dev/null 2>&1
    fi
    
    # Configure Jail
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
            return 0
        fi
    fi
    
    log "Installing Docker..."
    if ! retry_command curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        enhanced_log "ERROR" "Failed to download Docker install script."
        return 1
    fi
    
    if ! sh /tmp/get-docker.sh >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker installation script failed."
        return 1
    fi
    
    systemctl enable docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
    return 0
}

configure_smart_swap() {
    log "Checking Swap configuration..."
    
    local swap_total
    swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    
    if [[ "${swap_total}" -gt 0 ]]; then return 0; fi
    
    local swap_file="/swapfile"
    local mem_total
    mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "Creating 1GB Swap file..."
        touch "${swap_file}"
        if command -v chattr >/dev/null 2>&1; then chattr +C "${swap_file}" 2>/dev/null || true; fi
        
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
    fi
    return 0
}

install_enhanced_globalping_probe() {
    log "Installing Globalping Probe (v2.5)..."
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "ERROR" "Adoption Token is missing."
        return 1
    fi
    
    install_docker || return 1
    
    # 1. Pull Image (with Retry)
    log "Pulling Docker Image..."
    if ! retry_command docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        enhanced_log "ERROR" "Failed to pull Globalping image."
        enhanced_notify "error" "Docker Error" "Failed to pull image after retries."
        return 1
    fi

    # 2. Cleanup Old
    if docker ps -a | grep -q globalping-probe; then
        docker stop globalping-probe >/dev/null 2>&1 || true
        docker rm globalping-probe >/dev/null 2>&1 || true
    fi
    
    # 3. Prepare Limits
    local limit_args=""
    [[ -n "${GP_CPU_LIMIT}" ]] && limit_args+=" --cpus=${GP_CPU_LIMIT}"
    [[ -n "${GP_MEM_LIMIT}" ]] && limit_args+=" --memory=${GP_MEM_LIMIT}"
    
    # 4. Run
    log "Starting container (Limits: CPU=${GP_CPU_LIMIT:-Default}, MEM=${GP_MEM_LIMIT:-Default})..."
    
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
    
    if retry_command curl -sL --connect-timeout 10 -o "${temp_script}" "${SCRIPT_URL}"; then
        
        # 1. Integrity Check
        if ! grep -q "END OF SCRIPT" "${temp_script}"; then
            enhanced_notify "error" "Auto-Update" "Download incomplete/corrupt."
            return 1
        fi
        
        # 2. Syntax Check (Rollback Protection)
        if ! bash -n "${temp_script}"; then
            enhanced_notify "error" "Auto-Update" "New script has SYNTAX ERRORS. Aborting update."
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
    fi
    return 0
}

# =============================================
# DIAGNOSTICS & MENU
# =============================================

run_enhanced_diagnostics() {
    echo "=== SYSTEM DIAGNOSTICS (v2.5) ==="
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
            echo "Settings saved."
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

# =============================================
# CLEANUP & MAIN
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
    if [[ "$telegram_test" == "true" ]]; then test_telegram_config; exit 0; fi

    # Weekly Mode
    if [[ "$auto_weekly" == "true" ]]; then
        perform_enhanced_auto_update
        enable_tcp_bbr
        # System cleanup logic simplified for weekly
        if command -v docker >/dev/null 2>&1; then docker system prune -f >/dev/null 2>&1; fi
        if command -v apt-get >/dev/null 2>&1; then wait_for_apt_locks; apt-get autoclean -y >/dev/null 2>&1; fi
        install_enhanced_globalping_probe
        exit 0
    fi

    # Default Install
    check_compatibility
    get_enhanced_system_info
    
    # Basic Deps
    if command -v apt-get >/dev/null 2>&1; then 
        wait_for_apt_locks; retry_command apt-get update >/dev/null 2>&1; retry_command apt-get install -y curl wget unzip docker.io >/dev/null 2>&1 || true
    fi
    
    configure_smart_swap
    enable_tcp_bbr
    if [[ "$fail2ban" == "true" ]]; then install_fail2ban; fi
    if [[ -n "$SSH_KEY" ]]; then mkdir -p "$SSH_DIR"; echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"; fi

    install_enhanced_globalping_probe
    
    # Auto-Update Setup (Simplified)
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

    enhanced_notify "install_success" "Installation Complete" "Setup finished successfully (v2.5)."
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