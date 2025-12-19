#!/bin/bash
set -euo pipefail

# =============================================
# GLOBAL VARIABLES
# =============================================
readonly TELEGRAM_API_URL="https://api.telegram.org/bot"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
# IMPORTANT: Ensure this URL points to the raw version of your script
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly CRON_JOB="0 2 * * 0 /usr/local/bin/globalping-maintenance"
readonly AUTO_UPDATE_CRON="0 3 * * 0 /usr/local/bin/install_globalping.sh --auto-weekly"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"
readonly SCRIPT_VERSION="2025.12.19-v2.3"

# Enhanced Configuration
readonly MIN_FREE_SPACE_GB="1.5"   # Minimum 1.5GB free
readonly MIN_RAM_MB="256"          # Minimum 256MB RAM
readonly MAX_LOG_SIZE_MB="50"      # Maximum log size
readonly SWAP_MIN_TOTAL_GB="1"     # RAM + SWAP minimum 1GB
readonly MIN_DISK_FOR_SWAP_GB="10" # Minimum 10GB disk space for Swap

# Timeout Configuration
readonly TIMEOUT_NETWORK="10"     # Network operations
readonly TIMEOUT_PACKAGE="1800"   # Package updates (30 min)
readonly TIMEOUT_DOCKER="900"     # Docker operations (15 min)
readonly TIMEOUT_CLEANUP="600"    # Cleanup operations (10 min)
readonly TIMEOUT_GENERAL="300"    # General operations (5 min)

# Initialize Variables
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"  # Flag to prevent duplicate messages

# System Information (dynamically set)
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""

# =============================================
# HELPER FUNCTIONS
# =============================================

# Safe math without bc
safe_calc() {
    local operation="$1"
    case "${operation}" in
        "gb_from_kb")
            local kb="$2"
            echo $((kb / 1024 / 1024))
            ;;
        "mb_from_kb")
            local kb="$2"
            echo $((kb / 1024))
            ;;
        "compare_gb")
            local val1="$2"
            local val2="$3"
            # Convert to MB for comparison (1.5GB = 1536MB)
            local val1_mb=$((val1 * 1024))
            local val2_mb
            val2_mb=$(echo "${val2}" | cut -d'.' -f1)
            val2_mb=$((val2_mb * 1024))
            if [[ ${val1_mb} -lt ${val2_mb} ]]; then
                echo "1"
            else
                echo "0"
            fi
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Wait for APT/DPKG Locks (Prevents Race Conditions)
# This fixes the issue where 'apt install unzip' fails during boot
wait_for_apt_locks() {
    local max_retries=30
    local i=0
    
    # Check locks if fuser is installed or use simple file checks
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        
        if [ $i -ge $max_retries ]; then
            enhanced_log "WARN" "Timeout waiting for APT locks. Attempting to proceed..."
            break
        fi
        
        enhanced_log "INFO" "Waiting for apt/dpkg lock release... ($((i+1))/${max_retries})"
        sleep 5
        ((i++))
    done
}

# =============================================
# CORE FUNCTIONS
# =============================================

# Collect enhanced system information
get_enhanced_system_info() {
    log "Collecting enhanced system information"
    
    # Determine public IP
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "unknown")
    
    # Collect Geo information
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
    
    # Set fallback values
    [[ -z "${COUNTRY}" ]] && COUNTRY="XX"
    [[ -z "${ASN}" ]] && ASN="unknown"
    [[ -z "${PROVIDER}" ]] && PROVIDER="unknown"
    
    # Determine Hostname - INTELLIGENT HOSTNAME
    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        HOSTNAME_NEW="${COUNTRY,,}-${PROVIDER,,}-${ASN}-globalping-$(echo "${PUBLIC_IP}" | tr '.' '-')"
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-$(date +%s)")
    fi
    
    log "System Info: ${COUNTRY}, ${PUBLIC_IP}, ${ASN}, ${PROVIDER}"
}

# Enhanced Logging Function
enhanced_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log Level Mapping
    local level_prefix
    case "${level}" in
        "ERROR") level_prefix="❌ [ERROR]" ;;
        "WARN")  level_prefix="⚠️  [WARN]" ;;
        "INFO")  level_prefix="ℹ️  [INFO]" ;;
        "DEBUG") level_prefix="🔍 [DEBUG]" ;;
        *) level_prefix="📝 [${level}]" ;;
    esac
    
    # Ensure log directory exists
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    # Write log
    echo "[${timestamp}] ${level_prefix} ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || {
        echo "[${timestamp}] ${level_prefix} ${message}" >&2
    }
    
    # Check log rotation
    rotate_logs_if_needed
}

# Wrapper for existing log calls
log() {
    enhanced_log "INFO" "$1"
}

# Log Rotation
rotate_logs_if_needed() {
    if [[ ! -f "${LOG_FILE}" ]]; then
        return 0
    fi
    
    local log_size_mb
    log_size_mb=$(stat -f%z "${LOG_FILE}" 2>/dev/null || stat -c%s "${LOG_FILE}" 2>/dev/null || echo "0")
    log_size_mb=$((log_size_mb / 1024 / 1024))
    
    if [[ ${log_size_mb} -gt ${MAX_LOG_SIZE_MB} ]]; then
        # Rotate log
        local backup_log="${LOG_FILE}.$(date +%Y%m%d)"
        mv "${LOG_FILE}" "${backup_log}"
        touch "${LOG_FILE}"
        chmod 644 "${LOG_FILE}"
        
        # Compress old logs
        gzip "${backup_log}" 2>/dev/null || true
        
        # Remove logs older than 30 days
        find "$(dirname "${LOG_FILE}")" -name "globalping-install.log.*.gz" -mtime +30 -delete 2>/dev/null || true
        
        enhanced_log "INFO" "Log file rotated (${log_size_mb}MB -> 0MB)"
    fi
}

# ENHANCED Telegram Notification (English)
enhanced_notify() {
    local level="$1"
    local title="$2"
    local message="$3"
    
    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then
        log "Telegram Success message already sent - skipping"
        return 0
    fi
    
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then
        return 0
    fi
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        log "Telegram configuration incomplete"
        return 0
    fi
    
    [[ -z "${COUNTRY}" ]] && get_enhanced_system_info
    
    local icon emoji
    case "${level}" in
        "error")
            icon="❌"
            emoji="CRITICAL ERROR"
            ;;
        "install_success")
            icon="✅"
            emoji="INSTALLATION SUCCESSFUL"
            TELEGRAM_SENT="true"
            ;;
    esac
    
    local extended_message
    if [[ "${level}" == "install_success" ]]; then
        local ram_info disk_info swap_info load_info
        local auto_update_status ssh_status ubuntu_pro_status
        local globalping_status docker_installed
        
        ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unknown")
        disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5" used)"}' || echo "unknown")
        swap_info=$(free -h 2>/dev/null | grep Swap | awk '{print $2}' || echo "0B")
        load_info=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "0")
        
        auto_update_status=$(systemctl is-enabled globalping-update.timer 2>/dev/null || echo "crontab")
        ssh_status="${SSH_KEY:+✓ Configured}${SSH_KEY:-✗ Not set}"
        ubuntu_pro_status="${UBUNTU_PRO_TOKEN:+✓ Active}${UBUNTU_PRO_TOKEN:-✗ Not used}"
        
        if command -v docker >/dev/null 2>&1; then
            docker_installed="✓ Installed"
            if docker ps --format "{{.Names}}" 2>/dev/null | grep -q globalping; then
                globalping_status="✓ Active"
            else
                globalping_status="✗ Not found"
            fi
        else
            docker_installed="✗ Not installed"
            globalping_status="✗ Docker missing"
        fi
        
        extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP Address: [${PUBLIC_IP}](https://ipinfo.io/${PUBLIC_IP})
├─ Provider: [${PROVIDER}](https://ipinfo.io/${ASN})
├─ ASN: [${ASN}](https://bgp.he.net/${ASN})
└─ Virtualization: $(systemd-detect-virt 2>/dev/null || echo "Bare Metal")

💾 SYSTEM STATUS:
├─ RAM: ${ram_info}
├─ Disk: ${disk_info}
├─ Swap: ${swap_info}
└─ Load: ${load_info}

🔧 SERVICES:
├─ Docker: ${docker_installed}
├─ Globalping: ${globalping_status}
├─ Auto-Update: ${auto_update_status}
├─ SSH Key: ${ssh_status}
├─ Ubuntu Pro: ${ubuntu_pro_status}
└─ Telegram: ✓ Active

📋 ${title}:
${message}

🔗 LINKS:
├─ [WHOIS Details](https://whois.net/ip/${PUBLIC_IP})
├─ [Geo Map](https://db-ip.com/${PUBLIC_IP})
└─ [BGP Routing](https://bgp.he.net/${ASN})

⏰ Maintenance: Sunday 03:00 UTC
📊 Logs: /var/log/globalping-install.log"

    elif [[ "${level}" == "error" ]]; then
        local system_status error_context
        
        local ram_status disk_status load_status
        ram_status=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unknown")
        disk_status=$(df -h / 2>/dev/null | awk 'NR==2 {print $4" free"}' || echo "unknown")
        load_status=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "unknown")
        
        system_status="RAM: ${ram_status} | HDD: ${disk_status} | Load: ${load_status}"
        error_context=$(tail -10 "${LOG_FILE}" 2>/dev/null | grep -E "(ERROR|CRITICAL|Failed)" | tail -2 | sed 's/^.*] //' || echo "No details available")
        
        extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ IP Address: [${PUBLIC_IP}](https://ipinfo.io/${PUBLIC_IP})
├─ Provider: [${PROVIDER}](https://ipinfo.io/${ASN})
├─ ASN: [${ASN}](https://bgp.he.net/${ASN})
└─ Hostname: ${HOSTNAME_NEW}

🚨 ERROR DETAILS:
${title}: ${message}

💻 SYSTEM STATUS: ${system_status}

📋 CONTEXT:
${error_context}

🔗 LINKS:
├─ [WHOIS Details](https://whois.net/ip/${PUBLIC_IP})
├─ [Geo Map](https://db-ip.com/${PUBLIC_IP})
└─ [BGP Routing](https://bgp.he.net/${ASN})

🔧 Access: ssh root@${PUBLIC_IP}
📊 Logs: tail -50 /var/log/globalping-install.log"
    fi
    
    if [[ ${#extended_message} -gt 4000 ]]; then
        extended_message=$(echo "${extended_message}" | head -c 3900)
        extended_message="${extended_message}

...Message truncated - Check via SSH"
    fi
    
    local result
    result=$(curl -s -X POST \
        --connect-timeout 10 \
        --max-time 15 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        -d "parse_mode=Markdown" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
    
    if ! echo "${result}" | grep -q '"ok":true'; then
        curl -s -X POST \
            --connect-timeout 10 \
            --max-time 15 \
            -d "chat_id=${TELEGRAM_CHAT}" \
            -d "text=${extended_message}" \
            "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1 >/dev/null
    fi
}

# Test Function for Telegram Configuration
test_telegram_config() {
    log "Testing Telegram configuration..."
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        echo "ERROR: Telegram Token or Chat ID missing"
        return 1
    fi
    
    local test_message="🧪 TEST MESSAGE

✅ Telegram configuration working!
🤖 Bot Token: ${TELEGRAM_TOKEN:0:20}...
💬 Chat ID: ${TELEGRAM_CHAT}
⏰ Time: $(date)

This test confirms that your bot can successfully send messages."
    
    local result
    result=$(curl -s -X POST \
        --connect-timeout 10 \
        --max-time 15 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${test_message}" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
    
    if echo "${result}" | grep -q '"ok":true'; then
        echo "✅ Test message sent successfully"
        return 0
    else
        echo "❌ Test message failed: ${result}"
        return 1
    fi
}

# Enhanced Error Handler
enhanced_error_handler() {
    local line_number="$1"
    local error_code="${2:-1}"
    local error_msg="Script failed in line ${line_number} (Exit Code: ${error_code})"
    
    log "CRITICAL ERROR: ${error_msg}"
    
    local last_telegram_file="/tmp/last_telegram_notification"
    local current_time=$(date +%s)
    local send_telegram=true
    
    if [[ -f "${last_telegram_file}" ]]; then
        local last_time
        last_time=$(cat "${last_telegram_file}" 2>/dev/null || echo "0")
        local time_diff=$((current_time - last_time))
        if [[ ${time_diff} -lt 60 ]]; then
            send_telegram=false
        fi
    fi
    
    if [[ "${send_telegram}" == "true" ]]; then
        local debug_info=""
        debug_info+="Last commands: $(history | tail -3 | tr '\n' '; ')
"
        debug_info+="Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
        enhanced_notify "error" "Error Message" "${error_msg}

Debug Info:
${debug_info}"
        echo "${current_time}" > "${last_telegram_file}"
    fi
    
    cleanup_on_error
    exit "${error_code}"
}

# Cleanup on Error
cleanup_on_error() {
    log "Performing error cleanup"
    if command -v docker >/dev/null 2>&1; then
        local our_containers
        our_containers=$(docker ps --filter "label=com.globalping.installer=true" -q 2>/dev/null || echo "")
        if [[ -n "${our_containers}" ]]; then
            # shellcheck disable=SC2086
            docker stop ${our_containers} >/dev/null 2>&1 || true
        fi
    fi
    rm -rf "${TMP_DIR}" 2>/dev/null || true
    rm -f "/var/lock/globalping-install-enhanced.lock" 2>/dev/null || true
    rm -f "/tmp/globalping_auto_update.lock" 2>/dev/null || true
}

# Install sudo
install_sudo() {
    log "Checking sudo installation"
    if command -v sudo >/dev/null 2>&1; then return 0; fi
    log "Installing sudo"
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get install -y sudo >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y sudo >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y sudo >/dev/null 2>&1
    else
        return 1
    fi
}

# Configure hostname
configure_hostname() {
    log "Configuring hostname"
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current_hostname
        current_hostname=$(hostname 2>/dev/null || echo "")
        if [[ "${current_hostname}" != "${HOSTNAME_NEW}" ]]; then
            log "Setting hostname to: ${HOSTNAME_NEW}"
            hostname "${HOSTNAME_NEW}" 2>/dev/null || true
            echo "${HOSTNAME_NEW}" > /etc/hostname 2>/dev/null || true
            if [[ -f /etc/hosts ]]; then
                sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
                if ! grep -q "127.0.1.1.*${HOSTNAME_NEW}" /etc/hosts; then
                    echo "127.0.1.1 ${HOSTNAME_NEW}" >> /etc/hosts
                fi
            fi
        fi
    fi
    return 0
}

# Ubuntu Pro Activation
ubuntu_pro_attach() {
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        enhanced_log "INFO" "Activating Ubuntu Pro with token"
        if ! command -v ua >/dev/null 2>&1; then
            wait_for_apt_locks
            apt-get update >/dev/null 2>&1 || true
            wait_for_apt_locks
            apt-get install -y ubuntu-advantage-tools >/dev/null 2>&1 || return 1
        fi
        if ua attach "${UBUNTU_PRO_TOKEN}" >/dev/null 2>&1; then
            enhanced_log "INFO" "Ubuntu Pro activated"
            ua enable esm-apps >/dev/null 2>&1 || true
            ua enable esm-infra >/dev/null 2>&1 || true
            ua enable livepatch >/dev/null 2>&1 || true
            wait_for_apt_locks
            apt-get update >/dev/null 2>&1 || true
        else
            return 1
        fi
    fi
    return 0
}

# Setup SSH Key
setup_ssh_key() {
    enhanced_log "INFO" "Setting up SSH Key"
    if [[ ! -d "${SSH_DIR}" ]]; then
        mkdir -p "${SSH_DIR}" && chmod 700 "${SSH_DIR}"
    fi
    if [[ -n "${SSH_KEY}" ]]; then
        if [[ -f "${SSH_DIR}/authorized_keys" ]] && grep -Fq "${SSH_KEY}" "${SSH_DIR}/authorized_keys"; then
            return 0
        fi
        echo "${SSH_KEY}" >> "${SSH_DIR}/authorized_keys" && chmod 600 "${SSH_DIR}/authorized_keys"
    fi
    return 0
}

# Install Fail2Ban
install_fail2ban() {
    enhanced_log "INFO" "Installing and Configuring Fail2Ban"
    
    if command -v fail2ban-client >/dev/null 2>&1; then
        enhanced_log "INFO" "Fail2Ban already installed"
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get install -y fail2ban >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Failed to install fail2ban"
            return 1
        }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y fail2ban >/dev/null 2>&1 || return 1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y fail2ban >/dev/null 2>&1 || return 1
    else
        enhanced_log "WARN" "Cannot install Fail2Ban (unsupported package manager)"
        return 1
    fi

    # Configure Jail for SSH
    local jail_file="/etc/fail2ban/jail.local"
    if [[ ! -f "${jail_file}" ]]; then
        enhanced_log "INFO" "Creating default Fail2Ban SSH jail"
        cat > "${jail_file}" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
EOF
    fi

    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    
    enhanced_log "INFO" "Fail2Ban successfully installed and configured"
    return 0
}

# ShellCheck Self-Test
run_shellcheck_self_test() {
    enhanced_log "INFO" "Running ShellCheck Self-Test"
    
    if ! command -v shellcheck >/dev/null 2>&1; then
        enhanced_log "INFO" "Installing ShellCheck..."
        if command -v apt-get >/dev/null 2>&1; then
            wait_for_apt_locks
            apt-get install -y shellcheck >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y shellcheck >/dev/null 2>&1 || true
        fi
    fi
    
    if command -v shellcheck >/dev/null 2>&1; then
        enhanced_log "INFO" "Analyzing script with ShellCheck..."
        if shellcheck "$0"; then
            echo "✅ ShellCheck Passed: No issues found."
            return 0
        else
            echo "⚠️ ShellCheck found issues (see above)."
            return 1
        fi
    else
        enhanced_log "WARN" "ShellCheck could not be installed."
        return 1
    fi
}

# Uninstall Procedure
perform_uninstall() {
    local force="$1"
    
    if [[ "${force}" != "true" ]]; then
        echo "⚠️  WARNING: You are about to UNINSTALL Globalping Probe and this script."
        echo "This will stop the container, remove the service, and delete the script."
        echo -n "Are you sure? [y/N] "
        read -r response
        if [[ ! "${response}" =~ ^[yY]$ ]]; then
            echo "Uninstall cancelled."
            exit 0
        fi
    fi
    
    enhanced_log "INFO" "Starting Uninstallation..."
    
    # Stop Container
    if command -v docker >/dev/null 2>&1; then
        if docker ps -a | grep -q globalping-probe; then
            docker stop globalping-probe >/dev/null 2>&1 || true
            docker rm globalping-probe >/dev/null 2>&1 || true
            docker rmi ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1 || true
            docker volume rm probe-data 2>/dev/null || true
            enhanced_log "INFO" "Docker resources removed"
        fi
    fi
    
    # Remove Systemd Timer/Service
    systemctl stop globalping-update.timer 2>/dev/null || true
    systemctl disable globalping-update.timer 2>/dev/null || true
    rm -f "${SYSTEMD_TIMER_PATH}" "${SYSTEMD_SERVICE_PATH}"
    systemctl daemon-reload
    
    # Remove Cron
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -v "install_globalping" | crontab - 2>/dev/null || true
    fi
    
    # Remove Script
    rm -f "${SCRIPT_PATH}"
    
    echo "✅ Uninstallation completed. (Logs at ${LOG_FILE} were kept)"
    exit 0
}

# Install Dependencies
install_dependencies() {
    enhanced_log "INFO" "Installing system dependencies"
    
    local required_cmds=("curl" "wget" "grep" "sed" "awk" "bc" "unzip" "tar" "gzip" "find" "xargs")
    local missing_cmds=()
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then missing_cmds+=("${cmd}"); fi
    done
    
    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        enhanced_log "INFO" "Dependencies already installed"
        perform_package_cleanup
        return 0
    fi
    
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get install -y curl wget awk sed grep coreutils bc unzip tar gzip bzip2 xz-utils findutils lsb-release iproute2 systemd procps psmisc ca-certificates gnupg software-properties-common >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget gawk sed grep coreutils bc unzip tar gzip bzip2 xz findutils iproute systemd procps-ng psmisc ca-certificates gnupg2 >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget gawk sed grep coreutils bc unzip tar gzip bzip2 xz findutils iproute systemd procps-ng psmisc ca-certificates gnupg2 >/dev/null 2>&1
    fi
    
    perform_package_cleanup
    return 0
}

# Package Cleanup
perform_package_cleanup() {
    enhanced_log "INFO" "Performing package cleanup"
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get autoclean >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
    fi
}

# System Update
update_system() {
    enhanced_log "INFO" "Running system update"
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get upgrade -y --fix-broken --fix-missing >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y --skip-broken >/dev/null 2>&1 || true
    fi
    perform_package_cleanup
}

# Architecture Detection (Stub for optimization)
detect_architecture() { return 0; }

# Swap Config
configure_smart_swap() {
    log "Checking Swap configuration"
    local swap_total_mb
    swap_total_mb=$(free -m | grep Swap | awk '{print $2}' || echo "0")
    
    if [[ ${swap_total_mb} -gt 0 ]]; then return 0; fi
    
    local swap_file="/swapfile"
    # RAM check
    local mem_mb
    mem_mb=$(free -m | grep Mem | awk '{print $2}' || echo "0")
    
    if [[ ${mem_mb} -gt 1024 ]]; then return 0; fi
    
    log "Creating Swap file"
    touch "${swap_file}"
    if command -v chattr >/dev/null 2>&1; then chattr +C "${swap_file}" 2>/dev/null || true; fi
    dd if=/dev/zero of="${swap_file}" bs=1M count=1024 2>/dev/null || return 1
    chmod 600 "${swap_file}"
    mkswap "${swap_file}" >/dev/null 2>&1
    swapon "${swap_file}" || return 1
    if ! grep -q "${swap_file}" /etc/fstab; then echo "${swap_file} none swap sw 0 0" >> /etc/fstab; fi
    return 0
}

# Check Critical Updates
check_critical_updates() {
    log "Checking for critical updates"
    local needs_reboot=false
    
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        if ! timeout "${TIMEOUT_PACKAGE}" apt-get update >/dev/null 2>&1; then return 0; fi
        
        local updates
        updates=$(apt list --upgradable 2>/dev/null | grep -v "WARNING" || echo "")
        
        # Check phased updates
        if echo "${updates}" | grep -q "phased"; then
            log "Phased updates detected - skipping reboot"
            return 0
        fi
        
        if echo "${updates}" | grep -qE "linux-image|systemd|libc6"; then
             log "Critical updates found, installing..."
             wait_for_apt_locks
             DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1
             needs_reboot=true
        fi
    elif command -v dnf >/dev/null 2>&1; then
        if dnf check-update kernel systemd >/dev/null 2>&1; then
             dnf update -y kernel systemd >/dev/null 2>&1
             needs_reboot=true
        fi
    fi
    
    if [[ -f /var/run/reboot-required ]]; then needs_reboot=true; fi
    
    if [[ "${needs_reboot}" == "true" ]]; then
        REBOOT_REQUIRED="true"
        schedule_reboot_with_cleanup
    fi
    return 0
}

schedule_reboot_with_cleanup() {
    log "Scheduling Reboot"
    shutdown -r +2 "System Reboot for updates" &
}

# Install Probe
install_enhanced_globalping_probe() {
    log "Installing Globalping Probe"
    if [[ -z "${ADOPTION_TOKEN}" ]]; then return 1; fi
    
    if ! command -v docker >/dev/null 2>&1; then
        install_docker || return 1
    fi
    
    # Check existing
    if docker ps -a | grep -q globalping-probe; then
        docker stop globalping-probe >/dev/null 2>&1 || true
        docker rm globalping-probe >/dev/null 2>&1 || true
    fi
    
    log "Starting Container"
    docker run -d \
        --name globalping-probe \
        --restart always \
        --network host \
        --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
        -e "GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
        -e "NODE_ENV=production" \
        -v globalping-data:/home/node/.globalping \
        ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1
        
    return 0
}

# Install Docker
install_docker() {
    log "Installing Docker"
    if command -v docker >/dev/null 2>&1; then return 0; fi
    
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh >/dev/null 2>&1
    systemctl enable docker >/dev/null 2>&1
    systemctl start docker >/dev/null 2>&1
    return 0
}

# Auto-Update Setup
setup_enhanced_auto_update() {
    log "Setting up Auto-Update"
    cp "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    
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
    
    systemctl daemon-reload
    systemctl enable globalping-update.timer >/dev/null 2>&1
    systemctl start globalping-update.timer >/dev/null 2>&1
    return 0
}

# Network Analysis (IPv6 Added)
analyze_network_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing network..."
    
    # IPv4
    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        info_ref+=("Public IPv4: ${PUBLIC_IP}")
    else
        issues_ref+=("No public IPv4 address")
    fi
    
    # IPv6 Check
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' | cut -d/ -f1)
    if [[ -n "${ipv6_addr}" ]]; then
        info_ref+=("IPv6 Address detected: ${ipv6_addr}")
        if ping6 -c 1 -W 2 google.com >/dev/null 2>&1; then
            info_ref+=("IPv6 Connectivity confirmed")
        else
            warnings_ref+=("IPv6 detected but no connectivity")
        fi
    else
        info_ref+=("No global IPv6 address found")
    fi
}

# Diagnostics
run_enhanced_diagnostics() {
    local issues=() warnings=() info=()
    echo "=== DIAGNOSTICS ==="
    analyze_network_enhanced issues warnings info
    
    echo "Info: ${info[*]}"
    if [[ ${#issues[@]} -gt 0 ]]; then echo "Issues: ${issues[*]}"; return 1; fi
    return 0
}

# Help
show_enhanced_help() {
    echo "Usage: ./install.sh [OPTIONS]"
    echo "--adoption-token TOKEN   Required"
    echo "--install-fail2ban       Install and configure Fail2Ban"
    echo "--uninstall              Uninstall Globalping and cleanup"
    echo "--self-check             Run ShellCheck on this script"
    echo "--diagnose               Run diagnostics (incl. IPv6)"
    exit 0
}

# Main Logic
process_enhanced_args() {
    local fail2ban="false"
    local uninstall="false"
    local self_check="false"
    local diagnose="false"
    local force="false"
    local auto_weekly="false"
    local no_reboot="false"
    local telegram_test="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-fail2ban) fail2ban="true"; shift ;;
            --uninstall) uninstall="true"; shift ;;
            --self-check) self_check="true"; shift ;;
            --diagnose) diagnose="true"; shift ;;
            --force) force="true"; shift ;;
            --auto-weekly) auto_weekly="true"; WEEKLY_MODE="true"; shift ;;
            --adoption-token) ADOPTION_TOKEN="$2"; shift 2 ;;
            --telegram-token) TELEGRAM_TOKEN="$2"; shift 2 ;;
            --telegram-chat) TELEGRAM_CHAT="$2"; shift 2 ;;
            --ssh-key) SSH_KEY="$2"; shift 2 ;;
            --ubuntu-token) UBUNTU_PRO_TOKEN="$2"; shift 2 ;;
            --test-telegram) telegram_test="true"; shift ;;
            --no-reboot) no_reboot="true"; shift ;;
            *) shift ;; # Ignore unknown for simplicity in snippet
        esac
    done

    if [[ "${self_check}" == "true" ]]; then run_shellcheck_self_test; exit $?; fi
    if [[ "${uninstall}" == "true" ]]; then perform_uninstall "${force}"; exit $?; fi
    if [[ "${diagnose}" == "true" ]]; then run_enhanced_diagnostics; exit $?; fi
    if [[ "${telegram_test}" == "true" ]]; then test_telegram_config; exit $?; fi
    
    # Standard Installation Flow
    if [[ "${fail2ban}" == "true" ]]; then install_fail2ban; fi
    
    if [[ "${auto_weekly}" == "true" ]]; then
        # Weekly Logic
        perform_enhanced_auto_update
        check_critical_updates
        if [[ "${REBOOT_REQUIRED}" != "true" ]]; then
             install_enhanced_globalping_probe
        fi
        exit 0
    fi

    # Full Install
    get_enhanced_system_info
    install_sudo
    install_dependencies
    update_system
    configure_hostname
    setup_ssh_key
    configure_smart_swap
    install_enhanced_globalping_probe
    setup_enhanced_auto_update
    
    if [[ "${fail2ban}" == "true" ]]; then install_fail2ban; fi
    
    enhanced_notify "install_success" "Setup Complete" "Installation successful."
}

# Entry Point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then show_enhanced_help; fi
    process_enhanced_args "$@"
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================