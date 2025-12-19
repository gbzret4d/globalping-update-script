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
readonly SCRIPT_VERSION="2025.12.19-v2.2"

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

# ENHANCED Telegram Notification
enhanced_notify() {
    local level="$1"
    local title="$2"
    local message="$3"
    
    # Prevent duplicate Telegram messages
    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then
        log "Telegram Success message already sent - skipping"
        return 0
    fi
    
    # Only send errors and initial success
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then
        return 0
    fi
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        log "Telegram configuration incomplete"
        return 0
    fi
    
    # Collect system info if missing
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
            TELEGRAM_SENT="true"  # Mark as sent
            ;;
    esac
    
    # Create enhanced message based on level
    local extended_message
    if [[ "${level}" == "install_success" ]]; then
        # Safely collect system info
        local ram_info disk_info swap_info load_info
        local auto_update_status ssh_status ubuntu_pro_status
        local globalping_status docker_installed
        
        ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unknown")
        disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5" used)"}' || echo "unknown")
        swap_info=$(free -h 2>/dev/null | grep Swap | awk '{print $2}' || echo "0B")
        load_info=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "0")
        
        # Status Information
        auto_update_status=$(systemctl is-enabled globalping-update.timer 2>/dev/null || echo "crontab")
        ssh_status="${SSH_KEY:+✓ Configured}${SSH_KEY:-✗ Not set}"
        ubuntu_pro_status="${UBUNTU_PRO_TOKEN:+✓ Active}${UBUNTU_PRO_TOKEN:-✗ Not used}"
        
        # Docker & Globalping Status
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
        
        # Extended Success Message (Markdown)
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
        # Extended Error Message
        local system_status error_context
        
        local ram_status disk_status load_status
        ram_status=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unknown")
        disk_status=$(df -h / 2>/dev/null | awk 'NR==2 {print $4" free"}' || echo "unknown")
        load_status=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "unknown")
        
        system_status="RAM: ${ram_status} | HDD: ${disk_status} | Load: ${load_status}"
        
        # Last relevant log entries
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
    
    log "Sending extended Telegram message (${#extended_message} chars)..."
    
    # Telegram limit check
    if [[ ${#extended_message} -gt 4000 ]]; then
        log "Message too long (${#extended_message} chars), truncating to 4000"
        extended_message=$(echo "${extended_message}" | head -c 3900)
        extended_message="${extended_message}

...Message truncated - Check via SSH"
    fi
    
    # Send with Markdown
    local result
    result=$(curl -s -X POST \
        --connect-timeout 10 \
        --max-time 15 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        -d "parse_mode=Markdown" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
    
    if echo "${result}" | grep -q '"ok":true'; then
        local message_id
        message_id=$(echo "${result}" | grep -o '"message_id":[0-9]*' | cut -d':' -f2 || echo "unknown")
        log "Telegram message sent successfully (ID: ${message_id})"
        return 0
    else
        # Fallback without Markdown
        log "Markdown error, sending fallback without formatting"
        result=$(curl -s -X POST \
            --connect-timeout 10 \
            --max-time 15 \
            -d "chat_id=${TELEGRAM_CHAT}" \
            -d "text=${extended_message}" \
            "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" 2>&1)
        
        if echo "${result}" | grep -q '"ok":true'; then
            log "Fallback message sent successfully"
            return 0
        else
            log "Telegram API Error: ${result}"
            return 1
        fi
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
        local message_id
        message_id=$(echo "${result}" | grep -o '"message_id":[0-9]*' | cut -d':' -f2 || echo "unknown")
        echo "✅ Test message sent successfully (Message ID: ${message_id})"
        return 0
    else
        echo "❌ Test message failed:"
        echo "API Response: ${result}"
        
        # Analyze common errors
        if echo "${result}" | grep -q "bot was blocked"; then
            echo "TIP: Bot blocked - Please unblock the bot in Telegram"
        elif echo "${result}" | grep -q "chat not found"; then
            echo "TIP: Invalid Chat ID - Please check the Chat ID"
        elif echo "${result}" | grep -q "Unauthorized"; then
            echo "TIP: Invalid Bot Token - Please check the Token"
        fi
        
        return 1
    fi
}

# Enhanced Error Handler (prevents spam)
enhanced_error_handler() {
    local line_number="$1"
    local error_code="${2:-1}"
    local error_msg="Script failed in line ${line_number} (Exit Code: ${error_code})"
    
    log "CRITICAL ERROR: ${error_msg}"
    
    # Check if a message was sent in the last 60 seconds
    local last_telegram_file="/tmp/last_telegram_notification"
    local current_time=$(date +%s)
    local send_telegram=true
    
    if [[ -f "${last_telegram_file}" ]]; then
        local last_time
        last_time=$(cat "${last_telegram_file}" 2>/dev/null || echo "0")
        local time_diff=$((current_time - last_time))
        
        if [[ ${time_diff} -lt 60 ]]; then
            log "Telegram message sent ${time_diff}s ago - skipping duplicate"
            send_telegram=false
        fi
    fi
    
    if [[ "${send_telegram}" == "true" ]]; then
        # Collect debug info
        local debug_info=""
        debug_info+="Last commands: $(history | tail -3 | tr '\n' '; ')
"
        debug_info+="Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')
"
        debug_info+="Disk: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5")"}')
"
        
        enhanced_notify "error" "Error Message" "${error_msg}

Debug Info:
${debug_info}"
        
        # Mark message as sent
        echo "${current_time}" > "${last_telegram_file}"
    fi
    
    # Cleanup
    cleanup_on_error
    exit "${error_code}"
}

# Cleanup on Error
cleanup_on_error() {
    log "Performing error cleanup"
    
    # Stop running critical operations
    if command -v docker >/dev/null 2>&1; then
        # Stop only containers we just created
        local our_containers
        our_containers=$(docker ps --filter "label=com.globalping.installer=true" -q 2>/dev/null || echo "")
        if [[ -n "${our_containers}" ]]; then
            # shellcheck disable=SC2086
            docker stop ${our_containers} >/dev/null 2>&1 || true
        fi
    fi
    
    # Remove temp files
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    
    # Remove locks
    rm -f "/var/lock/globalping-install-enhanced.lock" 2>/dev/null || true
    rm -f "/tmp/globalping_auto_update.lock" 2>/dev/null || true
}

# Install sudo
install_sudo() {
    log "Checking sudo installation"
    
    if command -v sudo >/dev/null 2>&1; then
        log "sudo is already installed"
        return 0
    fi
    
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
        enhanced_log "WARN" "No supported package manager found for sudo installation"
        return 1
    fi
    
    return $?
}

# Configure hostname
configure_hostname() {
    log "Configuring hostname"
    
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current_hostname
        current_hostname=$(hostname 2>/dev/null || echo "")
        
        if [[ "${current_hostname}" != "${HOSTNAME_NEW}" ]]; then
            log "Setting hostname to: ${HOSTNAME_NEW}"
            
            # Set temp hostname
            hostname "${HOSTNAME_NEW}" 2>/dev/null || true
            
            # Persist hostname
            echo "${HOSTNAME_NEW}" > /etc/hostname 2>/dev/null || true
            
            # Update /etc/hosts
            if [[ -f /etc/hosts ]]; then
                sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
                
                # Add entry if missing
                if ! grep -q "127.0.1.1.*${HOSTNAME_NEW}" /etc/hosts; then
                    echo "127.0.1.1 ${HOSTNAME_NEW}" >> /etc/hosts
                fi
            fi
            
            log "Hostname configured: ${HOSTNAME_NEW}"
        else
            log "Hostname already correct: ${current_hostname}"
        fi
    else
        log "No valid hostname available, using current"
    fi
    
    return 0
}

# Ubuntu Pro Activation
ubuntu_pro_attach() {
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        enhanced_log "INFO" "Activating Ubuntu Pro with token"
        
        # Install Ubuntu Advantage Tools
        if ! command -v ua >/dev/null 2>&1; then
            wait_for_apt_locks
            apt-get update >/dev/null 2>&1 || true
            wait_for_apt_locks
            apt-get install -y ubuntu-advantage-tools >/dev/null 2>&1 || {
                enhanced_log "ERROR" "Could not install ubuntu-advantage-tools"
                return 1
            }
        fi

        # Apply Token
        if ua attach "${UBUNTU_PRO_TOKEN}" >/dev/null 2>&1; then
            enhanced_log "INFO" "Ubuntu Pro Token successfully activated"
            
            # Enable ESM and security updates
            ua enable esm-apps >/dev/null 2>&1 || true
            ua enable esm-infra >/dev/null 2>&1 || true
            ua enable livepatch >/dev/null 2>&1 || true
            
            # Update system
            wait_for_apt_locks
            apt-get update >/dev/null 2>&1 || true
            wait_for_apt_locks
            apt-get upgrade -y >/dev/null 2>&1 || true
            
            enhanced_log "INFO" "Ubuntu Pro with ESM/Livepatch activated"
            return 0
        else
            enhanced_log "ERROR" "Ubuntu Pro Token activation failed"
            return 1
        fi
    else
        enhanced_log "INFO" "Ubuntu Pro not applicable (not Ubuntu or no Token)"
        return 0
    fi
}

# Setup SSH Key
setup_ssh_key() {
    enhanced_log "INFO" "Setting up SSH Key"
    
    if [[ ! -d "${SSH_DIR}" ]]; then
        mkdir -p "${SSH_DIR}" || {
            enhanced_log "ERROR" "Could not create SSH directory"
            return 1
        }
        chmod 700 "${SSH_DIR}"
    fi
    
    if [[ -n "${SSH_KEY}" ]]; then
        # Check if key exists
        if [[ -f "${SSH_DIR}/authorized_keys" ]] && grep -Fq "${SSH_KEY}" "${SSH_DIR}/authorized_keys"; then
            enhanced_log "INFO" "SSH key already exists"
            return 0
        fi
        
        # Validate SSH Key format
        if ! echo "${SSH_KEY}" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-)"; then
            enhanced_log "ERROR" "Invalid SSH Key format"
            return 1
        fi
        
        # Add Key
        echo "${SSH_KEY}" >> "${SSH_DIR}/authorized_keys" || {
            enhanced_log "ERROR" "Could not add SSH Key"
            return 1
        }
        chmod 600 "${SSH_DIR}/authorized_keys"
        enhanced_log "INFO" "SSH Key successfully added"
        return 0
    else
        enhanced_log "INFO" "No SSH Key provided"
        return 0
    fi
}

# Install Dependencies with Cleanup
install_dependencies() {
    enhanced_log "INFO" "Installing system dependencies"
    
    # Detect Distro
    local is_debian_based=false
    local is_rhel_based=false
    
    if [[ -f /etc/debian_version ]] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    # List of required commands
    local required_cmds=("curl" "wget" "grep" "sed" "awk" "bc" "unzip" "tar" "gzip" "find" "xargs")
    local missing_cmds=()
    
    # Check missing commands
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing_cmds+=("${cmd}")
        fi
    done
    
    # If all present, clean up and return
    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        enhanced_log "INFO" "All required dependencies are already installed"
        perform_package_cleanup
        return 0
    fi
    
    enhanced_log "INFO" "Installing missing dependencies: ${missing_cmds[*]}"
    
    if [[ "${is_debian_based}" == "true" ]] && command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get update failed"
        }
        
        # Install bc separately if missing
        if [[ " ${missing_cmds[*]} " =~ " bc " ]]; then
            enhanced_log "INFO" "Installing bc (Basic Calculator)"
            wait_for_apt_locks
            apt-get install -y bc >/dev/null 2>&1 || {
                enhanced_log "WARN" "bc installation failed - using fallback math"
            }
        fi
        
        wait_for_apt_locks
        apt-get install -y \
            curl wget awk sed grep coreutils bc \
            unzip tar gzip bzip2 xz-utils \
            findutils lsb-release iproute2 \
            systemd procps psmisc \
            ca-certificates gnupg \
            software-properties-common \
            apt-transport-https >/dev/null 2>&1 || {
            enhanced_log "WARN" "Some dependencies could not be installed"
        }
        
        perform_package_cleanup
        
    elif [[ "${is_rhel_based}" == "true" ]]; then
        if command -v dnf >/dev/null 2>&1; then
            # RHEL/CentOS/Rocky/Alma with DNF
            dnf install -y \
                curl wget gawk sed grep coreutils bc \
                unzip tar gzip bzip2 xz \
                findutils redhat-lsb-core iproute \
                systemd procps-ng psmisc \
                ca-certificates gnupg2 \
                dnf-plugins-core >/dev/null 2>&1 || {
                enhanced_log "WARN" "Some dependencies could not be installed"
            }
            
            dnf clean all >/dev/null 2>&1 || true
            dnf autoremove -y >/dev/null 2>&1 || true
            
        elif command -v yum >/dev/null 2>&1; then
            # Older RHEL/CentOS with YUM
            yum install -y \
                curl wget gawk sed grep coreutils bc \
                unzip tar gzip bzip2 xz \
                findutils redhat-lsb-core iproute \
                systemd procps-ng psmisc \
                ca-certificates gnupg2 \
                yum-utils >/dev/null 2>&1 || {
                enhanced_log "WARN" "Some dependencies could not be installed"
            }
            
            yum clean all >/dev/null 2>&1 || true
            yum autoremove -y >/dev/null 2>&1 || true
            
        else
            enhanced_log "ERROR" "No supported package manager found"
            return 1
        fi
    else
        enhanced_log "WARN" "Unknown distribution, skipping dependency installation"
    fi
    
    # Verify critical tools
    local verification_failed=false
    for cmd in "curl" "unzip" "tar"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            enhanced_log "ERROR" "Critical tool '${cmd}' could not be installed"
            verification_failed=true
        fi
    done
    
    if [[ "${verification_failed}" == "true" ]]; then
        enhanced_log "ERROR" "Installation of critical dependencies failed"
        return 1
    fi
    
    enhanced_log "INFO" "System dependencies successfully installed"
    return 0
}

# Package Cleanup
perform_package_cleanup() {
    enhanced_log "INFO" "Performing package cleanup"
    
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get clean >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get autoclean >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get autoremove -y >/dev/null 2>&1 || true
        
        # Remove old archives and lists
        rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true
        rm -rf /var/lib/apt/lists/* 2>/dev/null || true
        
        enhanced_log "INFO" "Debian/Ubuntu package cleanup completed"
        
    elif command -v dnf >/dev/null 2>&1; then
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/dnf/* 2>/dev/null || true
        
        enhanced_log "INFO" "DNF package cleanup completed"
        
    elif command -v yum >/dev/null 2>&1; then
        yum clean all >/dev/null 2>&1 || true
        yum autoremove -y >/dev/null 2>&1 || true
        rm -rf /var/cache/yum/* 2>/dev/null || true
        
        enhanced_log "INFO" "YUM package cleanup completed"
    fi
}

# System Update with Cleanup
update_system() {
    enhanced_log "INFO" "Running system update with cleanup"
    
    local is_debian_based=false
    local is_rhel_based=false
    
    if [[ -f /etc/debian_version ]] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        is_debian_based=true
    elif grep -qi "rhel\|centos\|fedora\|rocky\|alma" /etc/os-release 2>/dev/null; then
        is_rhel_based=true
    fi
    
    if [[ "${is_debian_based}" == "true" ]] && command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get update >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get update failed"
        }
        wait_for_apt_locks
        apt-get upgrade -y --fix-broken --fix-missing >/dev/null 2>&1 || {
            enhanced_log "WARN" "apt-get upgrade failed"
        }
        
        perform_package_cleanup
        
    elif [[ "${is_rhel_based}" == "true" ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf update -y --skip-broken >/dev/null 2>&1 || {
                enhanced_log "WARN" "dnf update failed"
            }
            dnf clean all >/dev/null 2>&1 || true
            dnf autoremove -y >/dev/null 2>&1 || true
            
        elif command -v yum >/dev/null 2>&1; then
            yum update -y --skip-broken >/dev/null 2>&1 || {
                enhanced_log "WARN" "yum update failed"
            }
            yum clean all >/dev/null 2>&1 || true
            yum autoremove -y >/dev/null 2>&1 || true
            
        else
            enhanced_log "WARN" "No supported package manager found"
        fi
    else
        enhanced_log "WARN" "Unknown distribution, skipping system update"
    fi
    
    enhanced_log "INFO" "System update completed"
    return 0
}

# Architecture Detection
detect_architecture() {
    enhanced_log "INFO" "Detecting system architecture"
    
    local arch
    arch=$(uname -m)
    local is_arm=false
    local is_raspberry_pi=false
    
    case "${arch}" in
        arm*|aarch*)
            is_arm=true
            enhanced_log "INFO" "ARM architecture detected: ${arch}"
            ;;
        x86_64|amd64)
            enhanced_log "INFO" "x86_64 architecture detected"
            ;;
        *)
            enhanced_log "WARN" "Unknown architecture: ${arch}"
            ;;
    esac
    
    # Raspberry Pi specific check
    if [[ "${is_arm}" == "true" ]] && [[ -f /proc/device-tree/model ]] && grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
        is_raspberry_pi=true
        local pi_model
        pi_model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "Raspberry Pi")
        enhanced_log "INFO" "Raspberry Pi detected: ${pi_model}"
        
        optimize_for_raspberry_pi
    fi
    
    export ARCH="${arch}"
    export IS_ARM="${is_arm}"
    export IS_RASPBERRY_PI="${is_raspberry_pi}"
    
    return 0
}

# Raspberry Pi Optimization
optimize_for_raspberry_pi() {
    enhanced_log "INFO" "Performing Raspberry Pi specific optimizations"
    
    # Swap opt for SD cards
    if [[ -f /etc/dphys-swapfile ]]; then
        enhanced_log "INFO" "Optimizing Swap settings for Raspberry Pi"
        cp /etc/dphys-swapfile /etc/dphys-swapfile.backup 2>/dev/null || true
        
        if ! grep -q "CONF_SWAPPINESS" /etc/dphys-swapfile; then
            echo "CONF_SWAPPINESS=10" >> /etc/dphys-swapfile
        fi
        
        systemctl restart dphys-swapfile >/dev/null 2>&1 || true
    fi
    
    # GPU Memory for headless
    if [[ -f /boot/config.txt ]]; then
        enhanced_log "INFO" "Configuring GPU memory for headless operation"
        if ! grep -q "^gpu_mem=" /boot/config.txt; then
            echo "gpu_mem=16" >> /boot/config.txt
        fi
    elif [[ -f /boot/firmware/config.txt ]]; then
        if ! grep -q "^gpu_mem=" /boot/firmware/config.txt; then
            echo "gpu_mem=16" >> /boot/firmware/config.txt
        fi
    fi
    
    enhanced_log "INFO" "Raspberry Pi optimizations completed"
    return 0
}

# Enhanced System Validation
enhanced_validate_system() {
    log "Performing enhanced system validation"
    
    local errors=()
    local warnings=()
    
    # Check RAM
    local mem_kb mem_mb
    mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_mb=$((mem_kb / 1024))
    
    if [[ ${mem_mb} -lt ${MIN_RAM_MB} ]]; then
        errors+=("Insufficient RAM: ${mem_mb}MB (Minimum: ${MIN_RAM_MB}MB)")
    elif [[ ${mem_mb} -lt 512 ]]; then
        warnings+=("Low RAM: ${mem_mb}MB - Performance might be degraded")
    fi
    
    # Check Disk Space
    local disk_available_kb disk_available_gb disk_usage_percent
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_usage_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "100")
    
    if [[ ${disk_available_kb} -gt 0 ]]; then
        local disk_available_mb=$((disk_available_kb / 1024))
        disk_available_gb=$((disk_available_mb / 1024))
        
        local min_space_mb=1536  # 1.5 * 1024
        
        log "DEBUG: Available: ${disk_available_mb}MB, Minimum: ${min_space_mb}MB"
        
        if [[ ${disk_available_mb} -lt ${min_space_mb} ]]; then
            if [[ ${disk_available_gb} -eq 0 ]]; then
                local display_gb
                if command -v bc >/dev/null 2>&1; then
                    display_gb=$(echo "scale=1; ${disk_available_mb} / 1024" | bc 2>/dev/null)
                else
                    display_gb="${disk_available_mb}MB"
                fi
                errors+=("Insufficient free disk space: ${display_gb}GB (Minimum: ${MIN_FREE_SPACE_GB}GB)")
            else
                errors+=("Insufficient free disk space: ${disk_available_gb}GB (Minimum: ${MIN_FREE_SPACE_GB}GB)")
            fi
        elif [[ ${disk_usage_percent} -gt 85 ]]; then
            warnings+=("Disk usage at ${disk_usage_percent}% (${disk_available_gb}GB free)")
        fi
    else
        errors+=("Unable to determine free disk space")
    fi
    
    # Output Validation
    if [[ ${#errors[@]} -gt 0 ]]; then
        enhanced_log "ERROR" "Critical system requirements not met:"
        for error in "${errors[@]}"; do
            enhanced_log "ERROR" "  ${error}"
        done
        
        enhanced_notify "error" "System Validation" "Critical requirements not met:
$(printf '%s\n' "${errors[@]}")"
        
        return 1
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        enhanced_log "WARN" "System requirements warnings:"
        for warning in "${warnings[@]}"; do
            enhanced_log "WARN" "  ${warning}"
        done
    fi
    
    log "System validation successful (RAM: ${mem_mb}MB, Free: ${disk_available_gb}GB)"
    return 0
}

# Smart Swap Configuration (Btrfs Safe)
configure_smart_swap() {
    log "Checking and configuring Swap memory"
    
    # Check current swap
    local swap_total_kb swap_total_mb
    swap_total_kb=$(grep "SwapTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    swap_total_mb=$((swap_total_kb / 1024))
    
    if [[ ${swap_total_mb} -gt 0 ]]; then
        log "Swap already configured: ${swap_total_mb}MB"
        return 0
    fi
    
    # Check total disk size
    local disk_total_kb disk_total_gb
    disk_total_kb=$(df / | awk 'NR==2 {print $2}' || echo "0")
    disk_total_gb=$((disk_total_kb / 1024 / 1024))
    
    if [[ ${disk_total_gb} -lt ${MIN_DISK_FOR_SWAP_GB} ]]; then
        log "Disk too small for Swap: ${disk_total_gb}GB (Minimum: ${MIN_DISK_FOR_SWAP_GB}GB)"
        return 0
    fi
    
    # Get RAM size
    local mem_kb mem_mb
    mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_mb=$((mem_kb / 1024))
    
    # Calculate required swap size
    local target_total_mb swap_size_mb
    target_total_mb=$((SWAP_MIN_TOTAL_GB * 1024))
    
    if [[ ${mem_mb} -lt ${target_total_mb} ]]; then
        swap_size_mb=$((target_total_mb - mem_mb))
    else
        log "RAM (${mem_mb}MB) is sufficient, no swap required"
        return 0
    fi
    
    # Limit Swap to 2GB
    if [[ ${swap_size_mb} -gt 2048 ]]; then
        swap_size_mb=2048
    fi
    
    log "Creating ${swap_size_mb}MB Swap file"
    
    local swap_file="/swapfile"
    
    # Create empty file
    touch "${swap_file}"
    
    # IMPORTANT: Disable Copy-on-Write (CoW) for Btrfs before writing data
    if command -v chattr >/dev/null 2>&1; then
        chattr +C "${swap_file}" 2>/dev/null || true
    fi
    
    if ! dd if=/dev/zero of="${swap_file}" bs=1M count="${swap_size_mb}" 2>/dev/null; then
        enhanced_log "ERROR" "Could not create Swap file"
        return 1
    fi
    
    chmod 600 "${swap_file}"
    
    if ! mkswap "${swap_file}" >/dev/null 2>&1; then
        enhanced_log "ERROR" "Could not format Swap file"
        rm -f "${swap_file}"
        return 1
    fi
    
    if ! swapon "${swap_file}"; then
        enhanced_log "ERROR" "Could not activate Swap file"
        rm -f "${swap_file}"
        return 1
    fi
    
    # Persist in /etc/fstab
    if ! grep -q "${swap_file}" /etc/fstab 2>/dev/null; then
        echo "${swap_file} none swap sw 0 0" >> /etc/fstab
    fi
    
    # Optimize swappiness
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
    sysctl vm.swappiness=10 >/dev/null 2>&1 || true
    
    log "Swap successfully configured: ${swap_size_mb}MB"
    return 0
}

# Check for Critical Updates (Phased Updates Aware)
check_critical_updates() {
    log "Checking for critical updates (Phased Updates Aware)"
    
    local needs_reboot=false
    
    # Debian/Ubuntu
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        if ! timeout "${TIMEOUT_PACKAGE}" apt-get update >/dev/null 2>&1; then
            enhanced_log "WARN" "apt-get update failed"
            return 0
        fi
        
        # Check for REAL updates (not phased)
        local available_updates
        available_updates=$(apt list --upgradable 2>/dev/null | grep -v "WARNING" | grep -v "Listing" || echo "")
        
        local kernel_updates=0
        local critical_updates=0
        
        if [[ -n "${available_updates}" ]]; then
            local kernel_count
            kernel_count=$(echo "${available_updates}" | grep -c "linux-image\|linux-generic\|linux-headers" 2>/dev/null || echo "0")
            kernel_updates=$(echo "${kernel_count}" | tr -d '\n\r' | head -c 10)
            if ! [[ "${kernel_updates}" =~ ^[0-9]+$ ]]; then kernel_updates=0; fi
            
            local critical_count
            critical_count=$(echo "${available_updates}" | grep -c "systemd\|libc6\|glibc" 2>/dev/null || echo "0")
            critical_updates=$(echo "${critical_count}" | tr -d '\n\r' | head -c 10)
            if ! [[ "${critical_updates}" =~ ^[0-9]+$ ]]; then critical_updates=0; fi
            
            # Check for phased updates
            local phased_count
            phased_count=$(echo "${available_updates}" | grep -c "phased" 2>/dev/null || echo "0")
            phased_count=$(echo "${phased_count}" | tr -d '\n\r' | head -c 10)
            if ! [[ "${phased_count}" =~ ^[0-9]+$ ]]; then phased_count=0; fi
            
            if [[ ${phased_count} -gt 0 ]] 2>/dev/null; then
                log "Phased Updates detected (${phased_count}) - skipping reboot"
                wait_for_apt_locks
                if DEBIAN_FRONTEND=noninteractive timeout "${TIMEOUT_PACKAGE}" apt-get upgrade -y \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    -o APT::Get::Assume-Yes=true \
                    --fix-broken --fix-missing >/dev/null 2>&1; then
                    log "Phased Updates installed without reboot"
                fi
                perform_package_cleanup
                return 0
            fi
        fi
        
        # Perform updates BEFORE reboot decision
        if [[ ${kernel_updates} -gt 0 || ${critical_updates} -gt 0 ]] 2>/dev/null; then
            log "Installing critical updates..."
            
            if [[ ${kernel_updates} -gt 0 ]] 2>/dev/null; then
                log "Installing Kernel updates with dist-upgrade..."
                wait_for_apt_locks
                if DEBIAN_FRONTEND=noninteractive timeout "${TIMEOUT_PACKAGE}" apt-get dist-upgrade -y \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    -o APT::Get::Assume-Yes=true \
                    --fix-broken --fix-missing >/dev/null 2>&1; then
                    log "Kernel updates installed via dist-upgrade"
                else
                    enhanced_log "WARN" "dist-upgrade failed, trying normal upgrade"
                    wait_for_apt_locks
                    DEBIAN_FRONTEND=noninteractive timeout "${TIMEOUT_PACKAGE}" apt-get upgrade -y \
                        -o Dpkg::Options::="--force-confdef" \
                        -o Dpkg::Options::="--force-confold" \
                        -o APT::Get::Assume-Yes=true \
                        --fix-broken --fix-missing >/dev/null 2>&1
                fi
            else
                wait_for_apt_locks
                DEBIAN_FRONTEND=noninteractive timeout "${TIMEOUT_PACKAGE}" apt-get upgrade -y \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    -o APT::Get::Assume-Yes=true \
                    --fix-broken --fix-missing >/dev/null 2>&1
            fi
            
            if [[ $? -eq 0 ]]; then
                log "Updates successfully installed"
                
                # Check if kernel updates were actually installed
                local remaining_updates
                remaining_updates=$(apt list --upgradable 2>/dev/null | grep -v "WARNING" | grep -v "Listing" || echo "")
                
                local remaining_kernel_updates=0
                local remaining_critical_updates=0
                
                if [[ -n "${remaining_updates}" ]]; then
                    remaining_kernel_updates=$(echo "${remaining_updates}" | grep -c "linux-image\|linux-generic\|linux-headers" 2>/dev/null || echo "0")
                    remaining_critical_updates=$(echo "${remaining_updates}" | grep -c "systemd\|libc6\|glibc" 2>/dev/null || echo "0")
                fi
                
                if [[ ${kernel_updates} -gt 0 && ${remaining_kernel_updates} -lt ${kernel_updates} ]] 2>/dev/null; then
                    log "Kernel updates verified installed"
                    needs_reboot=true
                fi
                
                if [[ ${critical_updates} -gt 0 && ${remaining_critical_updates} -lt ${critical_updates} ]] 2>/dev/null; then
                    log "Critical updates verified installed"
                    needs_reboot=true
                fi
            else
                enhanced_log "ERROR" "Update installation failed"
                return 1
            fi
            perform_package_cleanup
        fi
        
    # RHEL/CentOS/Fedora
    elif command -v dnf >/dev/null 2>&1; then
        local kernel_updates
        kernel_updates=$(dnf check-update kernel* 2>/dev/null | grep -c "kernel" || echo "0")
        
        if [[ ${kernel_updates} -gt 0 ]] 2>/dev/null; then
            log "Kernel updates found, installing..."
            if timeout "${TIMEOUT_PACKAGE}" dnf update -y --skip-broken kernel* >/dev/null 2>&1; then
                needs_reboot=true
            fi
        fi
        
        if timeout "${TIMEOUT_PACKAGE}" dnf update -y --skip-broken systemd glibc openssh* >/dev/null 2>&1; then
            log "Critical updates installed"
            needs_reboot=true
        fi
        
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
        
    elif command -v yum >/dev/null 2>&1; then
        if timeout "${TIMEOUT_PACKAGE}" yum update -y kernel* systemd glibc openssh* >/dev/null 2>&1; then
            needs_reboot=true
            log "Critical updates installed via YUM"
        fi
        yum clean all >/dev/null 2>&1 || true
        yum autoremove -y >/dev/null 2>&1 || true
    fi
    
    # Check /var/run/reboot-required
    if [[ -f /var/run/reboot-required ]]; then
        log "/var/run/reboot-required found - Reboot required"
        needs_reboot=true
    fi
    
    if [[ "${needs_reboot}" == "true" ]]; then
        log "Reboot required after REAL critical updates"
        REBOOT_REQUIRED="true"
        schedule_reboot_with_cleanup
    else
        log "No REAL critical updates or reboot required"
    fi
    
    return 0
}

# Schedule Reboot with Cleanup
schedule_reboot_with_cleanup() {
    log "Scheduling Reboot with automatic cleanup"
    
    local post_reboot_script="/usr/local/bin/post-reboot-cleanup"
    
    cat > "${post_reboot_script}" << 'EOF'
#!/bin/bash
# Post-Reboot Cleanup Script

LOG_FILE="/var/log/globalping-install.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [POST-REBOOT] $1" >> "${LOG_FILE}"
}

log "Starting Post-Reboot Cleanup"

# Wait for system to settle
sleep 30

if [[ -x "/usr/local/bin/install_globalping.sh" ]]; then
    /usr/local/bin/install_globalping.sh --cleanup >> "${LOG_FILE}" 2>&1
    log "Post-Reboot Cleanup completed"
else
    log "Cleanup script not found"
fi

systemctl disable post-reboot-cleanup.service 2>/dev/null || true
rm -f /etc/systemd/system/post-reboot-cleanup.service
rm -f /usr/local/bin/post-reboot-cleanup

log "Post-Reboot Service removed"
EOF
    
    chmod +x "${post_reboot_script}"
    
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
    
    log "Post-Reboot Service configured"
    
    log "System rebooting in 2 minutes..."
    shutdown -r +2 "System Reboot after critical updates" &
    
    enhanced_notify "error" "System Reboot" "System is restarting after critical updates.
Post-Reboot cleanup is scheduled."
}

# Install Globalping Probe with restart=always
install_enhanced_globalping_probe() {
    log "Installing enhanced Globalping Probe with restart=always"
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "ERROR" "No Adoption Token provided"
        enhanced_notify "error" "Configuration Error" "Globalping Probe: No Adoption Token provided"
        return 1
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        log "Docker required for Globalping Probe"
        if ! install_docker; then
            enhanced_log "ERROR" "Docker installation failed"
            enhanced_notify "error" "Docker Installation" "Docker could not be installed"
            return 1
        fi
    fi
    
    local existing_container
    existing_container=$(docker ps -a --format "{{.Names}}" | grep -i globalping | head -1 || echo "")
    
    if [[ -n "${existing_container}" ]]; then
        log "Existing Globalping container found: ${existing_container}"
        
        local current_token
        current_token=$(docker inspect "${existing_container}" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}' 2>/dev/null || echo "")
        
        if [[ "${current_token}" == "${ADOPTION_TOKEN}" ]]; then
            log "Container already using correct token"
            update_globalping_container_restart_policy "${existing_container}"
            return 0
        else
            log "Container using wrong token, removing..."
            docker stop "${existing_container}" >/dev/null 2>&1 || true
            docker rm "${existing_container}" >/dev/null 2>&1 || true
        fi
    fi
    
    local globalping_dir="/opt/globalping"
    mkdir -p "${globalping_dir}"
    cd "${globalping_dir}" || return 1
    
    create_enhanced_globalping_compose "${globalping_dir}"
    
    if ! start_enhanced_globalping_probe "${globalping_dir}"; then
        enhanced_log "ERROR" "Globalping Probe start failed"
        enhanced_notify "error" "Globalping Probe" "Container could not start"
        return 1
    fi
    
    if ! verify_enhanced_globalping_probe; then
        enhanced_log "ERROR" "Globalping Probe verification failed"
        enhanced_notify "error" "Globalping Probe" "Container verification failed"
        return 1
    fi
    
    create_enhanced_globalping_maintenance
    
    log "Enhanced Globalping Probe successfully installed"
    return 0
}

# Update Container Restart Policy
update_globalping_container_restart_policy() {
    local container_name="$1"
    
    log "Updating restart policy for ${container_name}"
    
    local current_policy
    current_policy=$(docker inspect "${container_name}" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null || echo "")
    
    if [[ "${current_policy}" == "always" ]]; then
        log "Restart policy already set to 'always'"
        return 0
    fi
    
    if docker update --restart=always "${container_name}" >/dev/null 2>&1; then
        log "Restart policy successfully updated to 'always'"
    else
        enhanced_log "WARN" "Could not update restart policy, recreating container"
        docker stop "${container_name}" >/dev/null 2>&1 || true
        docker rm "${container_name}" >/dev/null 2>&1 || true
        start_enhanced_globalping_probe "/opt/globalping"
    fi
}

# Docker Compose Configuration
create_enhanced_globalping_compose() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Creating enhanced Docker Compose configuration"
    
    cat > "${compose_file}" << EOF
version: '3.8'

services:
  globalping-probe:
    image: globalping/globalping-probe
    container_name: globalping-probe
    restart: always
    environment:
      - GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}
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
    
    log "Enhanced Docker Compose configuration created"
    return 0
}

# Start Globalping Probe
start_enhanced_globalping_probe() {
    local globalping_dir="$1"
    local compose_file="${globalping_dir}/docker-compose.yml"
    
    log "Starting enhanced Globalping Probe"
    
    cd "${globalping_dir}" || return 1
    
    log "Pulling latest Globalping Probe image..."
    if ! docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        enhanced_log "WARN" "Could not pull latest image, using local"
    fi
    
    if command -v docker-compose >/dev/null 2>&1; then
        if ! docker-compose -f "${compose_file}" up -d; then
            enhanced_log "ERROR" "Docker Compose start failed"
            return 1
        fi
    elif docker compose version >/dev/null 2>&1; then
        if ! docker compose -f "${compose_file}" up -d; then
            enhanced_log "ERROR" "Docker Compose start failed"
            return 1
        fi
    else
        enhanced_log "WARN" "Docker Compose not available, using docker run"
        
        docker stop globalping-probe >/dev/null 2>&1 || true
        docker rm globalping-probe >/dev/null 2>&1 || true
        
        docker volume create globalping-probe-data >/dev/null 2>&1 || true
        
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
            -e "GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
            -e "NODE_ENV=production" \
            -v globalping-probe-data:/home/node/.globalping \
            -v /etc/localtime:/etc/localtime:ro \
            globalping/globalping-probe; then
            enhanced_log "ERROR" "Container start with docker run failed"
            return 1
        fi
    fi
    
    log "Enhanced Globalping Probe successfully started"
    return 0
}

# Verify Probe
verify_enhanced_globalping_probe() {
    log "Verifying enhanced Globalping Probe"
    
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
        enhanced_log "ERROR" "Container did not start after ${max_wait} seconds"
        return 1
    fi
    
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' globalping-probe 2>/dev/null || echo "unknown")
    
    if [[ "${container_status}" != "running" ]]; then
        enhanced_log "ERROR" "Container status not 'running': ${container_status}"
        enhanced_log "ERROR" "Container Logs:"
        docker logs globalping-probe 2>&1 | tail -10 | while IFS= read -r line; do
            enhanced_log "ERROR" "  ${line}"
        done
        return 1
    fi
    
    local restart_policy
    restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' globalping-probe 2>/dev/null || echo "")
    
    if [[ "${restart_policy}" != "always" ]]; then
        enhanced_log "WARN" "Restart policy not 'always': ${restart_policy}"
    else
        log "Restart policy correctly set to 'always'"
    fi
    
    log "Waiting for Probe initialization..."
    sleep 20
    
    local connection_check
    connection_check=$(docker logs globalping-probe 2>&1 | grep -c "Connection to API established\|Connected from" || echo "0")
    
    if [[ ${connection_check} -gt 0 ]]; then
        log "Globalping Probe successfully connected to API"
    else
        enhanced_log "WARN" "No API connection detected in logs"
    fi
    
    log "Enhanced Globalping Probe successfully verified"
    return 0
}

create_enhanced_globalping_maintenance() {
    log "Creating enhanced Globalping maintenance"
    log "Maintenance is handled via weekly Auto-Update"
    return 0
}

# Weekly Automatic Maintenance
run_weekly_maintenance() {
    log "Starting weekly automatic maintenance"
    
    WEEKLY_MODE="true"
    
    log "Phase 1: Script Update"
    if ! perform_enhanced_auto_update; then
        enhanced_log "WARN" "Auto-Update failed"
    fi
    
    log "Phase 2: System Updates and Reboot Check"
    if ! check_critical_updates; then
        enhanced_log "WARN" "System Update Check failed"
    fi
    
    if [[ "${REBOOT_REQUIRED}" == "true" ]]; then
        log "Reboot scheduled, ending weekly maintenance"
        return 0
    fi
    
    log "Phase 3: Globalping Maintenance"
    if ! perform_enhanced_globalping_maintenance; then
        enhanced_log "WARN" "Globalping Maintenance failed"
    fi
    
    log "Phase 4: System Cleanup"
    if ! perform_enhanced_system_cleanup; then
        enhanced_log "WARN" "System Cleanup failed"
    fi
    
    log "Phase 5: Swap Check"
    if ! configure_smart_swap; then
        enhanced_log "WARN" "Swap Configuration failed"
    fi
    
    log "Phase 6: Log Rotation"
    perform_log_rotation
    
    log "Weekly automatic maintenance completed"
    return 0
}

perform_enhanced_globalping_maintenance() {
    log "Performing enhanced Globalping maintenance"
    
    if ! command -v docker >/dev/null 2>&1; then
        enhanced_log "WARN" "Docker not available for maintenance"
        return 1
    fi
    
    local container_name="globalping-probe"
    
    if ! docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"; then
        enhanced_log "WARN" "Globalping container not found"
        return 1
    fi
    
    local container_status
    container_status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    
    if [[ "${container_status}" != "running" ]]; then
        enhanced_log "WARN" "Globalping container not active: ${container_status}"
        
        if docker start "${container_name}" >/dev/null 2>&1; then
            log "Globalping container successfully started"
        else
            enhanced_log "ERROR" "Could not start Globalping container"
            enhanced_notify "error" "Container Issue" "Globalping container failed to start"
            return 1
        fi
    fi
    
    log "Checking for Globalping Image Updates"
    local current_image_id latest_image_id
    current_image_id=$(docker inspect -f '{{.Image}}' "${container_name}" 2>/dev/null || echo "")
    
    if docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        latest_image_id=$(docker images --format "{{.ID}}" ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null | head -1 || echo "")
        
        if [[ -n "${current_image_id}" && -n "${latest_image_id}" && "${current_image_id}" != "${latest_image_id}" ]]; then
            log "New Globalping Image available, updating container"
            
            if [[ -f "/opt/globalping/docker-compose.yml" ]]; then
                cd /opt/globalping || return 1
                if command -v docker-compose >/dev/null 2>&1; then
                    docker-compose pull && docker-compose up -d
                elif docker compose version >/dev/null 2>&1; then
                    docker compose pull && docker compose up -d
                fi
            else
                docker stop "${container_name}" >/dev/null 2>&1 || true
                docker rm "${container_name}" >/dev/null 2>&1 || true
                start_enhanced_globalping_probe "/opt/globalping"
            fi
            
            log "Globalping container successfully updated"
        else
            log "Globalping Image already up to date"
        fi
    else
        enhanced_log "WARN" "Could not check for image updates"
    fi
    
    local restart_policy
    restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "${container_name}" 2>/dev/null || echo "")
    
    if [[ "${restart_policy}" != "always" ]]; then
        enhanced_log "WARN" "Restart Policy incorrect, fixing..."
        update_globalping_container_restart_policy "${container_name}"
    fi
    
    local health_status
    health_status=$(docker inspect -f '{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
    
    if [[ "${health_status}" == "unhealthy" ]]; then
        enhanced_log "WARN" "Container unhealthy, restarting"
        docker restart "${container_name}" >/dev/null 2>&1
        sleep 30
        
        health_status=$(docker inspect -f '{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "none")
        if [[ "${health_status}" == "unhealthy" ]]; then
            enhanced_notify "error" "Container Health" "Globalping container remains 'unhealthy' after restart"
        fi
    fi
    
    local log_path
    log_path=$(docker inspect -f '{{.LogPath}}' "${container_name}" 2>/dev/null || echo "")
    
    if [[ -n "${log_path}" && -f "${log_path}" ]]; then
        local log_size_mb
        log_size_mb=$(stat -f%z "${log_path}" 2>/dev/null || stat -c%s "${log_path}" 2>/dev/null || echo "0")
        log_size_mb=$((log_size_mb / 1024 / 1024))
        
        if [[ ${log_size_mb} -gt ${MAX_LOG_SIZE_MB} ]]; then
            log "Container log too large (${log_size_mb}MB), truncating"
            tail -c $((MAX_LOG_SIZE_MB * 1024 * 1024)) "${log_path}" > "${log_path}.tmp" && mv "${log_path}.tmp" "${log_path}" 2>/dev/null || true
        fi
    fi
    
    log "Enhanced Globalping maintenance completed"
    return 0
}

# Enhanced System Cleanup
perform_enhanced_system_cleanup() {
    log "Starting enhanced system cleanup"
    
    local disk_available_kb disk_available_gb disk_usage_percent
    disk_available_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_usage_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%' || echo "100")
    
    local disk_available_mb=$((disk_available_kb / 1024))
    disk_available_gb=$((disk_available_mb / 1024))
    
    log "Current Disk Space: ${disk_available_gb}GB free (${disk_usage_percent}% used)"
    
    local cleanup_needed=false
    
    if [[ ${disk_available_mb} -lt 1536 ]]; then
        log "Cleanup triggered by low disk space: ${disk_available_mb}MB < 1536MB"
        cleanup_needed=true
    elif [[ ${disk_usage_percent} -gt 80 ]]; then
        log "Cleanup triggered by high usage: ${disk_usage_percent}%"
        cleanup_needed=true
    fi
    
    if [[ "${cleanup_needed}" == "false" && "${WEEKLY_MODE}" == "false" ]]; then
        log "No cleanup required"
        return 0
    fi
    
    log "Performing enhanced cleanup"
    
    if command -v docker >/dev/null 2>&1; then
        log "Cleaning Docker resources (protecting Globalping)"
        
        docker images --format "{{.Repository}}:{{.Tag}} {{.ID}}" | \
            grep -v globalping | awk '{print $2}' | \
            xargs -r docker rmi >/dev/null 2>&1 || true
        
        docker volume ls -q | grep -v globalping | \
            xargs -r docker volume rm >/dev/null 2>&1 || true
        
        docker system prune -f >/dev/null 2>&1 || true
    fi
    
    cleanup_package_cache_enhanced
    perform_log_rotation
    cleanup_temp_files_enhanced
    
    local disk_available_after_kb disk_available_after_mb disk_available_after_gb
    disk_available_after_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    disk_available_after_mb=$((disk_available_after_kb / 1024))
    disk_available_after_gb=$((disk_available_after_mb / 1024))
    
    local freed_space_mb=$((disk_available_after_mb - disk_available_mb))
    local freed_space_gb=$((freed_space_mb / 1024))
    
    log "Cleanup completed: ${freed_space_gb}GB freed (${disk_available_after_gb}GB available)"
    
    if [[ ${disk_available_after_mb} -lt 1536 ]]; then
        enhanced_notify "error" "Critical Disk Space" "After cleanup only ${disk_available_after_gb}GB free (Min: ${MIN_FREE_SPACE_GB}GB)"
    fi
    
    return 0
}

cleanup_package_cache_enhanced() {
    log "Cleaning package manager cache"
    
    if command -v apt-get >/dev/null 2>&1; then
        wait_for_apt_locks
        apt-get clean >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get autoclean >/dev/null 2>&1 || true
        wait_for_apt_locks
        apt-get autoremove -y >/dev/null 2>&1 || true
        
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

cleanup_temp_files_enhanced() {
    log "Cleaning temporary files"
    
    find /tmp -type f -atime +1 -delete 2>/dev/null || true
    find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
    find /var/crash -type f -mtime +1 -delete 2>/dev/null || true
    find / -xdev -name "core" -o -name "core.*" -type f -mtime +1 -delete 2>/dev/null || true
    find /home -path "*/.cache/*" -type f -atime +7 -delete 2>/dev/null || true
    find /root -path "*/.cache/*" -type f -atime +7 -delete 2>/dev/null || true
}

perform_log_rotation() {
    log "Performing centralized log rotation"
    
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size="${MAX_LOG_SIZE_MB}M" --vacuum-time=7d >/dev/null 2>&1 || true
    fi
    
    find /var/log -type f -size +${MAX_LOG_SIZE_MB}M -not -path "*/globalping*" | while IFS= read -r log_file; do
        if [[ -n "${log_file}" ]]; then
            tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}" 2>/dev/null || true
            log "Log rotated: ${log_file}"
        fi
    done
    
    find /var/log -name "*.1" -o -name "*.2" -o -name "*.old" -o -name "*.gz" -mtime +7 -delete 2>/dev/null || true
}

perform_emergency_cleanup() {
    log "Performing EMERGENCY cleanup"
    
    systemctl stop docker >/dev/null 2>&1 || true
    
    if command -v docker >/dev/null 2>&1; then
        docker ps -q | grep -v globalping | xargs -r docker stop >/dev/null 2>&1 || true
        docker container prune -f >/dev/null 2>&1 || true
        docker image prune -a -f >/dev/null 2>&1 || true
        docker volume prune -f >/dev/null 2>&1 || true
        docker network prune -f >/dev/null 2>&1 || true
        docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi
    
    cleanup_package_cache_enhanced
    
    find /tmp -type f -size +10M -delete 2>/dev/null || true
    find /var/tmp -type f -size +10M -delete 2>/dev/null || true
    rm -rf /var/cache/*/* 2>/dev/null || true
    rm -rf /root/.cache/* 2>/dev/null || true
    
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-size=10M --vacuum-time=1d >/dev/null 2>&1 || true
    fi
    
    systemctl start docker >/dev/null 2>&1 || true
    
    log "Emergency cleanup completed"
    return 0
}

setup_enhanced_auto_update() {
    log "Setting up enhanced Auto-Update"
    
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
        log "Downloading script for Auto-Update..."
        current_script="${TMP_DIR}/downloaded_install.sh"
        if ! curl -s -o "${current_script}" "${SCRIPT_URL}"; then
            enhanced_log "ERROR" "Could not download script"
            return 1
        fi
        chmod +x "${current_script}"
    fi
    
    mkdir -p "$(dirname "${SCRIPT_PATH}")" || return 1
    if [[ "${current_script}" != "${SCRIPT_PATH}" ]]; then
        cp "${current_script}" "${SCRIPT_PATH}" || return 1
        chmod +x "${SCRIPT_PATH}"
        log "Script installed to ${SCRIPT_PATH}"
    fi
    
    remove_old_enhanced_schedulers
    setup_enhanced_systemd_timers
    
    log "Enhanced Auto-Update setup completed"
    return 0
}

setup_enhanced_systemd_timers() {
    if ! check_systemd_available; then
        enhanced_log "WARN" "systemd not available, using crontab"
        setup_enhanced_crontab
        return $?
    fi
    
    log "Setting up enhanced systemd timers"
    
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
    
    local random_delay=$((RANDOM % 43200))  # 0-720 min
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
    
    systemctl daemon-reload >/dev/null 2>&1 || return 1
    if systemctl enable globalping-update.timer >/dev/null 2>&1 && \
       systemctl start globalping-update.timer >/dev/null 2>&1; then
        log "Systemd timer successfully set: Sunday 03:00 (+${random_delay}s)"
        return 0
    else
        enhanced_log "ERROR" "Could not setup systemd timer"
        return 1
    fi
}

setup_enhanced_crontab() {
    if ! check_crontab_available; then
        enhanced_log "ERROR" "Neither systemd nor crontab available"
        return 1
    fi
    
    log "Setting up enhanced crontab"
    
    local random_hour=$((3 + RANDOM % 13))
    local random_minute=$((RANDOM % 60))
    
    local crontab_entry="${random_minute} ${random_hour} * * 0 ${SCRIPT_PATH} --auto-weekly >/dev/null 2>&1"
    
    local current_crontab="${TMP_DIR}/current_crontab"
    local new_crontab="${TMP_DIR}/new_crontab"
    
    crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
    grep -v "install_globalping.*--auto-weekly\|globalping.*--auto-update" "${current_crontab}" > "${new_crontab}"
    echo "${crontab_entry}" >> "${new_crontab}"
    
    if crontab "${new_crontab}" 2>/dev/null; then
        log "Crontab successfully set: Sunday ${random_hour}:${random_minute}"
        return 0
    else
        enhanced_log "ERROR" "Could not update crontab"
        return 1
    fi
}

remove_old_enhanced_schedulers() {
    log "Removing old Auto-Update schedulers"
    
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
    
    if check_crontab_available; then
        local current_crontab="${TMP_DIR}/current_crontab"
        local new_crontab="${TMP_DIR}/new_crontab"
        
        crontab -l > "${current_crontab}" 2>/dev/null || echo "" > "${current_crontab}"
        grep -v "globalping-maintenance\|install_globalping" "${current_crontab}" > "${new_crontab}"
        
        if ! cmp -s "${current_crontab}" "${new_crontab}"; then
            crontab "${new_crontab}" 2>/dev/null || true
        fi
    fi
    
    rm -f "/usr/local/bin/globalping-maintenance" 2>/dev/null || true
    rm -f "/etc/cron.weekly/globalping-update" 2>/dev/null || true
}

perform_enhanced_auto_update() {
    log "Performing enhanced automatic update"
    
    local lock_file="/tmp/globalping_auto_update.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            log "Auto-Update already active (PID: ${lock_pid})"
            return 0
        else
            rm -f "${lock_file}"
        fi
    fi
    
    echo "$$" > "${lock_file}"
    trap 'rm -f "${lock_file}"' EXIT
    
    local temp_script="${TMP_DIR}/update_script.sh"
    local download_attempts=0
    local max_attempts=3
    
    while [[ ${download_attempts} -lt ${max_attempts} ]]; do
        ((download_attempts++))
        
        if curl -sL --connect-timeout 10 \
           -o "${temp_script}" "${SCRIPT_URL}"; then
            log "Download successful (Attempt ${download_attempts})"
            break
        else
            enhanced_log "WARN" "Download failed (Attempt ${download_attempts}/${max_attempts})"
            if [[ ${download_attempts} -eq ${max_attempts} ]]; then
                enhanced_notify "error" "Auto-Update" "Could not download current version after ${max_attempts} attempts"
                return 1
            fi
            sleep 10
        fi
    done
    
    if [[ ! -f "${temp_script}" || ! -s "${temp_script}" ]]; then
        enhanced_notify "error" "Auto-Update" "Downloaded file is empty or missing"
        return 1
    fi
    
    if ! head -1 "${temp_script}" | grep -q "^#!/bin/bash"; then
        enhanced_notify "error" "Auto-Update" "Downloaded file is not a valid bash script"
        return 1
    fi
    
    # Check for End Marker (Integrity Check)
    if ! tail -n 1 "${temp_script}" | grep -q "END OF SCRIPT"; then
         enhanced_notify "error" "Auto-Update" "Download incomplete (End marker missing)"
         return 1
    fi
    
    if ! timeout 10 bash -n "${temp_script}"; then
        enhanced_notify "error" "Auto-Update" "Syntax error in downloaded script"
        return 1
    fi
    
    local current_version new_version
    current_version=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    new_version=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "unknown")
    
    log "Version Check: ${current_version} -> ${new_version}"
    
    if [[ "${current_version}" == "${new_version}" && "${new_version}" != "unknown" ]]; then
        log "Already running latest version"
        return 0
    fi
    
    local backup_path="${SCRIPT_PATH}.backup.$(date +%s)"
    if [[ -f "${SCRIPT_PATH}" ]]; then
        cp "${SCRIPT_PATH}" "${backup_path}" || {
            enhanced_log "WARN" "Could not create backup"
        }
    fi
    
    local config_backup="${TMP_DIR}/config_backup"
    if [[ -f "${SCRIPT_PATH}" ]]; then
        grep -E "^(ADOPTION_TOKEN|TELEGRAM_TOKEN|TELEGRAM_CHAT|UBUNTU_PRO_TOKEN|SSH_KEY)=" "${SCRIPT_PATH}" > "${config_backup}" 2>/dev/null || true
    fi
    
    if ! cp "${temp_script}" "${SCRIPT_PATH}"; then
        enhanced_notify "error" "Auto-Update" "Could not update script file"
        return 1
    fi
    
    chmod +x "${SCRIPT_PATH}"
    
    if [[ -s "${config_backup}" ]]; then
        while IFS= read -r var_line; do
            if [[ -n "${var_line}" ]]; then
                local var_name
                var_name=$(echo "${var_line}" | cut -d'=' -f1)
                sed -i "s/^${var_name}=.*/${var_line}/" "${SCRIPT_PATH}" 2>/dev/null || true
            fi
        done < "${config_backup}"
    fi
    
    log "Script successfully updated to version ${new_version}"
    rm -f "${temp_script}" "${config_backup}"
    
    return 0
}

# Install Docker
install_docker() {
    enhanced_log "INFO" "Installing Docker"
    
    if command -v docker >/dev/null 2>&1; then
        if docker --version >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
            enhanced_log "INFO" "Docker is already installed and active"
            return 0
        else
            enhanced_log "INFO" "Docker is installed but not functional - repairing"
        fi
    fi
    
    local distro_id=""
    local distro_version=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro_id="${ID,,}"
        distro_version="${VERSION_ID}"
    else
        enhanced_log "ERROR" "Cannot determine distribution"
        return 1
    fi
    
    enhanced_log "INFO" "Detected Distribution: ${distro_id} ${distro_version}"
    
    case "${distro_id}" in
        ubuntu|debian)
            install_docker_debian_ubuntu "${distro_id}"
            ;;
        rhel|centos|rocky|almalinux|fedora)
            install_docker_rhel_family "${distro_id}"
            ;;
        *)
            enhanced_log "INFO" "Unknown distribution, attempting universal installation"
            install_docker_universal
            ;;
    esac
    
    if ! verify_docker_installation; then
        enhanced_log "ERROR" "Docker installation failed"
        return 1
    fi
    
    enhanced_log "INFO" "Docker successfully installed and configured"
    return 0
}

install_docker_debian_ubuntu() {
    local distro="$1"
    
    enhanced_log "INFO" "Installing Docker for ${distro}"
    
    apt-get remove -y docker docker-engine docker.io containerd runc >/dev/null 2>&1 || true
    
    wait_for_apt_locks
    apt-get update >/dev/null 2>&1 || {
        enhanced_log "WARN" "apt-get update failed"
    }
    
    wait_for_apt_locks
    apt-get install -y --fix-broken --fix-missing \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Could not install dependencies"
        return 1
    }
    
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "${keyring_dir}"
    
    if ! curl -fsSL "https://download.docker.com/linux/${distro}/gpg" | \
         gpg --dearmor -o "${keyring_dir}/docker.gpg" 2>/dev/null; then
        enhanced_log "ERROR" "Could not add Docker GPG key"
        return 1
    fi
    
    chmod a+r "${keyring_dir}/docker.gpg"
    
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    local codename
    codename=$(lsb_release -cs 2>/dev/null || echo "stable")
    
    echo "deb [arch=${arch} signed-by=${keyring_dir}/docker.gpg] https://download.docker.com/linux/${distro} ${codename} stable" | \
        tee /etc/apt/sources.list.d/docker.list >/dev/null
    
    wait_for_apt_locks
    apt-get update >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Could not update Docker repository"
        return 1
    }
    
    wait_for_apt_locks
    apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin >/dev/null 2>&1 || {
        enhanced_log "ERROR" "Docker installation failed"
        return 1
    }
    
    return 0
}

install_docker_rhel_family() {
    local distro="$1"
    
    enhanced_log "INFO" "Installing Docker for ${distro}"
    
    if command -v dnf >/dev/null 2>&1; then
        dnf remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine podman runc >/dev/null 2>&1 || true
        
        dnf install -y dnf-plugins-core >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Could not install DNF plugins"
            return 1
        }
        
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        dnf config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Could not add Docker repo"
            return 1
        }
        
        dnf install -y --skip-broken docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Docker installation failed"
            return 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum remove -y docker docker-client docker-client-latest docker-common \
                     docker-latest docker-latest-logrotate docker-logrotate \
                     docker-engine >/dev/null 2>&1 || true
        
        yum install -y yum-utils >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Could not install YUM utils"
            return 1
        }
        
        local repo_distro="${distro}"
        if [[ "${distro}" == "rocky" || "${distro}" == "almalinux" ]]; then
            repo_distro="centos"
        fi
        
        yum-config-manager --add-repo \
            "https://download.docker.com/linux/${repo_distro}/docker-ce.repo" >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Could not add Docker repo"
            return 1
        }
        
        yum install -y docker-ce docker-ce-cli containerd.io \
                      docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || {
            enhanced_log "ERROR" "Docker installation failed"
            return 1
        }
    else
        enhanced_log "ERROR" "No supported package manager found"
        return 1
    fi
    
    return 0
}

install_docker_universal() {
    enhanced_log "INFO" "Attempting universal Docker installation"
    
    local install_script="${TMP_DIR}/get-docker.sh"
    
    if ! curl -fsSL https://get.docker.com -o "${install_script}"; then
        enhanced_log "ERROR" "Could not download Docker install script"
        return 1
    fi
    
    if ! grep -q "#!/bin/sh" "${install_script}"; then
        enhanced_log "ERROR" "Docker install script is invalid"
        return 1
    fi
    
    chmod +x "${install_script}"
    
    if ! "${install_script}" >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker install script failed"
        return 1
    fi
    
    rm -f "${install_script}"
    return 0
}

verify_docker_installation() {
    enhanced_log "INFO" "Verifying Docker installation"
    
    if ! command -v docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker command not available"
        return 1
    fi
    
    if ! systemctl enable docker >/dev/null 2>&1; then
        enhanced_log "WARN" "Could not enable Docker service"
    fi
    
    if ! systemctl start docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Could not start Docker service"
        return 1
    fi
    
    local wait_count=0
    while [[ ${wait_count} -lt 30 ]]; do
        if systemctl is-active docker >/dev/null 2>&1; then
            break
        fi
        sleep 2
        ((wait_count++))
    done
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker service is not active"
        return 1
    fi
    
    if ! docker version >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker is not functional"
        return 1
    fi
    
    enhanced_log "INFO" "Docker installation verified successfully"
    return 0
}

install_docker_compose() {
    enhanced_log "INFO" "Checking Docker Compose"
    
    if docker compose version >/dev/null 2>&1; then
        enhanced_log "INFO" "Docker Compose Plugin already available"
        return 0
    fi
    
    if command -v docker-compose >/dev/null 2>&1; then
        enhanced_log "INFO" "Docker Compose (standalone) already installed"
        return 0
    fi
    
    enhanced_log "INFO" "Installing Docker Compose"
    
    local compose_version
    compose_version=$(curl -s "https://api.github.com/repos/docker/compose/releases/latest" | \
                     grep '"tag_name":' | cut -d'"' -f4 2>/dev/null || echo "")
    
    if [[ -z "${compose_version}" ]]; then
        compose_version="v2.21.0"
        enhanced_log "INFO" "Using fallback version: ${compose_version}"
    else
        enhanced_log "INFO" "Latest version found: ${compose_version}"
    fi
    
    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        armv7l) arch="armv7" ;;
        *) 
            enhanced_log "ERROR" "Unsupported architecture: ${arch}"
            return 1
            ;;
    esac
    
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-${os}-${arch}"
    local compose_path="/usr/local/bin/docker-compose"
    
    if ! curl -L "${compose_url}" -o "${compose_path}"; then
        enhanced_log "ERROR" "Could not download Docker Compose"
        return 1
    fi
    
    chmod +x "${compose_path}"
    
    if ! "${compose_path}" --version >/dev/null 2>&1; then
        enhanced_log "ERROR" "Docker Compose not functional"
        rm -f "${compose_path}"
        return 1
    fi
    
    enhanced_log "INFO" "Docker Compose successfully installed"
    return 0
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        enhanced_log "ERROR" "This script requires root privileges!"
        return 1
    fi
    enhanced_log "INFO" "Root check passed"
    return 0
}

check_internet() {
    enhanced_log "INFO" "Checking Internet connection..."
    
    local targets=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    local http_targets=("https://www.google.com" "https://www.cloudflare.com" "https://httpbin.org/ip")
    local connected=false
    
    for target in "${targets[@]}"; do
        if ping -c 1 -W 3 "${target}" >/dev/null 2>&1; then
            connected=true
            enhanced_log "INFO" "ICMP connection to ${target} successful"
            break
        fi
    done
    
    if [[ "${connected}" == "false" ]]; then
        for target in "${http_targets[@]}"; do
            if curl -s --connect-timeout 5 --max-time 10 "${target}" >/dev/null 2>&1; then
                connected=true
                enhanced_log "INFO" "HTTP connection to ${target} successful"
                break
            fi
        done
    fi
    
    if [[ "${connected}" == "false" ]]; then
        enhanced_log "ERROR" "No Internet connection available"
        enhanced_notify "error" "Network Issue" "No Internet connection available"
        return 1
    fi
    
    enhanced_log "INFO" "Internet connection verified"
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
        if crontab -l >/dev/null 2>&1 || [[ $? -eq 1 ]]; then
            return 0
        fi
    fi
    return 1
}

create_temp_dir() {
    [[ -d "${TMP_DIR}" ]] && rm -rf "${TMP_DIR}"
    
    mkdir -p "${TMP_DIR}" || {
        enhanced_log "WARN" "Could not create temp dir, using /tmp"
        TMP_DIR="/tmp/globalping_install_$$"
        mkdir -p "${TMP_DIR}" || {
            enhanced_log "ERROR" "Could not create any temp directory"
            return 1
        }
    }
    
    chmod 700 "${TMP_DIR}"
    enhanced_log "INFO" "Temp dir created: ${TMP_DIR}"
    
    trap 'rm -rf "${TMP_DIR}" 2>/dev/null || true' EXIT
    
    return 0
}

# Analysis Functions

analyze_network_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing network basics..."
    
    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "unknown" ]]; then
        echo "Public IP: ${PUBLIC_IP}"
        info_ref+=("Public IP: ${PUBLIC_IP}")
    else
        issues_ref+=("No public IP address determined")
    fi
    
    if ! nslookup google.com >/dev/null 2>&1; then
        warnings_ref+=("DNS resolution failed")
    else
        info_ref+=("DNS resolution working")
    fi
    
    local gateway
    gateway=$(ip route | grep default | awk '{print $3}' | head -1 2>/dev/null || echo "")
    if [[ -n "${gateway}" ]]; then
        if ping -c 1 -W 3 "${gateway}" >/dev/null 2>&1; then
            info_ref+=("Gateway reachable: ${gateway}")
        else
            warnings_ref+=("Gateway not reachable: ${gateway}")
        fi
    fi
}

analyze_globalping_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing Globalping status..."
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        warnings_ref+=("No Adoption Token configured")
        return 0
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        issues_ref+=("Docker not available for Globalping")
        return 0
    fi
    
    local container_name="globalping-probe"
    if docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        local status
        status=$(docker inspect -f '{{.State.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
        if [[ "${status}" == "running" ]]; then
            info_ref+=("Globalping container active")
            
            local restart_policy
            restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "${container_name}" 2>/dev/null || echo "")
            if [[ "${restart_policy}" == "always" ]]; then
                info_ref+=("Restart policy correct: always")
            else
                warnings_ref+=("Restart policy not optimal: ${restart_policy}")
            fi
        else
            warnings_ref+=("Globalping container not active: ${status}")
        fi
    else
        warnings_ref+=("Globalping container not found")
    fi
}

analyze_autoupdate_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing Auto-Update system..."
    
    if check_systemd_available; then
        if systemctl is-enabled globalping-update.timer >/dev/null 2>&1; then
            if systemctl is-active globalping-update.timer >/dev/null 2>&1; then
                info_ref+=("Systemd timer active and scheduled")
                
                local next_run
                next_run=$(systemctl list-timers globalping-update.timer --no-pager 2>/dev/null | grep globalping | awk '{print $1" "$2}' || echo "unknown")
                if [[ "${next_run}" != "unknown" ]]; then
                    info_ref+=("Next maintenance: ${next_run}")
                fi
            else
                warnings_ref+=("Systemd timer inactive")
            fi
        else
            warnings_ref+=("Systemd timer not enabled")
        fi
    else
        if check_crontab_available; then
            if crontab -l 2>/dev/null | grep -q "install_globalping.*--auto-weekly"; then
                info_ref+=("Crontab entry found")
            else
                warnings_ref+=("No Auto-Update crontab found")
            fi
        else
            issues_ref+=("Neither systemd nor crontab available")
        fi
    fi
    
    if [[ -f "${SCRIPT_PATH}" && -x "${SCRIPT_PATH}" ]]; then
        info_ref+=("Auto-Update script installed")
    else
        warnings_ref+=("Auto-Update script missing or not executable")
    fi
}

analyze_security_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing security configuration..."
    
    if [[ -f "${SSH_DIR}/authorized_keys" ]]; then
        local key_count
        key_count=$(wc -l < "${SSH_DIR}/authorized_keys" 2>/dev/null || echo "0")
        if [[ ${key_count} -gt 0 ]]; then
            info_ref+=("SSH Key configured (${key_count})")
        else
            warnings_ref+=("SSH authorized_keys empty")
        fi
    else
        warnings_ref+=("No SSH Keys configured")
    fi
    
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
        if [[ "${ufw_status}" == "active" ]]; then
            info_ref+=("UFW Firewall active")
        else
            warnings_ref+=("UFW Firewall not active")
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active firewalld >/dev/null 2>&1; then
            info_ref+=("Firewalld active")
        else
            warnings_ref+=("Firewalld not active")
        fi
    fi
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        local permit_root
        permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
        if [[ "${permit_root}" == "no" ]]; then
            info_ref+=("Root SSH disabled")
        else
            warnings_ref+=("Root SSH allowed: ${permit_root}")
        fi
    fi
    
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        info_ref+=("Automatic security updates configured")
    elif [[ -f /etc/dnf/automatic.conf ]]; then
        info_ref+=("DNF automatic updates configured")
    else
        warnings_ref+=("No automatic security updates configured")
    fi
}

run_enhanced_diagnostics() {
    log "Running enhanced system diagnostics"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== ENHANCED SYSTEM DIAGNOSTICS ==="
    echo "Time: $(date)"
    echo "Hostname: $(hostname 2>/dev/null || echo 'unknown')"
    echo "Script Version: ${SCRIPT_VERSION}"
    echo "==================================="
    
    echo -e "\nAnalyzing Hardware..."
    analyze_hardware_enhanced issues warnings info_items
    
    echo -e "\nAnalyzing Memory (Extended)..."
    analyze_memory_enhanced issues warnings info_items
    
    echo -e "\nAnalyzing Network..."
    analyze_network_enhanced issues warnings info_items
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "\nAnalyzing Docker System (Extended)..."
        analyze_docker_enhanced issues warnings info_items
    fi
    
    echo -e "\nAnalyzing Globalping Probe..."
    analyze_globalping_enhanced issues warnings info_items
    
    echo -e "\nAnalyzing Auto-Update System..."
    analyze_autoupdate_enhanced issues warnings info_items
    
    echo -e "\nAnalyzing Security Configuration..."
    analyze_security_enhanced issues warnings info_items
    
    echo -e "\nAnalyzing System Performance..."
    analyze_performance_enhanced issues warnings info_items
    
    echo -e "\n=== DIAGNOSTIC RESULTS ==="
    echo "Critical Issues: ${#issues[@]}"
    echo "Warnings: ${#warnings[@]}"
    echo "Information: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 CRITICAL ISSUES:"
        printf ' - %s\n' "${issues[@]}"
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo -e "\n🟡 WARNINGS:"
        printf ' - %s\n' "${warnings[@]}"
    fi
    
    if [[ ${#info_items[@]} -gt 0 ]]; then
        echo -e "\n🔵 SYSTEM INFORMATION:"
        printf ' - %s\n' "${info_items[@]}"
    fi
    
    echo "=============================="
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        enhanced_notify "error" "Diagnostic Issues" "$(printf '%s\n' "${issues[@]}" | head -5)"
        return 1
    fi
    
    return 0
}

analyze_hardware_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing Hardware..."
    
    local cpu_cores cpu_model
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unknown")
    echo "CPU: ${cpu_model} (${cpu_cores} Cores)"
    info_ref+=("CPU: ${cpu_cores} Cores")
    
    local arch
    arch=$(uname -m 2>/dev/null || echo "unknown")
    echo "Architecture: ${arch}"
    
    local virt_type="Bare Metal"
    if systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "Virtualized")
    fi
    echo "Virtualization: ${virt_type}"
    info_ref+=("Virtualization: ${virt_type}")
}

analyze_memory_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing Memory (Extended)..."
    
    local mem_total_kb mem_available_kb mem_total_mb mem_available_mb
    mem_total_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    mem_available_kb=$(grep "MemAvailable" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    
    if [[ "${mem_total_kb}" =~ ^[0-9]+$ ]]; then
        mem_total_mb=$((mem_total_kb / 1024))
    else
        mem_total_mb=0
    fi
    
    if [[ "${mem_available_kb}" =~ ^[0-9]+$ ]]; then
        mem_available_mb=$((mem_available_kb / 1024))
    else
        mem_available_mb=0
    fi
    
    echo "RAM: ${mem_available_mb}MB free of ${mem_total_mb}MB"
    
    if [[ ${mem_total_mb} -lt ${MIN_RAM_MB} ]] 2>/dev/null; then
        issues_ref+=("Insufficient RAM: ${mem_total_mb}MB (Minimum: ${MIN_RAM_MB}MB)")
    elif [[ ${mem_available_mb} -lt 100 ]] 2>/dev/null; then
        warnings_ref+=("Low free RAM: ${mem_available_mb}MB")
    fi
    
    local swap_total_kb swap_used_kb swap_total_mb swap_used_mb
    swap_total_kb=$(grep "SwapTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    swap_used_kb=$(grep "SwapUsed" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    
    if [[ "${swap_total_kb}" =~ ^[0-9]+$ ]]; then
        swap_total_mb=$((swap_total_kb / 1024))
    else
        swap_total_mb=0
    fi
    
    if [[ "${swap_used_kb}" =~ ^[0-9]+$ ]]; then
        swap_used_mb=$((swap_used_kb / 1024))
    else
        swap_used_mb=0
    fi
    
    if [[ ${swap_total_mb} -eq 0 ]] 2>/dev/null; then
        echo "Swap: Not configured"
        local combined_mb=$((mem_total_mb + swap_total_mb))
        local min_combined_mb=$((SWAP_MIN_TOTAL_GB * 1024))
        if [[ ${combined_mb} -lt ${min_combined_mb} ]] 2>/dev/null; then
            warnings_ref+=("RAM+Swap under ${SWAP_MIN_TOTAL_GB}GB: ${combined_mb}MB")
        fi
    else
        echo "Swap: ${swap_used_mb}MB used of ${swap_total_mb}MB"
        local swap_usage_percent=0
        if [[ ${swap_total_mb} -gt 0 ]] 2>/dev/null; then
            swap_usage_percent=$((swap_used_mb * 100 / swap_total_mb))
        fi
        if [[ ${swap_usage_percent} -gt 80 ]] 2>/dev/null; then
            warnings_ref+=("High Swap usage: ${swap_used_mb}MB/${swap_total_mb}MB")
        fi
    fi
    
    info_ref+=("Memory: ${mem_available_mb}MB RAM free")
}

analyze_docker_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing Docker System (Extended)..."
    
    if ! systemctl is-active docker >/dev/null 2>&1; then
        issues_ref+=("Docker service not active")
        return 1
    fi
    
    local docker_version
    docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "unknown")
    echo "Docker Version: ${docker_version}"
    
    local total_containers running_containers
    total_containers=$(docker ps -a -q 2>/dev/null | wc -l || echo "0")
    running_containers=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    
    total_containers=$(echo "${total_containers}" | tr -d '\n\r' | head -c 10)
    if ! [[ "${total_containers}" =~ ^[0-9]+$ ]]; then total_containers=0; fi
    
    running_containers=$(echo "${running_containers}" | tr -d '\n\r' | head -c 10)
    if ! [[ "${running_containers}" =~ ^[0-9]+$ ]]; then running_containers=0; fi
    
    echo "Containers: ${running_containers}/${total_containers} active"
    
    local unhealthy_count
    unhealthy_count=$(docker ps --filter health=unhealthy -q 2>/dev/null | wc -l || echo "0")
    unhealthy_count=$(echo "${unhealthy_count}" | tr -d '\n\r' | head -c 10)
    if ! [[ "${unhealthy_count}" =~ ^[0-9]+$ ]]; then unhealthy_count=0; fi
    
    if [[ ${unhealthy_count} -gt 0 ]] 2>/dev/null; then
        warnings_ref+=("${unhealthy_count} containers with status 'unhealthy'")
    fi
    
    info_ref+=("Docker: ${running_containers} containers active")
}

analyze_performance_enhanced() {
    local -n issues_ref=$1
    local -n warnings_ref=$2
    local -n info_ref=$3
    
    echo "Analyzing System Performance..."
    
    if [[ -r /proc/loadavg ]]; then
        local load_1min load_5min
        read -r load_1min load_5min _ _ _ < /proc/loadavg
        echo "Load Average: ${load_1min} (1min), ${load_5min} (5min)"
        
        local cpu_cores
        cpu_cores=$(nproc 2>/dev/null || echo "1")
        cpu_cores=$(echo "${cpu_cores}" | tr -d '\n\r' | head -c 10)
        if ! [[ "${cpu_cores}" =~ ^[0-9]+$ ]]; then cpu_cores=1; fi
        
        if command -v bc >/dev/null 2>&1; then
            local load_threshold
            load_threshold=$(echo "${cpu_cores} * 2" | bc 2>/dev/null || echo "2")
            if (( $(echo "${load_1min} > ${load_threshold}" | bc -l 2>/dev/null || echo "0") )); then
                warnings_ref+=("High CPU Load: ${load_1min} (Cores: ${cpu_cores})")
            fi
        else
            local load_int
            load_int=$(echo "${load_1min}" | cut -d'.' -f1)
            if [[ "${load_int}" =~ ^[0-9]+$ ]] && [[ ${load_int} -gt $((cpu_cores * 2)) ]] 2>/dev/null; then
                warnings_ref+=("High CPU Load: ${load_1min} (Cores: ${cpu_cores})")
            fi
        fi
    fi
    
    local iowait
    iowait=$(top -bn1 | grep "Cpu(s)" | awk '{print $10}' | tr -d '%' 2>/dev/null || echo "0")
    echo "I/O Wait: ${iowait}%"
    
    if [[ "${iowait}" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        if command -v bc >/dev/null 2>&1; then
            if (( $(echo "${iowait} > 20" | bc -l 2>/dev/null || echo "0") )); then
                warnings_ref+=("High I/O Wait: ${iowait}%")
            fi
        else
            local iowait_int
            iowait_int=$(echo "${iowait}" | cut -d'.' -f1)
            if [[ "${iowait_int}" =~ ^[0-9]+$ ]] && [[ ${iowait_int} -gt 20 ]] 2>/dev/null; then
                warnings_ref+=("High I/O Wait: ${iowait}%")
            fi
        fi
    fi
    
    local open_files
    open_files=$(lsof 2>/dev/null | wc -l || echo "0")
    open_files=$(echo "${open_files}" | tr -d '\n\r' | head -c 10)
    if ! [[ "${open_files}" =~ ^[0-9]+$ ]]; then open_files=0; fi
    echo "Open Files: ${open_files}"
    
    info_ref+=("Performance: Load ${load_1min}, I/O Wait ${iowait}%")
}

show_enhanced_help() {
    cat << 'HELP_EOF'
==========================================
Globalping Server Setup Script (Enhanced)
==========================================

DESCRIPTION:
    Enhanced automation for Globalping Probe Servers with intelligent
    maintenance, rich notifications, and robust error handling.

USAGE:
    ./install.sh [OPTIONS]
    
    Script must be run with root privileges.

MAIN OPTIONS:
    -h, --help                      Show this help
    --adoption-token TOKEN          Globalping Adoption Token (Required)
    --telegram-token TOKEN          Telegram Bot Token for notifications
    --telegram-chat ID              Telegram Chat ID for notifications
    --ubuntu-token TOKEN            Ubuntu Pro Token (Ubuntu only)
    --ssh-key "KEY"                 SSH Public Key for secure access

MAINTENANCE OPTIONS:
    --auto-weekly                   Weekly automatic maintenance (internal)
    --cleanup                       Enhanced system cleanup
    --emergency-cleanup             Aggressive emergency cleanup  
    --diagnose                      Full system diagnostics
    --network-diagnose              Detailed network diagnostics
    --test-telegram                 Test Telegram configuration

ADVANCED OPTIONS:
    -d, --docker                    Install Docker only
    -l, --log FILE                  Alternative log file
    --debug                         Debug mode with verbose logging
    --force                         Skip safety checks
    --no-reboot                     Prevent automatic reboots

TELEGRAM CONFIGURATION:
    1. Create a bot: @BotFather
    2. Get Token and Chat ID
    3. Test with: ./install.sh --test-telegram --telegram-token "TOKEN" --telegram-chat "CHAT_ID"

NEW FEATURES:
    ✓ Phased Updates Awareness (prevents unnecessary reboots)
    ✓ Enhanced Update Cleanup (apt clean/autoremove for all OS)
    ✓ Improved Telegram Error Messages with IP/Provider/ASN links
    ✓ Intelligent Swap Config (RAM + Swap ≥ 1GB, Btrfs safe)
    ✓ Automatic Reboots only for REAL critical updates
    ✓ restart=always for Globalping container
    ✓ Daily Log Rotation (max 50MB)
    ✓ Weekly Automatic Maintenance

SYSTEM REQUIREMENTS:
    - Linux (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora)
    - Minimum 256MB RAM
    - Minimum 1.5GB free disk space
    - Root privileges
    - Internet connection

EXAMPLES:
    # Full Installation
    ./install.sh --adoption-token "token" \
                  --telegram-token "bot-token" \
                  --telegram-chat "chat-id"

    # Test Telegram Config
    ./install.sh --test-telegram --telegram-token "123:ABC" --telegram-chat "456"

    # Diagnostics Only
    ./install.sh --diagnose

    # System Cleanup
    ./install.sh --cleanup

HELP_EOF
    exit 0
}

process_enhanced_args() {
    local install_docker_only="false"
    local run_diagnostics_only="false"
    local run_network_diagnostics_only="false"
    local auto_weekly_mode="false"
    local cleanup_mode="false"
    local emergency_cleanup_mode="false"
    local force_mode="false"
    local no_reboot="false"
    local test_telegram_mode="false"
    
    if [[ $# -eq 0 ]]; then
        show_enhanced_help
    fi
    
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
                    enhanced_log "ERROR" "--log requires a filename"
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
                    enhanced_log "ERROR" "--adoption-token requires a value"
                    exit 1
                fi
                ;;
            --telegram-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-token requires a value"
                    exit 1
                fi
                ;;
            --telegram-chat)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    TELEGRAM_CHAT="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--telegram-chat requires a value"
                    exit 1
                fi
                ;;
            --ubuntu-token)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    UBUNTU_PRO_TOKEN="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ubuntu-token requires a value"
                    exit 1
                fi
                ;;
            --ssh-key)
                if [[ -n "${2:-}" && "${2}" != --* ]]; then
                    SSH_KEY="$2"
                    shift 2
                else
                    enhanced_log "ERROR" "--ssh-key requires a value"
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
                enhanced_log "ERROR" "Unknown option: $1"
                echo "Use --help for assistance" >&2
                exit 1
                ;;
            *)
                enhanced_log "ERROR" "Unexpected argument: $1"
                echo "Use --help for assistance" >&2
                exit 1
                ;;
        esac
    done
    
    if [[ "${test_telegram_mode}" == "true" ]]; then
        execute_telegram_test_mode
        exit $?
    fi
    
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

execute_telegram_test_mode() {
    echo "=== TELEGRAM CONFIGURATION TEST ==="
    echo "Testing Telegram Token and Chat ID..."
    echo "==================================="
    
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then
        echo "ERROR: --telegram-token and --telegram-chat are required"
        echo "Example: ./install.sh --test-telegram --telegram-token \"123:ABC\" --telegram-chat \"456\""
        return 1
    fi
    
    get_enhanced_system_info
    
    if test_telegram_config; then
        echo "✅ Telegram configuration verified!"
        echo "Bot can send messages to Chat ${TELEGRAM_CHAT}."
        return 0
    else
        echo "❌ Telegram configuration failed!"
        echo "Check Token and Chat ID."
        return 1
    fi
}

execute_enhanced_special_modes() {
    local install_docker_only="$1"
    local run_diagnostics_only="$2"
    local run_network_diagnostics_only="$3"
    local auto_weekly_mode="$4"
    local cleanup_mode="$5"
    local emergency_cleanup_mode="$6"
    local force_mode="$7"
    local no_reboot="$8"
    
    local active_modes=0
    [[ "${install_docker_only}" == "true" ]] && ((active_modes++))
    [[ "${run_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${run_network_diagnostics_only}" == "true" ]] && ((active_modes++))
    [[ "${auto_weekly_mode}" == "true" ]] && ((active_modes++))
    [[ "${cleanup_mode}" == "true" ]] && ((active_modes++))
    [[ "${emergency_cleanup_mode}" == "true" ]] && ((active_modes++))
    
    if [[ ${active_modes} -gt 1 ]]; then
        enhanced_log "ERROR" "Only one special mode can be used at a time"
        exit 1
    fi
    
    check_root || {
        enhanced_log "ERROR" "Root privileges required"
        exit 1
    }
    
    create_temp_dir || {
        enhanced_log "ERROR" "Could not create temp dir"
        exit 1
    }
    
    if [[ "${no_reboot}" == "true" ]]; then
        export NO_REBOOT="true"
    fi
    
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
    
    validate_installation_args
    return 0
}

execute_docker_only_mode() {
    log "Executing Docker-only installation"
    install_dependencies || enhanced_log "WARN" "Dependency installation partially failed"
    install_docker || {
        enhanced_log "ERROR" "Docker installation failed"
        return 1
    }
    install_docker_compose || enhanced_log "WARN" "Docker Compose installation failed"
    log "Docker installation completed"
    return 0
}

execute_diagnostics_mode() {
    log "Executing full system diagnostics"
    run_enhanced_diagnostics
    return $?
}

execute_network_diagnostics_mode() {
    log "Executing network diagnostics"
    run_enhanced_network_diagnosis
    return $?
}

execute_weekly_mode() {
    log "Executing weekly automatic maintenance"
    get_enhanced_system_info
    run_weekly_maintenance
    return $?
}

execute_cleanup_mode() {
    log "Executing enhanced system cleanup"
    perform_enhanced_system_cleanup
    return $?
}

execute_emergency_cleanup_mode() {
    local force_mode="$1"
    
    if [[ "${force_mode}" != "true" ]]; then
        echo "WARNING: Emergency cleanup will take aggressive actions!"
        echo "Press Ctrl+C within 10 seconds to cancel..."
        sleep 10
    fi
    
    log "Executing emergency cleanup"
    perform_emergency_cleanup
    return $?
}

validate_installation_args() {
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "WARN" "No Adoption Token - Globalping Probe will not be installed"
        echo "Warning: Without --adoption-token, no Globalping Probe will be installed" >&2
    fi
    
    if [[ -n "${TELEGRAM_TOKEN}" && -z "${TELEGRAM_CHAT}" ]] || [[ -z "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]]; then
        enhanced_log "WARN" "Incomplete Telegram configuration"
        echo "Telegram notifications require both --telegram-token and --telegram-chat" >&2
    fi
}

enable_enhanced_debug_mode() {
    enhanced_log "INFO" "Activating Enhanced Debug Mode"
    
    set -x
    
    local debug_log="/var/log/globalping-debug-$(date +%Y%m%d-%H%M%S).log"
    exec 19>"${debug_log}"
    BASH_XTRACEFD=19
    
    DEBUG_MODE="true"
    
    {
        echo "=== ENHANCED DEBUG SESSION ==="
        echo "Date: $(date)"
        echo "User: $(whoami)"
        echo "Work Dir: $(pwd)"
        echo "Script Path: ${0}"
        echo "Arguments: $*"
        echo "System: $(uname -a)"
        echo "Shell: ${SHELL} (${BASH_VERSION})"
        echo "Memory: $(free -h | grep Mem)"
        echo "Disk: $(df -h / | grep /)"
        echo "=============================="
    } >&19
    
    enhanced_log "INFO" "Enhanced Debug Mode active: ${debug_log}"
    return 0
}

run_enhanced_network_diagnosis() {
    log "Running enhanced network diagnostics"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== ENHANCED NETWORK DIAGNOSTICS ==="
    echo "Time: $(date)"
    echo "==================================="
    
    analyze_network_enhanced issues warnings info_items
    
    echo -e "\n=== NETWORK DIAGNOSTIC RESULTS ==="
    echo "Issues: ${#issues[@]}, Warnings: ${#warnings[@]}, Info: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 NETWORK ISSUES:"
        printf ' - %s\n' "${issues[@]}"
        enhanced_notify "error" "Network Issues" "$(printf '%s\n' "${issues[@]}" | head -3)"
        return 1
    fi
    
    return 0
}

enhanced_main() {
    local start_time
    start_time=$(date +%s)
    
    enhanced_log "INFO" "=== STARTING ENHANCED SERVER SETUP ==="
    enhanced_log "INFO" "Version: ${SCRIPT_VERSION}"
    enhanced_log "INFO" "Mode: ${WEEKLY_MODE:-false}"
    enhanced_log "INFO" "Start Time: $(date)"
    enhanced_log "INFO" "========================================="
    
    get_enhanced_system_info
    
    enhanced_log "INFO" "Phase 1: Enhanced System Validation"
    if ! enhanced_validate_system; then
        return 1
    fi
    
    enhanced_log "INFO" "Phase 2: System Preparation"
    
    install_sudo || enhanced_log "WARN" "sudo installation failed"
    
    if ! install_dependencies; then
        enhanced_log "WARN" "Dependency installation partially failed"
    fi
    
    if ! update_system; then
        enhanced_log "WARN" "System update failed"
    fi
    
    enhanced_log "INFO" "Phase 3: Smart Swap Configuration"
    if ! configure_smart_swap; then
        enhanced_log "WARN" "Swap configuration failed"
    fi
    
    enhanced_log "INFO" "Phase 4: System Configuration"
    
    if ! configure_hostname; then
        enhanced_log "WARN" "Hostname configuration failed"
    fi
    
    if [[ -n "${SSH_KEY}" ]]; then
        if ! setup_ssh_key; then
            enhanced_log "WARN" "SSH Key setup failed"
        fi
    fi
    
    enhanced_log "INFO" "Phase 5: Ubuntu Pro Activation"
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        if ! ubuntu_pro_attach; then
            enhanced_log "WARN" "Ubuntu Pro activation failed"
        fi
    fi
    
    enhanced_log "INFO" "Phase 6: Docker System"
    
    if [[ -n "${ADOPTION_TOKEN}" ]] || ! command -v docker >/dev/null 2>&1; then
        if ! install_docker; then
            enhanced_log "ERROR" "Docker installation failed"
            enhanced_notify "error" "Docker Installation" "Docker could not be installed. Globalping Probe unavailable."
        else
            if ! install_docker_compose; then
                enhanced_log "WARN" "Docker Compose installation failed"
            fi
        fi
    fi
    
    enhanced_log "INFO" "Phase 7: Enhanced Globalping Probe"
    if [[ -n "${ADOPTION_TOKEN}" ]]; then
        if ! install_enhanced_globalping_probe; then
            enhanced_log "ERROR" "Globalping Probe installation failed"
            enhanced_notify "error" "Globalping Probe" "Globalping Probe installation failed"
        fi
    else
        enhanced_log "INFO" "No Adoption Token - skipping Globalping Probe"
    fi
    
    enhanced_log "INFO" "Phase 8: Enhanced Auto-Update Configuration"
    if ! setup_enhanced_auto_update; then
        enhanced_log "WARN" "Auto-Update setup failed"
    fi
    
    enhanced_log "INFO" "Phase 9: Critical Updates and Reboot Check"
    if [[ "${NO_REBOOT:-}" != "true" ]]; then
        if ! check_critical_updates; then
            enhanced_log "WARN" "Update check failed"
        fi
        
        if [[ "${REBOOT_REQUIRED}" == "true" ]]; then
            enhanced_log "INFO" "Reboot scheduled - Setup will resume after restart"
            return 0
        fi
    else
        enhanced_log "INFO" "Reboot check skipped (--no-reboot)"
    fi
    
    enhanced_log "INFO" "Phase 10: Enhanced System Optimization"
    if ! perform_enhanced_system_cleanup; then
        enhanced_log "WARN" "System cleanup failed"
    fi
    
    enhanced_log "INFO" "Phase 11: Final Diagnostics"
    local diagnosis_success=true
    if ! run_enhanced_diagnostics_silent; then
        enhanced_log "WARN" "Final diagnostics reported issues"
        diagnosis_success=false
    fi
    
    enhanced_log "INFO" "Phase 12: Completion and Summary"
    create_enhanced_summary
    
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    enhanced_log "INFO" "=== ENHANCED SERVER SETUP COMPLETED ==="
    enhanced_log "INFO" "Duration: ${duration} seconds"
    enhanced_log "INFO" "Finish Time: $(date)"
    enhanced_log "INFO" "======================================="
    
    if [[ "${WEEKLY_MODE}" != "true" && "${TELEGRAM_SENT}" != "true" && "${diagnosis_success}" == "true" ]]; then
        enhanced_notify "install_success" "Installation Completed" "Server successfully setup in ${duration} seconds.

Configured Features:
${ADOPTION_TOKEN:+✓ Globalping Probe}
${TELEGRAM_TOKEN:+✓ Telegram Notifications}
${SSH_KEY:+✓ SSH Access}
✓ Automatic Maintenance
✓ Smart Swap Configuration"
    fi
    
    return 0
}

run_enhanced_diagnostics_silent() {
    log "Running enhanced system diagnostics"
    
    local issues=()
    local warnings=()
    local info_items=()
    
    echo "=== ENHANCED SYSTEM DIAGNOSTICS ==="
    echo "Time: $(date)"
    echo "Hostname: $(hostname 2>/dev/null || echo 'unknown')"
    echo "Script Version: ${SCRIPT_VERSION}"
    echo "==================================="
    
    analyze_hardware_enhanced issues warnings info_items
    analyze_memory_enhanced issues warnings info_items
    analyze_network_enhanced issues warnings info_items
    
    if command -v docker >/dev/null 2>&1; then
        analyze_docker_enhanced issues warnings info_items
    fi
    
    analyze_globalping_enhanced issues warnings info_items
    analyze_autoupdate_enhanced issues warnings info_items
    analyze_security_enhanced issues warnings info_items
    analyze_performance_enhanced issues warnings info_items
    
    echo -e "\n=== DIAGNOSTIC RESULTS ==="
    echo "Critical Issues: ${#issues[@]}"
    echo "Warnings: ${#warnings[@]}"
    echo "Information: ${#info_items[@]}"
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        echo -e "\n🔴 CRITICAL ISSUES:"
        printf ' - %s\n' "${issues[@]}"
        return 1
    fi
    
    return 0
}

create_enhanced_summary() {
    local summary_file="/root/enhanced_setup_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    enhanced_log "INFO" "Creating enhanced summary: ${summary_file}"
    
    {
        echo "=========================================="
        echo "    ENHANCED SERVER SETUP SUMMARY"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Script Version: ${SCRIPT_VERSION}"
        echo "Hostname: $(hostname 2>/dev/null || echo 'unknown')"
        echo "Country: ${COUNTRY}, IP: ${PUBLIC_IP}"
        echo "Globalping Probe: ${ADOPTION_TOKEN:+Installed}${ADOPTION_TOKEN:-Not installed}"
        echo "Telegram: ${TELEGRAM_TOKEN:+Configured}${TELEGRAM_TOKEN:-Not configured}"
        echo "Auto-Update: Weekly active"
        echo "=========================================="
    } > "${summary_file}"
    
    echo "=== SETUP SUCCESSFULLY COMPLETED ==="
    echo "Details: ${summary_file}"
    echo "Automatic Maintenance: Weekly scheduled"
    echo "========================================"
    
    return 0
}

initialize_enhanced_script() {
    umask 022
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    
    local lock_file="/var/lock/globalping-install-enhanced.lock"
    if [[ -f "${lock_file}" ]]; then
        local lock_pid
        lock_pid=$(cat "${lock_file}" 2>/dev/null || echo "")
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            enhanced_log "ERROR" "Script already running (PID: ${lock_pid})"
            exit 1
        else
            rm -f "${lock_file}"
        fi
    fi
    
    echo "$$" > "${lock_file}"
    
    trap 'enhanced_cleanup_and_exit $?' EXIT
    
    enhanced_log "INFO" "Enhanced script initialization completed (PID: $$)"
}

enhanced_cleanup_and_exit() {
    local exit_code="$1"
    
    rm -f "/var/lock/globalping-install-enhanced.lock" 2>/dev/null || true
    rm -f "/tmp/globalping_auto_update.lock" 2>/dev/null || true
    
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}" 2>/dev/null || true
    fi
    
    if [[ "${DEBUG_MODE}" == "true" ]]; then
        set +x
        [[ -n "${BASH_XTRACEFD}" ]] && exec 19>&- 2>/dev/null || true
    fi
    
    if [[ ${exit_code} -eq 0 ]]; then
        enhanced_log "INFO" "Script finished successfully"
    else
        enhanced_log "ERROR" "Script finished with error (Exit Code: ${exit_code})"
    fi
    
    exit "${exit_code}"
}

enhanced_script_main() {
    local start_time
    start_time=$(date +%s)
    export start_time
    
    initialize_enhanced_script
    
    trap 'enhanced_error_handler ${LINENO} $?' ERR
    
    if ! check_root; then
        enhanced_log "ERROR" "Root privileges required"
        exit 1
    fi
    
    if ! check_internet; then
        enhanced_log "ERROR" "Internet connection required"
        exit 1
    fi
    
    if ! create_temp_dir; then
        enhanced_log "ERROR" "Could not create temp directory"
        exit 1
    fi
    
    process_enhanced_args "$@"
    
    enhanced_main
}

load_environment_variables() {
    [[ -z "${ADOPTION_TOKEN}" && -n "${ADOPTION_TOKEN:-}" ]] && ADOPTION_TOKEN="${ADOPTION_TOKEN}"
    [[ -z "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_TOKEN:-}" ]] && TELEGRAM_TOKEN="${TELEGRAM_TOKEN}"
    [[ -z "${TELEGRAM_CHAT}" && -n "${TELEGRAM_CHAT:-}" ]] && TELEGRAM_CHAT="${TELEGRAM_CHAT}"
    [[ -z "${UBUNTU_PRO_TOKEN}" && -n "${UBUNTU_PRO_TOKEN:-}" ]] && UBUNTU_PRO_TOKEN="${UBUNTU_PRO_TOKEN}"
    [[ -z "${SSH_KEY}" && -n "${SSH_KEY:-}" ]] && SSH_KEY="${SSH_KEY}"
    
    if [[ -n "${ADOPTION_TOKEN}" ]]; then
        enhanced_log "INFO" "Adoption Token loaded from environment variables"
    fi
    if [[ -n "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT}" ]]; then
        enhanced_log "INFO" "Telegram configuration loaded from environment variables"
    fi
}

# ===========================================
# SCRIPT EXECUTION START (ENHANCED)
# ===========================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_environment_variables
    enhanced_script_main "$@"
else
    enhanced_log "INFO" "Enhanced script functions loaded (sourced)"
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================