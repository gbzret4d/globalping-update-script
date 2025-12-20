#!/bin/bash
set -u # Error on undefined variables

# =============================================
# GLOBAL VARIABLES (COMPATIBILITY LAYER)
# =============================================
# DO NOT REMOVE: Required for legacy auto-update migration
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# CONFIGURATION & CONSTANTS
# =============================================
readonly SCRIPT_VERSION="2025.12.21-v4.2-Fixed"
readonly CONFIG_FILE="/etc/globalping/config.env"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly LOCK_FILE="/var/lock/globalping-manager.lock"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"

# System Requirements
readonly MIN_FREE_SPACE_GB="1.5"
readonly MIN_RAM_MB="256"
readonly MAX_LOG_SIZE_MB="50"
readonly SWAP_MIN_TOTAL_GB="1"
readonly MIN_DISK_FOR_SWAP_GB="10"

# Timeouts
readonly TIMEOUT_NETWORK="15"
readonly TIMEOUT_PACKAGE="1800"
readonly TIMEOUT_DOCKER="900"

# Runtime State
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"
FORCE_RECREATE="false"
DRY_RUN="false"

# Defaults
GP_CPU_LIMIT="0.90"
GP_MEM_LIMIT=""

# Detected Info
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""
OS_TYPE=""
PKG_MANAGER=""

# =============================================
# 0. LOCKING & SETUP
# =============================================

acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "❌ Script is already running! Aborting."
        exit 1
    fi
}

# =============================================
# 1. CONFIG MIGRATION
# =============================================

load_and_migrate_config() {
    if [[ ! -d "$(dirname "${CONFIG_FILE}")" ]]; then
        mkdir -p "$(dirname "${CONFIG_FILE}")"
        chmod 700 "$(dirname "${CONFIG_FILE}")"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi

    local save_needed=false

    migrate_var() {
        local n="$1"; local v="$2"
        if [[ -n "${v}" ]] && ! grep -q "${n}=" "${CONFIG_FILE}" 2>/dev/null; then
            echo "${n}=\"${v}\"" >> "${CONFIG_FILE}"
            save_needed=true
        fi
    }

    migrate_var "ADOPTION_TOKEN" "${ADOPTION_TOKEN}"
    migrate_var "TELEGRAM_TOKEN" "${TELEGRAM_TOKEN}"
    migrate_var "TELEGRAM_CHAT" "${TELEGRAM_CHAT}"
    migrate_var "SSH_KEY" "${SSH_KEY}"
    migrate_var "UBUNTU_PRO_TOKEN" "${UBUNTU_PRO_TOKEN}"

    if ! grep -q "GP_CPU_LIMIT=" "${CONFIG_FILE}" 2>/dev/null; then
        echo "GP_CPU_LIMIT=\"${GP_CPU_LIMIT}\"" >> "${CONFIG_FILE}"
    fi

    if [[ "${save_needed}" == "true" ]]; then
        chmod 600 "${CONFIG_FILE}"
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        echo "[INFO] Configuration successfully migrated to ${CONFIG_FILE}" >> "${LOG_FILE}"
    fi
}

save_config_var() {
    local key="$1"; local value="$2"
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    touch "${CONFIG_FILE}"; chmod 600 "${CONFIG_FILE}"
    
    if grep -q "^${key}=" "${CONFIG_FILE}"; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "${CONFIG_FILE}"
    else
        echo "${key}=\"${value}\"" >> "${CONFIG_FILE}"
    fi
}

# =============================================
# 2. HELPERS & LOGGING
# =============================================

setup_colors() {
    if [ -t 1 ]; then
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
    else
        RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""
    fi
}

enhanced_log() {
    local level="$1"; local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local prefix; local color
    
    case "${level}" in
        "ERROR") prefix="❌ [ERROR]"; color="${RED}" ;;
        "WARN")  prefix="⚠️  [WARN]";  color="${YELLOW}" ;;
        "INFO")  prefix="ℹ️  [INFO]";  color="${GREEN}" ;;
        *)       prefix="📝 [${level}]"; color="${NC}" ;;
    esac
    
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    echo "[${timestamp}] ${prefix} ${message}" >> "${LOG_FILE}"
    echo -e "${color}[${timestamp}] ${prefix} ${message}${NC}"
}

log() { enhanced_log "INFO" "$1"; }
warn() { enhanced_log "WARN" "$1"; }
err() { enhanced_log "ERROR" "$1"; }

retry_command() {
    local retries=3; local count=0; local delay=5; local cmd="$*"
    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [ $count -lt $retries ]; then
            warn "Command failed ($count/$retries). Retrying in ${delay}s..."
            sleep $delay
        else
            err "Command failed after $retries attempts: $cmd"
            return $exit_code
        fi
    done
    return 0
}

wait_for_apt_locks() {
    if [ -f /etc/debian_version ]; then
        local max=60; local i=0
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
              fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
              fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
            if [ $i -ge $max ]; then warn "Timeout waiting for APT locks. Proceeding..."; break; fi
            if [ $i -eq 0 ]; then log "Waiting for APT locks..."; fi
            sleep 2; ((i++))
        done
    fi
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        err "Root privileges required. Please run with sudo."
        return 1
    fi
}

run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        enhanced_log "DRY" "Would execute: $*"
        return 0
    fi
    "$@"
}

# =============================================
# 3. SYSTEM INFO & TELEGRAM
# =============================================

get_enhanced_system_info() {
    log "Collecting system information..."
    PUBLIC_IP=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "unknown")
    local ipinfo=$(curl -s --connect-timeout 5 "https://ipinfo.io/json" 2>/dev/null || echo "")
    
    if [[ -n "$ipinfo" ]]; then
        COUNTRY=$(echo "$ipinfo" | grep -o '"country": *"[^"]*"' | cut -d'"' -f4 | head -1)
        local asn_raw=$(echo "$ipinfo" | grep -o '"org": *"[^"]*"' | cut -d'"' -f4 | head -1)
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
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g' | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-node")
    fi
    log "Detected: IP=${PUBLIC_IP}, Host=${HOSTNAME_NEW}, ISP=${PROVIDER}"
}

enhanced_notify() {
    local level="$1"; local title="$2"; local message="$3"
    
    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then return 0; fi
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then return 0; fi
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then return 0; fi
    
    [[ -z "${COUNTRY}" ]] && get_enhanced_system_info
    
    local icon emoji
    case "${level}" in
        "error") icon="❌"; emoji="CRITICAL ERROR" ;;
        "install_success") icon="✅"; emoji="INSTALLATION SUCCESSFUL"; TELEGRAM_SENT="true" ;;
    esac
    
    local ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "unknown")
    local disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5" used)"}' || echo "unknown")
    local load_info=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',' || echo "0")
    local virt_type=$(systemd-detect-virt 2>/dev/null || echo "Bare Metal")
    
    local fail2ban_stat="Not Installed"
    if command -v fail2ban-client >/dev/null 2>&1; then fail2ban_stat="Active"; fi
    
    local extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP: ${PUBLIC_IP}
├─ Provider: ${PROVIDER}
├─ ASN: ${ASN}
└─ Virtualization: ${virt_type}

💾 SYSTEM STATUS:
├─ RAM: ${ram_info}
├─ Disk: ${disk_info}
└─ Load: ${load_info}

🔧 SERVICES:
├─ Fail2Ban: ${fail2ban_stat}
├─ SSH Key: ${SSH_KEY:+Configured}${SSH_KEY:-Not set}
└─ Ubuntu Pro: ${UBUNTU_PRO_TOKEN:+Active}${UBUNTU_PRO_TOKEN:-Not used}

📋 ${title}:
${message}

📊 Logs: ${LOG_FILE}"

    curl -s -X POST --connect-timeout 10 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        -d "parse_mode=Markdown" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" >/dev/null 2>&1 || true
}

# =============================================
# 4. SYSTEM VALIDATION
# =============================================

enhanced_validate_system() {
    log "Running system validation..."
    local errors=(); local warnings=()
    
    local mem_kb=$(grep "MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    local mem_mb=$((mem_kb / 1024))
    
    if [[ ${mem_mb} -lt ${MIN_RAM_MB} ]]; then
        errors+=("Not enough RAM: ${mem_mb}MB (Min: ${MIN_RAM_MB}MB)")
    elif [[ ${mem_mb} -lt 512 ]]; then
        warnings+=("Low RAM: ${mem_mb}MB")
    fi
    
    local disk_avail_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    local disk_avail_mb=$((disk_avail_kb / 1024))
    
    # 1.5GB = 1536MB
    if [[ ${disk_avail_mb} -lt 1536 ]]; then
         errors+=("Not enough disk space: ${disk_avail_mb}MB (Min: 1.5GB)")
    fi
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        enhanced_log "ERROR" "System requirements not met:"
        printf '%s\n' "${errors[@]}"
        enhanced_notify "error" "Validation Failed" "$(printf '%s\n' "${errors[@]}")"
        return 1
    fi
    log "Validation passed (RAM: ${mem_mb}MB, Free Disk: ${disk_avail_mb}MB)"
    return 0
}

# =============================================
# 5. INSTALLATION & SETUP
# =============================================

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|raspbian|kali) OS_TYPE="debian"; PKG_MANAGER="apt-get" ;;
            centos|rhel|fedora|rocky|almalinux) OS_TYPE="rhel"
                if command -v dnf >/dev/null; then PKG_MANAGER="dnf"; else PKG_MANAGER="yum"; fi ;;
            *) OS_TYPE="unknown"; PKG_MANAGER="unknown" ;;
        esac
    else
        OS_TYPE="unknown"
    fi
}

install_dependencies() {
    enhanced_log "INFO" "Checking system dependencies..."
    
    local missing_cmds=()
    for cmd in curl wget unzip tar gzip bc; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then missing_cmds+=("${cmd}"); fi
    done
    
    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        log "All dependencies are installed."
        return 0
    fi
    
    log "Installing missing dependencies: ${missing_cmds[*]}"
    
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        log "Updating package lists..."
        retry_command apt-get update -q
        
        if ! apt-get install -y curl wget bc unzip tar gzip bzip2 xz-utils findutils iproute2 ca-certificates gnupg; then
             warn "Dependency installation failed. Attempting self-repair..."
             dpkg --configure -a || true
             apt-get install --fix-broken -y || true
             retry_command apt-get install -y curl wget bc unzip tar gzip bzip2 xz-utils findutils iproute2 ca-certificates gnupg
        fi
        
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        retry_command $PKG_MANAGER install -y curl wget bc unzip tar gzip bzip2 xz findutils iproute ca-certificates
    fi
}

# --- THIS FUNCTION WAS MISSING IN v4.1 ---
update_system_packages() {
    log "Updating system packages..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        
        # Check for phased updates
        if apt list --upgradable 2>/dev/null | grep -q "phased"; then
             log "Phased updates detected. Running safe upgrade only."
             run_cmd apt-get upgrade -y || true
        else
             run_cmd apt-get upgrade -y || true
        fi
        
        run_cmd apt-get autoremove -y || true
        
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        run_cmd $PKG_MANAGER update -y || true
    fi
}
# ----------------------------------------

check_critical_updates() {
    log "Checking for critical updates..."
    local needs_reboot="false"

    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        
        local updates=$(apt list --upgradable 2>/dev/null | grep -v "WARNING" || echo "")
        if echo "$updates" | grep -qE "linux-image|systemd|libc6"; then
             log "Critical updates (kernel/systemd) found."
             needs_reboot="true"
        fi
        
    elif [[ "$OS_TYPE" == "rhel" ]]; then
         if $PKG_MANAGER check-update kernel >/dev/null 2>&1; then
             needs_reboot="true"
         fi
    fi

    if [[ -f /var/run/reboot-required ]]; then needs_reboot="true"; fi

    if [[ "${needs_reboot}" == "true" ]]; then
        log "Reboot required for updates."
        REBOOT_REQUIRED="true"
    fi
}

configure_hostname() {
    log "Checking hostname..."
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current=$(hostname)
        if [[ "$current" != "$HOSTNAME_NEW" ]]; then
            log "Updating hostname to: ${HOSTNAME_NEW}"
            hostname "$HOSTNAME_NEW"
            echo "$HOSTNAME_NEW" > /etc/hostname
            sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
        else
            log "Hostname is correct."
        fi
    fi
}

setup_ssh_key() {
    log "Configuring SSH..."
    if [[ -n "${SSH_KEY}" ]]; then
        if [[ ! -d "${SSH_DIR}" ]]; then
            mkdir -p "${SSH_DIR}"; chmod 700 "${SSH_DIR}"
        fi
        if ! grep -Fq "${SSH_KEY}" "${SSH_DIR}/authorized_keys" 2>/dev/null; then
            echo "${SSH_KEY}" >> "${SSH_DIR}/authorized_keys"
            chmod 600 "${SSH_DIR}/authorized_keys"
            log "SSH Key added."
        else
            log "SSH Key already exists."
        fi
    fi
}

ubuntu_pro_attach() {
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -qi "ubuntu" /etc/os-release; then
        log "Attaching Ubuntu Pro..."
        if ! command -v ua >/dev/null 2>&1; then
            apt-get install -y ubuntu-advantage-tools >/dev/null 2>&1 || true
        fi
        if ua attach "${UBUNTU_PRO_TOKEN}" >/dev/null 2>&1; then
            log "Ubuntu Pro attached."
            ua enable esm-apps esm-infra livepatch >/dev/null 2>&1 || true
        else
            warn "Ubuntu Pro attachment failed (Check Token)."
        fi
    fi
}

configure_smart_swap() {
    log "Checking Swap..."
    local swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    if [[ "${swap_total}" -gt 0 ]]; then
        log "Swap is configured."
        return 0
    fi
    
    local mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "Low RAM (<1GB). Creating 1GB Swap..."
        touch /swapfile
        if command -v chattr >/dev/null 2>&1; then chattr +C /swapfile 2>/dev/null || true; fi
        dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null 2>&1
        swapon /swapfile
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        log "Swap created."
    fi
    return 0
}

enable_tcp_bbr() {
    log "Checking TCP BBR..."
    if grep -q "bbr" /etc/sysctl.conf; then return 0; fi
    log "Enabling BBR..."
    if ! echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf || \
       ! echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf; then
        warn "Could not write to sysctl.conf"
        return 1
    fi
    sysctl -p >/dev/null 2>&1 || true
}

install_fail2ban() {
    if command -v fail2ban-client >/dev/null 2>&1; then 
        log "Fail2Ban is already installed."
        return 0
    fi
    log "Installing Fail2Ban..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        apt-get install -y fail2ban >/dev/null 2>&1 || true
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        $PKG_MANAGER install -y fail2ban >/dev/null 2>&1 || true
    fi
    
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        echo -e "[sshd]\nenabled=true\nport=ssh\nmaxretry=5\nbantime=1h" > /etc/fail2ban/jail.local
        systemctl restart fail2ban >/dev/null 2>&1 || true
    fi
    systemctl enable fail2ban >/dev/null 2>&1 || true
}

# =============================================
# 6. DOCKER & CONTAINER
# =============================================

install_docker() {
    log "Checking Docker installation..."
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active docker >/dev/null 2>&1; then
            log "Docker is already active."
            return 0
        fi
        log "Starting Docker..."
        systemctl start docker && return 0
    fi
    
    log "Installing Docker..."
    if ! retry_command curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        err "Download failed."
        return 1
    fi
    
    if ! sh /tmp/get-docker.sh; then
        err "Docker install script failed. Trying fallback..."
        if [[ "$OS_TYPE" == "debian" ]]; then
             apt-get install -y docker.io || return 1
        elif [[ "$OS_TYPE" == "rhel" ]]; then
             $PKG_MANAGER install -y docker || return 1
        else
             return 1
        fi
    fi
    systemctl enable --now docker >/dev/null 2>&1
    log "Docker installed."
    return 0
}

install_enhanced_globalping_probe() {
    log "Installing Globalping Probe (v4.2)..."
    if [[ -z "${ADOPTION_TOKEN}" ]]; then err "Adoption Token missing!"; return 1; fi
    
    install_docker || return 1
    
    log "Pulling latest image..."
    retry_command docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1
    
    local cname="globalping-probe"
    local recreate_needed=false
    
    # Smart Check Logic
    if docker ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
        log "Container exists. Verifying..."
        
        local cur_tok=$(docker inspect "$cname" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "GP_ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}')
        local cur_img=$(docker inspect "$cname" --format '{{.Image}}')
        local new_img=$(docker inspect ghcr.io/jsdelivr/globalping-probe:latest --format '{{.Id}}')
        local state=$(docker inspect -f '{{.State.Status}}' "$cname")
        
        if [[ "$cur_tok" != "$ADOPTION_TOKEN" ]]; then
            recreate_needed=true
            log "Reason: Token changed."
        elif [[ "$cur_img" != "$new_img" ]]; then
            recreate_needed=true
            log "Reason: New image available."
        elif [[ "$state" != "running" ]]; then
            recreate_needed=true
            log "Reason: Container not running."
        elif [[ "${FORCE_RECREATE}" == "true" ]]; then
            recreate_needed=true
            log "Reason: Forced recreation."
        else
            log "Container is up-to-date."
            return 0
        fi
    else
        recreate_needed=true
    fi
    
    if [[ "$recreate_needed}" == "true" ]]; then
        log "Recreating container..."
        docker rm -f "$cname" >/dev/null 2>&1 || true
        
        local limits=""
        [[ -n "${GP_CPU_LIMIT}" ]] && limits+=" --cpus=$GP_CPU_LIMIT"
        [[ -n "${GP_MEM_LIMIT}" ]] && limits+=" --memory=$GP_MEM_LIMIT"
        
        if ! docker run -d --name "$cname" \
            --restart always --network host \
            --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
            $limits \
            -e "GP_ADOPTION_TOKEN=$ADOPTION_TOKEN" \
            -e "NODE_ENV=production" \
            -v globalping-data:/home/node/.globalping \
            ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
                local d_err=$(docker run 2>&1 || true)
                err "Start failed: $d_err"
                enhanced_notify "error" "Docker Failed" "$d_err"
                return 1
        fi
        log "Probe started."
    fi
    return 0
}

# =============================================
# 7. UPDATER & CLEANUP
# =============================================

perform_enhanced_auto_update() {
    log "Checking for script updates..."
    local temp="${TMP_DIR}/update.sh"
    
    if retry_command curl -sL --connect-timeout 10 -o "$temp" "${SCRIPT_URL}"; then
        if ! grep -q "END OF SCRIPT" "$temp"; then enhanced_notify "error" "Auto-Update" "Corrupt download."; return 1; fi
        if ! bash -n "$temp"; then enhanced_notify "error" "Auto-Update" "Syntax Error."; return 1; fi
        
        local cur=$(grep "^readonly SCRIPT_VERSION=" "$SCRIPT_PATH" | cut -d'"' -f2 || echo "0")
        local new=$(grep "^readonly SCRIPT_VERSION=" "$temp" | cut -d'"' -f2 || echo "0")
        
        if [[ "$cur" != "$new" ]]; then
            log "Updating: $cur -> $new"
            cp "$SCRIPT_PATH" "$SCRIPT_PATH.bak"
            cp "$temp" "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"
            log "Update successful."
        else
            log "Script is up-to-date."
        fi
    fi
}

perform_aggressive_cleanup() {
    log "🧹 Starting System Cleanup..."
    
    local disk_kb=$(df / | awk 'NR==2 {print $4}' || echo "0")
    local disk_mb=$((disk_kb / 1024))
    if [[ ${disk_mb} -gt 2048 && "${WEEKLY_MODE}" == "false" ]]; then
        log "Sufficient free space (${disk_mb}MB). Skipping."
        return 0
    fi

    if command -v docker >/dev/null 2>&1; then
        log "Cleaning Docker..."
        docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi
    
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        log "Cleaning Apt..."
        apt-get autoremove -y >/dev/null 2>&1 || true
        apt-get clean >/dev/null 2>&1 || true
    fi
    
    log "Truncating logs..."
    find /var/log -type f -size +50M -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
    
    local free=$(df -h / | awk 'NR==2 {print $4}')
    log "Cleanup done. Free: $free"
}

setup_auto_update_systemd() {
    cp "$0" "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"
    cat > "$SYSTEMD_SERVICE_PATH" << EOF
[Unit]
Description=Globalping Auto-Update
After=network.target
[Service]
ExecStart=$SCRIPT_PATH --auto-weekly
[Install]
WantedBy=multi-user.target
EOF
    cat > "$SYSTEMD_TIMER_PATH" << EOF
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
    systemctl enable --now globalping-update.timer >/dev/null 2>&1
    log "Auto-update timer active."
}

# =============================================
# 8. MAIN CONTROL
# =============================================

run_diagnostics() {
    echo "=== DIAGNOSTICS (v4.2) ==="
    get_enhanced_system_info
    echo "--- Config ---"
    echo "File: $CONFIG_FILE"
    echo "Token: $([[ -n $ADOPTION_TOKEN ]] && echo OK || echo MISSING)"
    echo "--- Docker ---"
    if command -v docker >/dev/null 2>&1; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    else
        echo "Not installed"
    fi
    exit 0
}

perform_uninstall() {
    local force="$1"
    if [[ "$force" != "true" ]]; then
        read -p "Uninstall? [y/N] " r; [[ "$r" != "y" ]] && exit 0
    fi
    log "Uninstalling..."
    if command -v docker >/dev/null; then
        docker stop globalping-probe 2>/dev/null || true
        docker rm globalping-probe 2>/dev/null || true
        docker rmi ghcr.io/jsdelivr/globalping-probe:latest 2>/dev/null || true
        docker volume rm globalping-data 2>/dev/null || true
    fi
    systemctl disable --now globalping-update.timer 2>/dev/null || true
    rm -f "$SCRIPT_PATH" "$SYSTEMD_TIMER_PATH" "$SYSTEMD_SERVICE_PATH" "$CONFIG_FILE"
    systemctl daemon-reload
    log "Done."
    exit 0
}

show_menu() {
    clear
    echo "Globalping Manager v${SCRIPT_VERSION##*-}"
    echo "1. Install/Update"
    echo "2. Configure"
    echo "3. Diagnostics"
    echo "4. Cleanup"
    echo "5. Uninstall"
    echo "6. Exit"
    read -p "Select: " c
    case "$c" in
        1) process_args --force ;;
        2) 
            read -p "Token: " t; save_config_var "ADOPTION_TOKEN" "$t"
            read -p "TG Token: " tt; save_config_var "TELEGRAM_TOKEN" "$tt"
            read -p "TG Chat: " tc; save_config_var "TELEGRAM_CHAT" "$tc"
            load_and_migrate_config; show_menu ;;
        3) process_args --diagnose ;;
        4) process_args --cleanup ;;
        5) process_args --uninstall ;;
        *) exit 0 ;;
    esac
}

process_args() {
    local uninstall="false"; local diagnose="false"; local force="false"; local auto="false"
    local fail2ban="false"; local cleanup="false"; local test_tg="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall) uninstall="true"; shift ;;
            --diagnose) diagnose="true"; shift ;;
            --cleanup) cleanup="true"; shift ;;
            --force) force="true"; FORCE_RECREATE="true"; shift ;;
            --auto-weekly) auto="true"; WEEKLY_MODE="true"; shift ;;
            --install-fail2ban) fail2ban="true"; shift ;;
            --test-telegram) test_tg="true"; shift ;;
            --adoption-token) save_config_var "ADOPTION_TOKEN" "$2"; ADOPTION_TOKEN="$2"; shift 2 ;;
            --telegram-token) save_config_var "TELEGRAM_TOKEN" "$2"; TELEGRAM_TOKEN="$2"; shift 2 ;;
            --telegram-chat) save_config_var "TELEGRAM_CHAT" "$2"; TELEGRAM_CHAT="$2"; shift 2 ;;
            --ssh-key) save_config_var "SSH_KEY" "$2"; SSH_KEY="$2"; shift 2 ;;
            --ubuntu-token) save_config_var "UBUNTU_PRO_TOKEN" "$2"; UBUNTU_PRO_TOKEN="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ "$uninstall" == "true" ]]; then perform_uninstall "$force"; exit 0; fi
    if [[ "$diagnose" == "true" ]]; then run_diagnostics; exit 0; fi
    if [[ "$cleanup" == "true" ]]; then perform_aggressive_cleanup; exit 0; fi
    if [[ "$test_tg" == "true" ]]; then test_telegram_config; exit 0; fi

    if [[ "$auto" == "true" ]]; then
        perform_enhanced_auto_update
        enable_tcp_bbr
        update_system_packages
        check_critical_updates
        if [[ "$REBOOT_REQUIRED" != "true" ]]; then
             install_enhanced_globalping_probe
        fi
        perform_aggressive_cleanup
        exit 0
    fi

    # INSTALL FLOW
    acquire_lock
    check_root
    run_preflight_checks
    setup_colors
    detect_os
    
    get_enhanced_system_info
    enhanced_validate_system
    
    install_dependencies
    update_system_packages
    
    configure_hostname
    setup_ssh_key
    ubuntu_pro_attach
    configure_smart_swap
    enable_tcp_bbr
    if [[ "$fail2ban" == "true" ]]; then install_fail2ban; fi

    install_enhanced_globalping_probe
    setup_auto_update_systemd
    
    # Check if a reboot is pending after all updates
    check_critical_updates
    
    if [[ "$REBOOT_REQUIRED" == "true" ]]; then
        log "Reboot required for updates."
        shutdown -r +2 "Reboot" &
    fi

    enhanced_notify "install_success" "Setup Complete" "Installation successful (v4.2)."
    log "✅ Installation complete."
}

# ENTRY
load_and_migrate_config
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then show_menu; else process_args "$@"; fi
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================