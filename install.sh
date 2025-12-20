#!/bin/bash
set -u # Error on undefined variables

# =============================================
# 0. COMPATIBILITY LAYER (DO NOT TOUCH)
# =============================================
# Variables used by legacy auto-updaters via 'sed' injection.
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# 1. CONSTANTS & CONFIGURATION
# =============================================
readonly SCRIPT_VERSION="2025.12.21-v4.1-EN"
readonly CONFIG_FILE="/etc/globalping/config.env"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly LOCK_FILE="/var/lock/globalping-manager.lock"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"

# Resource Limits (Defaults)
GP_CPU_LIMIT="0.90"
GP_MEM_LIMIT=""

# System Thresholds (Pre-Flight)
readonly MIN_FREE_SPACE_MB="500"
readonly MIN_RAM_MB="256"

# Runtime Flags
DEBUG_MODE="false"
DRY_RUN="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"
FORCE_RECREATE="false"

# Colors
RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""

# Detected Info
OS_TYPE=""
PKG_MANAGER=""
PUBLIC_IP=""
HOSTNAME_NEW=""
COUNTRY=""
ASN=""
PROVIDER=""

# =============================================
# 2. LOCKING & SETUP
# =============================================

acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "❌ Script is already running! Aborting to prevent race conditions."
        exit 1
    fi
}

setup_colors() {
    if [ -t 1 ]; then
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
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
        "DRY")   prefix="🧪 [DRY-RUN]"; color="${BLUE}" ;;
        *)       prefix="📝 [${level}]"; color="${NC}" ;;
    esac
    
    if [[ "$DRY_RUN" == "true" && "$level" != "ERROR" ]]; then
        prefix="🧪 [DRY]"
        color="${BLUE}"
    fi

    # Log to file
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
        echo "[${timestamp}] ${prefix} ${message}" >> "${LOG_FILE}"
    fi
    
    # Log to screen
    echo -e "${color}[${timestamp}] ${prefix} ${message}${NC}"
}

log() { enhanced_log "INFO" "$1"; }
warn() { enhanced_log "WARN" "$1"; }
err() { enhanced_log "ERROR" "$1"; }

# Wrapper for critical commands
run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        enhanced_log "DRY" "Would execute: $*"
        return 0
    fi
    "$@"
}

# =============================================
# 3. ROBUSTNESS FUNCTIONS
# =============================================

retry_command() {
    local retries=3; local count=0; local delay=5; local cmd="$*"
    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [ $count -lt $retries ]; then
            local wait_time=$((delay * count))
            warn "Command failed ($count/$retries). Retrying in ${wait_time}s..."
            if [[ "$DRY_RUN" == "false" ]]; then sleep $wait_time; fi
        else
            err "Command failed after $retries attempts: $cmd"
            return $exit_code
        fi
    done
    return 0
}

run_preflight_checks() {
    log "Running Pre-Flight Checks..."
    
    if [[ "${EUID}" -ne 0 ]]; then err "Root required."; return 1; fi

    # Check Read-Only Filesystem
    if grep -q " / ro," /proc/mounts; then
        err "Root filesystem is Read-Only! Cannot proceed."
        return 1
    fi

    # Check Disk Space
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [[ "$free_space" -lt "$MIN_FREE_SPACE_MB" ]]; then
        err "Not enough disk space. Free: ${free_space}MB, Required: ${MIN_FREE_SPACE_MB}MB."
        return 1
    fi

    log "Pre-Flight Checks Passed."
}

wait_for_apt_locks() {
    if [[ "$OS_TYPE" == "debian" && "$DRY_RUN" == "false" ]]; then
        local max=60; local i=0
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
              fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
            if [ $i -ge $max ]; then warn "Lock stuck. Proceeding anyway..."; break; fi
            if [ $i -eq 0 ]; then log "Waiting for package manager locks..."; fi
            sleep 2; ((i++))
        done
    fi
}

fix_package_manager() {
    warn "Attempting to repair package manager..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        dpkg --configure -a || true
        apt-get install -f -y || true
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        $PKG_MANAGER clean all || true
    fi
}

# =============================================
# 4. CONFIGURATION & MIGRATION
# =============================================

load_and_migrate_config() {
    if [[ ! -d "$(dirname "${CONFIG_FILE}")" ]]; then
        run_cmd mkdir -p "$(dirname "${CONFIG_FILE}")"
        run_cmd chmod 700 "$(dirname "${CONFIG_FILE}")"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then source "${CONFIG_FILE}"; fi

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

    if [[ "${save_needed}" == "true" && "$DRY_RUN" == "false" ]]; then
        chmod 600 "${CONFIG_FILE}"
        source "${CONFIG_FILE}"
        log "Configuration migrated to ${CONFIG_FILE}"
    fi
}

save_config_var() {
    local key="$1"; local value="$2"
    if [[ "$DRY_RUN" == "true" ]]; then log "[DRY] Would save $key"; return 0; fi
    
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    touch "${CONFIG_FILE}"; chmod 600 "${CONFIG_FILE}"
    
    if grep -q "^${key}=" "${CONFIG_FILE}"; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "${CONFIG_FILE}"
    else
        echo "${key}=\"${value}\"" >> "${CONFIG_FILE}"
    fi
}

# =============================================
# 5. SYSTEM INFO & TELEGRAM
# =============================================

get_system_info() {
    log "Gathering system info..."
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
        HOSTNAME_NEW=$(echo "${HOSTNAME_NEW}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | cut -c1-63)
    else
        HOSTNAME_NEW=$(hostname 2>/dev/null || echo "globalping-node")
    fi
    log "Identity: $HOSTNAME_NEW ($PUBLIC_IP)"
}

enhanced_notify() {
    local level="$1"; local title="$2"; local message="$3"
    
    if [[ "$DRY_RUN" == "true" ]]; then log "[DRY] Telegram: $title"; return 0; fi
    if [[ "${TELEGRAM_SENT}" == "true" && "${level}" == "install_success" ]]; then return 0; fi
    if [[ "${level}" != "error" && "${level}" != "install_success" ]]; then return 0; fi
    if [[ -z "${TELEGRAM_TOKEN}" || -z "${TELEGRAM_CHAT}" ]]; then return 0; fi
    
    [[ -z "${COUNTRY}" ]] && get_system_info
    
    local icon emoji
    case "${level}" in
        "error") icon="❌"; emoji="CRITICAL ERROR" ;;
        "install_success") icon="✅"; emoji="INSTALLATION SUCCESSFUL"; TELEGRAM_SENT="true" ;;
    esac
    
    local ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "?")
    local disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2" ("$5")"}' || echo "?")
    local load_info=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs || echo "?")
    local virt_type=$(systemd-detect-virt 2>/dev/null || echo "Bare Metal")
    
    local fail2ban_stat="Not Installed"
    if command -v fail2ban-client >/dev/null 2>&1; then fail2ban_stat="Active"; fi
    
    local extended_message="${icon} ${emoji}

🌍 SERVER DETAILS:
├─ Country: ${COUNTRY}
├─ Hostname: ${HOSTNAME_NEW}
├─ IP: ${PUBLIC_IP}
├─ ISP: ${PROVIDER}
├─ ASN: ${ASN}
└─ Virt: ${virt_type}

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
# 6. SYSTEM INSTALL & CONFIG
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
    log "Checking system dependencies..."
    local missing=()
    for cmd in curl wget unzip tar gzip bc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then missing+=("$cmd"); fi
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        log "Dependencies OK."
        return 0
    fi
    
    log "Installing: ${missing[*]}"
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        retry_command run_cmd apt-get update -q
        if ! run_cmd apt-get install -y curl wget awk sed grep coreutils bc unzip tar gzip bzip2 xz-utils findutils iproute2 ca-certificates gnupg; then
            fix_package_manager
            retry_command run_cmd apt-get install -y curl wget awk sed grep coreutils bc unzip tar gzip bzip2 xz-utils findutils iproute2 ca-certificates gnupg
        fi
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        retry_command run_cmd $PKG_MANAGER install -y curl wget unzip tar gzip bc bind-utils
    fi
}

update_system_packages() {
    log "Updating OS packages..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        if apt list --upgradable 2>/dev/null | grep -q "phased"; then
             log "Phased updates detected. Safe upgrade only."
             run_cmd apt-get upgrade -y || true
        else
             run_cmd apt-get upgrade -y || true
        fi
        run_cmd apt-get autoremove -y || true
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        run_cmd $PKG_MANAGER update -y || true
    fi
    
    if [ -f /var/run/reboot-required ]; then
        REBOOT_REQUIRED="true"
    fi
}

configure_hostname() {
    log "Checking hostname..."
    if [[ -n "${HOSTNAME_NEW}" && "${HOSTNAME_NEW}" != "unknown" ]]; then
        local current=$(hostname)
        if [[ "$current" != "$HOSTNAME_NEW" ]]; then
            log "Updating hostname to ${HOSTNAME_NEW}"
            run_cmd hostname "$HOSTNAME_NEW"
            run_cmd echo "$HOSTNAME_NEW" > /etc/hostname
            if [[ "$DRY_RUN" == "false" ]]; then
                sed -i "s/^127.0.1.1.*/127.0.1.1\t${HOSTNAME_NEW}/" /etc/hosts 2>/dev/null || true
            fi
        fi
    fi
}

setup_ssh_key() {
    if [[ -n "${SSH_KEY}" ]]; then
        log "Configuring SSH..."
        if [[ ! -d "${SSH_DIR}" ]]; then
            run_cmd mkdir -p "${SSH_DIR}"; run_cmd chmod 700 "${SSH_DIR}"
        fi
        if ! grep -Fq "${SSH_KEY}" "${SSH_DIR}/authorized_keys" 2>/dev/null; then
            if [[ "$DRY_RUN" == "false" ]]; then
                echo "${SSH_KEY}" >> "${SSH_DIR}/authorized_keys"
                chmod 600 "${SSH_DIR}/authorized_keys"
            else
                log "[DRY] Would append SSH key"
            fi
            log "SSH Key added."
        else
            log "SSH Key exists."
        fi
    fi
}

ubuntu_pro_attach() {
    if [[ -n "${UBUNTU_PRO_TOKEN}" ]] && grep -qi "ubuntu" /etc/os-release; then
        log "Attaching Ubuntu Pro..."
        if ! command -v ua >/dev/null 2>&1; then
            run_cmd apt-get install -y ubuntu-advantage-tools || true
        fi
        run_cmd ua attach "${UBUNTU_PRO_TOKEN}" || true
        run_cmd ua enable esm-apps esm-infra livepatch || true
    fi
}

configure_smart_swap() {
    log "Checking Swap..."
    local swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    if [[ "${swap_total}" -gt 0 ]]; then return 0; fi
    
    local mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "Low RAM. Creating 1GB Swap..."
        run_cmd touch /swapfile
        if command -v chattr >/dev/null 2>&1; then run_cmd chattr +C /swapfile 2>/dev/null || true; fi
        
        if [[ "$DRY_RUN" == "false" ]]; then
            dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null 2>&1
            swapon /swapfile
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        else
            log "[DRY] Would create and activate swapfile"
        fi
    fi
}

enable_tcp_bbr() {
    log "Checking TCP BBR..."
    if grep -q "bbr" /etc/sysctl.conf; then return 0; fi
    
    log "Enabling TCP BBR..."
    if [[ "$DRY_RUN" == "false" ]]; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    else
        log "[DRY] Would enable BBR"
    fi
}

install_fail2ban() {
    if command -v fail2ban-client >/dev/null 2>&1; then return 0; fi
    log "Installing Fail2Ban..."
    
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        retry_command run_cmd apt-get install -y fail2ban
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        retry_command run_cmd $PKG_MANAGER install -y fail2ban
    fi
    
    if [[ ! -f "/etc/fail2ban/jail.local" && "$DRY_RUN" == "false" ]]; then
        echo -e "[sshd]\nenabled=true\nport=ssh\nmaxretry=5\nbantime=1h" > /etc/fail2ban/jail.local
        systemctl restart fail2ban >/dev/null 2>&1 || true
    fi
}

# =============================================
# 7. DOCKER & CONTAINER (Smart Check)
# =============================================

install_docker() {
    log "Checking Docker..."
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active docker >/dev/null 2>&1; then return 0; fi
        run_cmd systemctl start docker && return 0
    fi
    
    log "Installing Docker..."
    if ! retry_command curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        err "Download failed."
        return 1
    fi
    run_cmd sh /tmp/get-docker.sh
    run_cmd systemctl enable --now docker
}

install_globalping_probe() {
    log "Installing Globalping Probe (v4.1)..."
    if [[ -z "${ADOPTION_TOKEN}" ]]; then err "Token missing!"; return 1; fi
    
    install_docker || return 1
    
    log "Pulling image..."
    retry_command run_cmd docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1
    
    local cname="globalping-probe"
    local recreate=false
    
    # Smart Check Logic
    if docker ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
        log "Container exists. Verifying..."
        local cur_tok=$(docker inspect "$cname" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "GP_ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}')
        local cur_img=$(docker inspect "$cname" --format '{{.Image}}')
        local new_img=$(docker inspect ghcr.io/jsdelivr/globalping-probe:latest --format '{{.Id}}')
        local state=$(docker inspect -f '{{.State.Status}}' "$cname")

        if [[ "$cur_tok" != "$ADOPTION_TOKEN" ]]; then recreate=true; log "Reason: Token changed."; fi
        elif [[ "$cur_img" != "$new_img" ]]; then recreate=true; log "Reason: Update available."; fi
        elif [[ "$state" != "running" ]]; then recreate=true; log "Reason: Stopped."; fi
        elif [[ "${FORCE_RECREATE}" == "true" ]]; then recreate=true; log "Reason: Forced."; fi
        else
            log "Container OK. No changes."
            return 0
        fi
    else
        recreate=true
    fi
    
    if [[ "$recreate" == "true" ]]; then
        log "Recreating container..."
        run_cmd docker rm -f "$cname" >/dev/null 2>&1 || true
        
        local limits=""
        [[ -n "${GP_CPU_LIMIT}" ]] && limits+=" --cpus=$GP_CPU_LIMIT"
        [[ -n "${GP_MEM_LIMIT}" ]] && limits+=" --memory=$GP_MEM_LIMIT"
        
        if ! run_cmd docker run -d --name "$cname" \
            --restart always --network host \
            --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
            $limits \
            -e "GP_ADOPTION_TOKEN=$ADOPTION_TOKEN" \
            -e "NODE_ENV=production" \
            -v globalping-data:/home/node/.globalping \
            ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
                err "Docker run failed."
                enhanced_notify "error" "Docker Failed" "Could not start container."
                return 1
        fi
        log "Probe started."
    fi
}

# =============================================
# 8. ATOMIC UPDATES & CLEANUP
# =============================================

perform_atomic_update() {
    log "Checking for updates..."
    local temp="${TMP_DIR}/update.sh"
    
    if retry_command curl -sL --connect-timeout 10 -o "$temp" "$SCRIPT_URL"; then
        # Integrity & Syntax Check
        if ! grep -q "END OF SCRIPT" "$temp"; then err "Corrupt download."; return 1; fi
        if ! bash -n "$temp"; then err "Syntax error in update."; return 1; fi
        
        local cur=$(grep "^readonly SCRIPT_VERSION=" "$SCRIPT_PATH" | cut -d'"' -f2)
        local new=$(grep "^readonly SCRIPT_VERSION=" "$temp" | cut -d'"' -f2)
        
        if [[ "$cur" != "$new" ]]; then
            log "Updating: $cur -> $new"
            # Backup
            run_cmd cp "$SCRIPT_PATH" "$SCRIPT_PATH.bak"
            # Atomic Move
            run_cmd mv "$temp" "$SCRIPT_PATH"
            run_cmd chmod +x "$SCRIPT_PATH"
            log "Update applied."
        else
            log "Script up-to-date."
        fi
    fi
}

perform_aggressive_cleanup() {
    log "🧹 System Cleanup..."
    if command -v docker >/dev/null 2>&1; then
        run_cmd docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        run_cmd apt-get autoremove -y >/dev/null 2>&1
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        run_cmd $PKG_MANAGER clean all
    fi
    run_cmd find /var/log -name "*.log" -size +50M -exec truncate -s 0 {} \;
}

setup_systemd() {
    if [[ "$DRY_RUN" == "true" ]]; then log "[DRY] Would install systemd timer"; return 0; fi
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
}

# =============================================
# 9. MENU & ARGS
# =============================================

run_diagnostics() {
    echo "=== DIAGNOSTICS ==="
    get_system_info
    echo "OS: $OS_TYPE"
    echo "Config: $CONFIG_FILE"
    echo "Token: $([[ -n $ADOPTION_TOKEN ]] && echo OK || echo MISSING)"
    echo "--- Docker ---"
    if command -v docker >/dev/null; then
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    else
        echo "Missing"
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
        run_cmd docker stop globalping-probe 2>/dev/null || true
        run_cmd docker rm globalping-probe 2>/dev/null || true
        run_cmd docker volume rm globalping-data 2>/dev/null || true
    fi
    run_cmd systemctl disable --now globalping-update.timer 2>/dev/null || true
    run_cmd rm -f "$SCRIPT_PATH" "$SYSTEMD_TIMER_PATH" "$SYSTEMD_SERVICE_PATH" "$CONFIG_FILE"
    run_cmd systemctl daemon-reload
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
    echo "6. Dry Run Install"
    echo "7. Exit"
    read -p "Option: " c
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
        6) process_args --dry-run ;;
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
            --dry-run) DRY_RUN="true"; shift ;;
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

    if [[ "$uninstall" == "true" ]]; then perform_uninstall "$force"; fi
    if [[ "$diagnose" == "true" ]]; then run_diagnostics; fi
    if [[ "$cleanup" == "true" ]]; then perform_aggressive_cleanup; exit 0; fi

    if [[ "$auto" == "true" ]]; then
        perform_atomic_update
        enable_tcp_bbr
        if command -v docker >/dev/null; then docker system prune -f >/dev/null 2>&1; fi
        install_globalping_probe
        exit 0
    fi

    # INSTALL FLOW
    acquire_lock
    check_root
    run_preflight_checks
    setup_colors
    detect_os
    
    get_system_info
    install_dependencies
    update_system_packages
    configure_hostname
    setup_ssh_key
    ubuntu_pro_attach
    configure_smart_swap
    enable_tcp_bbr
    if [[ "$fail2ban" == "true" ]]; then install_fail2ban; fi

    install_globalping_probe
    setup_systemd

    if [[ "$REBOOT_REQUIRED" == "true" ]]; then
        log "Reboot required."
    fi

    enhanced_notify "install_success" "Setup Complete" "Installation successful (v4.1)."
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