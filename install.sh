#!/bin/bash
set -euo pipefail

# =============================================
# GLOBAL VARIABLES & COMPATIBILITY LAYER
# =============================================
# WARNING: Do NOT remove these. Used for migration from older versions.
UBUNTU_PRO_TOKEN=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""
SSH_KEY=""
ADOPTION_TOKEN=""

# =============================================
# CONFIGURATION
# =============================================
readonly SCRIPT_VERSION="2025.12.21-v2.8"
readonly CONFIG_FILE="/etc/globalping/config.env"
readonly LOG_FILE="/var/log/globalping-install.log"
readonly TMP_DIR="/tmp/globalping_install"
readonly SSH_DIR="/root/.ssh"
readonly SCRIPT_URL="https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh"
readonly SCRIPT_PATH="/usr/local/bin/install_globalping.sh"
readonly SYSTEMD_TIMER_PATH="/etc/systemd/system/globalping-update.timer"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/globalping-update.service"

# Resource Limits
GP_CPU_LIMIT="0.90"
GP_MEM_LIMIT=""

# Runtime
DEBUG_MODE="false"
WEEKLY_MODE="false"
REBOOT_REQUIRED="false"
TELEGRAM_SENT="false"
FORCE_RECREATE="false"

# Colors
RED=""
GREEN=""
YELLOW=""
BLUE=""
NC=""

# System Info
COUNTRY=""
HOSTNAME_NEW=""
PUBLIC_IP=""
ASN=""
PROVIDER=""
OS_TYPE=""   # debian, rhel
OS_DISTRO="" # ubuntu, centos, rocky...

# =============================================
# 1. SETUP & VISUALS
# =============================================

setup_colors() {
    # Only use colors if connected to a terminal
    if [ -t 1 ]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        NC='\033[0m' # No Color
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
    
    # Log to file (no color)
    mkdir -p "$(dirname "${LOG_FILE}")"
    echo "[${timestamp}] ${prefix} ${message}" >> "${LOG_FILE}"
    
    # Log to screen (with color)
    echo -e "${color}[${timestamp}] ${prefix} ${message}${NC}"
}

log() { enhanced_log "INFO" "$1"; }
warn() { enhanced_log "WARN" "$1"; }
err() { enhanced_log "ERROR" "$1"; }

# =============================================
# 2. ROBUSTNESS & COMPATIBILITY
# =============================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_DISTRO="${ID}"
        
        case "${ID}" in
            debian|ubuntu|raspbian|kali)
                OS_TYPE="debian"
                ;;
            centos|rhel|fedora|rocky|almalinux)
                OS_TYPE="rhel"
                ;;
            *)
                OS_TYPE="unknown"
                warn "Unknown distribution '${ID}'. Proceeding with caution."
                ;;
        esac
    else
        err "Cannot detect OS (/etc/os-release missing). Script might fail."
        return 1
    fi
}

check_compatibility() {
    # 1. Root Check
    if [[ "${EUID}" -ne 0 ]]; then
        err "This script requires root privileges. Try 'sudo ./install.sh'"
        return 1
    fi

    # 2. Systemd Check (Crucial for Auto-Update)
    if ! pidof systemd >/dev/null 2>&1 && [[ ! -d /run/systemd/system ]]; then
        warn "Systemd not detected. Automatic updates will NOT work."
    fi
    
    # 3. Architecture Check
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" && "$arch" != "armv7l" ]]; then
        err "Unsupported architecture: $arch. Docker image might not exist."
        # We don't exit, but we warn heavily
    fi
}

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
    # Only relevant for Debian based systems
    [[ "$OS_TYPE" != "debian" ]] && return 0

    local max_retries=60
    local i=0
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        
        if [ $i -ge $max_retries ]; then
            warn "Timeout waiting for APT locks. Attempting to proceed anyway..."
            break
        fi
        if [ $i -eq 0 ]; then log "Waiting for apt locks (other updates running?)..."; fi
        sleep 2
        ((i++))
    done
}

# =============================================
# 3. CONFIGURATION & MIGRATION
# =============================================

load_and_migrate_config() {
    mkdir -p "$(dirname "${CONFIG_FILE}")"

    if [[ -f "${CONFIG_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi

    local save_needed=false

    migrate_var() {
        local var_name="$1"
        local var_value="$2"
        if [[ -n "${var_value}" ]] && ! grep -q "${var_name}=" "${CONFIG_FILE}" 2>/dev/null; then
            echo "${var_name}=\"${var_value}\"" >> "${CONFIG_FILE}"
            save_needed=true
        fi
    }

    # Migrate from memory (old script injection) to file
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
        source "${CONFIG_FILE}"
        log "Configuration migrated to ${CONFIG_FILE}"
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
# 4. SYSTEM MAINTENANCE & FEATURES
# =============================================

configure_automatic_updates() {
    log "Configuring automatic security updates..."
    
    if [[ "$OS_TYPE" == "debian" ]]; then
        if ! command -v unattended-upgrades >/dev/null 2>&1; then
            wait_for_apt_locks
            retry_command apt-get install -y unattended-upgrades
        fi
        # Basic config enabling
        if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
            log "Auto-upgrades already configured."
        else
            echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
            log "Enabled unattended-upgrades."
        fi
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        if ! command -v dnf-automatic >/dev/null 2>&1; then
            retry_command dnf install -y dnf-automatic
        fi
        # Configure to apply updates
        sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
        log "Enabled dnf-automatic."
    fi
}

perform_aggressive_cleanup() {
    log "🧹 Starting aggressive storage cleanup..."
    
    # 1. Docker Cleanup (Safe)
    if command -v docker >/dev/null 2>&1; then
        log "Pruning Docker (unused images, networks, build cache)..."
        # -a removes all unused images, not just dangling ones. Safe if container is running.
        # -f forces no prompt
        docker system prune -a -f --volumes >/dev/null 2>&1 || true
    fi

    # 2. Package Manager Cleanup
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        apt-get autoremove -y >/dev/null 2>&1 || true
        apt-get clean >/dev/null 2>&1 || true
        rm -rf /var/lib/apt/lists/*
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        dnf clean all >/dev/null 2>&1 || true
        dnf autoremove -y >/dev/null 2>&1 || true
    fi

    # 3. Log Truncation (Logs > 50MB)
    log "Truncating large log files..."
    find /var/log -type f -size +50M -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
    # Remove old rotated logs
    find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null || true
    find /var/log -name "*.1" -mtime +7 -delete 2>/dev/null || true

    # 4. Systemd Journal
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --vacuum-time=3d >/dev/null 2>&1 || true
    fi

    local disk_free
    disk_free=$(df -h / | awk 'NR==2 {print $4}')
    log "Cleanup finished. Free space: ${disk_free}"
}

enable_tcp_bbr() {
    log "Optimizing Network (TCP BBR)..."
    if grep -q "bbr" /etc/sysctl.conf; then return 0; fi
    
    if ! echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf || \
       ! echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf; then
        warn "Could not write to sysctl.conf (Read-only fs?)"
        return 1
    fi
    sysctl -p >/dev/null 2>&1 || true
}

install_fail2ban() {
    if command -v fail2ban-client >/dev/null 2>&1; then return 0; fi
    
    log "Installing Fail2Ban for SSH protection..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        retry_command apt-get install -y fail2ban >/dev/null 2>&1
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        retry_command dnf install -y fail2ban >/dev/null 2>&1
    fi
    
    # Create Jail only if it doesn't exist
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
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
}

configure_smart_swap() {
    log "Checking Swap..."
    local swap_total
    swap_total=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    
    if [[ "${swap_total}" -gt 0 ]]; then return 0; fi
    
    local mem_total
    mem_total=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    
    # Only if RAM < 1GB
    if [[ "${mem_total}" -lt 1048576 ]]; then
        log "RAM is low. Creating 1GB Swap file..."
        touch /swapfile
        # Btrfs/COW safety check
        if command -v chattr >/dev/null 2>&1; then chattr +C /swapfile 2>/dev/null || true; fi
        
        if dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; then
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null 2>&1
            swapon /swapfile
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
            log "Swap created."
        else
            err "Could not create swap file."
        fi
    fi
}

# =============================================
# 5. DOCKER & APP LOGIC
# =============================================

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        # Check if daemon is running
        if systemctl is-active docker >/dev/null 2>&1; then return 0; fi
        log "Docker installed but not running. Starting..."
        systemctl start docker && return 0
    fi
    
    log "Installing Docker..."
    if ! retry_command curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
        err "Failed to download Docker installer."
        return 1
    fi
    sh /tmp/get-docker.sh >/dev/null 2>&1
    systemctl enable --now docker
}

install_globalping_probe() {
    log "Installing/Updating Globalping Probe..."
    
    if [[ -z "${ADOPTION_TOKEN}" ]]; then
        err "Adoption Token is missing! Use --adoption-token <TOKEN>"
        return 1
    fi
    
    install_docker || return 1
    
    # 1. Pull Image (Retry logic handled inside docker/network)
    log "Pulling latest image..."
    if ! docker pull ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
        err "Failed to pull Docker image. Check internet connection."
        return 1
    fi

    # 2. Smart Recreate Logic
    local container_name="globalping-probe"
    local recreate=false
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
        # Check Token
        local cur_token
        cur_token=$(docker inspect "${container_name}" --format '{{range .Config.Env}}{{if eq (index (split . "=") 0) "GP_ADOPTION_TOKEN"}}{{index (split . "=") 1}}{{end}}{{end}}')
        # Check Image
        local cur_img
        cur_img=$(docker inspect "${container_name}" --format '{{.Image}}')
        local new_img
        new_img=$(docker inspect ghcr.io/jsdelivr/globalping-probe:latest --format '{{.Id}}')
        
        if [[ "$cur_token" != "$ADOPTION_TOKEN" ]]; then
            log "Token changed. Recreating container."
            recreate=true
        elif [[ "$cur_img" != "$new_img" ]]; then
            log "New image version found. Updating..."
            recreate=true
        elif [[ "${FORCE_RECREATE}" == "true" ]]; then
            log "Forced recreation requested."
            recreate=true
        elif ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
             log "Container exists but is stopped. Restarting..."
             recreate=true
        else
            log "Container is up-to-date and running."
        fi
    else
        recreate=true
    fi

    if [[ "$recreate" == "true" ]]; then
        # Force remove to resolve conflicts
        docker rm -f "${container_name}" >/dev/null 2>&1 || true
        
        local limit_args=""
        [[ -n "${GP_CPU_LIMIT}" ]] && limit_args+=" --cpus=${GP_CPU_LIMIT}"
        [[ -n "${GP_MEM_LIMIT}" ]] && limit_args+=" --memory=${GP_MEM_LIMIT}"
        
        log "Starting container..."
        if ! docker run -d \
            --name "${container_name}" \
            --restart always \
            --network host \
            --log-driver json-file --log-opt max-size=50m --log-opt max-file=3 \
            ${limit_args} \
            -e "GP_ADOPTION_TOKEN=${ADOPTION_TOKEN}" \
            -e "NODE_ENV=production" \
            -v globalping-data:/home/node/.globalping \
            ghcr.io/jsdelivr/globalping-probe:latest >/dev/null 2>&1; then
                err "Docker run failed."
                enhanced_notify "error" "Installation Failed" "Docker run command failed."
                return 1
        fi
        log "Globalping Probe started."
    fi
}

perform_auto_update() {
    log "Checking for script updates..."
    local temp_script="${TMP_DIR}/update_script.sh"
    
    if retry_command curl -sL --connect-timeout 10 -o "${temp_script}" "${SCRIPT_URL}"; then
        # Integrity
        if ! grep -q "END OF SCRIPT" "${temp_script}"; then
            err "Update download incomplete."
            return 1
        fi
        # Syntax
        if ! bash -n "${temp_script}"; then
            err "Update has syntax errors. Aborting."
            return 1
        fi
        
        # Version
        local cur_ver
        cur_ver=$(grep "^readonly SCRIPT_VERSION=" "${SCRIPT_PATH}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        local new_ver
        new_ver=$(grep "^readonly SCRIPT_VERSION=" "${temp_script}" 2>/dev/null | cut -d'"' -f2 || echo "0")
        
        if [[ "$cur_ver" != "$new_ver" ]]; then
            log "Updating script: $cur_ver -> $new_ver"
            cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.backup"
            cp "${temp_script}" "${SCRIPT_PATH}"
            chmod +x "${SCRIPT_PATH}"
            return 0
        else
            log "Script is up to date ($cur_ver)."
        fi
    fi
    return 0
}

# =============================================
# 6. TELEGRAM
# =============================================

get_enhanced_system_info() {
    # Only fetch if we need to send a message
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
    HOSTNAME_NEW=$(hostname)
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
        icon="❌"; emoji="ERROR"
    fi

    local ram_info
    ram_info=$(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo "?")
    local disk_info
    disk_info=$(df -h / 2>/dev/null | awk 'NR==2 {print $3"/"$2}' || echo "?")

    local extended_message="${icon} ${emoji}

🌍 ${HOSTNAME_NEW} (${PUBLIC_IP})
📍 ${COUNTRY} | ${PROVIDER}

💾 RAM: ${ram_info} | Disk: ${disk_info}

📋 ${title}:
${message}

📊 Logs: ${LOG_FILE}"

    curl -s -X POST --connect-timeout 10 \
        -d "chat_id=${TELEGRAM_CHAT}" \
        -d "text=${extended_message}" \
        "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" >/dev/null 2>&1 || true
}

# =============================================
# 7. MAIN LOGIC
# =============================================

setup_auto_update_systemd() {
    cp "$0" "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"
    
    cat > "${SYSTEMD_SERVICE_PATH}" << EOF
[Unit]
Description=Globalping Maintenance
After=network.target
[Service]
ExecStart=${SCRIPT_PATH} --auto-weekly
[Install]
WantedBy=multi-user.target
EOF

    cat > "${SYSTEMD_TIMER_PATH}" << EOF
[Unit]
Description=Weekly Globalping Maintenance
[Timer]
OnCalendar=Sun 03:00:00
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now globalping-update.timer >/dev/null 2>&1
    log "Auto-update timer configured."
}

run_diagnostics() {
    log "Running Diagnostics..."
    get_enhanced_system_info
    echo "--- Info ---"
    echo "OS: $OS_DISTRO ($OS_TYPE)"
    echo "IP: $PUBLIC_IP (IPv6: $(ip -6 addr show scope global | grep inet6 | head -1 | awk '{print $2}' || echo 'None'))"
    echo "Ping: $(ping -c 1 1.1.1.1 >/dev/null && echo OK || echo FAIL)"
    echo "Docker: $(docker --version 2>/dev/null || echo 'Not installed')"
    echo "--- Probe ---"
    docker ps | grep globalping || echo "Probe not running"
    exit 0
}

show_menu() {
    clear
    echo "Globalping Installer v${SCRIPT_VERSION##*-}"
    echo "1. Install/Update"
    echo "2. Configure"
    echo "3. Diagnostics"
    echo "4. Cleanup (Aggressive)"
    echo "5. Uninstall"
    echo "6. Exit"
    read -p "Choice: " c
    case "$c" in
        1) process_args --force ;;
        2) 
            read -p "Token: " t; [[ -n "$t" ]] && save_config_var "ADOPTION_TOKEN" "$t"
            read -p "TG Token: " tt; [[ -n "$tt" ]] && save_config_var "TELEGRAM_TOKEN" "$tt"
            read -p "TG Chat: " tc; [[ -n "$tc" ]] && save_config_var "TELEGRAM_CHAT" "$tc"
            load_and_migrate_config
            show_menu
            ;;
        3) process_args --diagnose ;;
        4) process_args --cleanup ;;
        5) process_args --uninstall ;;
        6) exit 0 ;;
        *) show_menu ;;
    esac
}

process_args() {
    local uninstall="false"
    local cleanup="false"
    local diagnose="false"
    local auto_weekly="false"
    local force="false"
    local fail2ban="false"
    local test_tg="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall) uninstall="true"; shift ;;
            --cleanup) cleanup="true"; shift ;;
            --diagnose) diagnose="true"; shift ;;
            --force) force="true"; FORCE_RECREATE="true"; shift ;;
            --auto-weekly) auto_weekly="true"; WEEKLY_MODE="true"; shift ;;
            --install-fail2ban) fail2ban="true"; shift ;;
            --test-telegram) test_tg="true"; shift ;;
            
            # Config setters
            --adoption-token) save_config_var "ADOPTION_TOKEN" "$2"; ADOPTION_TOKEN="$2"; shift 2 ;;
            --telegram-token) save_config_var "TELEGRAM_TOKEN" "$2"; TELEGRAM_TOKEN="$2"; shift 2 ;;
            --telegram-chat) save_config_var "TELEGRAM_CHAT" "$2"; TELEGRAM_CHAT="$2"; shift 2 ;;
            --ssh-key) save_config_var "SSH_KEY" "$2"; SSH_KEY="$2"; shift 2 ;;
            --ubuntu-token) save_config_var "UBUNTU_PRO_TOKEN" "$2"; UBUNTU_PRO_TOKEN="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Modes
    if [[ "$uninstall" == "true" ]]; then
        [[ "$force" != "true" ]] && read -p "Uninstall? [y/N] " r && [[ "$r" != "y" ]] && exit 0
        docker stop globalping-probe 2>/dev/null || true
        docker rm globalping-probe 2>/dev/null || true
        rm -f "$SCRIPT_PATH" "$SYSTEMD_TIMER_PATH" "$SYSTEMD_SERVICE_PATH"
        systemctl daemon-reload
        log "Uninstalled."
        exit 0
    fi

    if [[ "$cleanup" == "true" ]]; then perform_aggressive_cleanup; exit 0; fi
    if [[ "$diagnose" == "true" ]]; then run_diagnostics; exit 0; fi

    # Weekly Task
    if [[ "$auto_weekly" == "true" ]]; then
        perform_auto_update
        configure_automatic_updates
        install_globalping_probe
        perform_aggressive_cleanup # Weekly cleanup
        exit 0
    fi

    # Normal Install
    check_compatibility
    setup_colors
    detect_os
    
    # Dependencies
    if [[ "$OS_TYPE" == "debian" ]]; then
        wait_for_apt_locks
        retry_command apt-get update >/dev/null 2>&1
        retry_command apt-get install -y curl wget unzip docker.io >/dev/null 2>&1 || true
    elif [[ "$OS_TYPE" == "rhel" ]]; then
        retry_command dnf install -y curl wget unzip docker >/dev/null 2>&1 || true
    fi

    configure_smart_swap
    enable_tcp_bbr
    configure_automatic_updates
    if [[ "$fail2ban" == "true" ]]; then install_fail2ban; fi

    if [[ -n "$SSH_KEY" ]]; then
        mkdir -p "$SSH_DIR"; echo "$SSH_KEY" >> "$SSH_DIR/authorized_keys"
        chmod 600 "$SSH_DIR/authorized_keys"
    fi

    install_globalping_probe
    setup_auto_update_systemd

    enhanced_notify "install_success" "Setup Complete" "Installation successful (v2.8)."
    log "✅ Installation complete."
}

# Entry
load_and_migrate_config
setup_colors

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then show_menu; else process_args "$@"; fi
fi

# ===========================================
# === END OF SCRIPT ===
# ===========================================