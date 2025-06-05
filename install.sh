#!/bin/bash
set -euo pipefail

# Configuration
readonly SCRIPT_NAME="globalping-probe-installer.sh"
readonly INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
readonly VERSION="3.0.0"
readonly MAX_OFFSET_MINUTES=720
readonly CLEANUP_DAYS=30
readonly DOCKER_COMPOSE_VERSION="1.29.2"
readonly LOG_FILE="/var/log/globalping-probe.log"
readonly GP_PROBE_IMAGE="globalping/globalping-probe"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Parameters
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
UBUNTU_PRO_TOKEN=""
GP_ADOPTION_TOKEN=""
SSH_KEY=""

function log() {
  echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

function error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
  send_telegram_notification "❌ Globalping Probe Installation Failed on $(hostname)
  - Error: $1
  - IP: $(curl -s ifconfig.me || echo 'unknown')
  - Token: ${GP_ADOPTION_TOKEN:0:4}...${GP_ADOPTION_TOKEN: -4}"
  exit 1
}

function send_telegram_notification() {
  [[ -z "${TELEGRAM_BOT_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ]] && return

  local message="$1"
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="${message}" >/dev/null || echo "Failed to send Telegram notification" >&2
}

function check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
  fi
}

function install_docker() {
  if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh || error "Docker installation failed"
    systemctl enable --now docker || error "Failed to start Docker"
  fi
}

function install_docker_compose() {
  if ! command -v docker-compose &>/dev/null; then
    log "Installing Docker Compose v${DOCKER_COMPOSE_VERSION}..."
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/docker-compose || error "Failed to download Docker Compose"
    chmod +x /usr/local/bin/docker-compose || error "Failed to make docker-compose executable"
  fi
}

function deploy_probe() {
  log "Deploying Globalping Probe..."

  # Cleanup existing container if needed
  if docker ps -a --format '{{.Names}}' | grep -q "^globalping-probe$"; then
    log "Removing existing probe container..."
    docker stop globalping-probe || true
    docker rm globalping-probe || true
  fi

  # Start new container
  docker run -d \
    --name globalping-probe \
    -e ADOPTION_TOKEN="${GP_ADOPTION_TOKEN}" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --restart unless-stopped \
    --network host \
    ${GP_PROBE_IMAGE} || error "Failed to start probe container"

  log "Probe container started successfully"
}

function configure_ssh() {
  [[ -z "${SSH_KEY}" ]] && return

  log "Configuring SSH key..."
  mkdir -p /root/.ssh
  grep -qF "${SSH_KEY}" /root/.ssh/authorized_keys || echo "${SSH_KEY}" >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
}

function configure_ubuntu_pro() {
  [[ -z "${UBUNTU_PRO_TOKEN}" ]] && return

  log "Attaching Ubuntu Pro..."
  apt-get update && apt-get install -y ubuntu-advantage-tools || error "Failed to install ubuntu-advantage-tools"
  ua attach "${UBUNTU_PRO_TOKEN}" || error "Ubuntu Pro attachment failed"
}

function parse_parameters() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --adoption-token)
        GP_ADOPTION_TOKEN="$2"
        shift 2
        ;;
      --telegram-token)
        TELEGRAM_BOT_TOKEN="$2"
        shift 2
        ;;
      --telegram-chat)
        TELEGRAM_CHAT_ID="$2"
        shift 2
        ;;
      --ubuntu-token)
        UBUNTU_PRO_TOKEN="$2"
        shift 2
        ;;
      --ssh-key)
        SSH_KEY="$2"
        shift 2
        ;;
      *)
        error "Unknown parameter: $1"
        ;;
    esac
  done

  if [[ -z "${GP_ADOPTION_TOKEN}" ]]; then
    error "Adoption token is required"
  fi
}

function main() {
  check_root
  parse_parameters "$@"

  install_docker
  install_docker_compose
  deploy_probe
  configure_ssh
  configure_ubuntu_pro

  log "${GREEN}Installation completed successfully!${NC}"
  log "Check probe status: docker ps -a | grep globalping-probe"
  log "View logs: docker logs globalping-probe"
}

main "$@"
