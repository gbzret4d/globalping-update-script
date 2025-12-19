# Globalping Probe Installer & Manager

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Bash](https://img.shields.io/badge/language-Bash-green.svg)

An advanced, fully automated setup and maintenance script for [Globalping Probes](https://globalping.io/). This script handles not just the installation, but the entire server lifecycle—including security updates, self-healing, and automated cleanup.

## ✨ Features

* **Automated Installation:** Sets up Docker, dependencies, and the Globalping Probe with a single command.
* **Smart Auto-Updates:**
    * Weekly self-updates for the script and the probe container.
    * Handles **Ubuntu Phased Updates** intelligently to avoid unnecessary reboots.
    * Only reboots if critical system updates (Kernel/Libc) require it.
* **Rich Notifications:** Sends detailed status reports (including IP, ASN, Provider, and Hardware stats) via Telegram.
* **Self-Healing & Optimization:**
    * **Watchdog:** Detects unhealthy containers and restarts them (`restart=always`).
    * **Storage:** Automatically cleans up old Docker images and logs to prevent disk saturation.
    * **Memory:** Automatically configures Swap if RAM is low (detects <1GB scenarios).
    * **Raspberry Pi:** Applies specific optimizations for SD cards and GPU memory.

## 🚀 Installation

### Prerequisites
* A Linux server (Ubuntu, Debian, CentOS, Rocky, AlmaLinux, Fedora).
* Root privileges (`sudo -i`).
* A **Globalping Adoption Token** (get it from the Globalping Dashboard).

### Quick Start

Download the script, make it executable, and run it:

```bash
curl -O [https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh](https://raw.githubusercontent.com/gbzret4d/globalping-update-script/main/install.sh)
chmod +x install.sh
./install.sh --adoption-token "YOUR_ADOPTION_TOKEN"
```

### Recommended Setup (with Telegram)

To receive status updates and error alerts, configure a Telegram Bot:

```bash
./install.sh \
  --adoption-token "YOUR_ADOPTION_TOKEN" \
  --telegram-token "123456789:ABCdefGHIjklMNOpqrs..." \
  --telegram-chat "987654321"
```

## ⚙️ Configuration Options

| Option | Description |
| :--- | :--- |
| `--adoption-token <TOKEN>` | **Required.** Your Globalping Adoption Token. |
| `--telegram-token <TOKEN>` | Your Telegram Bot Token. |
| `--telegram-chat <ID>` | Telegram Chat ID (User or Group) for notifications. |
| `--ssh-key "<KEY>"` | Adds a public SSH key to `authorized_keys`. |
| `--ubuntu-token <TOKEN>` | Attaches Ubuntu Pro (ESM) for extended security updates. |
| `--no-reboot` | Prevents automatic reboots during the initial installation. |
| `--diagnose` | Runs a full system diagnostic check without installing anything. |
| `--cleanup` | Immediately runs the system cleanup routine (Docker prune, logs, cache). |
| `--test-telegram` | Sends a test message to verify your Telegram config. |

## 🔄 Automated Maintenance

The script installs a **Systemd Timer** (or a Crontab fallback) to handle maintenance:

* **Schedule:** Every Sunday at 03:00 AM (local server time) + a random delay.
* **Tasks Performed:**
    1.  Checks for script updates from GitHub.
    2.  Installs system security updates.
    3.  Updates the Globalping Probe Docker container.
    4.  Rotates logs and cleans up temporary files.
    5.  Reboots only if strictly necessary (e.g., Kernel update).

## 📂 Logs & Troubleshooting

* **Main Log:** `/var/log/globalping-install.log`
* **Debug Mode:** Run the script with `--debug` for verbose output.

**Common Issues:**

1.  **Container not starting:**
    * Check Docker status: `systemctl status docker`
    * View Container logs: `docker logs globalping-probe`
2.  **No Telegram messages:**
    * Verify your Token/Chat ID.
    * Run the test: `./install.sh --test-telegram --telegram-token "..." --telegram-chat "..."`

## 📝 License

This project is licensed under the [MIT License](LICENSE).