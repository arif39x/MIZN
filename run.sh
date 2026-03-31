#!/bin/bash

DB_FILE="miznd_telemetry.db"
GUI_DIR="mizn-gui"

if [ "$EUID" -ne 0 ]; then
  echo " Please run as root (sudo ./run.sh)"
  exit 1
fi

export PATH="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)/.cargo/bin}:$PATH"

clear
echo "==================================================="
echo "              MIZN INTRUSION DETECTION             "
echo "==================================================="

echo "[*] Building workspace..."
sudo -u "$SUDO_USER" cargo build --workspace

echo "[*] Checking core daemon status..."
# Ensure sockets have correct permissions even if already running
if [ -S "/run/miznd.sock" ]; then
    chmod 666 /run/miznd.sock 2>/dev/null
    chmod 666 /run/miznd_cmd.sock 2>/dev/null
fi

if pgrep -x "miznd" > /dev/null; then
    echo "[+] MIZN Daemon is already running."
else
    echo "[*] Starting MIZN Daemon in the background..."
    rm -f /run/miznd.sock /run/miznd_cmd.sock
    ./target/debug/miznd &
    DAEMON_PID=$!
    sleep 2
    chmod 666 /run/miznd.sock 2>/dev/null
    chmod 666 /run/miznd_cmd.sock 2>/dev/null
    echo "[+] Daemon started with PID $DAEMON_PID."
fi

sleep 1

show_menu() {
    echo ""
    echo "Choose your interface:"
    echo "  1)  Launch TUI (Terminal Interface)"
    echo "  2)  Launch Native Rust GUI (Desktop)"
    echo "  3)  Stop Daemon and Exit"
    echo ""
}

while true; do
    show_menu
    read -p "Select [1-3]: " choice
    case $choice in
        1)
            echo "[*] Launching Terminal UI..."
            sleep 1
            sudo -u "$SUDO_USER" ./target/debug/mizn-ui
            if [ $? -ne 0 ]; then
                echo " [!] TUI exited with an error. Check if 'miznd' is running and socket permissions are correct."
                sleep 2
            fi
            ;;
        2)
            echo "[*] Launching Native Rust GUI..."
            sleep 1
            sudo -u "$SUDO_USER" ./target/debug/mizn-gui
            if [ $? -ne 0 ]; then
                echo " [!] GUI exited with an error. Check if 'miznd' is running and socket permissions are correct."
                sleep 2
            fi
            ;;
        3)
            echo "[*] Shutting down MIZN daemon..."
            killall miznd 2>/dev/null
            echo "[+] Shutdown complete."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1, 2, or 3."
            ;;
    esac
done
