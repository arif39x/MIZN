#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

DB_FILE="miznd_telemetry.db"

if [ "$EUID" -ne 0 ]; then
  echo " Please run as root (sudo ./run.sh)"
  exit 1
fi

RUN_USER="${SUDO_USER:-root}"
SOCKET_GROUP="mizn"

if ! getent group "$SOCKET_GROUP" >/dev/null; then
    groupadd --system "$SOCKET_GROUP"
fi

if [ "$RUN_USER" != "root" ] && ! id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx "$SOCKET_GROUP"; then
    usermod -aG "$SOCKET_GROUP" "$RUN_USER"
    echo "[+] Added $RUN_USER to the $SOCKET_GROUP group. Restart your session for this to take effect."
fi

export MIZN_SOCKET_GROUP="$SOCKET_GROUP"

export PATH="${RUN_USER:+$(getent passwd "$RUN_USER" | cut -d: -f6)/.cargo/bin}:$PATH"

clear
echo "==================================================="
echo "              MIZN INTRUSION DETECTION             "
echo "==================================================="

echo "[*] Building workspace..."
echo "[*] Building eBPF program and user-space binaries..."
REQUIRED_BPF_LINKER_VERSION="0.9.15"
if ! command -v bpf-linker >/dev/null 2>&1 || \
   ! bpf-linker --version 2>/dev/null | grep -q "${REQUIRED_BPF_LINKER_VERSION}"; then
    echo "[!] bpf-linker ${REQUIRED_BPF_LINKER_VERSION} is required to build the eBPF program."
    echo "    Install it with: cargo +nightly install bpf-linker --version ${REQUIRED_BPF_LINKER_VERSION}"
    exit 1
fi
sudo -u "$RUN_USER" cargo run -p xtask -- build

if [ ! -s "target/bpfel-unknown-none/release/mizn-ebpf" ]; then
    echo "[!] eBPF build did not produce target/bpfel-unknown-none/release/mizn-ebpf"
    exit 1
fi

echo "[*] Checking core daemon status..."
# Ensure sockets have correct permissions even if already running
if [ -S "/run/miznd.sock" ]; then
    for socket in /run/miznd.sock /run/miznd_cmd.sock; do
        if [ -S "$socket" ]; then
            chgrp "$SOCKET_GROUP" "$socket"
            chmod 660 "$socket"
        fi
    done
fi

if pgrep -x "miznd" > /dev/null; then
    echo "[+] MIZN Daemon is already running."
else
    echo "[*] Starting MIZN Daemon in the background..."
    rm -f /run/miznd.sock /run/miznd_cmd.sock
    DAEMON_LOG="/tmp/miznd.log"
    : > "$DAEMON_LOG"
    ./target/debug/miznd >"$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!
    sleep 2

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "[!] MIZN daemon exited during startup."
        sed -n '1,120p' "$DAEMON_LOG"
        exit 1
    fi

    for socket in /run/miznd.sock /run/miznd_cmd.sock; do
        if [ -S "$socket" ]; then
            chgrp "$SOCKET_GROUP" "$socket"
            chmod 660 "$socket"
        fi
    done
    echo "[+] Daemon started with PID $DAEMON_PID."
fi

DAEMON_PID="${DAEMON_PID:-}"

sleep 1

show_menu() {
    echo ""
    echo "Choose your interface:"
    echo "  1)  Launch TUI (Terminal Interface)"
    echo "  2)  Stop Daemon and Exit"
    echo ""
}

while true; do
    show_menu
    read -p "Select [1-2]: " choice
    case $choice in
        1)
            echo "[*] Launching Terminal UI..."
            sleep 1
            sudo -u "$RUN_USER" ./target/debug/mizn-ui
            if [ $? -ne 0 ]; then
                echo " [!] TUI exited with an error. Check if 'miznd' is running and socket permissions are correct."
                sleep 2
            fi
            ;;
        2)
            echo "[*] Shutting down MIZN daemon..."
            if [ -n "$DAEMON_PID" ]; then
                kill "$DAEMON_PID" 2>/dev/null
            else
                pkill -x miznd 2>/dev/null
            fi
            echo "[+] Shutdown complete."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1 or 2."
            ;;
    esac
done
