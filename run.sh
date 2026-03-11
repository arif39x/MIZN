#!/usr/bin/env bash
set -euo pipefail

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
export PATH="$REAL_HOME/.cargo/bin:$PATH"

SOCKET="/run/miznd.sock"
BINARY_PATH="./target/bpfel-unknown-none/release/mizn-ebpf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[mizn]${NC} $*"; }
warn()  { echo -e "${YELLOW}[mizn]${NC} $*"; }
error() { echo -e "${RED}[mizn]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root (sudo ./run.sh) — miznd needs CAP_BPF/NET_ADMIN."

if [[ ! -f "$BINARY_PATH" ]]; then
    warn "eBPF binary not found. Running xtask build first..."
    cargo xtask build
fi

info "Building miznd and mizn-ui..."

if [[ -f "$BINARY_PATH" ]]; then
    info "Setting capabilities on eBPF binary..."
    sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep "$BINARY_PATH" || warn "Failed to set capabilities; ensure libcap2-bin is installed."
fi
cargo build --bin miznd --bin mizn-ui

[[ -S "$SOCKET" ]] && rm -f "$SOCKET"

info "Starting miznd..."
./target/debug/miznd &
DAEMON_PID=$!


trap 'info "Shutting down..."; kill "$DAEMON_PID" 2>/dev/null; rm -f "$SOCKET"' EXIT INT TERM

info "Waiting for $SOCKET..."
for i in $(seq 1 20); do
    [[ -S "$SOCKET" ]] && break
    sleep 0.5
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        error "miznd exited unexpectedly. Check output above."
    fi
done

[[ -S "$SOCKET" ]] || error "Socket never appeared after 10 s."
info "Daemon ready (PID $DAEMON_PID)."

info "Launching mizn-ui..."
./target/debug/mizn-ui
