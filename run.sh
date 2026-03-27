#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${GREEN}${BOLD}[mizn]${NC} $*"; }
warn()  { echo -e "${YELLOW}${BOLD}[mizn]${NC} $*"; }
error() { echo -e "${RED}${BOLD}[mizn]${NC} $*"; exit 1; }
dim()   { echo -e "${DIM}$*${NC}"; }

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ░█▄█░▀█▀░▀▀█░█▀█"
    echo "  ░█░█░░█░░▄▀░░█░█"
    echo "  ░▀░▀░▀▀▀░▀▀▀░▀░▀"
    echo -e "  ${DIM}kernel-level network agent${NC}"
    echo
}

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
export PATH="$REAL_HOME/.cargo/bin:$PATH"

[[ $EUID -ne 0 ]] && error "MIZN requires root (sudo ./run.sh) for CAP_BPF + CAP_NET_ADMIN."

print_banner

TELEMETRY_SOCK="/run/miznd.sock"
CMD_SOCK="/run/miznd_cmd.sock"

cleanup() {
    echo
    info "Initiating shutdown..."
    [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -f "$TELEMETRY_SOCK" "$CMD_SOCK"
    info "All resources released. Goodbye."
}
trap cleanup EXIT INT TERM

info "Ensuring nightly rust-src component is present..."
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu 2>/dev/null || \
    rustup component add rust-src --toolchain nightly 2>/dev/null || \
    warn "Could not add rust-src — build may fail if not already installed."

info "Building eBPF program and userspace binaries..."
dim "  cargo xtask build"
if ! cargo xtask build; then
    error "Build failed — check output above."
fi
info "Build successful."
echo

rm -f "$TELEMETRY_SOCK" "$CMD_SOCK"

IFACE="${MIZN_IFACE:-}"
if [[ -z "$IFACE" ]]; then
    IFACE=$(find /sys/class/net -mindepth 1 -maxdepth 1 | while read -r p; do
        n=$(basename "$p")
        [[ "$n" == "lo" ]] && continue
        state=$(cat "$p/operstate" 2>/dev/null || echo "down")
        [[ "$state" == "up" ]] && echo "$n" && break
    done)
    IFACE="${IFACE:-wlan0}"
fi
info "Attaching XDP to interface: ${CYAN}${BOLD}${IFACE}${NC}"
export MIZN_IFACE="$IFACE"

info "Igniting kernel daemon (miznd)..."
./target/debug/miznd &
DAEMON_PID=$!

info "Waiting for IPC channels to stabilise..."
TIMEOUT=30
while (( TIMEOUT > 0 )); do
    if [[ -S "$TELEMETRY_SOCK" ]] && [[ -S "$CMD_SOCK" ]]; then
        break
    fi
    sleep 0.5
    (( TIMEOUT -= 1 ))
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        error "Daemon (miznd) died unexpectedly during startup."
    fi
done

if [[ ! -S "$TELEMETRY_SOCK" ]]; then
    error "Telemetry socket never appeared — is the eBPF program loading correctly?"
fi

info "Daemon ready (PID ${BOLD}$DAEMON_PID${NC})."
echo


info "Launching btop-style dashboard (mizn-ui)..."
dim "  Press [Q] to quit  |  Press [B] to block the top IP via XDP"
echo
./target/debug/mizn-ui
