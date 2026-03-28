#!/usr/bin/env bash
# MIZN — build & launch script
# Usage:
#   sudo ./run.sh
#   sudo MIZN_IFACE=eth0 ./run.sh
#   sudo MIZN_WEBHOOK_URL="https://hooks.slack.com/..." ./run.sh
#   sudo MIZN_SMTP_RELAY=smtp.gmail.com MIZN_SMTP_FROM=... MIZN_SMTP_TO=... ./run.sh
#   sudo MIZN_CH_URL=http://localhost:8123 ./run.sh      # ClickHouse streaming
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
    echo -e "  ${DIM}kernel-level network agent — ebpf / xdp / ipv6 / l7-dpi / sqlite / webhooks${NC}"
    echo
}

# ── Privilege check ──────────────────────────────────────────────────────────
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

# ── Dependency checks ────────────────────────────────────────────────────────
info "Checking build dependencies..."

command -v clang &>/dev/null  || error "clang not found — sudo apt install clang llvm"
command -v llvm-strip &>/dev/null || warn "llvm-strip not found (optional) — sudo apt install llvm"
dim "  clang $(clang --version 2>&1 | head -1)"

if command -v bpftool &>/dev/null; then
    dim "  bpftool $(bpftool version 2>&1 | head -1)"
else
    warn "bpftool not found — BTF/CO-RE debugging unavailable."
    warn "  Install: sudo apt install linux-tools-$(uname -r)"
fi

# ── CO-RE: generate vmlinux.h for BTF-based cross-kernel builds ─────────────
# This step is optional but strongly recommended for kernel portability.
# It extracts all kernel type definitions into a single header that makes
# MIZN work on any kernel 5.8+ without local kernel headers.
if command -v bpftool &>/dev/null && [[ ! -f mizn-ebpf/src/vmlinux.h ]]; then
    info "Generating CO-RE vmlinux.h from running kernel BTF..."
    if bpftool btf dump file /sys/kernel/btf/vmlinux format c > mizn-ebpf/src/vmlinux.h 2>/dev/null; then
        info "vmlinux.h generated — CO-RE / BTF enabled."
    else
        warn "vmlinux.h generation failed — falling back to manual structs."
        rm -f mizn-ebpf/src/vmlinux.h
    fi
elif [[ -f mizn-ebpf/src/vmlinux.h ]]; then
    dim "  vmlinux.h present — CO-RE enabled."
fi

# ── Rust nightly ─────────────────────────────────────────────────────────────
info "Ensuring nightly rust-src component is present..."
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu 2>/dev/null || \
    rustup component add rust-src --toolchain nightly 2>/dev/null || \
    warn "Could not add rust-src — build may fail."

# ── Build ────────────────────────────────────────────────────────────────────
info "Building eBPF program and all userspace binaries..."
dim "  cargo run --package xtask -- build"
cargo run --package xtask -- build || error "Build failed — check output above."
info "Build successful."
echo

rm -f "$TELEMETRY_SOCK" "$CMD_SOCK"

# ── Interface detection ──────────────────────────────────────────────────────
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

# ── Optional features summary ────────────────────────────────────────────────
echo
info "Optional integrations:"
if [[ -n "${MIZN_WEBHOOK_URL:-}" ]]; then
    dim "   Webhook alerting  ENABLED  → ${MIZN_WEBHOOK_URL}"
    export MIZN_WEBHOOK_URL
else
    dim "   Webhook alerting  disabled (set MIZN_WEBHOOK_URL)"
fi

if [[ -n "${MIZN_SMTP_RELAY:-}" ]]; then
    dim "   SMTP alerts       ENABLED  → ${MIZN_SMTP_FROM} → ${MIZN_SMTP_TO}"
    export MIZN_SMTP_RELAY MIZN_SMTP_FROM MIZN_SMTP_TO MIZN_SMTP_USER MIZN_SMTP_PASS
else
    dim "   SMTP alerts       disabled (set MIZN_SMTP_RELAY, MIZN_SMTP_FROM, MIZN_SMTP_TO)"
fi

if [[ -n "${MIZN_CH_URL:-}" ]]; then
    dim "   ClickHouse stream ENABLED  → ${MIZN_CH_URL}"
    export MIZN_CH_URL MIZN_CH_DB MIZN_CH_USER MIZN_CH_PASSWORD
else
    dim "   ClickHouse stream disabled (set MIZN_CH_URL)"
fi
echo

# ── PCAP capture directory ───────────────────────────────────────────────────
PCAP_DIR="/var/lib/mizn/pcap"
mkdir -p "$PCAP_DIR"
dim "  PCAP directory: $PCAP_DIR"
export MIZN_PCAP_DIR="$PCAP_DIR"

# ── Launch daemon ─────────────────────────────────────────────────────────────
info "Igniting kernel daemon (miznd)..."
./target/debug/miznd &
DAEMON_PID=$!

info "Waiting for IPC channels to stabilise..."
TIMEOUT=30
while (( TIMEOUT > 0 )); do
    if [[ -S "$TELEMETRY_SOCK" ]] && [[ -S "$CMD_SOCK" ]]; then break; fi
    sleep 0.5
    (( TIMEOUT -= 1 ))
    kill -0 "$DAEMON_PID" 2>/dev/null || error "Daemon (miznd) died during startup."
done
[[ -S "$TELEMETRY_SOCK" ]] || error "Telemetry socket never appeared."

info "Daemon ready (PID ${BOLD}$DAEMON_PID${NC})."
echo

# ── Launch TUI ────────────────────────────────────────────────────────────────
info "Launching btop-style dashboard (mizn-ui)..."
dim "  [Q] Quit  |  [B] Block top IP via XDP"
echo
./target/debug/mizn-ui
