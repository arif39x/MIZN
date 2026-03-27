```
░█▄█░▀█▀░▀▀█░█▀█
░█░█░░█░░▄▀░░█░█
░▀░▀░▀▀▀░▀▀▀░▀░▀
```

<p align="center">
  <img src="asset/MIZN-LOGO.png" width="340" alt="MIZN Logo"/>
</p>

<p align="center">
  <b>Real-time network monitor that lives inside your kernel.</b><br/>
  <i>eBPF / XDP / Ratatui / Rust / Zero-Copy / SNI Extraction / XDP Firewall</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/lang-Rust-orange?style=flat-square&logo=rust"/>
  <img src="https://img.shields.io/badge/kernel-eBPF%20%2F%20XDP-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20only-informational?style=flat-square&logo=linux"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

## Overview

MIZN is a kernel-level network monitoring tool built in Rust. It hooks into the Linux networking stack at the XDP (eXpress Data Path) layer — intercepting packets at the NIC driver before the kernel allocates memory for them. A userspace daemon reads the eBPF maps, resolves process ownership, and streams telemetry to a btop-style terminal dashboard over a Unix socket.

---

## Features

- **XDP-level packet interception** — captures traffic before the kernel networking stack processes it
- **Per-process bandwidth tracking** — maps network flows to PIDs via `/proc/net/tcp` and `/proc/net/udp`
- **TLS SNI extraction** — reads the plaintext Server Name Indication field from TLS Client Hello messages
- **TCP and UDP flow tracking** — parses both Protocol 6 (TCP) and Protocol 17 (UDP)
- **XDP Firewall / IPS** — dynamically blocks source IPs at the driver level using a BPF hash map and `XDP_DROP`
- **TCP anomaly detection** — flags SYN-without-ACK patterns (port scans) and highlights them in the UI
- **Local telemetry persistence** — writes historical flow logs (timestamp, PID, process, bytes, SNI) to a CSV file
- **Process watchlist** — pins critical processes (sshd, nginx) to the top of the dashboard regardless of bandwidth
- **Zero-copy data path** — kernel maps to daemon to TUI with no unnecessary allocations
- **btop-style terminal dashboard** — Braille graphs, rounded borders, modular panels, live security alerts

---

## Dashboard Layout

<p align="center">
  <img src="asset/MIZN_UI.png" alt="MIZN TUI Dashboard" width="700"/>
</p>

```
+-- RX/s --------+-- TX/s --------+-- PEAK --------+-- INTERFACE ---+
|  1.2 MB/s       |  340 KB/s      |  8.4 MB/s      |  wlp3s0        |
+-----------------+----------------+----------------+----------------+
+-- THROUGHPUT 60s --------------------------------------------------+
|  [Braille RX/TX line chart]                                        |
+--------------------------------------------------------------------+
+-- PROCESS & CONNECTION MONITOR -----------+-- ACTIVE ALERTS -------+
|  PID  BINARY      RX/s  TX/s  SNI  FLAGS |  Port Scan: sshd       |
|  ...  nginx       ...   ...   ...  ACK   +-- XDP FIREWALL --------+
|  ...  curl        ...   ...   ...  SYN   |  1.2.3.4 (blocked)     |
+------------------------------------------+------------------------+
+-- [Q] Quit  [B] Block Top IP  MIZN kernel agent active ------------+
```

**Panels:**

| Panel | Purpose |
|-------|---------|
| Header | Live RX/TX rates, peak throughput, active network interface |
| Throughput Graph | 60-second Braille chart with dual RX/TX datasets |
| Process Table | Per-process PID, binary name, RX, TX, total, SNI/destination, TCP flags |
| Active Alerts | Scrolling list of detected anomalies (SYN scans, high bandwidth spikes) |
| XDP Firewall | List of IPs currently blocked at the driver level |

---

## Architecture

```
+--------------------------------------------------+
|                  Linux Kernel                     |
|  +--------------------------------------------+  |
|  |  mizn-ebpf  (eBPF/XDP program)             |  |
|  |  - hooks at NIC driver level                |  |
|  |  - parses Ethernet > IP > TCP/UDP           |  |
|  |  - writes to FLOW_METRICS map               |  |
|  |  - enforces BLOCKLIST map (XDP_DROP)        |  |
|  +---------------------+----------------------+  |
+-----------------------|--------------------------+
                        | aya (reads BPF maps)
              +---------v----------+
              |       miznd        |
              |  userspace daemon  |
              |  - resolves PIDs   |
              |  - writes CSV log  |
              |  - manages blocklist|
              +---------+----------+
                        | /run/miznd.sock (telemetry)
                        | /run/miznd_cmd.sock (commands)
              +---------v----------+
              |      mizn-ui       |
              |  ratatui terminal  |
              |  btop-style layout |
              +--------------------+
```

### mizn-ebpf

XDP program compiled for the BPF VM using `cargo +nightly` with `build-std=core`. Runs at the NIC driver level. Parses Ethernet, IPv4, TCP, and UDP headers. Builds flow keys, extracts SNI from TLS Client Hello messages, and enforces the BLOCKLIST map by returning `XDP_DROP` for matched source IPs.

### miznd

Userspace daemon. Reads eBPF maps via the `aya` crate. Resolves socket-to-PID mappings by scanning `/proc/net/tcp` and `/proc/net/udp`. Writes historical flow logs to `miznd_flow_history.csv`. Manages a command socket (`/run/miznd_cmd.sock`) for dynamic IP blocking. Streams serialized telemetry snapshots (via `rkyv`) to the UI over `/run/miznd.sock` every second.

### mizn-ui

Terminal dashboard built with `ratatui`. Four-panel btop-style layout with a header stats row, 60-second Braille throughput chart, annotated process/connection table, and a live security panel showing active alerts and blocked IPs.

### mizn-common

Shared types used by both kernel and userspace: `FlowKey`, `FlowMetrics`, `IpcState`, `IpcProcessMetrics`, and `IpcCommand`.

---

## Warning

**This is alpha software. Do not run this on a production machine.**

This tool injects eBPF bytecode into the kernel's critical networking path. Incorrect behaviour can cause kernel panics and system crashes.

Requirements:
- Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN`)
- Linux only (tested on kernel 5.15+)
- Will not work on WSL or VMs without NIC passthrough
- Falls back to XDP SKB mode if native mode is not supported

---

## Getting Started

### Prerequisites

```bash
# Rust nightly toolchain with BPF target
rustup install nightly
rustup target add bpfel-unknown-none
rustup component add rust-src --toolchain nightly

# Kernel headers and clang
sudo apt install linux-headers-$(uname -r) clang llvm libelf-dev

# Optional: bpftool for debugging
sudo apt install linux-tools-$(uname -r)
```

### Clone

```bash
git clone https://github.com/arif39x/MIZN.git
cd MIZN
```

### Build and Run

```bash
sudo ./run.sh
```

The script builds the eBPF object and all userspace binaries, then starts the daemon and launches the dashboard.

To force a specific network interface:

```bash
sudo MIZN_IFACE=eth0 ./run.sh
```

### Keybindings

| Key | Action |
|-----|--------|
| `q` / `Esc` | Exit |
| `b` | Block the top bandwidth-consuming IP via XDP |

---

## Project Structure

```
MIZN/
├── mizn-ebpf/         # eBPF/XDP kernel program (Rust, no_std)
│                        TCP + UDP parsing, SNI extraction, BLOCKLIST enforcement
├── miznd/             # Userspace daemon
│                        BPF map reader, PID resolver, CSV logger, IPS command socket
├── mizn-ui/           # Terminal dashboard (ratatui)
│                        Header, graph, process table, security panel
├── mizn-common/       # Shared types
│                        FlowKey, FlowMetrics, IpcState, IpcCommand
├── xtask/             # Build orchestrator
│                        Compiles eBPF before userspace
├── asset/             # Logo and screenshots
├── run.sh             # One-shot build and launch script
└── .gitignore
```

---

## Roadmap

Prerequisites for deep learning integration:

- [ ] Persistent time-series logging to SQLite or ClickHouse for ML training datasets
- [ ] ICMP parsing and full IPv6 support
- [ ] Layer 7 protocol dissectors (HTTP, DNS, SQL) for deep packet inspection
- [ ] Headless alerting engine (webhooks, Slack, email)
- [ ] On-demand PCAP recording for forensic analysis

---

## Contributing

If you know eBPF or Rust kernel internals, issues and pull requests are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-thing`)
3. Verify the build (`cargo xtask build`)
4. Open a pull request with a description of what changed and why

When reporting bugs, include:
- Kernel version (`uname -r`)
- NIC type and driver
- Full error output

---

## Contact

**Sk Arif Ali**

- GitHub: [@arif39x](https://github.com/arif39x)
- Email: [aliarif1168@gmail.com](mailto:aliarif1168@gmail.com)

---

<p align="center">
  <sub>Built with too much caffeine and an unhealthy obsession with kernel internals.</sub>
</p>

---

`#ebpf` `#xdp` `#rust` `#linux` `#network-monitor` `#kernel` `#tui` `#ratatui` `#zero-copy` `#aya` `#bpf` `#networking` `#terminal` `#sni` `#tls` `#systems-programming` `#low-level` `#performance` `#observability` `#linux-kernel` `#xdp-firewall` `#ips`
