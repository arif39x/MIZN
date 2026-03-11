```
░█▄█░▀█▀░▀▀█░█▀█
░█░█░░█░░▄▀░░█░█
░▀░▀░▀▀▀░▀▀▀░▀░▀
```

<p align="center">
  <img src="asset/MIZN-LOGO.png" width="340" alt="MIZN Logo"/>
</p>

<p align="center">
  <b>real-time network monitor that lives inside your kernel.</b><br/>
  <i>eBPF · XDP · TUI · Rust · Zero-Copy · SNI extraction</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha%20%F0%9F%94%A5-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/lang-Rust-orange?style=flat-square&logo=rust"/>
  <img src="https://img.shields.io/badge/kernel-eBPF%20%2F%20XDP-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20only-informational?style=flat-square&logo=linux"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

## ok so what even is this

honestly i dont fully know why im doing this.

like.. i already have `nethogs`, i already have `iftop`, i already have like 14 other tools that do "network monitoring" but none of them felt right. they're all slow, heavy, ugly, or they just.. lie to me. I wanted something that tells me _exactly_ what's happening on my machine at the driver level. not after the kernel finishes playing with the packet. not after 3 layers of abstraction. **right now. at the wire.**

so i built MIZN. its probably overkill. it definitely broke my system twice during development. I dont know why im doing this but here we are.

---

## what it actually does

<p align="center">
  <img src="asset/MIZN_UI.png" alt="MIZN TUI Dashboard" width="700"/>
</p>

- **hooks into your kernel at XDP** — intercepts packets before linux even touches them
- **shows you per-process bandwidth** — firefox eating 40 MB/s? you'll see it immediately
- **extracts SNI from TLS handshakes** — even with encrypted traffic it can tell you _where_ a process is connecting to (by reading the plain-text SNI field in the TLS Client Hello)
- **zero-copy everything** — kernel maps → daemon → TUI, no unnecessary data movement
- **works in a terminal** — no electron, no browser, no java, just a blazing fast ratatui TUI

---

## how its built

```
┌─────────────────────────────────────────────────┐
│                  Linux Kernel                   │
│  ┌─────────────────────────────────────────┐    │
│  │  mizn-ebpf  (eBPF/XDP program)          │    │
│  │  hooks at network driver, reads packets │    │
│  │  writes to BPF maps (FLOW_METRICS)      │    │
│  └────────────────────┬────────────────────┘    │
└───────────────────────┼─────────────────────────┘
                        │ reads maps via aya
              ┌─────────▼──────────┐
              │       miznd        │
              │  user-space daemon │
              │  resolves PID/name │
              │  via /proc/net/tcp │
              │  streams over unix │
              │  socket (rkyv)     │
              └─────────┬──────────┘
                        │ unix socket
              ┌─────────▼──────────┐
              │      mizn-ui       │
              │  ratatui terminal  │
              │  live charts/table │
              └────────────────────┘
```

### `mizn-ebpf`

XDP program compiled for the BPF VM. sits at the NIC level and grabs packets before the kernel networking stack even thinks about allocating memory for them. parses ethernet → ip → tcp, builds flow keys, extracts SNI from TLS Client Hello.

### `miznd`

the daemon that does the boring but important stuff. reads the ebpf maps via `aya`, audits `/proc` to figure out which open sockets belong to which process, and streams serialized telemetry over a unix domain socket every second.

### `mizn-ui`

terminal UI built with `ratatui`. live bandwidth graph (60s history), per-process table sorted by throughput, bar chart showing traffic distribution. press `q` to quit.

---

## WARNING ⚠️

**THIS IS ALPHA SOFTWARE. DO NOT RUN THIS ON A MACHINE YOU CARE ABOUT.**

this thing injects eBPF bytecode directly into your kernel's critical path. if something goes wrong the kernel panics and your system dies. ive had it happen. it's not fun. you've been warned.

- requires **root** (or `CAP_BPF` + `CAP_NET_ADMIN`)
- **Linux only** (tested on kernel 5.15+)
- wont work on WSL or VMs without proper NIC passthrough
- XDP in `SKB` mode is used as fallback if native mode isn't supported

---

## getting started

### prereqs

```bash
# you need the rust nightly toolchain + bpf target
rustup install nightly
rustup target add bpfel-unknown-none

# kernel headers + clang (for bpf compilation)
sudo apt install linux-headers-$(uname -r) clang llvm libelf-dev

# bpftool (optional but helpful for debugging)
sudo apt install linux-tools-$(uname -r)
```

### clone it

```bash
git clone https://github.com/arif39x/MIZN.git
cd MIZN
```

### build & run

```bash
# builds ebpf binary first, then miznd + mizn-ui
sudo ./run.sh
```

thats it. the script handles everything — builds the eBPF object, sets capabilities, starts the daemon, waits for the socket, then launches the UI.

> **tip:** if you have multiple network interfaces or MIZN picks the wrong one you can force it:
>
> ```bash
> sudo MIZN_IFACE=eth0 ./run.sh
> ```

### keybindings

| key         | action |
| ----------- | ------ |
| `q` / `Esc` | exit   |

---

## project structure

```
MIZN/
├── mizn-ebpf/     # eBPF/XDP kernel program (Rust, no_std)
├── miznd/         # user-space daemon
├── mizn-ui/       # terminal UI client
├── mizn-common/   # shared types (FlowKey, FlowMetrics, IPC structs)
├── xtask/         # build orchestrator (builds ebpf before userspace)
└── run.sh         # one shot run script
```

---

## wanna contribute?

honestly if you're reading this and you know eBPF or Rust kernel stuff better than me (which is likely) please open an issue or a PR. i am figuring this out as i go.

some things i actually need help with:

- [ ] IPv6 support (currently only IPv4)
- [ ] UDP flow tracking
- [ ] proper SNI hostname string extraction beyond 16 bytes
- [ ] persisting flow history to disk
- [ ] packaging (nix flake? deb? idk)
- [ ] making it not crash ur system

**how to contribute:**

1. fork the repo
2. make your changes in a new branch (`git checkout -b feat/your-thing`)
3. make sure it builds (`cargo xtask build`)
4. open a pull request with a short description of what you changed and why
5. i'll review it when i'm not debugging kernel panics

if you find a bug please open an issue with:

- your kernel version (`uname -r`)
- your NIC type / driver
- the full error output

---

## contact

**Sk Arif Ali**

- GitHub: [@arif39x](https://github.com/arif39x)
- Mail: [aliarif1168@gmail.com](mailto:aliarif1168@gmail.com)

---

<p align="center">
  <sub>built with too much caffeine and a unhealthy obsession with kernel internals</sub>
</p>

---

`#ebpf` `#xdp` `#rust` `#linux` `#network-monitor` `#kernel` `#tui` `#ratatui` `#zero-copy` `#aya` `#bpf` `#networking` `#terminal` `#sni` `#tls` `#systems-programming` `#low-level` `#performance` `#observability` `#linux-kernel`
