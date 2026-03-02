# MIZN

![MIZN Logo](asset/MIZN-logo.jpeg)

MIZN is a side project I’m building to get a raw, unfiltered look at how my network talks with my system. The purpose will be to provide a ‘raw and dirty’ view on how a system communicates with my system, built by human for humans.

---

## The "Why Factor..!!" Behind this project

Majority of the network tools are heavy. They have to watch the kernel completely before seeing a packet themselves. By this time, CPU cycles have been wasted and context information is lost. Mechanical Sympathy is one of the mindsets I’m building **MIZN** with. I want to make the code work with the hardware, not against it. This means:

### Early Packet Capture

The way I’ve built this is all about Mechanical Sympathy. Most monitoring tools wait for the kernel to do the heavy lifting—parsing the packet, moving it through the network stack, and finally handing it to an application. By the time a normal tool sees a packet, the CPU has already burned through thousands of cycles just moving data around.
I didn't want that overhead.
Instead, I’m using **XDP** (Express Data Path) to "hook" into the network driver itself. In my mizn-ebpf code, I’m essentially placing a specialized guard right at the system's "front door" (the Network Interface Card). Before the kernel even allocates memory for the packet in the main system stack, my eBPF program is already looking at the raw bytes.

### Seeing through encryption

Encryption usually makes network monitoring a **Black Box** where you can see the volume of data but have no idea where it’s actually going.
I’ve engineered MIZN to be a bit smarter than that.Insted of trying to break the encryption "Which is impossible without key"..I am trying to create somthing intercepts **TLS Clint Hello** the very first handshake message a browser or app sends out. During this initial exchange, the destination is actually sent in plain text as part of the Server Name Indication (SNI).By surgically extracting this fie;d directly in the kernal..MIZN can identify if a process is reaching out to a trusted site like google.com or a potentially malicious endpoint, all without ever needing to touch your private data. It’s about getting maximum visibility while respecting the "Zero-Trust" nature of modern traffic.

### Zero-Copy Logic

MIZN — the idea that software should cooperate with hardware, not fight it. By using XDP, it captures packets at the network driver level, long before they travel through the heavy kernel stack. That early access allows true zero-copy data handling, updating telemetry directly in eBPF maps without wasting CPU cycles. To stay stable under heavy traffic, it relies on branchless logic and atomic operations to avoid stalls and race conditions. Even with encrypted traffic, it extracts SNI from the TLS handshake to understand connection intent. From kernel to TUI, zero-copy IPC keeps everything fast and lightweight.

---

## How It's Actually Built

### mizn-ebpf

This is the "front line" of the system. While it is written in Rust, it is compiled specifically for the BPF virtual machine to run directly inside the Linux kernel. By attaching to the XDP (Express Data Path) hook, it intercepts raw packets at the network driver level—before the kernel even begins the expensive process of parsing them for the standard networking stack.

### miznd

user-space daemon acts as the system's controller and "detective". the kernel sees the packets, it doesn't naturally know which application they belong to. miznd solves this by performing a low-level audit of the /proc filesystem. It maps every open network socket to a specific Process ID (PID) and binary name (like firefox or discord) by correlating socket inodes with local ports. It then pulls the raw metrics from the eBPF maps, merges them with this process metadata, and streams the result to the UI.

mizn-ui
TUI is terminal-based dashboard which turns raw binary data into a real-time command center. Instead of wasting CPU cycles on heavy graphical overhead, it uses Ratatui to render live bandwidth graphs, process-specific throughput lists, and distribution charts directly in terminal. Because I hate wasting memory, the UI doesn't "re-create" the data it receives; it uses a zero-copy pattern to look directly at the memory buffer sent by the daemon, ensuring that dashboard stays fluid and responsive even if your network is hitting gigabit speeds.

---

## WARNING(Its in α-STATUS)

**This project is in the ACTIVE BULDING PHASE.It is experimental, incomplete and unstable**

**SYSTEM TERMINATION RISK**: Executing this codebase injects raw eBPF bytecode directly into your kernel's critical path; any logic failure or unhandled edge case will result in an immediate, catastrophic kernel panic and total system death. I accept zero liability for the destruction of your hardware, the corruption of your data, or the permanent instability of your network stack—if you trigger this machine and it annihilates your environment, the fault is yours alone.

---

**Sk Arif Ali**
**GitHub**: [arif39x](https://www.google.com/search?q=https://github.com/arif39x)
**Mail**:[arif](aliarif1168@gmail.com)
