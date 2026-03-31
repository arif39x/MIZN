# MIZN

MIZN is a digital guardian for your computer's network. It acts like a watchful sentinel that looks at every piece of data entering or leaving your system, ensuring that everything is working as it should and that no unwanted guests are trying to cause trouble.

Unlike traditional security software that might slow down your computer, MIZN works deep inside the system using modern technology that allows it to monitor traffic with almost zero impact on performance. It is designed to be both powerful for experts and clear for everyone else.

## What MIZN Does

MIZN provides several layers of protection and visibility into your network activity:

**Smart Connection Monitoring**
It observes all network traffic in real-time. By working at a very deep level within the system, it can see everything without your computer even noticing it is there.

**Application Awareness**
MIZN doesn't just see traffic; it knows which application is responsible for it. It connects the dots between the data on the wire and the programs running on your machine, so you always know exactly what your software is doing online.

**Hidden Pattern Detection**
Security isn't just about where data is going, but what it looks like. MIZN analyzes the data for unusual patterns or hidden signals that might suggest something suspicious, like an infected program trying to talk to a malicious server.

**Digital Decoys**
To catch intruders before they can do any harm, MIZN sets up clever traps called honey-ports. These look like vulnerable entry points to a hacker, but in reality, they are silent alarms that alert you the moment someone tries to poke around where they shouldn't.

**Network Identity Protection**
On a local network, it is possible for a device to pretend to be another. MIZN watches for these identity theft attempts (known as ARP spoofing) and ensures that your connection stays mapped to the right hardware.

**A Smooth Control Center**
All this data is brought together in a fast, beautiful desktop interface. It is built to be incredibly responsive, giving you a clear view of your network's health without any lag or complexity.

## Technology

MIZN is built using some of the most reliable and efficient tools available today:

- **Rust**: A modern programming language focused on safety and high performance.
- **eBPF**: A specialized technology that allows for deep, safe, and lightning-fast network monitoring.
- **SQLite**: A robust and lightweight database used to store your network history securely.
- **egui**: A modern framework used to create the smooth and responsive dashboard.

## Getting Started

To use MIZN, you will need to run it with administrative privileges because it interacts directly with the core of your operating system.

1. Download the project code.
2. Open your terminal in the project folder.
3. Run the master launcher script:
   `sudo ./run.sh`

This will guide you through starting the background monitor and opening the visual dashboard.
