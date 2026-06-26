<div align="center">

# 🔍 Network Packet Sniffer

**A human-friendly, real-time network packet analyzer built with Python & Scapy**

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Internship](https://img.shields.io/badge/CodeAlpha-Task%201-orange?style=for-the-badge)

*Built as Task 1 of the CodeAlpha Cybersecurity Internship*

</div>

---

## 📌 Overview

**Network Packet Sniffer** is a command-line tool that captures and analyzes live network traffic in real time. It decodes packets layer by layer — from Ethernet frames all the way up to application-layer payloads — and prints everything in clean, human-readable format. A summary of all captured traffic is displayed at the end of each session.

This project was built from scratch using **Python** and **Scapy**, with no third-party GUI dependencies.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📦 **Layer-by-Layer Decoding** | Parses Ethernet → IP → TCP / UDP / ICMP in sequence |
| 🔎 **Service Detection** | Identifies 12 common services by port (HTTP, HTTPS, SSH, DNS, RDP, etc.) |
| 🏳️ **TCP Flag Analysis** | Detects SYN, ACK, FIN, RST, PSH flags for connection state tracking |
| 📄 **Payload Preview** | Shows first 120 characters of UTF-8 application data per packet |
| 📊 **Capture Summary** | Prints protocol breakdown totals at end of every session |
| ⚙️ **CLI Arguments** | `--count` and `--iface` flags for flexible capture control |
| 🛑 **Graceful Exit** | Handles `Ctrl+C` and permission errors cleanly with informative messages |
| 🕒 **Timestamps** | Millisecond-precision timestamps on every captured packet |

---

## 🧱 Protocol Support

```
┌─────────────────────────────────────────────┐
│              Application Layer               │  HTTP · HTTPS · SSH · FTP · DNS
│                                              │  SMTP · MySQL · RDP · and more
├─────────────────────────────────────────────┤
│               Transport Layer                │  TCP (with flag decoding) · UDP
├─────────────────────────────────────────────┤
│                Network Layer                 │  IPv4 (src, dst, TTL, length)
├─────────────────────────────────────────────┤
│                 Data Link                    │  Ethernet (MAC addresses)
└─────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
network-sniffer/
├── scapy_sniffer.py     ← Main sniffer script (all logic)
└── README.md            ← This file
```

---

## ⚙️ Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.7 or higher | [python.org](https://www.python.org/downloads/) |
| Scapy | 2.5 or higher | Installed via pip |
| **Windows** — Npcap | Latest | [npcap.com](https://npcap.com/) — required for raw socket access |
| **Linux/macOS** — Root | — | Run with `sudo` for capture permissions |

---

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CodeAlpha_ProjectName.git
cd CodeAlpha_ProjectName
```

### 2. Install Scapy

```bash
pip install scapy
```

### 3. Windows Only — Install Npcap

Download and install from **[https://npcap.com/](https://npcap.com/)**

> ✅ Check **"Install Npcap in WinPcap API-compatible Mode"** during installation.

---

## ▶️ Usage

### Basic Capture (20 packets — default)
```bash
python scapy_sniffer.py
```

### Capture a Custom Number of Packets
```bash
python scapy_sniffer.py --count 50
```

### Capture on a Specific Network Interface
```bash
python scapy_sniffer.py --iface eth0          # Linux
python scapy_sniffer.py --iface "Wi-Fi"       # Windows
```

### Capture Unlimited Packets (until Ctrl+C)
```bash
python scapy_sniffer.py --count 0
```

### Short Flags
```bash
python scapy_sniffer.py -c 30 -i eth0
```

### Windows — Run as Administrator
```
Right-click Command Prompt → Run as Administrator → python scapy_sniffer.py
```

### Linux/macOS — Run with sudo
```bash
sudo python scapy_sniffer.py --count 30
```

---

## 📋 Sample Output

```
Scapy Network Sniffer
Started at: 2024-11-15 14:32:07
Capturing: 20 packets

============================================================
PACKET #1  [14:32:07.412]
============================================================
Ethernet:  Src=a4:c3:f0:12:34:56  Dst=ff:ff:ff:ff:ff:ff
IP:        Src=192.168.1.105  Dst=142.250.194.46  TTL=64  Proto=6  Len=52
TCP:       54321 -> 443  Seq=1928374650  Ack=0
Flags:     SYN
Service:   HTTPS

============================================================
PACKET #2  [14:32:07.538]
============================================================
Ethernet:  Src=a4:c3:f0:12:34:56  Dst=00:1a:2b:3c:4d:5e
IP:        Src=192.168.1.105  Dst=8.8.8.8  TTL=64  Proto=17  Len=73
UDP:       52412 -> 53  Length=53
Service:   DNS

============================================================
PACKET #3  [14:32:07.621]
============================================================
IP:        Src=192.168.1.1  Dst=192.168.1.105  TTL=128  Proto=1  Len=60
ICMP:      Echo Reply  Code=0

============================================================
CAPTURE SUMMARY
============================================================
Total packets : 20
TCP           : 14
UDP           : 4
ICMP          : 1
Other         : 1
============================================================
```

---

## 🔧 Command-Line Reference

| Argument | Short | Default | Description |
|---|---|---|---|
| `--count` | `-c` | `20` | Number of packets to capture (`0` = unlimited) |
| `--iface` | `-i` | System default | Network interface to capture on |

---

## 🧠 How It Works

```
Network Traffic
      │
      ▼
┌─────────────┐
│  Scapy sniff│  ← Captures raw packets from NIC using Npcap / libpcap
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  handle_packet()│  ← Called for every captured packet
└──────┬──────────┘
       │
       ├──► Ethernet Layer  →  MAC addresses
       │
       ├──► IP Layer        →  Source/Destination IP, TTL, Protocol
       │
       ├──► TCP Layer       →  Ports, Flags (SYN/ACK/FIN/RST/PSH)
       │       └──► identify_service_by_port()  →  Service name
       │
       ├──► UDP Layer       →  Ports, Length
       │
       ├──► ICMP Layer      →  Type (Echo Request/Reply/Unreachable)
       │
       └──► Raw Payload     →  UTF-8 preview (first 120 chars)
              │
              ▼
       print_summary()  ←  Protocol totals after capture ends
```

---

## 🔒 Security & Ethics Notice

> **This tool is built for educational purposes and authorized network analysis only.**

- ✅ Use only on networks you own or have explicit written permission to test
- ✅ Ideal for learning network protocols in a home lab or classroom
- ❌ Do NOT use on public networks, corporate networks without authorization, or to intercept others' communications
- ❌ Unauthorized packet sniffing is illegal in most jurisdictions

*The author is not responsible for misuse of this tool.*

---

## 🛠️ Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `PermissionError` | Not running as admin/root | Windows: Run as Administrator. Linux: Use `sudo` |
| `Npcap not found` | Npcap not installed | Download from [npcap.com](https://npcap.com/) |
| `ModuleNotFoundError: scapy` | Scapy not installed | Run `pip install scapy` |
| No packets captured | Wrong interface | Run `python -c "from scapy.all import get_if_list; print(get_if_list())"` to list interfaces |
| Only non-IP packets | Loopback interface selected | Switch to your Wi-Fi or Ethernet interface |

---

## 🚀 Possible Improvements

- [ ] BPF filter support (`--filter "tcp port 80"`)
- [ ] Export captures to `.pcap` files (Wireshark-compatible)
- [ ] IPv6 packet parsing
- [ ] DNS query/response decoding
- [ ] HTTP request/response parsing
- [ ] Colored terminal output
- [ ] Real-time statistics dashboard

---

## 📚 References & Learning Resources

- [Scapy Official Documentation](https://scapy.readthedocs.io/)
- [Npcap — Windows Packet Capture](https://npcap.com/)
- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [Wireshark — Network Protocol Analyzer](https://www.wireshark.org/)

---

## 👨‍💻 Author

**Moses**
ECE Student — J.N.N. Institute of Engineering (JNNCE)
CodeAlpha Cybersecurity Intern

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/mosess26)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/YOUR_USERNAME)

---

## 📝 Internship Details

| Field | Detail |
|---|---|
| Organization | CodeAlpha |
| Program | Cybersecurity Internship |
| Task | Task 1 — Basic Network Sniffer |
| Language | Python 3 |
| Library | Scapy |
| Repository | `CodeAlpha_ProjectName` |

---

<div align="center">

*Built with 🔒 for the CodeAlpha Cybersecurity Internship*

</div>
