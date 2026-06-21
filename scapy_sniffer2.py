"""
╔══════════════════════════════════════════════════════════╗
║        NETWORK SNIFFER — Scapy Version (Easier!)         ║
║   Task 1: Capture, Analyze & Display Network Packets     ║
╚══════════════════════════════════════════════════════════╝

INSTALL: pip install scapy
RUN:     sudo python3 scapy_sniffer.py        (Linux/Mac)
         python scapy_sniffer.py              (Windows Admin)

Scapy auto-parses every layer — much less code than raw sockets.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
from datetime import datetime

# ─────────────────────────────────────────────
# PACKET COUNTER
# ─────────────────────────────────────────────
stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}

PACKET_LIMIT = 20   # how many packets to capture


# ─────────────────────────────────────────────
# CALLBACK: runs for every captured packet
# ─────────────────────────────────────────────
def process_packet(packet):
    """
    Scapy calls this function for each captured packet.
    We check which layers exist using the 'in' operator.
    """
    stats["total"] += 1
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"\n{'═'*60}")
    print(f"  📦 PACKET #{stats['total']}  [{ts}]")
    print(f"{'═'*60}")

    # ── Layer 2: Ethernet ──
    if Ether in packet:
        eth = packet[Ether]
        print(f"  {'[Ethernet]':<14} Src: {eth.src:<20} Dst: {eth.dst}")

    # ── Layer 3: IP ──
    if IP in packet:
        ip = packet[IP]
        print(f"  {'[IP]':<14} Src: {ip.src:<20} Dst: {ip.dst}")
        print(f"  {'':14} TTL: {ip.ttl}   Proto: {ip.proto}   Len: {ip.len} bytes")

        # ── Layer 4: TCP ──
        if TCP in packet:
            stats["tcp"] += 1
            tcp = packet[TCP]
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            print(f"  {'[TCP]':<14} Src Port: {tcp.sport:<8} Dst Port: {tcp.dport}")
            print(f"  {'':14} Seq: {tcp.seq}   Ack: {tcp.ack}")
            print(f"  {'':14} Flags: {' | '.join(flags) if flags else 'None'}")

            # Identify common services by port
            service = port_to_service(tcp.sport, tcp.dport)
            if service:
                print(f"  {'':14} Service: {service}")

        # ── Layer 4: UDP ──
        elif UDP in packet:
            stats["udp"] += 1
            udp = packet[UDP]
            print(f"  {'[UDP]':<14} Src Port: {udp.sport:<8} Dst Port: {udp.dport}")
            print(f"  {'':14} Length: {udp.len} bytes")

        # ── Layer 4: ICMP ──
        elif ICMP in packet:
            stats["icmp"] += 1
            icmp = packet[ICMP]
            type_names = {0: "Echo Reply", 8: "Echo Request (Ping)",
                          3: "Dest Unreachable", 11: "Time Exceeded"}
            type_label = type_names.get(icmp.type, f"Type {icmp.type}")
            print(f"  {'[ICMP]':<14} Type: {type_label}   Code: {icmp.code}")

        else:
            stats["other"] += 1

        # ── Payload / Application Data ──
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"  {'[Payload]':<14} {len(raw_data)} bytes")
            try:
                decoded = raw_data.decode("utf-8", errors="replace")
                preview = decoded[:120].replace("\n", " ").replace("\r", "")
                print(f"  {'':14} {preview}")
            except Exception:
                hex_preview = raw_data[:32].hex()
                print(f"  {'':14} (hex) {hex_preview}...")

    else:
        stats["other"] += 1
        print(f"  [Non-IP packet]  {packet.summary()}")


# ─────────────────────────────────────────────
# SERVICE IDENTIFICATION BY PORT
# ─────────────────────────────────────────────
def port_to_service(sport, dport):
    known = {
        80:   "HTTP", 443: "HTTPS", 22: "SSH",
        21:   "FTP",  25: "SMTP",   53: "DNS",
        110:  "POP3", 143: "IMAP",  3306: "MySQL",
        5432: "PostgreSQL", 3389: "RDP", 8080: "HTTP-Alt",
    }
    for port in [dport, sport]:
        if port in known:
            return known[port]
    return None


# ─────────────────────────────────────────────
# STATS SUMMARY
# ─────────────────────────────────────────────
def print_stats():
    print(f"\n\n{'═'*60}")
    print("  📊 CAPTURE SUMMARY")
    print(f"{'═'*60}")
    print(f"  Total packets : {stats['total']}")
    print(f"  TCP           : {stats['tcp']}")
    print(f"  UDP           : {stats['udp']}")
    print(f"  ICMP          : {stats['icmp']}")
    print(f"  Other         : {stats['other']}")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      🔍 SCAPY NETWORK SNIFFER — TASK 1                  ║")
    print("║   Capturing packets... Press Ctrl+C to stop             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Capturing {PACKET_LIMIT} packets...\n")

    try:
        sniff(
            prn=process_packet,       # callback per packet
            count=PACKET_LIMIT,       # 0 = unlimited
            store=False,              # don't store in memory (saves RAM)
            # iface="eth0",           # uncomment to filter by interface
            # filter="tcp port 80",   # BPF filter (optional)
        )
    except KeyboardInterrupt:
        print("\n\n  ⏹  Capture stopped by user.")
    except PermissionError:
        print("\n  ❌ Run with: sudo python3 scapy_sniffer.py")
    except RuntimeError as e:
        if "winpcap" in str(e).lower():
            print("\n  ❌ ERROR: WinPcap/Npcap not installed!")
            print("\n  📌 SOLUTION for Windows:")
            print("     1. Install Npcap: https://npcap.com/download.html")
            print("     2. During installation, check 'Install Npcap in WinPcap API-compatible Mode'")
            print("     3. Run as Administrator")
            print("\n  💡 Alternative: Use windows_sniffer.py (no dependencies needed!)")
        else:
            print(f"\n  ❌ ERROR: {e}")

    finally:
        print_stats()
