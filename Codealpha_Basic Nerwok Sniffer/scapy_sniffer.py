"""scapy_sniffer.py

Human-friendly Scapy-based packet sniffer.

Features:
- Clear, human-readable output
- Small packet limit by default to make testing easy
- Command-line options: ``--count`` and ``--iface``

Usage:
    pip install scapy
    python scapy_sniffer.py --count 20

This file keeps the original behaviour but uses clearer names,
docstrings and minimal formatting for readability.
"""

from datetime import datetime
import argparse

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
except Exception as e:
    raise SystemExit(
        "Scapy is required. Install with: pip install scapy\n" + str(e)
    )


# Simple counters for a short summary at the end
stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}

# Default packet capture limit for easy testing
DEFAULT_PACKET_LIMIT = 20


def identify_service_by_port(sport, dport):
    """Return a short service name for common ports, or None."""
    known = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
        53: "DNS", 110: "POP3", 143: "IMAP", 3306: "MySQL",
        5432: "PostgreSQL", 3389: "RDP", 8080: "HTTP-Alt",
    }
    for port in (dport, sport):
        if port in known:
            return known[port]
    return None


def handle_packet(packet):
    """Called by Scapy for every captured packet. Prints a readable summary."""
    stats["total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print("\n" + "=" * 60)
    print(f"PACKET #{stats['total']}  [{timestamp}]")
    print("=" * 60)

    # Layer 2: Ethernet (if present)
    if Ether in packet:
        eth = packet[Ether]
        print(f"Ethernet:  Src={eth.src}  Dst={eth.dst}")

    # Layer 3: IP
    if IP in packet:
        ip = packet[IP]
        print(f"IP:        Src={ip.src}  Dst={ip.dst}  TTL={ip.ttl}  Proto={ip.proto}  Len={ip.len}")

        # TCP
        if TCP in packet:
            stats["tcp"] += 1
            tcp = packet[TCP]
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            print(f"TCP:       {tcp.sport} -> {tcp.dport}  Seq={tcp.seq}  Ack={tcp.ack}")
            print(f"Flags:     {' | '.join(flags) if flags else 'None'}")
            service = identify_service_by_port(tcp.sport, tcp.dport)
            if service:
                print(f"Service:   {service}")

        # UDP
        elif UDP in packet:
            stats["udp"] += 1
            udp = packet[UDP]
            print(f"UDP:       {udp.sport} -> {udp.dport}  Length={udp.len}")

        # ICMP
        elif ICMP in packet:
            stats["icmp"] += 1
            icmp = packet[ICMP]
            icmp_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            label = icmp_names.get(icmp.type, f"Type {icmp.type}")
            print(f"ICMP:      {label}  Code={icmp.code}")

        else:
            stats["other"] += 1

        # Payload (application data)
        if Raw in packet:
            raw_data = packet[Raw].load
            length = len(raw_data)
            print(f"Payload:   {length} bytes")
            try:
                text = raw_data.decode("utf-8", errors="replace")
                preview = text[:120].replace("\n", " ").replace("\r", "")
                print(f"Preview:   {preview}")
            except Exception:
                print(f"Preview:   (binary, {raw_data[:32].hex()}...)")

    else:
        stats["other"] += 1
        print(f"Non-IP packet: {packet.summary()}")


def print_summary():
    """Print totals collected during the capture."""
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    print(f"Total packets : {stats['total']}")
    print(f"TCP           : {stats['tcp']}")
    print(f"UDP           : {stats['udp']}")
    print(f"ICMP          : {stats['icmp']}")
    print(f"Other         : {stats['other']}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Human-friendly Scapy packet sniffer")
    parser.add_argument("--count", "-c", type=int, default=DEFAULT_PACKET_LIMIT,
                        help="number of packets to capture (0 = unlimited)")
    parser.add_argument("--iface", "-i", default=None, help="interface to capture on (optional)")
    args = parser.parse_args()

    print("Scapy Network Sniffer")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Capturing: {args.count if args.count else 'unlimited'} packets")

    try:
        sniff(prn=handle_packet, count=args.count, store=False, iface=args.iface)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied: try running with elevated privileges or administrator rights.")
    except RuntimeError as e:
        msg = str(e).lower()
        if "winpcap" in msg or "npcap" in msg:
            print("Npcap/WinPcap not found or not configured. See https://npcap.com/")
        else:
            print(f"Runtime error: {e}")
    finally:
        print_summary()


if __name__ == "__main__":
    main()
