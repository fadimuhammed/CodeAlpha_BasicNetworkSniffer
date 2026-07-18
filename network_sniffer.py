#!/usr/bin/env python3
"""
Network Packet Sniffer & Analyzer
==================================
Captures live network packets using Scapy and displays useful
information about them: source/destination IPs, ports, protocol,
and a preview of the payload.

Requirements:
    pip install scapy

Usage:
    sudo python3 packet_sniffer.py                  # capture on default interface
    sudo python3 packet_sniffer.py -i eth0           # capture on a specific interface
    sudo python3 packet_sniffer.py -c 50             # stop after 50 packets
    sudo python3 packet_sniffer.py -f "tcp port 80"  # apply a BPF filter

NOTE: Packet capturing requires elevated/administrator privileges
      (root on Linux/macOS, "Run as Administrator" on Windows with Npcap installed).
"""

import argparse
import datetime

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR


# ----------------------------------------------------------------------
# Helper: map common port numbers to protocol names for readability
# ----------------------------------------------------------------------
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT",
}


def describe_port(port):
    """Return a friendly label for a port number, if known."""
    return COMMON_PORTS.get(port, str(port))


# ----------------------------------------------------------------------
# Core packet handler — called once per captured packet
# ----------------------------------------------------------------------
def process_packet(packet, show_payload=True, payload_len=64):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    lines = []

    # --- Layer 2: Ethernet -------------------------------------------------
    if Ether in packet:
        eth = packet[Ether]
        lines.append(f"[{timestamp}] Ethernet: {eth.src} -> {eth.dst}")

    # --- Layer 3: IP ---------------------------------------------------
    if IP in packet:
        ip = packet[IP]
        proto_num = ip.proto  # 6=TCP, 17=UDP, 1=ICMP
        lines.append(
            f"  IP: {ip.src} -> {ip.dst} | TTL={ip.ttl} | "
            f"len={ip.len} | proto_num={proto_num}"
        )

        # --- Layer 4: TCP ---------------------------------------------
        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%")
            lines.append(
                f"  TCP: {ip.src}:{tcp.sport} ({describe_port(tcp.sport)}) -> "
                f"{ip.dst}:{tcp.dport} ({describe_port(tcp.dport)}) | "
                f"flags={flags} seq={tcp.seq} ack={tcp.ack}"
            )

        # --- Layer 4: UDP ---------------------------------------------
        elif UDP in packet:
            udp = packet[UDP]
            lines.append(
                f"  UDP: {ip.src}:{udp.sport} ({describe_port(udp.sport)}) -> "
                f"{ip.dst}:{udp.dport} ({describe_port(udp.dport)}) | len={udp.len}"
            )

            # DNS is a common, easy-to-read UDP protocol to highlight
            if DNS in packet and packet[DNS].qdcount > 0:
                try:
                    qname = packet[DNSQR].qname.decode(errors="ignore")
                    lines.append(f"  DNS Query: {qname}")
                except Exception:
                    pass

        # --- Layer 4: ICMP ----------------------------------------------
        elif ICMP in packet:
            icmp = packet[ICMP]
            lines.append(f"  ICMP: type={icmp.type} code={icmp.code}")

        else:
            lines.append(f"  Other IP protocol (proto_num={proto_num})")

    else:
        # Non-IP traffic (ARP, etc.)
        lines.append(f"  Non-IP packet: {packet.summary()}")

    # --- Payload preview -------------------------------------------------
    if show_payload and packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        printable = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:payload_len]
        )
        lines.append(f"  Payload ({len(raw_bytes)} bytes): {printable}")

    print("\n".join(lines))
    print("-" * 70)


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Simple Scapy packet sniffer & analyzer")
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help='BPF filter string, e.g. "tcp port 80" or "udp port 53"')
    parser.add_argument("--no-payload", action="store_true",
                         help="Do not print payload contents")
    args = parser.parse_args()

    print("Starting packet capture...")
    print(f"  Interface : {args.iface or 'default'}")
    print(f"  Filter    : {args.filter or 'none'}")
    print(f"  Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter if args.filter else None,
            prn=lambda pkt: process_packet(pkt, show_payload=not args.no_payload),
            count=args.count,
            store=False,  # don't keep packets in memory, just process them
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
