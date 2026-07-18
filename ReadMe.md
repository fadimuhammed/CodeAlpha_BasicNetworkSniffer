# Network Packet Sniffer & Analyzer

A simple Python tool for capturing live network traffic and inspecting how
data flows across the OSI layers — Ethernet, IP, TCP/UDP, and application
payloads. Built with [Scapy](https://scapy.net/).

## What it does

- Captures live packets from a network interface
- Parses and displays:
  - Ethernet source/destination MAC addresses
  - IP source/destination addresses, TTL, length
  - TCP/UDP source/destination ports (with friendly names for common ports like HTTP, HTTPS, DNS, SSH)
  - TCP flags (SYN, ACK, FIN, etc.) and sequence numbers
  - ICMP type/code (e.g. ping traffic)
  - DNS query names, when present
  - A readable preview of the raw payload bytes
- Supports BPF filters (the same filter syntax used by `tcpdump`/Wireshark) so you can narrow capture to specific traffic
- Lets you limit capture to a fixed number of packets, or run indefinitely until stopped

## Requirements

- Python 3.7+
- [Npcap](https://npcap.com/) (Windows only — install with "WinPcap API-compatible mode" checked)
- Root/administrator privileges (raw packet capture requires elevated access)

## Installation

```bash
pip install scapy
```

## Usage

Basic capture (default interface, runs until Ctrl+C):

```bash
sudo python3 network_sniffer.py
```

Capture on a specific interface:

```bash
sudo python3 network_sniffer.py -i eth0
```

Capture a fixed number of packets:

```bash
sudo python3 network_sniffer.py -c 50
```

Apply a filter (BPF syntax) to capture only certain traffic:

```bash
sudo python3 network_sniffer.py -f "tcp port 80"
sudo python3 network_sniffer.py -f "udp port 53"
sudo python3 network_sniffer.py -f "icmp"
```

Suppress payload output (headers only):

```bash
sudo python3 network_sniffer.py --no-payload
```

Combine options:

```bash
sudo python3 network_sniffer.py -i eth0 -c 100 -f "tcp port 443"
```

### All options

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Network interface to sniff on | Scapy's default interface |
| `-c`, `--count` | Number of packets to capture (0 = unlimited) | 0 |
| `-f`, `--filter` | BPF filter string (e.g. `"tcp port 80"`) | none (captures everything) |
| `--no-payload` | Hide raw payload preview | payload shown |

## Example output

```
[14:32:07] Ethernet: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66
  IP: 192.168.1.10 -> 142.250.72.14 | TTL=64 | len=60 | proto_num=6
  TCP: 192.168.1.10:51422 (51422) -> 142.250.72.14:443 (HTTPS) | flags=S seq=123456 ack=0
----------------------------------------------------------------------
[14:32:07] Ethernet: 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff
  IP: 192.168.1.20 -> 192.168.1.1 | TTL=128 | len=70 | proto_num=17
  UDP: 192.168.1.20:54321 (54321) -> 192.168.1.1:53 (DNS) | len=42
  DNS Query: example.com.
----------------------------------------------------------------------
```

## Why privileges are needed

Capturing raw packets requires bypassing the operating system's normal
socket restrictions, which is why the OS requires elevated permissions
(`sudo` on Linux/macOS, "Run as Administrator" plus Npcap on Windows).
This is a standard requirement for any packet-capture tool, including
Wireshark and tcpdump.

## Learning notes

This script is a good way to observe protocol layering in practice:

1. **Ethernet (Layer 2)** — carries frames between devices on the same local network via MAC addresses.
2. **IP (Layer 3)** — routes packets between networks via IP addresses.
3. **TCP/UDP (Layer 4)** — delivers data to the correct application via port numbers; TCP adds reliability (flags, sequence numbers), UDP does not.
4. **Application data (Layer 7)** — the actual payload, such as an HTTP request or DNS query, carried inside the lower layers.

Try filtering to `tcp port 80` or watching DNS traffic first — both are
unencrypted, so you'll see readable payloads and query names. Most modern
traffic (HTTPS, port 443) is encrypted, so its payload will appear as
mostly non-printable bytes.

## Disclaimer

Only capture traffic on networks you own or have explicit permission to
monitor. Packet sniffing on networks without authorization may violate
local laws and organizational policies.
