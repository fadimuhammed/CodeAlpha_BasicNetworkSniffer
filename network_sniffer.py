from scapy.all import *

def packet_callback(packet):
    print("=" * 60)

    if IP in packet:
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol        : {packet[IP].proto}")

    if TCP in packet:
        print("Transport       : TCP")
        print(f"Source Port     : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif UDP in packet:
        print("Transport       : UDP")
        print(f"Source Port     : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    elif ICMP in packet:
        print("Transport       : ICMP")

    if packet.payload:
        payload = bytes(packet.payload)
        print(f"Payload ({len(payload)} bytes):")
        print(payload[:64])

print("Starting Network Sniffer...")
print("Press Ctrl+C to stop.\n")

sniff(prn=packet_callback, store=False)
