from scapy.all import sniff, wrpcap
from utils.analyzer import analyze_packet
from utils.colors import *

captured_packets = []

def capture_packet(packet):

    captured_packets.append(packet)
    analyze_packet(packet)

print(SUCCESS + "=" * 55)
print(SUCCESS + "        NETWORK PACKET SNIFFER")
print(SUCCESS + "=" * 55)

print(INFO + "\nChoose Packet Filter:\n")

print(WARNING + "1. TCP")
print(WARNING + "2. UDP")
print(WARNING + "3. ICMP")
print(WARNING + "4. ALL TRAFFIC")

choice = input(INFO + "\nEnter choice: ")

packet_filter = ""

if choice == "1":
    packet_filter = "tcp"

elif choice == "2":
    packet_filter = "udp"

elif choice == "3":
    packet_filter = "icmp"

elif choice == "4":
    packet_filter = ""

else:
    print(ERROR + "\nInvalid choice. Capturing all traffic.\n")

print(SUCCESS + "\nStarting packet capture...")
print(WARNING + "Press CTRL + C to stop.\n")

try:

    sniff(
        filter=packet_filter,
        prn=capture_packet,
        store=False
    )

except KeyboardInterrupt:

    print(ERROR + "\nStopping packet capture...")

    wrpcap("logs/capture.pcap", captured_packets)

    print(SUCCESS + "Packets saved to logs/capture.pcap")
    print(SUCCESS + "Logs saved to logs/packets.txt")