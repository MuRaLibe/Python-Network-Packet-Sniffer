from scapy.all import *
from datetime import datetime
from utils.colors import *

packet_count = 0

tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0

def analyze_packet(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global dns_count

    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    print(INFO + "\n========================================")

    print(SUCCESS + f"Packet Number   : {packet_count}")
    print(INFO + f"Timestamp       : {timestamp}")

    # Packet Size
    print(WARNING + f"Packet Size     : {len(packet)} bytes")

    # Ethernet Layer
    if packet.haslayer(Ether):

        print(INFO + f"Source MAC      : {packet[Ether].src}")
        print(INFO + f"Destination MAC : {packet[Ether].dst}")

    # IP Layer
    if packet.haslayer(IP):

        print(SUCCESS + f"Source IP       : {packet[IP].src}")
        print(SUCCESS + f"Destination IP  : {packet[IP].dst}")

    # TCP
    if packet.haslayer(TCP):

        tcp_count += 1

        print(WARNING + "Protocol        : TCP")

        print(INFO + f"Source Port     : {packet[TCP].sport}")
        print(INFO + f"Destination Port: {packet[TCP].dport}")

    # UDP
    elif packet.haslayer(UDP):

        udp_count += 1

        print(WARNING + "Protocol        : UDP")

        print(INFO + f"Source Port     : {packet[UDP].sport}")
        print(INFO + f"Destination Port: {packet[UDP].dport}")

    # ICMP
    elif packet.haslayer(ICMP):

        icmp_count += 1

        print(ERROR + "Protocol        : ICMP")

    # DNS Detection
    if packet.haslayer(DNSQR):

        dns_count += 1

        dns_query = packet[DNSQR].qname.decode()

        print(SUCCESS + "\n========== DNS DETECTED ==========")
        print(WARNING + f"Visited Website : {dns_query}")

    # Statistics
    print(SUCCESS + "\n========== STATISTICS ==========")

    print(INFO + f"Total Packets : {packet_count}")
    print(INFO + f"TCP Packets   : {tcp_count}")
    print(INFO + f"UDP Packets   : {udp_count}")
    print(INFO + f"ICMP Packets  : {icmp_count}")
    print(INFO + f"DNS Requests  : {dns_count}")

    # Save logs
    with open("logs/packets.txt", "a") as file:

        file.write(
            f"[{timestamp}] "
            f"{packet.summary()} | "
            f"Size: {len(packet)} bytes\n"
        )