from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        if proto == 6:  # TCP
            proto_name = 'TCP'
        elif proto == 17:  # UDP
            proto_name = 'UDP'
        else:
            proto_name = 'Other'

        print(f"IP Packet: {ip_src} -> {ip_dst} ({proto_name})")

# Capture packets
sniff(prn=packet_callback, store=0)
