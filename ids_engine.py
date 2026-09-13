from scapy.all import *
def packet_callback(packet):
    print(packet.summary())
    if IP in packet:
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        if TCP in packet:
            src_port=packet[TCP].sport
            dst_port=packet[TCP].dport
            fag=packet[TCP].flags
            print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flag: {fag}")
        elif ICMP in packet:
            icmp_type=packet[ICMP].type
            print(f"[ICMP] {src_ip} -> {dst_ip} | Type: {icmp_type}")
sniff(prn=packet_callback,count=10)
    