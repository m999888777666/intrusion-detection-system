from scapy.all import *
from stats_manager import StatsManager
stats=StatsManager() #yakalanan her paket aynı hafıza nesnesine işlenecek.
def packet_callback(packet):
    print(packet.summary()) #PAKET ÖZETİ
    if IP in packet:
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        if TCP in packet:
            src_port=packet[TCP].sport
            dst_port=packet[TCP].dport
            fag=packet[TCP].flags
            cnt=stats.record_port(src_ip,dst_port)
            if cnt>5:
                print(f"[!] ALARM: Port scan detected from {src_ip}!")
            if "S" in packet[TCP].flags:
                if stats.record_syn(src_ip)>10:
                    print(f"[!] ALARM: SYN Flood detected from {src_ip}!")
            print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flag: {fag}")
        elif ICMP in packet:
            icmp_type=packet[ICMP].type
            if stats.record_icmp(src_ip)>10:
                print(f"[!] ALARM: ICMP Flood detected from {src_ip}!")

            print(f"[ICMP] {src_ip} -> {dst_ip} | Type: {icmp_type}")
sniff(filter="ip", prn=packet_callback)
    