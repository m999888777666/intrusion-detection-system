from scapy.all import *
from models import Alert
import config
from stats_manager import *
class SYNFloodDetector:
    def __init__(self,stats_manager):
        self.stats_manager=stats_manager
    def detect(self,packet):
        if IP in packet and TCP in packet:
            if "S" in packet[TCP].flags:
                src_ip=packet[IP].src
                syn_count=self.stats_manager.record_syn(src_ip)
                if syn_count > config.SYN_FLOOD_THRESHOLD:
                    alert1=Alert=(       #CLASS...
                        src_ip=packet[IP].src,
                        alert_type="SYN_FLOOD",
                        severity="HIGH",
                        details=f"{syn_count} SYN packets detected in {config.WINDOW_SECONDS}s"
                    )
                    return alert1
            return None


