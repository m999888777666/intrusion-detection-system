from scapy.all import *
from models import Alert
import config
#from stats_manager import *
#   def record_icmp(self, src_ip, window_seconds=5):
class ICMPFloodDetector:
    def __init__(self,stats_manager):
        self.stats_manager=stats_manager
    def detect(self,packet):
        if IP in packet and ICMP in packet:
            src_ip=packet[IP].src
            cnt=self.stats_manager.record_icmp(src_ip)
            if cnt > config.ICMP_FLOOD_THRESHOLD:
                alert3=Alert(
                    src_ip=src_ip,
                    alert_type="ICMP_FLOOD",
                    severity="HIGH",
                    details=f"{cnt} ICMP packets detected in {config.WINDOW_SECONDS}s"
                )
                return alert3
        return None

