from scapy.all import *
from models import Alert
import config
from stats_manager import *
class PortScanDetector:
    def __init__(self,stats_manager):
        self.stats_manager=stats_manager
    def detect(self,packet):
        if IP in packet and TCP in packet:
            dst_port=packet[TCP].dport
            src_ip=packet[IP].src
            cnt=self.stats_manager.record_port(src_ip,dst_port)
            if cnt>config.PORT_SCAN_THRESHOLD:
                alert2=Alert(
                    src_ip=packet[IP].src,
                    alert_type="PORT_SCAN",
                    severity="MEDIUM",
                    details=f"{cnt} unique ports scanned"
                )
                return alert2
            return None


