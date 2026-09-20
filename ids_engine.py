from scapy.all import sniff
from stats_manager import StatsManager
from alert_manager import AlertManager
from detectors.syn_flood import SYNFloodDetector
from detectors.port_scan import PortScanDetector
from detectors.icmp_flood import ICMPFloodDetector
class IDSEngine:
    def __init__(self):
        self.stats_manager=StatsManager()
        self.alert_manager=AlertManager()
        self.detectors=[
            ICMPFloodDetector(self.stats_manager),
            SYNFloodDetector(self.stats_manager),
            PortScanDetector(self.stats_manager)
        ]
    def packet_callback(self, packet):
        for detector in self.detectors:
            alert=detector.detect(packet)
            if alert:
                self.alert_manager.process_alert(alert)
    def start(self):
        print("IDS has started...\n")
        sniff(filter="ip",prn=self.packet_callback,store=0)


