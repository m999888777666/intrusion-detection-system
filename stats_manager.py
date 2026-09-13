import time
class StatsManager:
    def __init__(self):
        self.ip_stats=dict()
    def record_syn(self,src_ip,window_seconds=5):
        now=time.time()
        if not src_ip in self.ip_stats:
            self.ip_stats[src_ip]={
                "syn_timestamps":list(),
                "scanned_ports":set(),
                "icmp_timestamps":list()
            }
        self.ip_stats[src_ip]["syn_timestamps"].append(now)
        guncel_zamanlar=list()
        for i in self.ip_stats[src_ip]["syn_timestamps"]:
            if now - i<= window_seconds:
                guncel_zamanlar.append(i)
        self.ip_stats[src_ip]["syn_timestamps"] = guncel_zamanlar
        return len(self.ip_stats[src_ip]["syn_timestamps"])
    def record_port(self, src_ip, dst_port):
        if not src_ip in self.ip_stats:
            self.ip_stats[src_ip]={
                "syn_timestamps":list(),
                "scanned_ports":set(),
                "icmp_timestamps":list()
            }
        self.ip_stats[src_ip]["scanned_ports"].add(dst_port)
        return len(self.ip_stats[src_ip]["scanned_ports"])
    def record_icmp(self, src_ip, window_seconds=5):
        now=time.time()
        if not src_ip in self.ip_stats:
            self.ip_stats[src_ip]={
                "syn_timestamps":list(),
                "scanned_ports":set(),
                "icmp_timestamps":list()
            }
        self.ip_stats[src_ip]["icmp_timestamps"].append(now)
        guncel_zamanlar=list()
        for i in self.ip_stats[src_ip]["icmp_timestamps"]:
            if now - i<= window_seconds:
                guncel_zamanlar.append(i)
        self.ip_stats[src_ip]["icmp_timestamps"] = guncel_zamanlar
        return len(self.ip_stats[src_ip]["icmp_timestamps"])

             
