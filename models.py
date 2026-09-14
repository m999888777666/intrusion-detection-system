from datetime import datetime
class Alert:
    def __init__(self,src_ip,alert_type,severity,details=""):
        self.src_ip=src_ip
        self.alert_type=alert_type
        self.severity=severity
        self.details=details
        self.timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    def __str__(self):
        return f"[{self.timestamp}] [{self.severity}] {self.alert_type} from {self.src_ip} - Details: {self.details}"
