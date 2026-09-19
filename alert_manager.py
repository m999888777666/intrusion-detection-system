import config
from models import Alert
class AlertManager:
    def __init__(self,log_file=config.LOG_FILE_PATH):
        self.log_file=log_file
    def process_alert(self,alert):
        print(f"[ALERT] {alert}")
        with open(self.log_file,"a") as dosya:
            dosya.write(f"{alert}\n")