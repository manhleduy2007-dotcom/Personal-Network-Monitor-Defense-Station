import csv
import os
from datetime import datetime

LOG_FILE = "logs/alert_log.csv"


def log_alert(ip: str):
    file_exists = os.path.exists(LOG_FILE)

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "ip"])

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip
        })

    print(f"[LOG] Ghi alert: {ip}")