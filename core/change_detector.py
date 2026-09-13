import json
from datetime import datetime
# pyrefly: ignore [missing-import]
from rich.console import Console
 
console = Console()
 
SAVE_FILE = "data/last_scan.json"
 
 
def save_scan(hosts):
    data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hosts": hosts
    }
    with open(SAVE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Results saved to {SAVE_FILE}[/dim]")
 
 
def load_last_scan():
    try:
        with open(SAVE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
 
 
def compare_scans(old_hosts, new_hosts):
    old_set = set(old_hosts)
    new_set = set(new_hosts)
 
    appeared = new_set - old_set    
    disappeared = old_set - new_set  
 
    return list(appeared), list(disappeared)