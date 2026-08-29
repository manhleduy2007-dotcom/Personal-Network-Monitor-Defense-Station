import json
from datetime import datetime
from rich.console import Console
 
console = Console()
 
SAVE_FILE = "data/last_scan.json"  # đổi từ phase1_scanner/ → data/
 
 
def save_scan(hosts):
    """Save scan results to JSON file."""
    data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hosts": hosts
    }
    with open(SAVE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Results saved to {SAVE_FILE}[/dim]")
 
 
def load_last_scan():
    """Load previous scan results. Returns None if no file found."""
    try:
        with open(SAVE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
 
 
def compare_scans(old_hosts, new_hosts):
    """Compare two scans — find new and missing devices."""
    old_set = set(old_hosts)
    new_set = set(new_hosts)
 
    appeared = new_set - old_set     # in new scan but not in old
    disappeared = old_set - new_set  # in old scan but not in new
 
    return list(appeared), list(disappeared)