import re
import socket
import subprocess
from rich.console import Console

console = Console()

def get_myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_network(ip):
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"

def scan_network(network):
    console.print(f"[dim]Scanning {network}...[/dim]")
    result = subprocess.run(
        ["nmap", "-sn", "--privileged", network],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return _parse_to_dicts(result.stdout)

def _parse_to_dicts(raw_output: str) -> list:
    devices = []
    current = {}
    for line in raw_output.split("\n"):
        if "Nmap scan report for" in line:
            if current.get("ip"):
                devices.append(current)

            m = re.search(r"\(?([\d\.]+)\)?$", line)
            ip = m.group(1) if m else line.split()[-1]
            current = {"ip": ip, "mac": "", "vendor": ""}
        elif "MAC Address:" in line:

            parts = line.split("MAC Address:", 1)[1].strip().split(" ", 1)
            current["mac"] = parts[0].lower()
            if len(parts) > 1:
                current["vendor"] = parts[1].strip("()")
    if current.get("ip"):
        devices.append(current)
    return devices

def parse_results(device_list) -> list:

    if not device_list:
        return []
    if isinstance(device_list[0], dict):
        return [d["ip"] for d in device_list]

    hosts = []
    for line in str(device_list).split("\n"):
        if "Nmap scan report for" in line:
            ip = line.split()[-1].strip("()")
            hosts.append(ip)
    return hosts
