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
        ["nmap", "-sn", network],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout
 
 
def parse_results(raw_output):
    hosts = []
    for line in raw_output.split("\n"):
        if "Nmap scan report for" in line:
            ip = line.split()[-1].strip("()")
            hosts.append(ip)
    return hosts
