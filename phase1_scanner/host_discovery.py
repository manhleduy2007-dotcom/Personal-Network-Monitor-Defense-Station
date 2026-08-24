import socket 
import subprocess 
from rich.console import Console
from rich.table import Table

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
        capture_output=True,
        text=True
    )
    return result.stdout

def parse_results(raw_output): 
    hosts = [] 
    lines = raw_output.split("\n") 
    for line in lines: 
        if "Nmap scan report for" in line: 
            parts = line.split() 
            ip = parts[-1] 
            hosts.append(ip)
    return hosts

def show_results(hosts, my_ip):
    table = Table(title="Devices on LAN Network")
    table.add_column("numbers", style="dim", width=5)
    table.add_column("IP Address", style="cyan")
    table.add_column("note", style="yellow")

    for i, ip in enumerate(hosts, 1):
        note = "← My laptop" if ip == my_ip else ""
        table.add_row(str(i), ip, note)

    console.print(table)
    console.print(f"[green]Find out {len(hosts)} devices[/green]\n")


def main():
    console.print("\n[bold]Personal Network Monitor — Phase 1[/bold]\n")
    my_ip = get_myip()
    console.print(f"myIP: [cyan]{my_ip}[/cyan]")
    network = get_network(my_ip)
    console.print(f"Network have to be scanned: [cyan]{network}[/cyan]\n")
    raw = scan_network(network)
    hosts = parse_results(raw)
    if hosts:
        show_results(hosts, my_ip)
    else:
        console.print("[red]Can't find any devices on network.[/red]")
if __name__ == "__main__":
    main()
"""
- Use socket to fake connect to Google DNS sever => get the IP of my laptop 
- Seperate the IP into 2 parts => get the network to be scanned 
- Call the nmap to send ARP request to all IPs in the net work 
(ARP request is in the layer 2 of OSI model) => get the result of the scan
"""