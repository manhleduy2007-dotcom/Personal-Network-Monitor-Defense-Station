import json
import socket
import subprocess
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
SAVE_FILE = "phase1_scanner/last_scan.json"


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

    appeared = new_set - old_set    # in new scan but not in old
    disappeared = old_set - new_set  # in old scan but not in new

    return list(appeared), list(disappeared)


def show_changes(appeared, disappeared, old_time):
    """Display changes compared to the previous scan."""
    console.print(f"\n[bold]Compared to scan at {old_time}:[/bold]\n")

    if not appeared and not disappeared:
        console.print("[green]No changes — network is stable.[/green]")
        return

    if appeared:
        table = Table(title="New Devices Detected", border_style="red")
        table.add_column("IP Address", style="red")
        table.add_column("Warning", style="yellow")
        for ip in appeared:
            table.add_row(ip, "Unknown device joined the network!")
        console.print(table)

    if disappeared:
        table = Table(title="Devices Gone Offline", border_style="dim")
        table.add_column("IP Address", style="dim")
        table.add_column("Status", style="dim")
        for ip in disappeared:
            table.add_row(ip, "No longer on network")
        console.print(table)


def show_current(hosts, my_ip):
    """Display current list of online devices."""
    table = Table(title="Devices Online")
    table.add_column("No.", style="dim", width=5)
    table.add_column("IP Address", style="cyan")
    table.add_column("Note", style="yellow")

    for i, ip in enumerate(hosts, 1):
        note = "← This machine" if ip == my_ip else ""
        table.add_row(str(i), ip, note)

    console.print(table)
    console.print(f"[green]Found {len(hosts)} device(s)[/green]\n")


def main():
    console.print("\n[bold]Personal Network Monitor — Change Detector[/bold]\n")

    # Current scan
    my_ip = get_myip()
    network = get_network(my_ip)
    console.print(f"My IP: [cyan]{my_ip}[/cyan]")
    console.print(f"Scanning: [cyan]{network}[/cyan]\n")

    raw = scan_network(network)
    current_hosts = parse_results(raw)

    # Show current results
    show_current(current_hosts, my_ip)

    # Compare with previous scan
    last_scan = load_last_scan()
    if last_scan is None:
        console.print("[yellow]First run — no previous data to compare.[/yellow]")
        console.print("[dim]Run again to see the comparison feature.[/dim]\n")
    else:
        appeared, disappeared = compare_scans(
            last_scan["hosts"],
            current_hosts
        )
        show_changes(appeared, disappeared, last_scan["scan_time"])

    # Save current results for next comparison
    save_scan(current_hosts)

if __name__ == "__main__":
    main()