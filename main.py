from rich.console import Console
from rich.table import Table

from core.scanner import get_myip, get_network, scan_network, parse_results
from core.change_detector import load_last_scan, save_scan, compare_scans
 
console = Console()
 
 
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