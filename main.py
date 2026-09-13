import time
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.table import Table
from core.scanner import get_myip, get_network, scan_network, parse_results
from core.change_detector import load_last_scan, save_scan, compare_scans
from core.notifier import send_alert
from core.whitelist import is_trusted, add_to_whitelist
from core.logger import log_alert
from config import SCAN_INTERVAL
console = Console()

def show_current(hosts, my_ip):
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
    console.print(f"\n[bold]Compared to scan at {old_time}:[/bold]\n")
    if not appeared and not disappeared:
        console.print("[green]No changes — network is stable.[/green]")
        return
    if appeared:
        table = Table(title="New Devices Detected", border_style="red")
        table.add_column("IP Address", style="red")
        table.add_column("Status", style="yellow")
        for ip in appeared:
            trusted = is_trusted(ip)
            status = "✓ Whitelisted" if trusted else "⚠ UNKNOWN — alert sent!"
            table.add_row(ip, status)
        console.print(table)
    if disappeared:
        table = Table(title="Devices Gone Offline", border_style="dim")
        table.add_column("IP Address", style="dim")
        table.add_column("Status", style="dim")
        for ip in disappeared:
            table.add_row(ip, "No longer on network")
        console.print(table)


def process_appeared(appeared: list):
    """Xử lý thiết bị mới — check whitelist, gửi alert, ghi log."""
    for ip in appeared:
        if is_trusted(ip):
            console.print(f"[green][OK] {ip} — whitelisted[/green]")
        else:
            console.print(f"[red][!!] {ip} — UNKNOWN, sending alert...[/red]")
            send_alert(ip)
            log_alert(ip)


def main():
    console.print("\n[bold]Personal Network Monitor — Phase 1[/bold]\n")
    my_ip = get_myip()
    if not is_trusted(my_ip):
        add_to_whitelist(my_ip)
        console.print(f"[dim]Auto-whitelisted own IP: {my_ip}[/dim]")

    network = get_network(my_ip)
    console.print(f"My IP: [cyan]{my_ip}[/cyan]")
    console.print(f"Network: [cyan]{network}[/cyan]\n")

    while True:
        console.print("[dim]Scanning...[/dim]")
        raw = scan_network(network)
        current_hosts = parse_results(raw)

        show_current(current_hosts, my_ip)

        last_scan = load_last_scan()
        if last_scan is None:
            console.print("[yellow]First run — no previous data.[/yellow]\n")
        else:
            appeared, disappeared = compare_scans(last_scan["hosts"], current_hosts)
            show_changes(appeared, disappeared, last_scan["scan_time"])
            process_appeared(appeared)

        save_scan(current_hosts)
        console.print(f"\n[dim]Next scan in {SCAN_INTERVAL}s...[/dim]\n")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()