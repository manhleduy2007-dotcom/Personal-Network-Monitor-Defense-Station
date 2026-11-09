import argparse
import logging
import os
import time
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)  

from rich.console import Console
from rich.markup import escape

from config import SCAN_INTERVAL
from core.monitor import Monitor

console = Console()
LEVEL_STYLE = {"ok": "green", "warn": "yellow", "err": "bold red", "dim": "dim", "info": "cyan"}


def print_event(event: dict):
    t = datetime.fromisoformat(event["time"]).strftime("%H:%M:%S")
    style = LEVEL_STYLE.get(event["level"], "")
    console.print(f"[dim]{t}[/dim] [{style}]{escape(event['msg'])}[/{style}]" if style
                  else f"[dim]{t}[/dim] {escape(event['msg'])}")


def parse_args():
    parser = argparse.ArgumentParser(description="Personal Network Monitor Defense Station")
    parser.add_argument("--no-web", action="store_true", help="run the monitor without the web dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="web host (default: 127.0.0.1, this machine only)")
    parser.add_argument("--port", type=int, default=5050, help="web port (default: 5050)")
    parser.add_argument("--interval", type=int, default=SCAN_INTERVAL, help="seconds between scans")
    return parser.parse_args()


def main():
    args = parse_args()
    console.print("\n[bold]Personal Network Monitor — Phase 4[/bold]\n")

    monitor = Monitor(interval=args.interval, on_event=print_event)
    console.print(f"My IP:    [cyan]{monitor.my_ip}[/cyan]")
    console.print(f"Network:  [cyan]{monitor.network}[/cyan]")
    console.print(f"Interval: [cyan]{monitor.interval}s[/cyan]\n")
    if not monitor.is_root:
        console.print("[bold red][!] Not running as root, scans will fail.[/bold red] "
                      "Use: sudo venv/bin/python main.py\n")

    monitor.start()

    try:
        if args.no_web:
            while True:
                time.sleep(1)
        else:
            from web.app import create_app
            logging.getLogger("werkzeug").setLevel(logging.WARNING)
            console.print(f"[bold green]Dashboard:[/bold green] http://{args.host}:{args.port}\n")
            create_app(monitor).run(host=args.host, port=args.port,
                                    debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        console.print("\n[dim]Monitor stopped.[/dim]")


if __name__ == "__main__":
    main()