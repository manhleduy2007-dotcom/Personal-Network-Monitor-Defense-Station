# core/monitor.py
"""
Background network monitor shared by the console and the web dashboard.

One thread runs the scan loop (what main.py used to do). The web layer only
reads its state and can ask it to scan now; it never scans by itself.
"""
import json
import os
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from core.change_detector import compare_scans, load_last_scan, save_scan
from core.logger import log_alert
from core.notifier import send_port_alert
from core.port_scanner import scan_ports
from core.risk_rater import rate_host
from core.scanner import get_myip, get_network, parse_results, scan_network
from core.whitelist import add_to_whitelist, is_trusted

RESULT_FILE = Path("data/web_scan_result.json")
EVENT_BUFFER = 500


class Monitor:
    def __init__(self, interval: int, on_event=None):
        self.interval = max(10, int(interval))
        self.on_event = on_event  # optional callback, e.g. print to console

        self.my_ip = get_myip()
        self.network = get_network(self.my_ip)
        self.is_root = getattr(os, "geteuid", lambda: 0)() == 0

        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None

        self._status = {
            "state": "starting",  # starting | discovering | scanning | waiting | error
            "current_ip": None,
            "done": 0,
            "total": 0,
            "error": None,
            "cycle": 0,
            "next_scan_at": None,  # unix timestamp
        }
        self._result = self._load_result()
        self._events = deque(maxlen=EVENT_BUFFER)
        self._event_id = 0

    # ------------------------------------------------------------------ public
    def start(self):
        if not is_trusted(self.my_ip):
            add_to_whitelist(self.my_ip)
            self.emit("dim", f"auto-whitelisted own IP {self.my_ip}")
        self._thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def trigger_scan(self) -> bool:
        """Ask the loop to scan now. Returns False if a scan is already running."""
        with self._lock:
            if self._status["state"] in ("discovering", "scanning"):
                return False
        self._wake.set()
        return True

    def status(self) -> dict:
        with self._lock:
            return dict(self._status, interval=self.interval,
                        finished_at=self._result.get("finished_at"))

    def result(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._result))  # deep copy

    def events_since(self, event_id: int, limit: int = 200) -> list:
        with self._lock:
            items = [e for e in self._events if e["id"] > event_id]
        return items[-limit:]

    def emit(self, level: str, msg: str):
        """level: info | ok | warn | err | dim"""
        with self._lock:
            self._event_id += 1
            event = {
                "id": self._event_id,
                "time": datetime.now().isoformat(timespec="seconds"),
                "level": level,
                "msg": msg,
            }
            self._events.append(event)
        if self.on_event:
            self.on_event(event)

    # ----------------------------------------------------------------- loop
    def _loop(self):
        self.emit("ok", f"monitor started on {self.network}, scanning every {self.interval}s")
        if not self.is_root:
            self.emit("err", "[!] not running as root: nmap will fail. Restart with: sudo venv/bin/python main.py")

        while not self._stop.is_set():
            self._run_cycle()

            next_at = time.time() + self.interval
            self._set_status(next_scan_at=next_at,
                             state="error" if self._status["error"] else "waiting")
            # Sleep until the interval passes, or until someone presses "scan now"
            self._wake.wait(timeout=self.interval)
            self._wake.clear()

    def _run_cycle(self):
        cycle = self._status["cycle"] + 1
        self._set_status(state="discovering", cycle=cycle, done=0, total=0,
                         current_ip=None, error=None, next_scan_at=None)
        self.emit("info", f"[>] scan #{cycle} started on {self.network}")

        try:
            hosts = parse_results(scan_network(self.network))
            if not hosts:
                # A working scan always finds at least this machine
                raise RuntimeError("no hosts found, not even this machine. "
                                   + ("Check nmap and the network range." if self.is_root
                                      else "Server is not running as root."))

            last = load_last_scan()
            appeared, disappeared = (compare_scans(last["hosts"], hosts) if last else ([], []))
            previous_ports = {d["ip"]: {p["port"] for p in d.get("ports", [])}
                              for d in self._result.get("devices", [])}

            self.emit("ok", f"[+] {len(hosts)} host(s) online")
            self._set_status(state="scanning", total=len(hosts))

            devices = []
            for i, ip in enumerate(hosts):
                if self._stop.is_set():
                    return
                self._set_status(current_ip=ip, done=i)
                self.emit("dim", f"[~] probing ports on {ip} ({i + 1}/{len(hosts)})")

                device, risk_result = self._scan_host(ip)
                devices.append(device)
                self._check_host(device, risk_result, appeared, previous_ports)

            for ip in disappeared:
                self.emit("dim", f"[-] {ip} went offline")

            save_scan(hosts)
            finished = datetime.now().isoformat(timespec="seconds")
            with self._lock:
                self._result = {"devices": devices, "finished_at": finished, "network": self.network}
            self._save_result()
            self._set_status(done=len(hosts), current_ip=None)

            threats = sum(1 for d in devices if d["risk"] in ("HIGH", "CRITICAL") and not d["is_self"])
            self.emit("warn" if threats else "ok",
                      f"[+] scan #{cycle} complete: {len(devices)} host(s), {threats} high-risk")

        except Exception as e:
            self._set_status(error=str(e), current_ip=None)
            self.emit("err", f"[x] scan #{cycle} failed: {e}")

    # ------------------------------------------------------------ per host
    def _scan_host(self, ip: str):
        open_ports = scan_ports(ip)
        risk_result = rate_host(open_ports)
        rated = {p["port"]: p for p in risk_result.get("rated_ports", [])}

        ports = []
        for p in open_ports:
            r = rated.get(p["port"], {})
            ports.append({
                "port": p["port"],
                "service": r.get("name") or p.get("service", "unknown"),
                "version": p.get("version", ""),
                "risk": str(r.get("risk", "UNKNOWN")).upper(),
                "note": r.get("description") or r.get("reason") or "",
            })
        device = {
            "ip": ip,
            "is_self": ip == self.my_ip,
            "ports": ports,
            "risk": str(risk_result.get("overall_risk", "UNKNOWN")).upper(),
        }
        return device, risk_result

    def _check_host(self, device: dict, risk_result: dict, appeared: list, previous_ports: dict):
        """
        Two independent checks:
          1. Unknown device joined the network            -> alert if not whitelisted
          2. Known host opened ports it did not have before -> alert EVEN IF whitelisted
        """
        ip = device["ip"]
        current = {p["port"] for p in device["ports"]}

        if ip in appeared and not is_trusted(ip):
            self._alert(ip, risk_result,
                        f"[!] NEW untrusted device {ip}, risk {device['risk']}, "
                        f"ports: {', '.join(map(str, sorted(current))) or 'none'}")
            return

        if ip in previous_ports:
            new_ports = current - previous_ports[ip]
            if new_ports:
                trust = "whitelisted" if is_trusted(ip) else "untrusted"
                self._alert(ip, risk_result,
                            f"[!] PORT CHANGE on {trust} host {ip}: newly open "
                            f"{', '.join(map(str, sorted(new_ports)))}")
            closed = previous_ports[ip] - current
            if closed:
                self.emit("dim", f"[-] {ip} closed port(s) {', '.join(map(str, sorted(closed)))}")

    def _alert(self, ip: str, risk_result: dict, message: str):
        self.emit("err", message)
        try:
            send_port_alert(ip, risk_result)
        except Exception as e:  # a broken notifier must never stop the monitor
            self.emit("warn", f"[!] notifier failed: {e}")
        try:
            log_alert(ip)
        except Exception as e:
            self.emit("warn", f"[!] alert log failed: {e}")

    # ------------------------------------------------------------- helpers
    def _set_status(self, **kwargs):
        with self._lock:
            self._status.update(kwargs)

    def _load_result(self) -> dict:
        try:
            return json.loads(RESULT_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"devices": [], "finished_at": None, "network": None}

    def _save_result(self):
        RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = RESULT_FILE.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(json.dumps(self._result, indent=2), encoding="utf-8")
        os.replace(tmp, RESULT_FILE)  # atomic: the file is never half-written