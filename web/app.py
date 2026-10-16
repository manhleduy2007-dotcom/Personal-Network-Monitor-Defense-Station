# web/app.py
"""
Phase 3 - Web dashboard for Personal Network Monitor Defense Station.

Run from the project root:
    sudo venv/bin/python web/app.py
Then open: http://127.0.0.1:5050
"""
import csv
import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# web/app.py lives in web/, so the project root is two levels up
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.chdir(BASE_DIR)  # core/ modules use relative paths like "data/whitelist.json"

from core import whitelist  # noqa: E402
from core.port_scanner import scan_ports  # noqa: E402
from core.risk_rater import rate_host  # noqa: E402
from core.scanner import get_myip, get_network, parse_results, scan_network  # noqa: E402
from core.whitelist import add_to_whitelist, load_whitelist  # noqa: E402

WEB_RESULT_FILE = BASE_DIR / "data" / "web_scan_result.json"  # separate file, does not touch last_scan.json
ALERT_LOG_FILE = BASE_DIR / "logs" / "alert_log.csv"
WHITELIST_FILE = BASE_DIR / getattr(whitelist, "WHITELIST_FILE", "data/whitelist.json")
PORT = 5050  # macOS AirPlay Receiver already uses 5000

MY_IP = get_myip()
NETWORK = get_network(MY_IP)


# ---------------------------------------------------------------------------
# Whitelist helpers (whitelist.json is a JSON list of IP strings)
# ---------------------------------------------------------------------------
def trusted_ips():
    try:
        return set(load_whitelist())
    except Exception:
        return set()


def remove_from_whitelist(ip):
    ips = sorted(trusted_ips() - {ip})
    WHITELIST_FILE.write_text(json.dumps(ips, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Background scan so the page never freezes while nmap runs
# ---------------------------------------------------------------------------
state_lock = threading.Lock()
scan_state = {"status": "idle", "current_ip": None, "done": 0, "total": 0, "error": None}
last_result = {"devices": [], "finished_at": None, "network": NETWORK}

if WEB_RESULT_FILE.exists():
    try:
        last_result = json.loads(WEB_RESULT_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        pass


def update_state(**kwargs):
    with state_lock:
        scan_state.update(kwargs)


def scan_one(ip):
    open_ports = scan_ports(ip)
    result = rate_host(open_ports)
    rated = {p["port"]: p for p in result.get("rated_ports", [])}

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
    return ports, str(result.get("overall_risk", "UNKNOWN")).upper()


def run_full_scan():
    global last_result
    try:
        update_state(status="discovering", done=0, total=0, current_ip=None, error=None)
        hosts = parse_results(scan_network(NETWORK))
        update_state(status="scanning", total=len(hosts))

        devices = []
        for i, ip in enumerate(hosts):
            update_state(current_ip=ip, done=i)
            ports, risk = scan_one(ip)
            devices.append({"ip": ip, "is_self": ip == MY_IP, "ports": ports, "risk": risk})

        last_result = {
            "devices": devices,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "network": NETWORK,
        }
        WEB_RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
        WEB_RESULT_FILE.write_text(json.dumps(last_result, indent=2), encoding="utf-8")
        update_state(status="done", done=len(devices), current_ip=None)
    except Exception as e:
        update_state(status="error", error=str(e), current_ip=None)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", network=NETWORK, my_ip=MY_IP)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    with state_lock:
        if scan_state["status"] in ("discovering", "scanning"):
            return jsonify({"ok": False, "message": "A scan is already running."}), 409
        scan_state["status"] = "discovering"
    threading.Thread(target=run_full_scan, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/status")
def status():
    with state_lock:
        return jsonify(dict(scan_state))


@app.route("/api/devices")
def devices():
    known = trusted_ips()
    result = dict(last_result)
    result["devices"] = [{**d, "trusted": d["ip"] in known} for d in last_result.get("devices", [])]
    return jsonify(result)


@app.route("/api/alerts")
def alerts():
    if not ALERT_LOG_FILE.exists():
        return jsonify({"columns": [], "rows": []})
    with open(ALERT_LOG_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return jsonify({"columns": [], "rows": []})
    return jsonify({"columns": rows[0], "rows": rows[1:][-100:][::-1]})  # newest 100


@app.route("/api/whitelist", methods=["GET", "POST", "DELETE"])
def whitelist_api():
    if request.method == "POST":
        ip = ((request.get_json(silent=True) or {}).get("ip") or "").strip()
        if not ip:
            return jsonify({"ok": False, "message": "Enter an IP address."}), 400
        if ip not in trusted_ips():
            add_to_whitelist(ip)
    elif request.method == "DELETE":
        remove_from_whitelist((request.args.get("ip") or "").strip())

    return jsonify({"ok": True, "entries": sorted(trusted_ips())})


if __name__ == "__main__":
    print(f"[+] Dashboard: http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=False)