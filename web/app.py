# web/app.py
"""
Web dashboard. It does not scan by itself: it reads the shared Monitor
(core/monitor.py) and asks it to scan now when the user presses the button.

Start everything from the project root with:
    sudo venv/bin/python main.py
"""
import csv
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from core.monitor import Monitor
from core.whitelist import add_to_whitelist, load_whitelist, save_whitelist

ALERT_LOG_FILE = Path("logs/alert_log.csv")


def create_app(monitor: Monitor) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            network=monitor.network,
            my_ip=monitor.my_ip,
            is_root=monitor.is_root,
            interval=monitor.interval,
        )

    @app.post("/api/scan")
    def scan_now():
        if not monitor.trigger_scan():
            return jsonify({"ok": False, "message": "A scan is already running."}), 409
        return jsonify({"ok": True})

    @app.get("/api/status")
    def status():
        return jsonify(monitor.status())

    @app.get("/api/devices")
    def devices():
        known = load_whitelist()
        result = monitor.result()
        result["devices"] = [{**d, "trusted": d["ip"].lower() in known} for d in result.get("devices", [])]
        return jsonify(result)

    @app.get("/api/events")
    def events():
        since = request.args.get("since", default=0, type=int)
        return jsonify(monitor.events_since(since))

    @app.get("/api/alerts")
    def alerts():
        if not ALERT_LOG_FILE.exists():
            return jsonify({"columns": [], "rows": []})
        with open(ALERT_LOG_FILE, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        if not rows:
            return jsonify({"columns": [], "rows": []})
        return jsonify({"columns": rows[0], "rows": rows[1:][-100:][::-1]})  # newest 100

    @app.route("/api/whitelist", methods=["GET", "POST", "DELETE"])
    def whitelist():
        if request.method == "POST":
            ip = ((request.get_json(silent=True) or {}).get("ip") or "").strip()
            if not ip:
                return jsonify({"ok": False, "message": "Enter an IP address."}), 400
            add_to_whitelist(ip)
            monitor.emit("ok", f"[+] {ip} added to whitelist (web)")
        elif request.method == "DELETE":
            ip = (request.args.get("ip") or "").strip().lower()
            wl = load_whitelist()
            if ip in wl:
                wl.discard(ip)
                save_whitelist(wl)
                monitor.emit("warn", f"[-] {ip} removed from whitelist (web)")
        return jsonify({"ok": True, "entries": sorted(load_whitelist())})

    return app