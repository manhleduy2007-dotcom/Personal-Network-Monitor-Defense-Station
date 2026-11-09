import csv
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from core.monitor import Monitor
from core.whitelist import add_to_whitelist, load_whitelist, remove_from_whitelist


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
        result["devices"] = [{**d, "trusted": d["is_self"] or d["ip"].lower() in known}
                     for d in result.get("devices", [])]
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
            value = (request.get_json(silent=True) or {}).get("ip") or ""
            try:
                if add_to_whitelist(value):
                    monitor.emit("ok", f"[+] {value.strip('<> ')} added to whitelist (web)")
            except ValueError as e:
                return jsonify({"ok": False, "message": str(e)}), 400
        elif request.method == "DELETE":
            value = request.args.get("ip") or ""
            if remove_from_whitelist(value):
                monitor.emit("warn", f"[-] {value} removed from whitelist (web)")
        return jsonify({"ok": True, "entries": sorted(load_whitelist())})

    return app
    