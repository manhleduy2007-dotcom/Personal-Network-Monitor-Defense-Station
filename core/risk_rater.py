# cái này dùng để tra cứu các thiết bị có port nguy hiểm
DANGEROUS_PORTS = {
    21:   ("FTP",      "HIGH",   "FTP gửi mật khẩu dạng plaintext"),
    22:   ("SSH",      "MEDIUM", "Điều khiển từ xa — dễ bị brute-force"),
    23:   ("Telnet",   "HIGH",   "Không mã hoá, nguy cơ nghe lén"),
    25:   ("SMTP",     "MEDIUM", "Có thể bị lạm dụng để spam"),
    80:   ("HTTP",     "LOW",    "Web không mã hóa"),
    443:  ("HTTPS",    "LOW",    "Web có mã hóa"),
    445:  ("SMB",      "HIGH",   "Từng bị WannaCry khai thác"),
    3306: ("MySQL",    "MEDIUM", "Database không nên lộ ra mạng"),
    3389: ("RDP",      "HIGH",   "Điều khiển từ xa Windows"),
    4444: ("Backdoor", "HIGH",   "Dấu hiệu bị hack / Metasploit"),
    5900: ("VNC",      "HIGH",   "Điều khiển màn hình từ xa"),
    8080: ("HTTP-alt", "MEDIUM", "Web quản trị / proxy không mã hóa"),
    8443: ("HTTPS-alt","LOW",    "Web có mã hóa"),
}

# Chú ý: chỉ dùng 4 mức SAFE/LOW/MEDIUM/HIGH để đồng nhất với app.py
RISK_LEVEL = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def rate_port(port: int) -> dict:
    if port in DANGEROUS_PORTS:
        name, risk, reason = DANGEROUS_PORTS[port]
        return {"port": port, "name": name, "risk": risk, "reason": reason}
    return {"port": port, "name": "unknown", "risk": "LOW", "reason": "Không có trong danh sách nguy hiểm"}


def rate_host(open_ports: list) -> dict:
    """Dùng bởi main.py — trả về dict với overall_risk và rated_ports."""
    if not open_ports:
        return {"overall_risk": "SAFE", "rated_ports": []}

    rated_ports = []
    highest_risk = "SAFE"

    for p in open_ports:
        rated = rate_port(p["port"])
        rated_ports.append(rated)
        if RISK_LEVEL[rated["risk"]] > RISK_LEVEL[highest_risk]:
            highest_risk = rated["risk"]

    return {"overall_risk": highest_risk, "rated_ports": rated_ports}


def rate_device(open_ports: list) -> tuple:
    """Dùng bởi web/app.py — trả về (level: str, reasons: list[str])."""
    if not open_ports:
        return "SAFE", []

    highest_risk = "SAFE"
    reasons = []

    for p in open_ports:
        rated = rate_port(p["port"])
        reasons.append(f"Port {rated['port']} ({rated['name']}): {rated['reason']}")
        if RISK_LEVEL[rated["risk"]] > RISK_LEVEL[highest_risk]:
            highest_risk = rated["risk"]

    return highest_risk, reasons