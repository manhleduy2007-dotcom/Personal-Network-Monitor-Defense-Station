# cái này dùng để tra cứu các thiết bị có port nguy hiểm 
DANGEROUS_PORTS = { 
    22: ("SSH", "MEDIUM", "Điều khiển từ xa"), 
    23: ("Telnet", "HIGH", "Không mã hoá"), 
    4444: ("Backdoor", "CRITICAL", "Dấu hiệu bị hack"), 
}

RISK_LEVEL = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def rate_host(open_ports: list) -> dict: 
    if not open_ports: 
        return {"overall_risk": "LOW", "rated_ports": []}
    
    rated_ports = [] 
    highest_risk = "LOW"

    for p in open_ports: 
        rated = rate_port(p["port"])
        rated_ports.append(rated)

        if RISK_LEVEL[rated["risk"]] > RISK_LEVEL[highest_risk]: 
            highest_risk = rated["risk"]

    return {"overall_risk": highest_risk, "rated_ports": rated_ports}

def rate_port(port: int) -> dict: 
    if port in DANGEROUS_PORTS: 
        name, risk, reason = DANGEROUS_PORTS[port]
        return {"port": port, "name": name, "risk": risk, "reason": reason}
    return {"port": port, "name": "unknown", "risk": "LOW", "reason": "Không rõ"}