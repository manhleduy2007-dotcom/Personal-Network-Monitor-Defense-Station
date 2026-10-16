import subprocess


# Danh sách port thường gặp cần kiểm tra
COMMON_PORTS = "21,22,23,25,80,443,445,3306,3389,4444,5900,8080,8443"

# Bảng tên dịch vụ (dùng khi không parse được từ nmap)
PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 4444: "backdoor",
    5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}


def scan_ports(ip: str) -> list:
    """Quét các port phổ biến của một IP.

    Dùng -T4 (nhanh) thay vì -sV (chậm) để web không bị đứng.
    Timeout cứng 15 giây mỗi host để tránh treo vô hạn.
    """
    try:
        result = subprocess.run(
            ["nmap", "-T4", "--open", "-p", COMMON_PORTS, ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15          # tối đa 15 giây / host
        )
        return parse_port_results(result.stdout)
    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        # nmap chưa cài
        return []


def parse_port_results(raw_output: str) -> list:
    """Phân tích output nmap thành list[dict{port, service, state}]."""
    open_ports = []
    for line in raw_output.split("\n"):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            try:
                port_num = int(parts[0].split("/")[0])
            except (ValueError, IndexError):
                continue
            service = parts[2] if len(parts) > 2 else PORT_NAMES.get(port_num, "unknown")
            open_ports.append({
                "port": port_num,
                "service": service,
                "state": "open",
            })
    return open_ports
