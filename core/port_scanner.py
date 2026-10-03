import subprocess 

def scan_ports(ip: str) -> list: 
    result = subprocess.run(["sudo", "nmap", "-sV", "--open", "-p", "21,22,23,25,80,443,445,3306,3389,4444,5900,8080,8443",ip],
    # sudo nmap -sV --open -p 21,22,... 
    stdout = subprocess.PIPE, 
    stderr = subprocess.PIPE, 
    text = True
    )
    return parse_port_results(result.stdout)

def parse_port_results(raw_output: str) -> list: 
    open_ports = []

    for line in raw_output.split("\n"): 
        if "/tcp" in line and "open" in line: 
            parts = line.split() 
            port_num = int(parts[0].split("/")[0]) 
            service = parts[2] if len(parts) > 2 else "unknown" 
            open_ports.append({ 
                "port": port_num, 
                "service": service, 
                "state": "open"
            })
    return open_ports 

"a great son and a great father"
'''
tổng quan về giao thức TCP => thuộc tầng Transport trong mô hình OSI / TCP - IP 
Connection oriented (hướng kết nối) => đảm bảo độ tin cậy tuyệt đối
Giao thức TCP: Đảm bảo độ tin cậy, đảm bảo thứ tự, kiểm soát luồng 

UDP (User Datagram Protocol) là giao thức truyền tải dữ liệu => thuộc tầng Transport, 
connectionless(phi kết nối), không đảm bảo độ tin cậy, đánh đổi an toàn để đạt được tốc
độ truyền tải tối đa độ trễ cực thấp
'''