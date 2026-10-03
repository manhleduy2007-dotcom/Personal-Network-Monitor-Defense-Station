import requests
from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

TELEGRAM_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"


def send_alert(ip: str):
    message = (
        f"🚨 *ALERT: Unknown device!*\n\n"
        f"📍 IP: `{ip}`\n"
        f"⚠️ This IP is not in whitelist."
    )
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(TELEGRAM_URL, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[✓] Alert sent: {ip}")
        else:
            print(f"[!] Alert failed: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Telegram connection error: {e}")



def send_port_alert(ip: str, risk_result: dict): 
    risk = risk_result["overall_risk"]
    rated_ports = risk_result["rated_ports"] 
    emoji = {
        "LOW":      "🟡",
        "MEDIUM":   "🟠",
        "HIGH":     "🔴",
        "CRITICAL": "🚨"
    }.get(risk, "⚠️")

    port_lines = ""
    for p in rated_ports:  
        port_lines += f"\n  • Port {p['port']} ({p['name']}) — {p['risk']}: {p['reason']}"
        
    message = (
        f"{emoji} *ALERT: Unknown device — Risk {risk}*\n\n"
        f"📍 IP: `{ip}`\n"
        f"🔓 Open ports:{port_lines}\n\n"
        f"⚠️ Check this device immediately!"
    ) 
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(TELEGRAM_URL, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[✓] Port alert sent: {ip} — {risk}")
        else:
            print(f"[!] Alert failed: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Telegram connection error: {e}")