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