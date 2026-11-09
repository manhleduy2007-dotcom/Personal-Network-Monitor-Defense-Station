import html
import requests
from config import TELEGRAM_CHAT_ID, TELEGRAM_TOKEN

TELEGRAM_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
TIMEOUT = 10
RISK_EMOJI = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}

class NotifierError(RuntimeError):
    pass

def _e(value) -> str:
    return html.escape(str(value))

def _send(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        raise NotifierError("TELEGRAM_TOKEN or TELEGRAM_CHAT_ID is missing, check .env")
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        response = requests.post(TELEGRAM_URL, json=payload, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        raise NotifierError(f"cannot reach Telegram ({e.__class__.__name__})") from None

    if response.status_code != 200:
        try:
            detail = response.json().get("description", "")
        except ValueError:
            detail = response.text[:200]
        raise NotifierError(f"Telegram API {response.status_code}: {detail}")


def send_alert(ip: str) -> None:
    _send(
        "🚨 <b>ALERT: Unknown device</b>\n\n"
        f"📍 IP: <code>{_e(ip)}</code>\n"
        "⚠️ This IP is not in the whitelist."
    )


def send_port_alert(ip: str, risk_result: dict, reason: str = "Unknown device") -> None:
    risk = str(risk_result.get("overall_risk", "UNKNOWN")).upper()

    lines = []
    for p in risk_result.get("rated_ports", []):
        line = f"  • Port {_e(p.get('port', '?'))} ({_e(p.get('name', '?'))}) — {_e(p.get('risk', '?'))}"
        if p.get("reason"):
            line += f": {_e(p['reason'])}"
        lines.append(line)

    _send(
        f"{RISK_EMOJI.get(risk, '⚠️')} <b>ALERT: {_e(reason)} — Risk {_e(risk)}</b>\n\n"
        f"📍 IP: <code>{_e(ip)}</code>\n"
        f"🔓 Open ports:\n{chr(10).join(lines) or '  • none'}\n\n"
        "⚠️ Check this device immediately!"
    )