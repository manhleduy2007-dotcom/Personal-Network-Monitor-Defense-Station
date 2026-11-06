import json
import os

WHITELIST_FILE = "data/whitelist.json"

def _load_raw():

    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, (list, dict)) else []
    except (json.JSONDecodeError, OSError):
        return []

def load_whitelist() -> set:

    raw = _load_raw()
    trusted = set()

    if isinstance(raw, dict):

        for key in raw:
            trusted.add(str(key).lower())
    else:
        for item in raw:
            if isinstance(item, str):
                trusted.add(item.lower())
            elif isinstance(item, dict):

                for field in ("mac", "ip"):
                    val = item.get(field)
                    if val:
                        trusted.add(str(val).lower())

    return trusted

def save_whitelist(whitelist: set) -> None:
    os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(whitelist), f, indent=2)

def add_to_whitelist(ip: str):
    wl = load_whitelist()
    wl.add(ip.lower())
    save_whitelist(wl)
    print(f"[+] Added {ip} to whitelist")

def is_trusted(ip: str) -> bool:
    return ip.lower() in load_whitelist()
