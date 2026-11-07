import json
import os
import ipaddress
import re
import tempfile 
import threading 
from pathlib import Path

WHITELIST_FILE = Path(__file__).resolve().parent.parent /"data"/"whitelist.json"

_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$")
_lock = threading.Lock() 
_warned = set()

def normalize_entry(value: str) -> str: 
    v = str(value).strip().strip("<>").strip().lower() 
    try: 
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if _MAC_RE.match(v):
        return v.replace("-", ":")
    raise ValueError(f"not a valid IP or MAC address: {value!r}")

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

def add_to_whitelist(value: str) -> bool:
    wl = load_whitelist()
    wl.add(normalize_entry(value))
    save_whitelist(wl)
    print(f"[+] Added {value} to whitelist")

def is_trusted(value: str) -> bool:
    try: 
        return normalize_entry(value) in load_whitelist()
    except ValueError: 
        return False
