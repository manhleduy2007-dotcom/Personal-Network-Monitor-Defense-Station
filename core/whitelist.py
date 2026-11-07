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

def _iter_values(raw):
    if isinstance(raw, dict):            
        yield from raw.keys()
        return
    for item in raw:
        if isinstance(item, str):       
            yield item
        elif isinstance(item, dict):     
            for field in ("mac", "ip"):
                if item.get(field):
                    yield item[field]
 

def load_whitelist() -> set:
    trusted = set()
    for value in _iter_values(_load_raw()):
        try:
            trusted.add(normalize_entry(value))
        except ValueError:
            if value not in _warned:
                _warned.add(value)
                print(f"[!] Ignoring invalid whitelist entry: {value!r}")
    return trusted

def save_whitelist(whitelist: set) -> None:
    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=WHITELIST_FILE.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(whitelist), f, indent=2)
        os.replace(tmp, WHITELIST_FILE)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
 

def add_to_whitelist(value: str) -> bool:
    entry = normalize_entry(value)
    with _lock: 
        wl = load_whitelist() 
        if entry in wl:
            return False
        wl.add(entry) 
        save_whitelist(wl)
    return True

def remove_from_whitelist(value: str) -> bool:
    try:
        entry = normalize_entry(value)
    except ValueError:
        return False
    with _lock:
        wl = load_whitelist()
        if entry not in wl:
            return False
        wl.discard(entry)
        save_whitelist(wl)
    return True
 

def is_trusted(value: str) -> bool:
    try: 
        return normalize_entry(value) in load_whitelist()
    except ValueError: 
        return False
