import json
import os

WHITELIST_FILE = "data/whitelist.json"


def load_whitelist() -> set:
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE) as f:
        return set(json.load(f))


def save_whitelist(whitelist: set) -> None:
    with open(WHITELIST_FILE, "w") as f:
        json.dump(list(whitelist), f, indent=2)


def add_to_whitelist(ip: str):
    wl = load_whitelist()
    wl.add(ip)
    save_whitelist(wl)
    print(f"[+] Added {ip} to whitelist")


def is_trusted(ip: str) -> bool:
    return ip in load_whitelist()