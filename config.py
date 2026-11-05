import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN   = os.environ.get("TG_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TG_CHAT_ID", "")

SCAN_INTERVAL = 60
