import os
from dotenv import load_dotenv

# Load biến từ file .env (nếu có), ưu tiên env var đã được export sẵn
load_dotenv()

TELEGRAM_TOKEN   = os.environ.get("TG_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TG_CHAT_ID", "")

SCAN_INTERVAL = 60

