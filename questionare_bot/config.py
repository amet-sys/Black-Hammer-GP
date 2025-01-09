from dotenv import load_dotenv
import os

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
API_URL = "http://127.0.0.1:5000/bot_logic"
AUTHORIZATION_URL = "http://127.0.0.1:5501"

REDIS_HOST = "localhost"  # IP или хост вашего Redis
REDIS_PORT = 6379         # Порт Redis (обычно 6379)
