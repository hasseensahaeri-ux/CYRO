"""Central configuration."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "cyberguard.db"
BLOCKLIST_PATH = BASE_DIR / "data" / "blocklist.txt"

MAX_FILE_MB = 25
MAX_CONTENT_LENGTH = (MAX_FILE_MB * 2 + 2) * 1024 * 1024   # room for two files
MAX_TEXT_CHARS = 20000
MAX_URL_CHARS = 2048
RATE_LIMIT_PER_MIN = 240
TLS_TIMEOUT = 4

# Where the protected lab server is drawn on the attack map (lat, lon). Change to your own location.
LAB_SERVER_GEO = (15.3694, 44.1910)  # Sana'a, Yemen (approximate lab server location)
