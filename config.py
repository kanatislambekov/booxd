from pathlib import Path

# Basic app configuration and seed data for two users.
APP_NAME = "Booxd"
DB_PATH = Path("data/db.json")

# Initial credentials; on first run they seed the JSON db with hashed versions.
# Update these before first launch if you prefer different defaults.
DEFAULT_USERS = [
    {"username": "kanat", "password": "readerpass1", "display_name": "Kanat"},
    {"username": "asem", "password": "readerpass2", "display_name": "Asem"},
]

# Simple theme accents
DEFAULT_THEME = {
    "accent": "#f59e0b",  # amber/gold
    "bg_gradient": "linear-gradient(135deg, #0b1224 0%, #111827 40%, #0d253f 100%)",
}
