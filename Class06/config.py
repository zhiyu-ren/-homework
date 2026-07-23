import os, secrets
from pathlib import Path

def _load_env_file(env_path=None):
    if env_path is None:
        base = Path(__file__).resolve().parent
        env_path = str(base / ".env")
    env_file = Path(env_path)
    if not env_file.exists(): return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key not in os.environ: os.environ[key] = value

_load_env_file()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    DEBUG = os.environ.get("FLASK_ENV") == "development"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    PERMANENT_SESSION_LIFETIME = 1800
    BASE_DIR = Path(__file__).resolve().parent
    DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "data" / "users.db"))
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = str(BASE_DIR / "static" / "uploads")
    LOG_FILE = os.environ.get("LOG_FILE", str(BASE_DIR / "logs" / "security.log"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
