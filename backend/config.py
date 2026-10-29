"""Settings. Change them with environment variables, no code edits needed."""
import os
import secrets

BASE = os.path.dirname(os.path.abspath(__file__))

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "fake_website_portal")
USE_MOCK_DB = os.environ.get("USE_MOCK_DB", "0") == "1"      # in-memory fake MongoDB, for testing only

# Secret used to sign login tokens. Generated once and kept in .secret_key if you do not set one.
def _secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip()

SECRET_KEY = _secret()
TOKEN_HOURS = 8

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@portal.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@123")   # CHANGE this before any real use
ADMIN_NAME = "Administrator"

REPORT_DIR = os.path.join(BASE, "generated_reports")
FRONTEND_DIR = os.path.abspath(os.path.join(BASE, "..", "frontend"))
ML_DIR = os.path.abspath(os.path.join(BASE, "..", "ml"))

LOGIN_LIMIT = (8, 60)      # max 8 login attempts per 60 seconds per IP+email
SCAN_LIMIT = (30, 60)      # max 30 scans per 60 seconds per user
DEEP_LIMIT = (6, 60)       # max 6 online page checks per 60 seconds per user

# threat monitor limits (see threat.py)
def _n(name, default):
    return int(os.environ.get(name, default))

REPEAT_COUNT, REPEAT_WINDOW_MIN = _n("REPEAT_COUNT", 3), _n("REPEAT_WINDOW_MIN", 10)        # same user, same fake site
CROWD_USERS, CROWD_WINDOW_H = _n("CROWD_USERS", 2), _n("CROWD_WINDOW_H", 24)               # different users, same fake site
CAMPAIGN_DOMAINS, CAMPAIGN_WINDOW_H = _n("CAMPAIGN_DOMAINS", 3), _n("CAMPAIGN_WINDOW_H", 24)  # look-alikes of one brand
RISKY_DOMAINS, RISKY_WINDOW_MIN = _n("RISKY_DOMAINS", 5), _n("RISKY_WINDOW_MIN", 10)       # one user, many fake sites
