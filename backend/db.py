"""MongoDB connection, indexes, ID counters and the default admin account."""
from datetime import datetime, timezone

import bcrypt

import config

_db = None


def now():
    return datetime.now(timezone.utc)


def get_db():
    global _db
    if _db is not None:
        return _db
    if config.USE_MOCK_DB:
        import mongomock
        _db = mongomock.MongoClient()[config.DB_NAME]
    else:
        from pymongo import MongoClient
        client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=3000)
        try:
            client.admin.command("ping")
        except Exception as e:
            raise SystemExit(
                "\nCannot connect to MongoDB at %s\n"
                "  -> Is MongoDB running? (Windows: start the 'MongoDB' service; Linux: sudo systemctl start mongod)\n"
                "  -> Details: %s\n" % (config.MONGO_URI, e))
        _db = client[config.DB_NAME]
    _setup(_db)
    return _db


def _setup(db):
    db.users.create_index("email", unique=True)
    db.users.create_index("user_id", unique=True)
    db.scans.create_index("scan_id", unique=True)
    db.scans.create_index([("user_id", 1), ("scan_date", -1)])
    db.detection_result.create_index("scan_id", unique=True)
    db.blacklist.create_index("domain", unique=True)
    db.incidents.create_index("incident_id", unique=True)
    db.verified_sites.create_index("verified_id", unique=True)
    db.verified_sites.create_index([("domain", 1), ("status", 1)])
    db.incidents.create_index([("status", 1), ("updated_at", -1)])
    # default admin account (only created once)
    if not db.users.find_one({"role": "admin"}):
        db.users.insert_one({
            "user_id": next_id("U", "users"), "name": config.ADMIN_NAME, "email": config.ADMIN_EMAIL.lower(),
            "password_hash": hash_password(config.ADMIN_PASSWORD), "role": "admin",
            "created_at": now(), "last_login": None})
        print("Created default admin:", config.ADMIN_EMAIL, "(change the password!)")


def next_id(prefix, counter):
    """Readable sequential IDs such as U001, S001, B001, R001 (atomic, safe with many users)."""
    from pymongo import ReturnDocument
    doc = get_counters().find_one_and_update({"_id": counter}, {"$inc": {"seq": 1}}, upsert=True,
                                             return_document=ReturnDocument.AFTER)
    return "%s%03d" % (prefix, doc["seq"])


def get_counters():
    # the counters collection is created lazily; avoids recursion with _setup
    from_db = _db if _db is not None else get_db()
    return from_db.counters


def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_password(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:
        return False
