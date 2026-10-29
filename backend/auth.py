"""Login tokens (JWT), role checks, and a small in-memory rate limiter."""
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

import config
import db


def error(msg, code=400):
    return jsonify({"error": msg}), code


def make_token(user):
    payload = {"sub": user["user_id"], "role": user["role"],
               "exp": datetime.now(timezone.utc) + timedelta(hours=config.TOKEN_HOURS)}
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")


def login_required(role=None):
    """role=None: any logged-in user. role='admin': admins only."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return error("Please log in.", 401)
            try:
                data = jwt.decode(header[7:], config.SECRET_KEY, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return error("Session expired. Please log in again.", 401)
            except jwt.InvalidTokenError:
                return error("Invalid session. Please log in again.", 401)
            # always re-read the user so role changes / deletions take effect immediately
            user = db.get_db().users.find_one({"user_id": data["sub"]})
            if not user:
                return error("Account no longer exists.", 401)
            if role and user["role"] != role:
                return error("Admin access required.", 403)
            g.user = user
            return fn(*a, **kw)
        return wrapper
    return deco


_hits = defaultdict(deque)


def rate_limited(key, limit):
    """True if `key` made more than limit[0] requests in the last limit[1] seconds."""
    maxn, window = limit
    q, t = _hits[key], time.time()
    while q and q[0] < t - window:
        q.popleft()
    if len(q) >= maxn:
        return True
    q.append(t)
    return False
