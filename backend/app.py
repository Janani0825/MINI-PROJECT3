"""
Fake Website Detection Portal - Flask backend.

    python app.py            ->  open http://localhost:5000

Serves the frontend AND the /api routes from one place.
"""
import csv
import os
import re
import sys
from datetime import timedelta

from flask import Flask, Response, g, jsonify, request, send_from_directory

import auth
import config
import db
import pagecheck
import report_pdf
import sites
import threat
from auth import error, login_required, rate_limited

sys.path.insert(0, config.ML_DIR)
from features import parse as parse_url  # noqa: E402
from predict import analyse  # noqa: E402  (the machine-learning engine)
import predict  # noqa: E402
import features as FEAT  # noqa: E402

app = Flask(__name__, static_folder=config.FRONTEND_DIR, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024     # requests are tiny; refuse anything big

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ----------------------------------------------------------------- helpers
def iso(d):
    if d is None:
        return None
    if d.tzinfo is None:
        return d.isoformat() + "Z"
    return d.isoformat().replace("+00:00", "Z")


def public_user(u):
    return {"user_id": u["user_id"], "name": u["name"], "email": u["email"], "role": u["role"],
            "created_at": iso(u.get("created_at")), "last_login": iso(u.get("last_login"))}


def scan_view(scan, result, user_name=None):
    out = {k: scan[k] for k in ("scan_id", "user_id", "submitted_url", "domain", "protocol", "status", "features")}
    out["scan_date"] = iso(scan["scan_date"])
    out["features"] = {k: v for k, v in scan["features"].items() if k != "all"}
    if user_name is not None:
        out["user_name"] = user_name
    out["result"] = {k: v for k, v in (result or {}).items() if k not in ("_id",)} or None
    return out


def joined_scans(query, limit=1000):
    d = db.get_db()
    scans = list(d.scans.find(query).sort("scan_date", -1).limit(limit))
    results = {r["scan_id"]: r for r in d.detection_result.find({"scan_id": {"$in": [s["scan_id"] for s in scans]}})}
    names = {u["user_id"]: u["name"] for u in d.users.find({}, {"user_id": 1, "name": 1})}
    return [scan_view(s, results.get(s["scan_id"]), names.get(s["user_id"], s["user_id"])) for s in scans]


def log_admin(action, details=""):
    d = db.get_db()
    d.admin_logs.insert_one({"log_id": db.next_id("L", "logs"), "admin_id": g.user["user_id"],
                             "action": action, "details": details, "at": db.now()})


def body():
    return request.get_json(silent=True) or {}


# ----------------------------------------------------------------- pages / errors
@app.route("/")
def home():
    return send_from_directory(config.FRONTEND_DIR, "index.html")


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return error("Not found.", 404)
    return e


@app.errorhandler(413)
def too_big(e):
    return error("Request too large.", 413)


@app.errorhandler(500)
def server_error(e):
    return error("Something went wrong on the server.", 500)


# ----------------------------------------------------------------- Module 1: authentication
@app.post("/api/register")
def register():
    b = body()
    name, email, pw = str(b.get("name", "")).strip(), str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
    if not name or not email or not pw:
        return error("All fields are required.")
    if len(name) > 80 or not EMAIL_RE.match(email) or len(email) > 120:
        return error("Enter a valid name and email address.")
    if len(pw) < 8 or len(pw) > 128:
        return error("Password must be 8 to 128 characters.")
    d = db.get_db()
    if d.users.find_one({"email": email}):
        return error("Email already registered.", 409)
    try:
        d.users.insert_one({"user_id": db.next_id("U", "users"), "name": name, "email": email,
                            "password_hash": db.hash_password(pw), "role": "user",
                            "created_at": db.now(), "last_login": None})
    except Exception:
        return error("Email already registered.", 409)
    return jsonify({"message": "Registered"}), 201


@app.post("/api/login")
def login():
    b = body()
    email, pw = str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
    if rate_limited("login:%s:%s" % (request.remote_addr, email), config.LOGIN_LIMIT):
        return error("Too many attempts. Wait a minute and try again.", 429)
    d = db.get_db()
    user = d.users.find_one({"email": email})
    if not user or not db.check_password(pw, user["password_hash"]):
        return error("Invalid email or password.", 401)    # same message for both cases on purpose
    d.users.update_one({"user_id": user["user_id"]}, {"$set": {"last_login": db.now()}})
    user["last_login"] = db.now()
    return jsonify({"token": auth.make_token(user), "user": public_user(user)})


@app.get("/api/profile")
@login_required()
def get_profile():
    return jsonify(public_user(g.user))


@app.put("/api/profile")
@login_required()
def update_profile():
    b, upd = body(), {}
    if "name" in b:
        name = str(b["name"]).strip()
        if not name or len(name) > 80:
            return error("Enter a valid name.")
        upd["name"] = name
    if b.get("password"):
        pw = str(b["password"])
        if len(pw) < 8 or len(pw) > 128:
            return error("Password must be 8 to 128 characters.")
        upd["password_hash"] = db.hash_password(pw)
    if upd:
        db.get_db().users.update_one({"user_id": g.user["user_id"]}, {"$set": upd})
    return jsonify(public_user(db.get_db().users.find_one({"user_id": g.user["user_id"]})))


def apply_verified(d, out):
    """If the admin has verified this website's owner, say so and mark it Safe (a blacklist entry still wins)."""
    r = out["result"]
    rec = sites.lookup(d, out["domain"])
    layer = {"layer": "Verified owner", "status": "pass", "note": "No verified owner on record"}
    if rec and r["decided_by"] == "blacklist":
        layer = {"layer": "Verified owner", "status": "skip", "note": "Has a verified owner, but the domain is blacklisted"}
    elif rec:
        pub = sites.public_record(rec)
        pub["verified_on"] = iso(pub["verified_on"])
        r.update(risk_score=min(r["risk_score"], 5), classification="Safe", decided_by="verified-owner", lookalike=None, signals=[],
                 reasons=["The administrator has verified this as the official website of %s." % rec["org_name"],
                          "Registered owner: %s. It is used for: %s" % (rec["owner_name"], rec["purpose"])],
                 recommendation="This website is verified by the portal administrator. It is safe to use, but always check the address bar.",
                 verified_site=pub)
        r["detection_reason"] = " ".join(r["reasons"])
        layer = {"layer": "Verified owner", "status": "hit", "note": "Verified: %s" % rec["org_name"]}
    r["pipeline"] = [layer] + [x for x in r.get("pipeline", []) if x["layer"] != "Verified owner"]


# ----------------------------------------------------------------- Modules 2-5: scanning
@app.post("/api/scan")
@login_required()
def scan():
    url = str(body().get("url", "")).strip()
    if rate_limited("scan:" + g.user["user_id"], config.SCAN_LIMIT):
        return error("Too many scans. Please wait a minute.", 429)
    d = db.get_db()
    blacklist = [b["domain"] for b in d.blacklist.find({}, {"domain": 1})]
    try:
        parse_url(url)                         # only a badly typed URL is reported as "Invalid URL"
    except ValueError:
        return error("Invalid URL. Example: https://example.com/login")
    deep = bool(body().get("deep"))
    if deep and rate_limited("deep:" + g.user["user_id"], config.DEEP_LIMIT):
        return error("Too many page checks. Please wait a minute.", 429)
    try:
        out = analyse(url, blacklist)          # the URL itself is analysed as text; the page is opened only for a deep scan
    except Exception as e:                     # a real engine problem: show it, and print the details in the terminal
        app.logger.exception("Detection engine failed")
        return error("Detection engine error: %s: %s" % (type(e).__name__, e), 500)

    if deep:                                   # optional deep scan (page content + security headers); never raises
        out = pagecheck.augment(out, url, __import__("features")._EXTRACT)

    apply_verified(d, out)                     # verified owner registry (admin-approved websites)

    duplicate = d.scans.count_documents({"user_id": g.user["user_id"], "submitted_url": url}) > 0
    scan_doc = {"scan_id": db.next_id("S", "scans"), "user_id": g.user["user_id"], "submitted_url": url,
                "domain": out["domain"], "protocol": out["protocol"], "scan_date": db.now(),
                "status": "completed", "features": out["features"], "duplicate": duplicate}
    res = dict(out["result"], scan_id=scan_doc["scan_id"])
    d.scans.insert_one(scan_doc)
    d.detection_result.insert_one(res)
    view = scan_view(scan_doc, res)
    view["duplicate"] = duplicate
    try:
        view["notice"] = threat.inspect(d, scan_doc, res)     # behaviour rules: repeat / crowd / campaign / risky user
    except Exception:
        app.logger.exception("Threat monitor failed")           # never let the monitor break a scan
        view["notice"] = None
    return jsonify(view), 201


@app.get("/api/scans")
@login_required()
def my_scans():
    return jsonify(joined_scans({"user_id": g.user["user_id"]}))


@app.get("/api/scans/<scan_id>/report.pdf")
@login_required()
def scan_pdf(scan_id):
    d = db.get_db()
    s = d.scans.find_one({"scan_id": scan_id})
    if not s or (s["user_id"] != g.user["user_id"] and g.user["role"] != "admin"):
        return error("Scan not found.", 404)
    pdf = report_pdf.build(scan_view(s, d.detection_result.find_one({"scan_id": scan_id})))
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=PhishGuard-%s.pdf" % scan_id})


@app.delete("/api/scans/<scan_id>")
@login_required()
def delete_scan(scan_id):
    d = db.get_db()
    s = d.scans.find_one({"scan_id": scan_id})
    if not s or (s["user_id"] != g.user["user_id"] and g.user["role"] != "admin"):
        return error("Scan not found.", 404)
    d.scans.delete_one({"scan_id": scan_id})
    d.detection_result.delete_one({"scan_id": scan_id})
    return jsonify({"message": "Deleted"})


# ----------------------------------------------------------------- Module 6: admin
@app.get("/api/admin/stats")
@login_required("admin")
def stats():
    d = db.get_db()
    c = lambda k: d.detection_result.count_documents({"classification": k})
    return jsonify({"users": d.users.count_documents({"role": "user"}), "scans": d.scans.count_documents({}),
                    "safe": c("Safe"), "suspicious": c("Suspicious"), "fake": c("Fake"),
                    "blacklist": d.blacklist.count_documents({}),
                    "incidents_open": d.incidents.count_documents({"status": "open"}),
                    "sites_pending": d.verified_sites.count_documents({"status": "pending"})})


@app.get("/api/admin/users")
@login_required("admin")
def admin_users():
    d = db.get_db()
    counts = {}
    for s in d.scans.find({}, {"user_id": 1}):
        counts[s["user_id"]] = counts.get(s["user_id"], 0) + 1
    return jsonify([dict(public_user(u), scan_count=counts.get(u["user_id"], 0)) for u in d.users.find().sort("user_id", 1)])


@app.get("/api/admin/scans")
@login_required("admin")
def admin_scans():
    return jsonify(joined_scans({}))


@app.get("/api/admin/trends")
@login_required("admin")
def trends():
    d = db.get_db()
    today = db.now().date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
    rows = {x: {"date": x, "safe": 0, "suspicious": 0, "fake": 0} for x in days}
    fake_domains = {}
    since = db.now() - timedelta(days=7)
    scans = {s["scan_id"]: s for s in d.scans.find({"scan_date": {"$gte": since.replace(tzinfo=None)}})}
    for r in d.detection_result.find({"scan_id": {"$in": list(scans)}}):
        s = scans[r["scan_id"]]
        day = s["scan_date"].date().isoformat()
        if day in rows:
            rows[day][r["classification"].lower()] += 1
    for r in d.detection_result.find({"classification": "Fake"}):       # all-time top fake domains
        s = d.scans.find_one({"scan_id": r["scan_id"]}, {"domain": 1})
        if s:
            fake_domains[s["domain"]] = fake_domains.get(s["domain"], 0) + 1
    top = sorted(fake_domains.items(), key=lambda kv: -kv[1])[:5]
    layers = {}
    for r in d.detection_result.find({}, {"decided_by": 1}):
        key = (r.get("decided_by") or "ml").split("+")[0]       # "lookalike+ml+page" -> "lookalike"
        layers[key] = layers.get(key, 0) + 1
    return jsonify({"daily": [rows[x] for x in days], "top_fake_domains": [{"domain": k, "count": v} for k, v in top],
                    "layers": layers})


@app.get("/api/admin/blacklist")
@login_required("admin")
def get_blacklist():
    return jsonify([{"blacklist_id": b["blacklist_id"], "domain": b["domain"], "source": b["source"],
                     "added_date": iso(b["added_date"])} for b in db.get_db().blacklist.find().sort("blacklist_id", -1)])


@app.post("/api/admin/blacklist")
@login_required("admin")
def add_blacklist():
    b = body()
    dom = str(b.get("domain", "")).strip().lower()
    dom = re.sub(r"^[a-z]+://", "", dom).split("/")[0].split(":")[0]
    if dom.startswith("www."):
        dom = dom[4:]
    if not re.match(r"^[a-z0-9.\-]+\.[a-z0-9\-]{2,}$", dom):
        return error("Enter a valid domain, for example bad-site.com")
    d = db.get_db()
    if d.blacklist.find_one({"domain": dom}):
        return error("Already blacklisted.", 409)
    d.blacklist.insert_one({"blacklist_id": db.next_id("B", "blacklist"), "domain": dom,
                            "added_date": db.now(), "source": str(b.get("source") or "Admin")[:60]})
    log_admin("blacklist_add", dom)
    return jsonify({"message": "Added"}), 201


@app.delete("/api/admin/blacklist/<bid>")
@login_required("admin")
def remove_blacklist(bid):
    r = db.get_db().blacklist.find_one_and_delete({"blacklist_id": bid})
    if not r:
        return error("Entry not found.", 404)
    log_admin("blacklist_remove", r["domain"])
    return jsonify({"message": "Removed"})


def incident_view(i):
    return {"incident_id": i["incident_id"], "kind": i["kind"], "severity": i["severity"], "title": i["title"],
            "details": i["details"], "domains": i.get("domains", []), "users": i.get("users", []),
            "auto_action": i.get("auto_action", ""), "status": i["status"],
            "created_at": iso(i["created_at"]), "updated_at": iso(i["updated_at"])}


@app.get("/api/admin/incidents")
@login_required("admin")
def get_incidents():
    return jsonify([incident_view(i) for i in db.get_db().incidents.find().sort("updated_at", -1).limit(200)])


@app.put("/api/admin/incidents/<iid>")
@login_required("admin")
def update_incident(iid):
    """status: reviewed | dismissed.  unblock=true also removes the domains this incident auto-blacklisted (false alarm)."""
    b, d = body(), db.get_db()
    status = str(b.get("status", ""))
    if status not in ("open", "reviewed", "dismissed"):
        return error("Status must be open, reviewed or dismissed.")
    inc = d.incidents.find_one({"incident_id": iid})
    if not inc:
        return error("Incident not found.", 404)
    removed = 0
    if b.get("unblock"):
        for dom in inc.get("domains", []):
            r = d.blacklist.delete_one({"domain": dom, "source": {"$regex": "^Auto"}})
            removed += r.deleted_count
    d.incidents.update_one({"incident_id": iid}, {"$set": {"status": status, "updated_at": db.now()}})
    log_admin("incident_" + status, iid + (" (unblocked %d)" % removed if removed else ""))
    return jsonify(incident_view(d.incidents.find_one({"incident_id": iid})))


# ----------------------------------------------------------------- verified website registry
def site_view(r, admin=False):
    out = {"verified_id": r["verified_id"], "domain": r["domain"], "org_name": r["org_name"], "category": r["category"],
           "purpose": r["purpose"], "status": r["status"], "requested_at": iso(r["requested_at"]),
           "reviewed_at": iso(r.get("reviewed_at")), "admin_note": r.get("admin_note", ""), "token": r["token"],
           "token_check": r.get("token_check")}
    if admin:
        out.update(owner_name=r["owner_name"], owner_user_id=r["owner_user_id"], contact_email=r["contact_email"],
                   evidence=r["evidence"], analysis=r.get("analysis", {}), admin_checks=r.get("admin_checks", []),
                   proof=sites.ownership_proof(r),
                   reviewer=r.get("reviewer_name"), flags=[{"level": a, "text": b} for a, b in sites.risk_flags(r)])
    return out


@app.get("/api/sites/categories")
@login_required()
def site_categories():
    return jsonify(sites.CATEGORIES)


@app.get("/api/sites/verified")
@login_required()
def verified_directory():
    rows = db.get_db().verified_sites.find({"status": "approved"}).sort("reviewed_at", -1)
    return jsonify([dict(sites.public_record(r), verified_on=iso(r.get("reviewed_at"))) for r in rows])


@app.get("/api/sites/mine")
@login_required()
def my_sites():
    rows = db.get_db().verified_sites.find({"owner_user_id": g.user["user_id"]}).sort("verified_id", -1)
    return jsonify([site_view(r) for r in rows])


@app.post("/api/sites/request")
@login_required()
def request_verification():
    b, d, uid = body(), db.get_db(), g.user["user_id"]
    if rate_limited("siteReq:" + uid, (5, 3600)):
        return error("Too many requests. Please try again later.", 429)
    org, cat = str(b.get("org_name", "")).strip(), str(b.get("category", ""))
    purpose, email = str(b.get("purpose", "")).strip(), str(b.get("contact_email", "")).strip().lower()
    evidence = str(b.get("evidence", "")).strip()
    if not org or not purpose or not evidence or not email:
        return error("Please fill in all the fields.")
    if cat not in sites.CATEGORIES:
        return error("Choose a category.")
    if len(org) > 120 or len(purpose) > 400 or len(evidence) > 1500 or not EMAIL_RE.match(email) or len(email) > 120:
        return error("Check the lengths and the e-mail address.")
    try:
        u, p = parse_url(str(b.get("domain", "")))
    except ValueError:
        return error("Enter the website address, for example mepcoeng.ac.in")
    host = (p.hostname or "").lower()
    if re.match(r"^[\d.]+$", host) or ":" in host:
        return error("An IP address cannot be verified. Use the website's domain name.")
    reg = sites.normalise_domain(FEAT._EXTRACT, host)
    if reg in predict._load()[1]:
        return error("%s is already a well-known, trusted website. It does not need verification." % reg, 409)
    if d.verified_sites.find_one({"domain": reg, "status": "approved"}):
        return error("%s is already verified by another owner." % reg, 409)
    if d.verified_sites.find_one({"domain": reg, "owner_user_id": uid, "status": "pending"}):
        return error("You already have a pending request for %s." % reg, 409)
    if d.verified_sites.count_documents({"owner_user_id": uid, "status": "pending"}) >= 5:
        return error("You already have 5 pending requests. Wait for the admin to review them.", 429)
    black = [x["domain"] for x in d.blacklist.find({}, {"domain": 1})]
    res = analyse("https://" + reg, black)["result"]
    em = sites.email_matches(email, reg)
    doc = {"verified_id": db.next_id("V", "verified_sites"), "domain": reg, "org_name": org, "category": cat, "purpose": purpose,
           "contact_email": email, "evidence": evidence, "owner_user_id": uid, "owner_name": g.user["name"], "token": sites.new_token(),
           "status": "pending", "requested_at": db.now(),
           "analysis": {"email_match": em, "free_mail": (not em) and email.rsplit("@", 1)[-1] in sites.FREE_MAIL,
                        "risk_score": res["risk_score"], "classification": res["classification"],
                        "lookalike": res.get("lookalike"), "blacklisted": res["decided_by"] == "blacklist",
                        "competing": d.verified_sites.count_documents({"domain": reg, "status": "pending"})}}
    d.verified_sites.insert_one(dict(doc))
    return jsonify(site_view(doc)), 201


@app.get("/api/admin/sites")
@login_required("admin")
def admin_sites():
    q = {}
    if request.args.get("status") in ("pending", "approved", "rejected", "revoked"):
        q["status"] = request.args["status"]
    rows = list(db.get_db().verified_sites.find(q).sort("verified_id", -1))
    return jsonify([site_view(r, admin=True) for r in rows])


def run_token_check(d, r):
    """Look for the owner's verification code on the live website (page text, meta tag or /.well-known/phishguard.txt)."""
    found, note = False, "the website could not be opened"
    for url in ("https://%s/.well-known/phishguard.txt" % r["domain"], "https://%s/" % r["domain"], "http://%s/" % r["domain"]):
        try:
            _, html = pagecheck.fetch(url)
        except ValueError as e:
            note = str(e)
            continue
        if r["token"] in html:
            found, note = True, "found at " + url
            break
        note = "the page opened but the code was not in it"
    d.verified_sites.update_one({"verified_id": r["verified_id"]}, {"$set": {"token_check": {"found": found, "note": note, "at": iso(db.now())}}})
    return d.verified_sites.find_one({"verified_id": r["verified_id"]})


@app.post("/api/admin/sites/<vid>/check")
@login_required("admin")
def check_site_token(vid):
    d = db.get_db()
    r = d.verified_sites.find_one({"verified_id": vid})
    if not r:
        return error("Request not found.", 404)
    return jsonify(site_view(run_token_check(d, r), admin=True))


@app.post("/api/sites/<vid>/check")
@login_required()
def owner_check_token(vid):
    """The owner presses 'Check my code' after adding the verification code to the website."""
    d = db.get_db()
    r = d.verified_sites.find_one({"verified_id": vid, "owner_user_id": g.user["user_id"]})
    if not r:
        return error("Request not found.", 404)
    if r["status"] != "pending":
        return error("This request is already reviewed.", 409)
    if rate_limited("siteChk:" + g.user["user_id"], (6, 60)):
        return error("Please wait a minute before checking again.", 429)
    return jsonify(site_view(run_token_check(d, r)))


@app.put("/api/admin/sites/<vid>")
@login_required("admin")
def review_site(vid):
    b, d = body(), db.get_db()
    action, note = str(b.get("action", "")), str(b.get("note", "")).strip()[:300]
    r = d.verified_sites.find_one({"verified_id": vid})
    if not r:
        return error("Request not found.", 404)
    if action not in ("approve", "reject", "revoke"):
        return error("Action must be approve, reject or revoke.")
    if action == "approve":
        if r["status"] != "pending":
            return error("Only pending requests can be approved.")
        a = r.get("analysis", {})
        risky = a.get("blacklisted") or a.get("lookalike")
        if risky and not b.get("override"):
            return error("This domain is blacklisted or looks like a popular brand. Approve only if you are completely sure (tick the override box).", 409)
        if d.verified_sites.find_one({"domain": r["domain"], "status": "approved"}):
            return error("This domain is already verified.", 409)
        checks = [c for c in (b.get("checks") or []) if c in sites.MANUAL_CHECKS]
        if not sites.ownership_proof(r)["proven"] and not checks:
            return error("Ownership is not proven yet. Ask the owner to add the code to the website and press 'Check my code', "
                         "or tick the manual check you completed (documents verified / organisation contacted).", 409)
        d.verified_sites.update_one({"verified_id": vid}, {"$set": {"admin_checks": checks}})
        new = "approved"
        if a.get("blacklisted"):
            d.blacklist.delete_one({"domain": r["domain"]})
    elif action == "reject":
        if r["status"] != "pending":
            return error("Only pending requests can be rejected.")
        new = "rejected"
    else:
        if r["status"] != "approved":
            return error("Only approved sites can be revoked.")
        new = "revoked"
    d.verified_sites.update_one({"verified_id": vid}, {"$set": {"status": new, "admin_note": note, "reviewed_at": db.now(),
                                                              "reviewed_by": g.user["user_id"], "reviewer_name": g.user["name"]}})
    log_admin("site_" + new, "%s %s" % (vid, r["domain"]))
    return jsonify(site_view(d.verified_sites.find_one({"verified_id": vid}), admin=True))


@app.get("/api/admin/reports")
@login_required("admin")
def get_reports():
    return jsonify([{"report_id": r["report_id"], "generated_by": r["generated_by"], "report_type": r["report_type"],
                     "date_range": r["date_range"], "generated_at": iso(r["generated_at"]), "file_path": r["file_path"]}
                    for r in db.get_db().reports.find().sort("report_id", -1)])


@app.post("/api/admin/reports")
@login_required("admin")
def make_report():
    b = body()
    rtype = str(b.get("report_type") or "Scan Summary")[:40]
    rng = str(b.get("date_range") or "All time")[:40]
    m = re.search(r"\d+", rng)
    query = {}
    if m:
        query["scan_date"] = {"$gte": (db.now() - timedelta(days=int(m.group()))).replace(tzinfo=None)}
    rows = joined_scans(query, limit=100000)
    if rtype == "Fake Websites":
        rows = [r for r in rows if r["result"] and r["result"]["classification"] == "Fake"]
    rid = db.next_id("R", "reports")
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    path = os.path.join("generated_reports", rid + ".csv")
    with open(os.path.join(config.BASE, path), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scan_id", "user", "url", "domain", "date", "risk_score", "classification", "reason"])
        for r in rows:
            res = r["result"] or {}
            w.writerow([r["scan_id"], r.get("user_name"), r["submitted_url"], r["domain"], r["scan_date"],
                        res.get("risk_score"), res.get("classification"), res.get("detection_reason")])
    doc = {"report_id": rid, "generated_by": g.user["user_id"], "report_type": rtype, "date_range": rng,
           "generated_at": db.now(), "file_path": path.replace("\\", "/")}
    db.get_db().reports.insert_one(dict(doc))
    log_admin("report_generated", rid)
    doc["generated_at"] = iso(doc["generated_at"])
    return jsonify(doc), 201


if __name__ == "__main__":
    db.get_db()    # connect now so a missing MongoDB is reported clearly at start-up
    print("Loading the detection model (one time, please wait)...")
    analyse("http://example.com")    # warm-up: loads the ML model and trusted-domain list now, not on the first scan
    print("\nPortal running ->  http://localhost:5000\n")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
