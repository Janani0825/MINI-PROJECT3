"""
Verified Website Registry.

A website owner asks the admin to certify their site. The admin reviews the request with help from automatic checks
(is the contact e-mail on the same domain? does the domain look like a popular brand? is it blacklisted? what does the
scanner say?) and either approves or rejects it. Approved sites are shown as "Verified" to everybody who scans them,
together with who owns the site and what it is used for.
"""
import re
import secrets

import db

CATEGORIES = ["College / School / University", "Government / Public service", "Bank / Finance", "Shop / Business",
              "Healthcare", "NGO / Community", "Personal / Portfolio", "Other"]
FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com", "live.com", "icloud.com", "proton.me", "protonmail.com"}


def normalise_domain(ext, host):
    return (ext(host).top_domain_under_public_suffix or host or "").lower()


def email_matches(email, domain):
    ed = email.rsplit("@", 1)[-1].lower()
    return ed == domain or ed.endswith("." + domain)


def new_token():
    return "phishguard-verify-" + secrets.token_hex(8)


def public_record(r):
    """What every logged-in user may see about a verified site."""
    return {"domain": r["domain"], "org_name": r["org_name"], "category": r["category"], "purpose": r["purpose"],
            "owner_name": r["owner_name"], "verified_on": r.get("reviewed_at")}


def lookup(d, domain):
    return d.verified_sites.find_one({"domain": domain, "status": "approved"})


MANUAL_CHECKS = {"documents": "Official documents / proof checked", "contacted": "Organisation contacted on its official phone or e-mail"}


def ownership_proof(rec):
    """Automatic proof = the owner's code was found on the live website (only the real owner can edit it).
    An e-mail address on the domain is only a hint: anyone can type one, so it never counts as proof by itself."""
    t = rec.get("token_check") or {}
    return {"proven": bool(t.get("found")), "ways": ["verification code found on the website"] if t.get("found") else []}


def risk_flags(rec):
    """Human-readable checks shown to the admin. [(level, text)] level: ok | warn | bad."""
    a, out = rec.get("analysis", {}), []
    pr = ownership_proof(rec)
    out.append(("ok", "Ownership proven: the verification code was found on the website.") if pr["proven"] else
               ("warn", "Ownership not proven automatically yet. Check the code, or verify the owner manually."))
    out.append(("ok", "Contact e-mail is on the same domain (a hint only: it is not proof).") if a.get("email_match") else
               ("warn", "Contact e-mail is a free address (Gmail etc.): cannot prove ownership.") if a.get("free_mail") else
               ("bad", "Contact e-mail is on a different domain."))
    if a.get("lookalike"):
        out.append(("bad", "Domain looks like %s (%s)." % (a["lookalike"]["matched_domain"], a["lookalike"]["kind"])))
    if a.get("blacklisted"):
        out.append(("bad", "Domain is in the blacklist."))
    out.append(("bad" if a.get("classification") == "Fake" else "warn" if a.get("classification") == "Suspicious" else "ok",
                "Scanner verdict: %s (risk %s%%)." % (a.get("classification"), a.get("risk_score"))))
    t = rec.get("token_check")
    if t:
        out.append(("ok" if t["found"] else "bad", "Ownership token %s (%s)." % ("found on the website" if t["found"] else "NOT found", t["note"])))
    if a.get("competing", 0):
        out.append(("warn", "%d other pending claim(s) for the same domain." % a["competing"]))
    return out
