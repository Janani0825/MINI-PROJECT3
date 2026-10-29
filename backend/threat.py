"""
Threat monitor: reacts to *behaviour over time*, not just to one URL.

Runs after every scan and applies four rules (limits are in config.py):

  repeat     one user keeps trying the same fake website            -> domain is auto-blacklisted
  crowd      several different users run into the same fake website -> domain is auto-blacklisted
  campaign   several look-alike domains of ONE popular brand appear  -> all of them are auto-blacklisted
             (fristcry.com, fristfry.com, fristtry.com -> campaign against firstcry.com)
  risky_user one user scans many different fake websites quickly     -> admin is alerted

Every action creates (or updates) an incident that the admin can review, dismiss, or undo (un-block).
"""
from datetime import timedelta

import config
import db


def _since(**kw):
    return (db.now() - timedelta(**kw)).replace(tzinfo=None)


def _fake_scans(d, since, **match):
    """Scans in the time window whose result is Fake, as (scan, result) pairs."""
    q = {"scan_date": {"$gte": since}}
    q.update(match)
    scans = {s["scan_id"]: s for s in d.scans.find(q)}
    if not scans:
        return []
    res = d.detection_result.find({"scan_id": {"$in": list(scans)}, "classification": "Fake"})
    return [(scans[r["scan_id"]], r) for r in res]


def _block(d, domain, source):
    """Add the domain to the blacklist. True only if it was newly added."""
    if d.blacklist.find_one({"domain": domain}):
        return False
    d.blacklist.insert_one({"blacklist_id": db.next_id("B", "blacklist"), "domain": domain,
                            "added_date": db.now(), "source": source[:60]})
    return True


def _incident(d, kind, key, severity, title, details, domains=(), users=(), auto_action=""):
    """Create the incident, or update the open one for the same (kind, key) so the admin sees one row, not spam."""
    inc = d.incidents.find_one({"kind": kind, "key": key, "status": "open"})
    fields = {"severity": severity, "title": title, "details": details, "domains": sorted(set(domains)),
              "users": sorted(set(users)), "auto_action": auto_action, "updated_at": db.now()}
    if inc:
        d.incidents.update_one({"incident_id": inc["incident_id"]}, {"$set": fields})
        return False
    d.incidents.insert_one(dict(fields, incident_id=db.next_id("I", "incidents"), kind=kind, key=key,
                                status="open", created_at=db.now()))
    return True


def inspect(d, scan, result):
    """Apply the rules for one new scan. Returns a short notice for the user, or None."""
    if result.get("classification") != "Fake" or result.get("decided_by") == "whitelist":
        return None
    domain, uid, notice = scan["domain"], scan["user_id"], None
    already = d.blacklist.find_one({"domain": domain}) is not None

    # 1. repeat: the same user keeps trying the same fake site
    mine = [s for s, _ in _fake_scans(d, _since(minutes=config.REPEAT_WINDOW_MIN), user_id=uid, domain=domain)]
    if len(mine) >= config.REPEAT_COUNT and not already:
        _block(d, domain, "Auto: repeated attempts")
        _incident(d, "repeat", domain + "|" + uid, "medium", "Repeated attempts on %s" % domain,
                  "%s scanned %s %d times in %d minutes; it was detected as Fake every time."
                  % (uid, domain, len(mine), config.REPEAT_WINDOW_MIN), [domain], [uid], "Domain added to blacklist")
        notice = "%s was scanned repeatedly and has been added to the blacklist automatically." % domain
        already = True

    # 2. crowd: different users run into the same fake site
    others = _fake_scans(d, _since(hours=config.CROWD_WINDOW_H), domain=domain)
    users = {s["user_id"] for s, _ in others}
    if len(users) >= config.CROWD_USERS and not already:
        _block(d, domain, "Auto: reported by %d users" % len(users))
        _incident(d, "crowd", domain, "high", "%s hit by %d different users" % (domain, len(users)),
                  "%d users scanned %s within %d hours and it was Fake each time." % (len(users), domain, config.CROWD_WINDOW_H),
                  [domain], users, "Domain added to blacklist")
        notice = "%s was detected for several users and has been added to the blacklist automatically." % domain
        already = True

    # 3. campaign: several look-alike domains of one popular brand
    lk = result.get("lookalike")
    if lk and lk.get("strength") == "strong":
        target = lk["matched_domain"]
        fam = {s["domain"] for s, r in _fake_scans(d, _since(hours=config.CAMPAIGN_WINDOW_H))
               if (r.get("lookalike") or {}).get("matched_domain") == target
               and (r.get("lookalike") or {}).get("strength") == "strong"}
        if len(fam) >= config.CAMPAIGN_DOMAINS:
            added = [x for x in sorted(fam) if _block(d, x, "Auto: campaign against " + target)]
            _incident(d, "campaign", target, "high", "Phishing campaign against %s" % target,
                      "%d look-alike domains of %s were detected within %d hours: %s."
                      % (len(fam), target, config.CAMPAIGN_WINDOW_H, ", ".join(sorted(fam))),
                      fam, [], "All %d look-alike domains blacklisted" % len(fam))
            if domain in fam and (added or already):
                notice = "%s is part of a phishing campaign against %s and is blacklisted." % (domain, target)

    # 4. risky user: many different fake sites in a short time
    recent = _fake_scans(d, _since(minutes=config.RISKY_WINDOW_MIN), user_id=uid)
    doms = {s["domain"] for s, _ in recent}
    if len(doms) >= config.RISKY_DOMAINS:
        _incident(d, "risky_user", uid, "medium", "User %s is scanning many fake sites" % uid,
                  "%s scanned %d different fake websites in %d minutes. They may be testing the system or be under attack."
                  % (uid, len(doms), config.RISKY_WINDOW_MIN), doms, [uid], "Admin alerted")
    return notice
