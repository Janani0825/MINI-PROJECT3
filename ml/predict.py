"""
Hybrid detector used by the Flask backend (and runnable from the command line).

Decision order
  1. Local BLACKLIST (domains the admin added)   -> Fake, risk 100
  2. Local WHITELIST (top 100k trusted domains)  -> Safe (only if the URL is not a look-alike)
  3. ML model probability                        -> risk score 0-100
  4. Look-alike check (typosquatting vs the top-20k popular domains)  -> raises the score, adds the matched real site
  5. Rule layer                                  -> human-readable reasons
Verdict: risk < 30 Safe | 30-59 Suspicious | >= 60 Fake

    python predict.py "http://paypa1-secure-login.com/verify"
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import features as F  # noqa: E402
import lookalike as LK  # noqa: E402
from treemodel import TreeModel  # noqa: E402

SAFE_MAX, FAKE_MIN = 30, 60
# domain endings that only verified institutions can register (a college cannot be faked by just buying a domain)
RESTRICTED_SUFFIXES = {"ac.in", "edu.in", "gov.in", "nic.in", "res.in", "edu", "gov", "mil", "ac.uk", "gov.uk", "edu.au", "gov.au",
                       "ac.lk", "edu.pk", "gov.pk", "ac.jp", "go.jp", "edu.sg", "gov.sg"}
_BUNDLE = None
_WHITELIST = None


def _load():
    global _BUNDLE, _WHITELIST
    if _BUNDLE is None:
        _BUNDLE = TreeModel.load(os.path.join(HERE, "model", "xgb_trees.json"))
        wl = os.path.join(HERE, "data", "whitelist_top100k.txt")
        _WHITELIST = set(open(wl).read().split()) if os.path.exists(wl) else set()
    return _BUNDLE, _WHITELIST


_BASE = None
FRIENDLY = {   # feature -> plain-English label shown in the "what pushed the score" chart
    "url_length": "URL length", "hostname_length": "Host name length", "num_dots_host": "Dots in host name",
    "path_length": "Path length", "query_length": "Query length", "num_dots": "Number of dots",
    "num_hyphens": "Hyphens in URL", "num_underscores": "Underscores", "num_digits": "Digits in URL",
    "digit_ratio": "Share of digits", "num_special_chars": "Special characters", "has_at_symbol": "'@' symbol",
    "has_ip_address": "IP address instead of a domain", "is_https": "HTTPS encryption", "non_standard_port": "Unusual port",
    "num_subdomains": "Number of sub-domains", "risky_tld": "Risky domain ending", "tld_length": "Domain ending length",
    "path_depth": "Path depth", "num_query_params": "Query parameters", "double_slash_in_path": "Double slash in path",
    "has_punycode": "Punycode characters", "hostname_entropy": "Randomness of host name", "path_entropy": "Randomness of path",
    "num_suspicious_keywords": "Phishing words (login, verify...)", "brand_in_subdomain_or_path": "Brand name used in sub-domain/path",
    "min_brand_distance": "Closeness to a brand name", "is_shortener": "URL shortener", "hyphens_in_domain": "Hyphens in domain",
    "digits_in_domain": "Digits in domain", "domain_length": "Domain length", "longest_host_token": "Longest host-name word",
    "uppercase_ratio": "Capital letters", "https_token_in_host": "'http(s)' inside host name", "risky_extension": "Risky file type",
    "num_encoded_chars": "Encoded characters", "vowel_ratio_domain": "Vowel pattern of domain",
}


def _baseline(bundle):
    """Feature values of a plain, harmless URL: what 'nothing suspicious' looks like."""
    global _BASE
    if _BASE is None:
        f = F.extract_features("https://example.com")
        _BASE = [f[n] for n in bundle.features]
    return _BASE


def explain_ml(bundle, x, top=6):
    """Per-URL explanation of the ML score by occlusion: set one feature at a time to its harmless value and
    measure how much the model's raw score (log-odds) drops. Positive = pushed towards phishing, negative = towards safe.
    Returns [{feature, label, impact, share}]  (share = % of the total movement, so the bars are easy to read)."""
    base, m0 = _baseline(bundle), bundle.margin(x)
    rows = []
    for i, name in enumerate(bundle.features):
        if x[i] == base[i]:
            continue
        y = list(x)
        y[i] = base[i]
        d = m0 - bundle.margin(y)
        if abs(d) >= 0.05:
            rows.append({"feature": name, "label": FRIENDLY.get(name, name), "impact": round(d, 2)})
    total = sum(abs(r["impact"]) for r in rows) or 1.0
    for r in rows:
        r["share"] = round(100 * r["impact"] / total)
    up = sorted((r for r in rows if r["impact"] > 0), key=lambda r: -r["impact"])[:top - 2]
    down = sorted((r for r in rows if r["impact"] < 0), key=lambda r: r["impact"])[:2]
    return up + down


def _similarity(lk, reg):
    if lk:
        label = reg.split(".")[0]
        return 100 if lk["distance"] == 0 else max(0, round(100 * (1 - lk["distance"] / max(len(label), 1))))
    return F.closest_brand(reg)[1]


def _brand_match(reg):
    b, sim = F.closest_brand(reg)
    return b + ".com" if sim >= 60 else "-"


def analyse(url, blacklist=()):
    """Return a dict ready to be stored in MongoDB (`features` + `result` parts of a scan)."""
    bundle, whitelist = _load()
    u, p = F.parse(url)
    host = (p.hostname or "").lower()
    reg = F._EXTRACT(host).top_domain_under_public_suffix or host
    feats = F.extract_features(u)
    reasons = F.explain(feats)

    ml_risk = bundle.predict_proba_one([feats[n] for n in bundle.features]) * 100
    source, risk = "ml", ml_risk

    in_black = reg in set(blacklist) or host in set(blacklist)
    if in_black:
        source, risk = "blacklist", 100.0
        reasons.insert(0, "This domain is in the blacklist of known malicious websites.")
    elif reg in whitelist and not feats["has_ip_address"] and not feats["has_at_symbol"]:
        # a trusted domain; only the very strongest ML signals (e.g. look-alike subdomain tricks) can override
        if feats["brand_in_subdomain_or_path"] == 0:
            source, risk = "whitelist", min(ml_risk, 10.0)
            reasons = ["This is a well-known, trusted domain."]

    lk = None
    if source != "blacklist":
        lk = LK.find(reg)
        if lk:
            reasons.insert(0, LK.describe(lk))
            if lk["strength"] == LK.STRONG:
                # a typo of a popular site is a strong signal; together with a high ML score it is almost certain
                risk = max(risk, 80.0 if ml_risk >= 30 else 50.0)
            else:
                risk = max(risk, min(59.0, ml_risk + 15))
            source = "lookalike+ml"
    # --- avoid false alarms: the ML model alone must not call an unfamiliar-but-harmless site "Fake" ---
    corroborated = bool(feats["has_ip_address"] or feats["has_at_symbol"] or feats["risky_tld"] or feats["has_punycode"]
                        or feats["is_shortener"] or feats["brand_in_subdomain_or_path"] or feats["min_brand_distance"] < 0.35
                        or feats["risky_extension"] or feats["num_subdomains"] >= 3 or feats["num_hyphens"] > 3
                        or feats["num_suspicious_keywords"] >= 2 or (lk and lk["strength"] == LK.STRONG))
    suffix = F._EXTRACT(host).suffix
    capped = os.environ.get("ML_ONLY_CAP", "1") == "1"       # set ML_ONLY_CAP=0 to let the ML model alone say "Fake"
    if capped and source not in ("blacklist", "whitelist") and not corroborated:
        if suffix in RESTRICTED_SUFFIXES:
            source, risk = "restricted-tld", min(risk, 20.0)
            reasons = ["The domain ends in .%s, which only verified institutions can register, and no phishing signs were found." % suffix]
        elif risk >= SAFE_MAX:
            risk = min(risk, 59.0 if lk else 49.0)       # ML only: at most "Suspicious", never "Fake"
            reasons.insert(0, "This site is not in the trusted list and looks unfamiliar to the model, but no specific phishing sign "
                              "was found. Verify the site before entering any personal details.")
    certain = ("blacklist", "whitelist", "restricted-tld")
    xvec = [feats[n] for n in bundle.features]
    pipeline = [
        {"layer": "Blacklist", "status": "hit" if in_black else "pass",
         "note": "Domain is in the blacklist" if in_black else "Not in the blacklist"},
        {"layer": "Trusted list", "status": "hit" if source in ("whitelist", "restricted-tld") else "pass",
         "note": ("Popular, trusted domain" if source == "whitelist" else "Restricted domain ending (.%s)" % suffix) if source in ("whitelist", "restricted-tld")
                 else "Not in the top-100k trusted domains"},
        {"layer": "Look-alike", "status": ("hit" if lk else "pass") if source != "blacklist" else "skip",
         "note": LK.describe(lk) if lk else "Does not imitate a popular domain"},
        {"layer": "ML model", "status": "skip" if source in certain else ("hit" if ml_risk >= SAFE_MAX else "pass"),
         "note": "Not needed: the verdict is already certain" if source in certain else "%.0f%% phishing probability" % ml_risk},
    ]
    signals = [] if source in certain else explain_ml(bundle, xvec)
    risk = round(risk)
    cls = "Fake" if risk >= FAKE_MIN else "Suspicious" if risk >= SAFE_MAX else "Safe"
    if not reasons:
        reasons = ["The model found patterns typical of phishing URLs."] if cls != "Safe" else \
                  ["No suspicious characteristics were found in this URL."]
    advice = {
        "Safe": "This URL looks safe, but always check the address bar before entering personal details.",
        "Suspicious": "Proceed with caution. Do not enter passwords or payment details until you verify the site.",
        "Fake": "Do not open this website or share any information. Report it to your administrator.",
    }[cls]
    return {
        "domain": reg, "protocol": p.scheme,
        "features": {  # names match the `scans.features` collection in the schema
            "url_length": feats["url_length"], "has_ip_address": bool(feats["has_ip_address"]),
            "has_at_symbol": bool(feats["has_at_symbol"]), "num_dots": feats["num_dots"],
            "num_hyphens": feats["num_hyphens"], "has_suspicious_keywords": feats["num_suspicious_keywords"] > 0,
            "is_blacklisted": in_black, "all": feats,
        },
        "result": {
            "risk_score": risk, "classification": cls, "detection_reason": " ".join(reasons), "reasons": reasons,
            "ml_probability": round(ml_risk, 1), "decided_by": source,
            "similarity_score": _similarity(lk, reg),
            "matched_legit_domain": lk["matched_domain"] if lk else _brand_match(reg),
            "lookalike": lk, "pipeline": pipeline, "signals": signals,
            "recommendation": advice,
        },
    }


if __name__ == "__main__":
    import json
    out = analyse(sys.argv[1] if len(sys.argv) > 1 else "http://paypa1-secure-login.com/verify")
    out["features"].pop("all")
    print(json.dumps(out, indent=2))
