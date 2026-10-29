"""
URL feature extraction for the Fake Website Detection Portal.

100% offline: only the URL text is analysed. The page is never opened.
The same function is used for training AND by the Flask backend at prediction
time, so the model always sees identical features.
"""
import math
import re
from urllib.parse import urlparse, unquote

import tldextract
from rapidfuzz.distance import Levenshtein

# offline extractor: no network call for the public-suffix list
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank", "confirm", "password",
    "wallet", "bonus", "free", "gift", "urgent", "suspend", "billing", "invoice", "payment",
    "webscr", "authenticate", "recover", "unlock", "limited", "alert", "support", "validate",
]
BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft", "apple", "instagram", "netflix", "twitter",
    "linkedin", "whatsapp", "youtube", "github", "dropbox", "adobe", "yahoo", "outlook", "office365",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "flipkart", "gpay", "phonepe", "airtel", "jio",
    "dhl", "fedex", "ebay", "chase", "wellsfargo", "citibank", "bankofamerica", "steam", "spotify",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "support", "zip",
              "country", "stream", "download", "loan", "men", "review", "icu", "buzz", "monster", "rest"}
RISKY_EXT = (".php", ".exe", ".zip", ".scr", ".apk", ".js", ".asp", ".aspx", ".cgi")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEXIP_RE = re.compile(r"^(0x[0-9a-f]+\.?)+$", re.I)

FEATURE_NAMES = [
    "url_length", "hostname_length", "num_dots_host", "path_length", "query_length", "num_dots", "num_hyphens",
    "num_underscores", "num_digits", "digit_ratio", "num_special_chars", "has_at_symbol", "has_ip_address",
    "is_https", "non_standard_port", "num_subdomains", "risky_tld", "tld_length", "path_depth",
    "num_query_params", "double_slash_in_path", "has_punycode", "hostname_entropy", "path_entropy",
    "num_suspicious_keywords", "brand_in_subdomain_or_path", "min_brand_distance", "is_shortener",
    "hyphens_in_domain", "digits_in_domain", "domain_length", "longest_host_token", "uppercase_ratio",
    "https_token_in_host", "risky_extension", "num_encoded_chars", "vowel_ratio_domain",
]


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in freq.values())


def parse(url):
    """Return a normalised (url, ParseResult) or raise ValueError for unusable input."""
    u = (url or "").strip()
    if not u or len(u) > 2048 or re.search(r"\s", u):
        raise ValueError("Invalid URL")
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
        u = "http://" + u
    p = urlparse(u)
    if not p.hostname or ("." not in p.hostname and not p.hostname.startswith("[")):
        raise ValueError("Invalid URL")
    return u, p


def extract_features(url):
    """Return a dict {feature_name: number} for one URL."""
    u, p = parse(url)
    host = (p.hostname or "").lower()
    path, query = unquote(p.path or ""), p.query or ""
    ext = _EXTRACT(host)
    domain, suffix, sub = ext.domain, ext.suffix, ext.subdomain
    reg_domain = ext.registered_domain or host
    is_ip = bool(_IP_RE.match(host) or _HEXIP_RE.match(host))
    low = u.lower()

    digits = sum(c.isdigit() for c in u)
    letters = sum(c.isalpha() for c in u)
    sub_labels = [x for x in sub.split(".") if x] if sub else []
    kw = sum(low.count(k) for k in SUSPICIOUS_KEYWORDS)

    # brand abuse: a brand name appears in subdomain/path but is NOT the real registered domain
    sub_path = (sub + "/" + path).lower()
    brand_abuse = int(any(b in sub_path and b != domain.lower() for b in BRANDS))
    # typosquatting: closest brand by edit distance to the domain label (0 = exact, tiny = look-alike)
    dl = domain.lower()
    parts = [t for t in re.split(r"[-_]", dl) if len(t) >= 4] or [dl]
    # an exact brand token is not a *misspelling* (that case is caught by brand_in_subdomain_or_path
    # and the whitelist layer), so only near-misses count as look-alikes
    dists = [Levenshtein.normalized_distance(t, b) for t in parts + [dl] for b in BRANDS if t != b]
    min_bd = min(dists, default=1.0)

    vowels = sum(c in "aeiou" for c in dl)
    tokens = re.split(r"[.\-_]", host)

    return {
        "url_length": len(u),
        "hostname_length": len(host),
        "num_dots_host": host.count("."),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": u.count("."),
        "num_hyphens": u.count("-"),
        "num_underscores": u.count("_"),
        "num_digits": digits,
        "digit_ratio": digits / len(u),
        "num_special_chars": sum(u.count(c) for c in "?&=%~#$!*"),
        "has_at_symbol": int("@" in u),
        "has_ip_address": int(is_ip),
        "is_https": int(p.scheme == "https"),
        "non_standard_port": int(p.port not in (None, 80, 443)) if _safe_port(p) else 1,
        "num_subdomains": len(sub_labels),
        "risky_tld": int(suffix.split(".")[-1] in RISKY_TLDS) if suffix else 0,
        "tld_length": len(suffix),
        "path_depth": len([x for x in path.split("/") if x]),
        "num_query_params": len([x for x in query.split("&") if x]),
        "double_slash_in_path": int("//" in path),
        "has_punycode": int("xn--" in host),
        "hostname_entropy": _entropy(host),
        "path_entropy": _entropy(path),
        "num_suspicious_keywords": kw,
        "brand_in_subdomain_or_path": brand_abuse,
        "min_brand_distance": min_bd,
        "is_shortener": int(reg_domain in SHORTENERS),
        "hyphens_in_domain": dl.count("-"),
        "digits_in_domain": sum(c.isdigit() for c in dl),
        "domain_length": len(dl),
        "longest_host_token": max((len(t) for t in tokens), default=0),
        "uppercase_ratio": sum(c.isupper() for c in u) / max(1, letters),
        "https_token_in_host": int("https" in host or "http" in host),
        "risky_extension": int(path.lower().endswith(RISKY_EXT)),
        "num_encoded_chars": u.count("%"),
        "vowel_ratio_domain": vowels / max(1, len(dl)),
    }


def _safe_port(p):
    try:
        p.port
        return True
    except ValueError:
        return False


def closest_brand(domain):
    """(brand, similarity 0-100) of the well-known brand the domain label most resembles."""
    dl = (domain or "").lower().split(".")[0]
    parts = [t for t in re.split(r"[-_]", dl) if len(t) >= 3] + [dl]
    best = ("", 0.0)
    for t in parts:
        for b in BRANDS:
            sim = 1 - Levenshtein.normalized_distance(t, b)
            if sim > best[1]:
                best = (b, sim)
    return best[0], round(best[1] * 100)


def explain(feats):
    """Human-readable reasons (used on the result page). Rule layer, independent of the ML model."""
    r = []
    if feats["has_ip_address"]: r.append("An IP address is used instead of a domain name.")
    if feats["has_at_symbol"]: r.append("The URL contains an '@' symbol, which can hide the real destination.")
    if feats["url_length"] > 75: r.append(f"The URL is unusually long ({feats['url_length']} characters).")
    if feats["num_subdomains"] >= 3: r.append(f"Too many sub-domains ({feats['num_subdomains']}).")
    if feats["num_hyphens"] > 3: r.append(f"Many hyphens ({feats['num_hyphens']}) in the URL.")
    if feats["num_suspicious_keywords"] >= 2: r.append("Contains several phishing-related words (login, verify, secure ...).")
    if feats["brand_in_subdomain_or_path"]: r.append("A well-known brand name appears in the sub-domain or path, but this is not that brand's real domain.")
    if feats["min_brand_distance"] < 0.35: r.append("The domain looks like a misspelling of a well-known brand (typosquatting).")
    if feats["risky_tld"]: r.append("Uses a domain ending commonly abused by phishing sites.")
    if not feats["is_https"]: r.append("The connection is not encrypted (HTTP instead of HTTPS).")
    if feats["has_punycode"]: r.append("Uses internationalised (punycode) characters that can imitate real letters.")
    if feats["is_shortener"]: r.append("A URL shortener hides the real destination.")
    if feats["risky_extension"]: r.append("Points to a script/executable file type often used in attacks.")
    return r


if __name__ == "__main__":
    import json, sys
    print(json.dumps(extract_features(sys.argv[1] if len(sys.argv) > 1 else "http://paypal.secure-login.xyz/verify.php"), indent=2))
