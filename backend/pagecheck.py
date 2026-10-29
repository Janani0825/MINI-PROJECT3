"""
Optional ONLINE page check ("deep scan").

The normal scan only reads the URL text. This extra step safely downloads the page (HTML only, no JavaScript is
run, nothing is saved) and looks for what a cloned phishing page does:

  * a password box on a page whose domain is not the brand it imitates
  * a login form that sends the data to a DIFFERENT domain
  * images / styles loaded straight from the real brand's website (typical for copied pages)
  * page text and structure almost identical to the real website's home page
  * a very recently registered domain (RDAP lookup)

If the site cannot be reached the result simply says so; the URL verdict is unchanged.
Safety: only http/https, only public IP addresses (blocks localhost / private networks), 6 s timeout, 1 MB limit,
max 4 redirects (each one re-checked).
"""
import ipaddress
import json
import os
import re
import socket
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import config

try:
    import requests
except ImportError:          # the portal still works without it; deep scan reports a clear message
    requests = None

UA = "Mozilla/5.0 (compatible; PhishGuardBot/1.0; +safety-check)"
TIMEOUT, MAX_BYTES, MAX_REDIRECTS = 6, 1_000_000, 4
_CACHE = {}                  # real-site fingerprints: domain -> (time, fingerprint)
CACHE_SECONDS = 3600


# ------------------------------------------------------------------ safe fetching
def _public_host(host):
    """Raise ValueError unless every address of `host` is a normal public IP."""
    if os.environ.get("ALLOW_PRIVATE_FETCH") == "1":          # for local demos / tests only
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("the domain does not resolve (it may not exist or be offline)")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("refused: the address is not a public internet address")


def fetch(url):
    """Return (final_url, html). Raises ValueError with a readable message."""
    final, html, _ = fetch_full(url)
    return final, html


def fetch_full(url):
    """Return (final_url, html, response_headers). Raises ValueError with a readable message."""
    if requests is None:
        raise ValueError("the 'requests' package is not installed (pip install requests)")
    cur = url
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(cur)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("unsupported address")
        _public_host(p.hostname)
        try:
            r = requests.get(cur, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False, stream=True)
        except requests.RequestException as e:
            raise ValueError("could not open the page (%s)" % type(e).__name__)
        if r.is_redirect and r.headers.get("Location"):
            cur = urljoin(cur, r.headers["Location"])
            r.close()
            continue
        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype.lower() and ctype:
            r.close()
            raise ValueError("the address is not a web page")
        raw = b""
        for chunk in r.iter_content(8192):
            raw += chunk
            if len(raw) > MAX_BYTES:
                break
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        try:
            hdrs["set-cookie-list"] = r.raw.headers.getlist("Set-Cookie")
        except Exception:
            hdrs["set-cookie-list"] = [hdrs["set-cookie"]] if hdrs.get("set-cookie") else []
        r.close()
        return cur, raw.decode(r.encoding or "utf-8", errors="replace"), hdrs
    raise ValueError("too many redirects")


# ------------------------------------------------------------------ security headers
SEC_HEADERS = [
    ("https", "HTTPS encryption", "Serve the whole site over HTTPS and redirect HTTP to HTTPS."),
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' so browsers always use HTTPS."),
    ("content-security-policy", "Content-Security-Policy", "Add a Content-Security-Policy to limit where scripts and images can load from. It reduces the impact of XSS."),
    ("x-frame-options", "Clickjacking protection", "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors rule) so the site cannot be embedded in another page."),
    ("x-content-type-options", "X-Content-Type-Options", "Add 'X-Content-Type-Options: nosniff' to stop browsers guessing file types."),
    ("referrer-policy", "Referrer-Policy", "Add 'Referrer-Policy: strict-origin-when-cross-origin' to avoid leaking full URLs."),
    ("cookies", "Secure cookies", "Mark cookies as Secure and HttpOnly (and SameSite) so they cannot be stolen or sent over HTTP."),
]


def security_headers(headers, final_url):
    """Pure function: which standard protections the site sends. Information only, it never changes the risk score."""
    h = headers or {}
    https = urlparse(final_url).scheme == "https"
    cookies = h.get("set-cookie-list") or []
    items = []
    for key, label, tip in SEC_HEADERS:
        if key == "https":
            ok = https
        elif key == "cookies":
            ok = None if not cookies else all("secure" in c.lower() and "httponly" in c.lower() for c in cookies)
        elif key == "x-frame-options":
            ok = bool(h.get("x-frame-options")) or "frame-ancestors" in (h.get("content-security-policy") or "").lower()
        else:
            ok = bool(h.get(key))
        if ok is None:
            items.append({"key": key, "label": label, "status": "na", "tip": ""})
        else:
            items.append({"key": key, "label": label, "status": "pass" if ok else "fail", "tip": "" if ok else tip})
    scored = [i for i in items if i["status"] != "na"]
    passed = sum(1 for i in scored if i["status"] == "pass")
    score = round(100 * passed / len(scored)) if scored else 0
    return {"score": score, "passed": passed, "total": len(scored), "items": items,
            "grade": "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"}


# ------------------------------------------------------------------ parsing
class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title, self._skip = "", False, 0
        self.text, self.tags = [], []
        self.password = 0
        self.form_actions, self.resources = [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if tag == "title": self._in_title = True
        if tag in ("script", "style", "noscript"): self._skip += 1
        if tag == "input" and (a.get("type") or "").lower() == "password": self.password += 1
        if tag == "form": self.form_actions.append(a.get("action") or "")
        for k in ("src", "href"):
            if a.get(k) and tag in ("img", "script", "link", "iframe", "source", "video"):
                self.resources.append(a[k])

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False
        if tag in ("script", "style", "noscript") and self._skip: self._skip -= 1

    def handle_data(self, data):
        if self._in_title: self.title += data
        elif not self._skip and data.strip(): self.text.append(data.strip())


def parse_page(html):
    p = _Page()
    try:
        p.feed(html[:MAX_BYTES])
    except Exception:
        pass
    return p


def _reg(host, ext):
    return (ext(host or "").top_domain_under_public_suffix or (host or "")).lower()


def fingerprint(html):
    p = parse_page(html)
    words = re.findall(r"[a-z0-9]+", " ".join(p.text).lower())
    shingles = {" ".join(words[i:i + 3]) for i in range(max(0, len(words) - 2))}
    return {"title": re.sub(r"\s+", " ", p.title).strip(), "shingles": shingles, "tags": "".join(t[0] for t in p.tags[:400])}


def similarity(fp_a, fp_b):
    """0..1 : how much the text (3-word shingles) and the HTML structure of two pages overlap."""
    from rapidfuzz import fuzz
    a, b = fp_a["shingles"], fp_b["shingles"]
    jac = len(a & b) / len(a | b) if a and b else 0.0
    struct = fuzz.ratio(fp_a["tags"], fp_b["tags"]) / 100 if fp_a["tags"] and fp_b["tags"] else 0.0
    return round(0.65 * jac + 0.35 * struct, 3)


def analyse_html(html, page_url, real_domain, ext, real_fp=None):
    """Pure function (no network): findings for one downloaded page. Easy to unit-test."""
    p = parse_page(html)
    here = _reg(urlparse(page_url).hostname, ext)
    f = {"title": re.sub(r"\s+", " ", p.title).strip()[:120], "has_password_form": p.password > 0,
         "form_to_other_domain": False, "hotlinked_from_brand": 0, "similarity_to_real": None, "points": 0, "reasons": []}
    for act in p.form_actions:
        if act.startswith(("http://", "https://", "//")):
            tgt = _reg(urlparse(urljoin(page_url, act)).hostname, ext)
            if tgt and tgt != here:
                f["form_to_other_domain"] = True
    if real_domain:
        base = _reg(real_domain, ext)
        f["hotlinked_from_brand"] = sum(1 for r in p.resources if r.startswith(("http", "//"))
                                        and _reg(urlparse(urljoin(page_url, r)).hostname, ext) == base)
    if f["has_password_form"]:
        f["points"] += 10
        f["reasons"].append("The page asks for a password.")
    if f["form_to_other_domain"]:
        f["points"] += 25
        f["reasons"].append("The form sends the entered data to a different website than the one you are on.")
    if f["hotlinked_from_brand"]:
        f["points"] += 25
        f["reasons"].append("The page loads %d images/files directly from %s: a sign it was copied from the real site."
                            % (f["hotlinked_from_brand"], real_domain))
    if real_fp is not None:
        f["similarity_to_real"] = similarity(fingerprint(html), real_fp)
        if f["similarity_to_real"] >= 0.6:
            f["points"] += 35
            f["reasons"].append("The page is %d%% identical to the real %s home page, but it is hosted on a different domain."
                                % (round(f["similarity_to_real"] * 100), real_domain))
    if real_domain and real_domain.split(".")[0] in f["title"].lower() and here != _reg(real_domain, ext):
        f["points"] += 10
        f["reasons"].append("The page title uses the name of %s." % real_domain)
    return f


# ------------------------------------------------------------------ domain age (RDAP)
def domain_age_days(reg_domain):
    if requests is None:
        return None
    try:
        r = requests.get("https://rdap.org/domain/" + reg_domain, headers={"User-Agent": UA}, timeout=TIMEOUT)
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                from datetime import datetime, timezone
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - d).days)
    except Exception:
        return None
    return None


# ------------------------------------------------------------------ entry point
def augment(out, url, ext):
    """Add page findings to the result of ml.predict.analyse(). Never raises.
    Page content can only RAISE the risk. The security-header report is information only."""
    r = out["result"]
    if r["decided_by"] == "blacklist":
        r["page"] = {"checked": False, "note": "Skipped: this domain is blacklisted, so it is not opened."}
        return out
    certain = r["decided_by"] in ("whitelist", "restricted-tld")
    real = None if certain else (r.get("lookalike") or {}).get("matched_domain")
    page = {"checked": False}
    try:
        final_url, html, hdrs = fetch_full(out_url(url))
        page["checked"] = True
        r["security"] = security_headers(hdrs, final_url)
        if certain:
            page["note"] = "Content analysis skipped: this domain is already trusted."
            r["page"] = page
            return out
        real_fp = None
        if real:
            try:
                real_fp = _real_fingerprint(real)
            except ValueError:
                real_fp = None            # real site not reachable: skip the comparison only
        f = analyse_html(html, final_url, real, ext, real_fp)
        age = domain_age_days(out["domain"])
        if age is not None:
            f["domain_age_days"] = age
            if age < 30:
                f["points"] += 20; f["reasons"].append("The domain was registered only %d days ago." % age)
            elif age < 180:
                f["points"] += 10; f["reasons"].append("The domain is less than 6 months old (%d days)." % age)
        page.update({k: v for k, v in f.items() if k not in ("reasons",)})
        if f["points"]:
            r["risk_score"] = min(100, round(r["risk_score"] + f["points"]))
            r["classification"] = "Fake" if r["risk_score"] >= 60 else "Suspicious" if r["risk_score"] >= 30 else "Safe"
            r["reasons"] = r["reasons"] + f["reasons"]
            r["detection_reason"] = " ".join(r["reasons"])
            r["decided_by"] = r["decided_by"] + "+page"
            if r["classification"] == "Fake":
                r["recommendation"] = "Do not open this website or share any information. Report it to your administrator."
        else:
            r["reasons"] = r["reasons"] + ["The page content was checked and nothing suspicious was found on it."]
            r["detection_reason"] = " ".join(r["reasons"])
    except ValueError as e:
        page["note"] = "Deep scan could not read this page (%s)." % e
        if not certain:
            r["reasons"] = r["reasons"] + [page["note"]]
            r["detection_reason"] = " ".join(r["reasons"])
    r["page"] = page
    return out


def out_url(url):
    return url if re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.I) else "http://" + url


def _real_fingerprint(domain):
    hit = _CACHE.get(domain)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    _, html = fetch("https://" + domain)
    fp = fingerprint(html)
    _CACHE[domain] = (time.time(), fp)
    return fp
