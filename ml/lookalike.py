"""
Look-alike (typosquatting / brand impersonation) detector.

Compares the registered domain of a URL with the 100,000 most popular domains (the same offline
whitelist the portal uses) instead of a short hand-written brand list.

    fristcry.com   -> looks like firstcry.com  (letters swapped)
    fristtry.com   -> looks like firstcry.com  (1 letter changed)
    paypa1.com     -> looks like paypal.com    (look-alike character)
    first-cry.com  -> looks like firstcry.com  (hyphen added)
    firstcry.net   -> same name as firstcry.com but a different ending

Everything is offline: only text comparison, nothing is opened.
"""
import os
import re
import sys

from rapidfuzz import process
from rapidfuzz.distance import OSA   # Damerau-Levenshtein: a swap of two letters counts as ONE edit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
_STATE = {}

# characters that look alike; each is replaced by the letter it imitates
_GLYPH = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l", "$": "s"}
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))
STRONG, WEAK = "strong", "weak"
TARGET_RANK = 20000          # only popular sites are worth impersonating; this keeps false alarms low


def _extract():
    import features as F
    return F._EXTRACT


def _load():
    if _STATE:
        return _STATE
    wl = os.path.join(HERE, "data", "whitelist_top100k.txt")
    domains = open(wl).read().split() if os.path.exists(wl) else []
    ext = _extract()
    labels, first_domain, rank = [], {}, {}
    for i, dom in enumerate(domains[:TARGET_RANK]):
        label = (ext(dom).domain or "").lower()
        if len(label) >= 5 and label not in first_domain:
            first_domain[label] = dom
            rank[label] = i + 1
            labels.append(label)
    _STATE.update(domains=set(domains), labels=labels, first=first_domain, rank=rank)
    return _STATE


def _normalise(label):
    s = "".join(_GLYPH.get(c, c) for c in label)
    for a, b in _MULTI:
        s = s.replace(a, b)
    return s


def _kind(query, target):
    """Describe how `query` differs from `target` in plain words."""
    if len(query) == len(target):
        diffs = [i for i in range(len(query)) if query[i] != target[i]]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 and query[diffs[0]] == target[diffs[1]] and query[diffs[1]] == target[diffs[0]]:
            return "two letters swapped"
        return "one letter changed"
    if len(query) == len(target) + 1:
        return "one extra letter"
    if len(query) == len(target) - 1:
        return "one letter missing"
    return "a few letters changed"


def find(reg_domain):
    """Return a dict describing the look-alike match, or None.

    {"matched_domain", "kind", "distance", "rank", "strength"}   strength: "strong" (typo-style) | "weak"
    """
    st = _load()
    reg = (reg_domain or "").lower()
    if not reg or reg in st["domains"]:
        return None                              # the real, popular site itself
    ext = _extract()(reg)
    label, suffix = (ext.domain or "").lower(), (ext.suffix or "").lower()
    if len(label) < 5 or label.startswith("xn--"):
        return None
    labels, first, rank = st["labels"], st["first"], st["rank"]   # labels = targets worth imitating (top TARGET_RANK)

    def hit(target, kind, dist, strength):
        return {"matched_domain": first[target], "kind": kind, "distance": dist, "rank": rank[target], "strength": strength}

    # 1. same name with hyphens / underscores removed  (first-cry.com -> firstcry.com)
    squashed = re.sub(r"[-_]", "", label)
    if squashed != label and squashed in first:
        return hit(squashed, "hyphen added inside the name", 1, STRONG)

    # 2. look-alike characters  (paypa1 -> paypal, rnicrosoft -> microsoft)
    norm = _normalise(squashed)
    if norm != squashed and norm in first:
        return hit(norm, "look-alike characters (such as 1 for l, 0 for o)", 1, STRONG)

    # 3. typo: a swap / change / missing or extra letter (Damerau-Levenshtein distance)
    #    1 edit for names of 5+ letters; 2 edits for names of 8+ letters that keep the same first and last letter
    #    (fristcry / fristfry / fristtry are all within 2 edits of firstcry)
    maxd = 1 if len(squashed) < 8 else 2
    best = None
    for q in {squashed, norm}:
        for target, d, _ in process.extract(q, labels, scorer=OSA.distance, score_cutoff=maxd, limit=10):
            if d < 1:
                continue
            if d == 2 and not (q[0] == target[0] and q[-1] == target[-1]):
                continue
            # short names have many innocent neighbours (rulex.ru / rolex.com): accept them only for very popular targets
            # on the SAME domain ending; longer names (8+ letters) are specific enough to be accepted on any ending
            if len(q) < 8:
                same_tld = first[target].split(".", 1)[-1] == suffix
                if not same_tld or (len(target) <= 5 and rank[target] > 1500):
                    continue
            if best is None or (d, rank[target]) < (best[1], rank[best[0]]):
                best = (target, d, q)
    if best:
        target, d, q = best
        return hit(target, _kind(q, target) if d == 1 else "%d letters swapped or changed" % d, d, STRONG)

    # 3b. one word of a longer hyphenated name imitates a popular brand  (paypa1-secure-login.com, amaz0n-offers.net)
    toks = [t for t in re.split(r"[-_]", label) if len(t) >= 5]
    if len(toks) >= 1 and len(toks) != len(re.split(r"[-_]", label)) or "-" in label or "_" in label:
        for tok in toks:
            ntok = _normalise(tok)
            if ntok != tok and ntok in first and rank[ntok] <= TARGET_RANK:
                return hit(ntok, "look-alike characters inside one word of the name", 1, STRONG)
            if len(tok) >= 7:
                for target, d, _ in process.extract(tok, labels, scorer=OSA.distance, score_cutoff=1, limit=3):
                    if d == 1 and rank[target] <= 3000:
                        return hit(target, "one word of the name is a misspelling (%s)" % _kind(tok, target), 1, STRONG)

    # 4. same name, different ending  (firstcry.net vs firstcry.com)
    if squashed in first:
        return hit(squashed, "same name as a popular site but a different domain ending", 0, WEAK)

    # 5. popular brand name used inside a longer hyphenated name  (firstcry-offers.com)
    for tok in re.split(r"[-_]", label):
        if len(tok) >= 7 and tok in first and rank[tok] <= 10000:
            return hit(tok, "popular brand name inside a different domain", 0, WEAK)
    return None


def describe(m):
    if not m:
        return None
    if m["strength"] == STRONG:
        return ("This domain looks like %s (%s). The real site is one of the most popular websites (rank %d)."
                % (m["matched_domain"], m["kind"], m["rank"]))
    return ("This domain uses the name of %s (%s), but it is a different website (rank %d for the real one)."
            % (m["matched_domain"], m["kind"], m["rank"]))


if __name__ == "__main__":
    import sys
    for d in sys.argv[1:] or ["fristcry.com", "fristfry.com", "fristtry.com", "paypa1.com", "first-cry.com", "firstcry.net",
                              "firstcry-offers.com", "firstcry.com", "example-shop.com"]:
        print(d.ljust(24), describe(find(d)))
