"""
Evaluate the hybrid detector (blacklist + trusted list + look-alike + ML + rules) against ML-only.

    python evaluate_hybrid.py --data-dir PATH [--n 1500]

Writes reports/hybrid_evaluation.md and reports/hybrid_evaluation.json.
Test sets (all built here, nothing is hard-coded):
  1. phishing        random URLs from the phishing feed (as they are)
  2. phishing_home   the same kind of URLs reduced to their home page
  3. legit_home      home pages of real sites that are NOT in the trusted top-100k (rank 100k-1M)
  4. legit_path      the same sites with a realistic path
  5. typosquat       generated misspellings of the top-2000 brands (names of 5+ letters) (swap / delete / insert / replace / look-alike char / hyphen)
Look-alike layer is also checked alone (20% of the typosquats use a different domain ending): hit rate on typosquats, false-alarm rate on real, unrelated domains.
"""
import argparse, json, os, random, re, sys, time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import features as F          # noqa: E402
import lookalike as LK        # noqa: E402
import predict                # noqa: E402

random.seed(7)
GLYPH = {"l": "1", "o": "0", "e": "3", "a": "4", "s": "5", "i": "1", "t": "7"}


def lines(p):
    with open(p, errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def typo(label):
    kind = random.choice(["swap", "delete", "insert", "replace", "glyph", "hyphen"])
    i = random.randrange(1, len(label) - 1)
    if kind == "swap": return label[:i] + label[i + 1] + label[i] + label[i + 2:]
    if kind == "delete": return label[:i] + label[i + 1:]
    if kind == "insert": return label[:i] + random.choice(label) + label[i:]
    if kind == "replace": return label[:i] + random.choice("abcdefghijklmnopqrstuvwxyz") + label[i + 1:]
    if kind == "hyphen": return label[:i] + "-" + label[i:]
    cands = [j for j, c in enumerate(label) if c in GLYPH] or [i]
    j = random.choice(cands)
    return label[:j] + GLYPH.get(label[j], "x") + label[j + 1:]


def verdict(risk):
    return "Fake" if risk >= 60 else "Suspicious" if risk >= 30 else "Safe"


def run(urls, mode):
    """mode: ml (ML probability only) | raw (hybrid, cap off) | hybrid (hybrid, cap on = portal default)"""
    out = {"Safe": 0, "Suspicious": 0, "Fake": 0}
    os.environ["ML_ONLY_CAP"] = "0" if mode == "raw" else "1"
    for u in urls:
        try:
            r = predict.analyse(u, [])["result"]
        except Exception:
            continue
        if mode == "ml":
            p = r.get("ml_probability")
            out[verdict(p if p is not None else r["risk_score"])] += 1
        else:
            out[r["classification"]] += 1
    return out


def pct(d, k):
    n = sum(d.values()) or 1
    return round(100 * d[k] / n, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--n", type=int, default=1500)
    a = ap.parse_args()
    n = a.n
    top = lines(os.path.join(a.data_dir, "top-1000000-domains"))
    white = set(top[:100000])

    phish = [u for u in lines(os.path.join(a.data_dir, "phishing-links-ACTIVE.txt")) if u.lower().startswith(("http://", "https://"))]
    random.shuffle(phish)
    seen, ph = {}, []
    for u in phish:
        h = urlparse(u).hostname or ""
        if seen.get(h, 0) < 2:
            seen[h] = seen.get(h, 0) + 1
            ph.append(u)
        if len(ph) >= n: break
    ph_home = ["%s://%s/" % (urlparse(u).scheme, urlparse(u).netloc) for u in ph]

    real_paths = []
    for u in lines(os.path.join(a.data_dir, "1.Benign_list_big_final.csv")):
        p = urlparse(u)
        if u.lower().startswith("http") and len(p.path) > 1:
            real_paths.append(p.path + (("?" + p.query) if p.query else ""))
    unk = random.sample(top[100000:], n)
    legit_home = ["https://%s/" % d for d in unk]
    legit_path = ["https://%s%s" % (d, random.choice(real_paths)[:150]) for d in unk]

    ext = F._EXTRACT
    brands = [d for d in top[:2000] if len(ext(d).domain) >= 5]
    typ = set()
    while len(typ) < n:
        d = random.choice(brands); e = ext(d)
        suf = e.suffix if random.random() < 0.8 else random.choice(["net", "org", "info", "xyz", "co"])   # 20% use another ending
        v = typo(e.domain) + "." + suf
        if v != d and v not in white:
            typ.add(v)
    typ = ["http://%s/" % v for v in sorted(typ)]

    sets = {"phishing (feed URLs)": ph, "phishing (home page only)": ph_home, "legit unknown (home page)": legit_home,
            "legit unknown (with path)": legit_path, "typosquat of top brands": typ}
    res = {}
    for name, urls in sets.items():
        t = time.time()
        res[name] = {m: run(urls, m) for m in ("ml", "raw", "hybrid")}
        res[name]["n"] = len(urls)
        print(name, len(urls), "%.0fs" % (time.time() - t), file=sys.stderr)

    lk_hit = sum(1 for u in typ if LK.find(ext(urlparse(u).hostname).top_domain_under_public_suffix))
    neg = [d for d in random.sample(top[20000:], n)]
    lk_fp = sum(1 for d in neg if LK.find(ext(d).top_domain_under_public_suffix) and LK.find(ext(d).top_domain_under_public_suffix)["strength"] == "strong")
    lk = {"typosquat_hit_rate": round(100 * lk_hit / len(typ), 1), "false_strong_alarm_rate": round(100 * lk_fp / len(neg), 2), "n_typo": len(typ), "n_neg": len(neg)}

    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    json.dump({"sets": res, "lookalike": lk}, open(os.path.join(HERE, "reports", "hybrid_evaluation.json"), "w"), indent=1)
    md = ["# Hybrid detector vs ML-only", "", "Share of URLs given each verdict (%). *Fake rate* is what matters for phishing and typosquats (higher = better); "
          "for legitimate sites lower is better.", "",
          "| Test set | n | ML only: Fake | ML only: flagged | Hybrid (no cap): Fake | Hybrid (no cap): flagged | **Portal default: Fake** | **Portal default: flagged** |",
          "|---|---|---|---|---|---|---|---|"]
    for name, r in res.items():
        f = lambda m, k: pct(r[m], k)
        fl = lambda m: round(100 - pct(r[m], "Safe"), 1)
        md.append("| %s | %d | %s | %s | %s | %s | **%s** | **%s** |" % (name, r["n"], f("ml", "Fake"), fl("ml"), f("raw", "Fake"), fl("raw"), f("hybrid", "Fake"), fl("hybrid")))
    md += ["", "*flagged* = Suspicious or Fake. *Portal default* = all layers with ML_ONLY_CAP=1.", "",
           "## Look-alike layer alone", "", "- Typosquat detection rate: **%s%%** of %d generated misspellings of the top-2000 brands" % (lk["typosquat_hit_rate"], lk["n_typo"]),
           "- Strong look-alike false alarms on %d real, unrelated domains (rank 20k-1M): **%s%%**" % (lk["n_neg"], lk["false_strong_alarm_rate"])]
    open(os.path.join(HERE, "reports", "hybrid_evaluation.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
