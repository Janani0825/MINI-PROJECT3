"""
Train and evaluate the phishing URL classifiers.

    python train.py                      # uses ./data
    python train.py --data-dir PATH --phish 60000 --benign 55000

Outputs: model/model.joblib, reports/metrics.json, reports/comparison.md,
         reports/confusion_matrix.png, reports/roc_curve.png, reports/feature_importance.png,
         data/whitelist_top100k.txt (trusted domains for the hybrid decision layer)
"""
import argparse
import json
import os
import random
import re
import sys
from collections import defaultdict
from multiprocessing import Pool
from urllib.parse import urlparse

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import features as F
from treemodel import export_from_xgboost

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
PATHS = ["/login", "/signin", "/account/settings", "/products?id=1042", "/about-us", "/contact",
         "/search?q=weather", "/blog/2024/05/how-to-save-money", "/news/world/article-8841", "/help/faq",
         "/user/profile", "/checkout/payment", "/support/ticket/2231", "/en/home", "/download/app"]


def read_lines(path):
    with open(path, errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def is_homepage(url):
    p = urlparse(url if "://" in url else "http://" + url)
    return p.path in ("", "/") and not p.query


def reg_domain(url):
    try:
        return F._EXTRACT(urlparse(url if "://" in url else "http://" + url).hostname or "").registered_domain or url
    except Exception:
        return url


def safe_features(url):
    try:
        d = F.extract_features(url)
        return [d[n] for n in F.FEATURE_NAMES]
    except Exception:
        return None


def cap_per_group(urls, cap, key=reg_domain):
    seen, out = defaultdict(int), []
    for u in urls:
        g = key(u)
        if seen[g] < cap:
            seen[g] += 1
            out.append(u)
    return out


def build_dataset(data_dir, n_phish, n_benign):
    phish = [u for u in read_lines(os.path.join(data_dir, "phishing-links-ACTIVE.txt"))
             if u.lower().startswith(("http://", "https://"))]
    random.shuffle(phish)
    phish = cap_per_group(phish[: n_phish * 4], 15)[:n_phish]  # limit single-campaign domination

    # 30% of phishing URLs are reduced to their homepage so "has a long path" cannot be a shortcut
    phish = [f"{urlparse(u).scheme}://{urlparse(u).netloc}/" if random.random() < 0.3 else u for u in phish]

    top = read_lines(os.path.join(data_dir, "top-1000000-domains"))
    whitelist = top[:100000]
    pool = list(top)
    random.shuffle(pool)

    # realistic legitimate paths: (a) real paths taken from known-good URLs, (b) generated from the real
    # vocabulary of those paths, with the file types real sites use (.html, .php, .aspx ...)
    withpath = [u for u in read_lines(os.path.join(data_dir, "1.Benign_list_big_final.csv"))
                if u.lower().startswith(("http://", "https://"))]
    real_paths = []
    vocab = set()
    for u in withpath:
        p = urlparse(u)
        tail = p.path + (("?" + p.query) if p.query else "")
        if len(tail) > 1:
            real_paths.append(tail[:200])
            vocab.update(w for w in re.split(r"[/\-_.]", p.path.lower()) if w.isalpha() and 3 <= len(w) <= 12)
    vocab = sorted(vocab) or ["news", "world", "story"]

    def fake_path():
        segs = ["-".join(random.choices(vocab, k=random.randint(1, 5))) for _ in range(random.randint(1, 4))]
        path = "/" + "/".join(segs)
        if random.random() < 0.3: path = f"/{random.randint(2010, 2025)}/{random.randint(1, 12):02d}" + path
        if random.random() < 0.15: path += random.choice([".html", ".php", ".aspx", ".htm", ".jsp"])
        if random.random() < 0.25: path += f"?id={random.randint(1, 99999)}&ref={random.choice(vocab)}"
        return path

    def benign_path():
        r = random.random()
        if r < 0.25: return random.choice(PATHS)
        if r < 0.65: return random.choice(real_paths)
        return fake_path()

    benign = []
    for d in pool[:n_benign]:
        scheme = "https" if random.random() < 0.8 else "http"   # similar to the share seen in phishing (~77%)
        host = ("www." + d) if random.random() < 0.35 else d
        if random.random() < 0.40:
            benign.append(f"{scheme}://{host}/")
        else:
            benign.append(f"{scheme}://{host}{benign_path()}")
    return phish, benign, whitelist


def rule_score(row):
    """Rule-based baseline = the scoring idea from the project review (no ML)."""
    f = dict(zip(F.FEATURE_NAMES, row))
    s = 0
    s += 25 * f["has_ip_address"] + 15 * f["has_at_symbol"]
    s += 15 if f["url_length"] > 75 else 7 if f["url_length"] > 54 else 0
    s += 12 * (f["num_dots"] > 4) + 10 * (f["num_hyphens"] > 2)
    s += 15 * (f["num_suspicious_keywords"] > 0) + 10 * (1 - f["is_https"])
    s += 35 * (f["min_brand_distance"] < 0.35)
    return s


def metrics(y, pred, proba=None):
    m = {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
         "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0)}
    if proba is not None and len(set(y)) > 1:
        m["roc_auc"] = roc_auc_score(y, proba)
    return {k: round(float(v), 4) for k, v in m.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--phish", type=int, default=60000)
    ap.add_argument("--benign", type=int, default=55000)
    a = ap.parse_args()
    os.makedirs("model", exist_ok=True); os.makedirs("reports", exist_ok=True)

    print("Building dataset ...")
    phish, benign, whitelist = build_dataset(a.data_dir, a.phish, a.benign)
    urls = phish + benign
    y_all = np.array([1] * len(phish) + [0] * len(benign))
    phish_home = sum(1 for u in phish if is_homepage(u))
    benign_home = sum(1 for u in benign if is_homepage(u))
    print(f"  Class balance: Phishing={len(phish)} ({len(phish)/len(urls):.1%}), Legitimate={len(benign)} ({len(benign)/len(urls):.1%})")
    print(f"  Homepage share: Phishing={phish_home}/{len(phish)} ({phish_home/len(phish):.1%}), Legitimate={benign_home}/{len(benign)} ({benign_home/len(benign):.1%})")

    print("Extracting features ...")
    with Pool() as p:
        feats = p.map(safe_features, urls, chunksize=2000)
        groups = p.map(reg_domain, urls, chunksize=2000)
    keep = [i for i, f in enumerate(feats) if f is not None]
    X = np.array([feats[i] for i in keep], dtype=float)
    y = y_all[keep]
    g = np.array([groups[i] for i in keep])
    urls = [urls[i] for i in keep]
    print(f"  usable rows={len(y)}  features={X.shape[1]}")

    # split BY DOMAIN so the test set contains websites the model has never seen
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(X, y, g))
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]
    assert not set(g[tr]) & set(g[te])

    # Second test set: bare homepages only (from held-out unseen domains)
    urls_te = [urls[i] for i in te]
    home_mask = np.array([is_homepage(u) for u in urls_te])
    Xte_home, yte_home = Xte[home_mask], yte[home_mask]
    n_phish_home = int(sum(yte_home))
    n_benign_home = int(len(yte_home) - n_phish_home)
    print(f"  train={len(tr)}  test={len(te)} (no domain appears in both)")
    print(f"  Homepage test set: total={len(yte_home)} (phishing={n_phish_home}, legitimate={n_benign_home})")

    models = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Decision Tree": DecisionTreeClassifier(max_depth=14, class_weight="balanced", random_state=SEED),
        "Random Forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1,
                                                class_weight="balanced", random_state=SEED),
        "XGBoost": XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.08, subsample=0.9,
                                 colsample_bytree=0.9, eval_metric="logloss", n_jobs=-1, random_state=SEED),
    }

    results = {}
    results_home = {}
    rs = np.array([rule_score(r) for r in Xte])
    rs_home = np.array([rule_score(r) for r in Xte_home])
    results["Rule-based (review baseline)"] = metrics(yte, (rs >= 30).astype(int), rs / 100)
    results_home["Rule-based (review baseline)"] = metrics(yte_home, (rs_home >= 30).astype(int), rs_home / 100)

    # Evaluate old model from backup if available
    old_backup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_backup_v4", "model", "xgb_trees.json")
    old_eval = {}
    if os.path.exists(old_backup_path):
        from treemodel import TreeModel
        old_tree = TreeModel.load(old_backup_path)
        old_pr = np.array([old_tree.predict_proba_one(r) for r in Xte])
        old_pr_home = old_pr[home_mask]
        old_pred = (old_pr >= 0.5).astype(int)
        old_pred_home = (old_pr_home >= 0.5).astype(int)
        old_eval["full"] = metrics(yte, old_pred, old_pr)
        old_eval["homepage"] = metrics(yte_home, old_pred_home, old_pr_home)
        old_eval["cm_full"] = confusion_matrix(yte, old_pred).tolist()
        old_eval["cm_home"] = confusion_matrix(yte_home, old_pred_home).tolist()
        old_legit_flagged_rate = old_eval["cm_home"][0][1] / max(1, n_benign_home)
        print("\n--- Old Model Evaluation (from backup) ---")
        print("  Old XGBoost on Full Test:    ", old_eval["full"])
        print("  Old XGBoost on Homepage Test:", old_eval["homepage"])
        print(f"  Old XGBoost Homepage CM (TN={old_eval['cm_home'][0][0]}, FP={old_eval['cm_home'][0][1]} / FN={old_eval['cm_home'][1][0]}, TP={old_eval['cm_home'][1][1]})")
        print(f"  Old XGBoost False-Fake rate on legit homepages: {old_eval['cm_home'][0][1]}/{n_benign_home} ({old_legit_flagged_rate:.1%})\n")

    fitted = {}
    for name, m in models.items():
        print("Training", name, "...")
        m.fit(Xtr, ytr)
        proba = m.predict_proba(Xte)[:, 1]
        results[name] = metrics(yte, (proba >= 0.5).astype(int), proba)
        proba_home = proba[home_mask]
        results_home[name] = metrics(yte_home, (proba_home >= 0.5).astype(int), proba_home)
        fitted[name] = (m, proba)
        print("   Full test:    ", results[name])
        print("   Homepage test:", results_home[name])

    best = max(fitted, key=lambda k: results[k]["f1"])
    model, proba = fitted[best]
    print("\nBest model:", best)

    # --- reports ---
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(yte, pred)
    fig, ax = plt.subplots(figsize=(4.6, 4))
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=13)
    ax.set_xticks([0, 1], ["Legitimate", "Phishing"]); ax.set_yticks([0, 1], ["Legitimate", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Confusion matrix - {best}")
    fig.tight_layout(); fig.savefig("reports/confusion_matrix.png", dpi=160); plt.close(fig)

    # Confusion matrix for Homepage test set
    pred_home = (proba[home_mask] >= 0.5).astype(int)
    cm_home = confusion_matrix(yte_home, pred_home)
    fig, ax = plt.subplots(figsize=(4.6, 4))
    ax.imshow(cm_home, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm_home[i, j]:,}", ha="center", va="center", color="white" if cm_home[i, j] > cm_home.max() / 2 else "black", fontsize=13)
    ax.set_xticks([0, 1], ["Legitimate", "Phishing"]); ax.set_yticks([0, 1], ["Legitimate", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Confusion matrix (Homepages) - {best}")
    fig.tight_layout(); fig.savefig("reports/confusion_matrix_homepages.png", dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    for name, (m, pr) in fitted.items():
        fpr, tpr, _ = roc_curve(yte, pr); ax.plot(fpr, tpr, label=f"{name} (AUC {results[name]['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=.8); ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate")
    ax.set_title("ROC curves (unseen domains)"); ax.legend(fontsize=8); fig.tight_layout()
    fig.savefig("reports/roc_curve.png", dpi=160); plt.close(fig)

    core = model.steps[-1][1] if hasattr(model, "steps") else model
    imp = getattr(core, "feature_importances_", None)
    if imp is None:
        imp = np.abs(core.coef_[0])
    order = np.argsort(imp)[::-1][:15][::-1]
    fig, ax = plt.subplots(figsize=(6.2, 4.6))
    ax.barh([F.FEATURE_NAMES[i] for i in order], imp[order], color="#1857d6")
    ax.set_title(f"Top 15 features - {best}"); fig.tight_layout()
    fig.savefig("reports/feature_importance.png", dpi=160); plt.close(fig)

    top_feats = {F.FEATURE_NAMES[i]: round(float(imp[i]), 4) for i in np.argsort(imp)[::-1][:15]}
    with open("reports/metrics.json", "w") as f:
        json.dump({"best_model": best, "train_rows": int(len(tr)), "test_rows": int(len(te)),
                   "homepage_test_rows": int(len(yte_home)),
                   "results": results, "homepage_results": results_home,
                   "top_features": top_feats,
                   "confusion_matrix": cm.tolist(),
                   "confusion_matrix_homepages": cm_home.tolist(),
                   "old_model_comparison": old_eval}, f, indent=2)

    with open("reports/comparison.md", "w") as f:
        f.write("# Model Comparison Report\n\n")
        f.write("## 1. Full Held-Out Test Set (Unseen Domains)\n\n")
        f.write("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |\n|---|---|---|---|---|---|\n")
        for k, v in results.items():
            f.write(f"| {k} | {v['accuracy']:.4f} | {v['precision']:.4f} | {v['recall']:.4f} | {v['f1']:.4f} | {v.get('roc_auc', 0):.4f} |\n")
        f.write("\n## 2. Bare Homepages Only (Unseen Domains)\n\n")
        f.write("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |\n|---|---|---|---|---|---|\n")
        for k, v in results_home.items():
            f.write(f"| {k} | {v['accuracy']:.4f} | {v['precision']:.4f} | {v['recall']:.4f} | {v['f1']:.4f} | {v.get('roc_auc', 0):.4f} |\n")
        if old_eval:
            f.write("\n## 3. Comparison with Old Model (XGBoost)\n\n")
            f.write("| Evaluation Set | Metric | Old XGBoost | Retrained XGBoost |\n|---|---|---|---|\n")
            for m_key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
                f.write(f"| Full Test | {m_key.capitalize()} | {old_eval['full'].get(m_key, '-')} | {results['XGBoost'].get(m_key, '-')} |\n")
            for m_key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
                f.write(f"| Homepages Only | {m_key.capitalize()} | {old_eval['homepage'].get(m_key, '-')} | {results_home['XGBoost'].get(m_key, '-')} |\n")

    joblib.dump({"model": model, "features": F.FEATURE_NAMES, "name": best, "metrics": results[best]}, "model/model.joblib")
    # the portal runs the XGBoost model from a plain JSON file, so it does not depend on library versions
    with open("model/xgb_trees.json", "w") as f:
        json.dump(export_from_xgboost(fitted["XGBoost"][0], F.FEATURE_NAMES, {"metrics": results["XGBoost"]}), f, separators=(",", ":"))
    with open(os.path.join("data", "whitelist_top100k.txt"), "w") as f:
        f.write("\n".join(whitelist))
    print("Saved model/model.joblib, model/xgb_trees.json, and reports/")


if __name__ == "__main__":
    main()
