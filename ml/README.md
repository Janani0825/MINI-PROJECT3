# Fake Website Detection – Detection Engine (Python)

Offline machine-learning engine for the portal. It only reads the **URL text** (never opens the site).

## Setup (once)
    pip install -r requirements.txt         # enough to RUN the detector
    # Only if you want to re-train the model yourself:
    pip install -r requirements-train.txt
    python download_data.py      # needs internet ONCE (~85 MB). Afterwards everything is offline.
    python train.py              # ~1 min. Creates model/, reports/, data/whitelist_top100k.txt

A trained model is already included (`model/xgb_trees.json`, plain JSON that works on any Python / library
version), so you can skip straight to testing:

    python predict.py "http://paypa1-secure-login.com/verify-account"

## How a URL is judged (hybrid decision)
1. **Blacklist** (admin-managed domains in MongoDB) -> Fake
2. **Whitelist** (top 100k trusted domains) -> Safe
3. **ML model** (XGBoost on 37 URL features) -> risk score 0-100
4. **Rule layer** -> the human-readable reasons shown to the user

Risk < 30 = Safe, 30-59 = Suspicious, 60+ = Fake.

## Use it from Flask
    from predict import analyse
    blacklist = [d["domain"] for d in db.blacklist.find()]
    out = analyse(url, blacklist)       # raises ValueError for an invalid URL
    # out["features"] -> store in scans.features      out["result"] -> store in detection_result

## Data
- Phishing: 60,000 URLs sampled from Phishing.Database (real, active phishing links); max 15 per domain.
- Legitimate: 55,000 URLs built from the top-1M popular-domains list, with realistic paths
  (real paths from known-good URLs + generated ones). 30% of phishing URLs are reduced to the homepage
  so that "has a long path" cannot be a shortcut.
- Split **by domain** (80/20): no website appears in both training and test data.

## Results (test set = websites never seen in training)
| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | 0.8624 | 0.8781 | 0.8576 | 0.8677 | 0.9433 |
| Decision Tree | 0.9211 | 0.9279 | 0.9217 | 0.9248 | 0.9631 |
| Random Forest | 0.9586 | 0.9490 | 0.9737 | 0.9612 | 0.9890 |
| **XGBoost (selected)** | **0.9637** | **0.9510** | **0.9815** | **0.9660** | **0.9931** |

Confusion matrix (XGBoost): 10,346 legit correct, 615 legit flagged, 225 phishing missed, 11,943 phishing caught.
Charts: `reports/confusion_matrix.png`, `reports/roc_curve.png`, `reports/feature_importance.png`.

## Honest limitations (put these in your report)
- **URL-only analysis has a ceiling.** Many real phishing links sit on hacked small-business sites whose
  address looks normal, so a small, unknown *legitimate* site can be flagged Suspicious/Fake
  (false positives). The whitelist removes this for popular sites only.
- The test set is built from the same kind of data as the training set; real-world accuracy will be lower
  than 96%. Test with fresh URLs and report both numbers.
- Legitimate URLs are partly generated (real popular domains + realistic paths) because no large public
  set of legitimate URLs with paths was available.
- A rule-based baseline from the review slides scored poorly here, but that comparison is biased:
  the generated legitimate URLs have long hyphenated paths that simple length/hyphen rules penalise.
  Do not present it as a fair benchmark.
- Future work: page-content features (forms, password fields), WHOIS/domain age, screenshot similarity,
  retraining from user feedback.

## Files
    features.py        37 URL features + reasons (used by training and prediction)
    train.py           builds dataset, trains 4 models, writes metrics and charts
    predict.py         hybrid detector used by Flask
    download_data.py   fetches the public datasets once
