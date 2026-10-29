# Hybrid detector vs ML-only

Share of URLs given each verdict (%). *Fake rate* is what matters for phishing and typosquats (higher = better); for legitimate sites lower is better.

| Test set | n | ML only: Fake | ML only: flagged | Hybrid (no cap): Fake | Hybrid (no cap): flagged | **Portal default: Fake** | **Portal default: flagged** |
|---|---|---|---|---|---|---|---|
| phishing (feed URLs) | 1500 | 97.1 | 98.7 | 88.5 | 90.1 | **42.9** | **90.1** |
| phishing (home page only) | 1500 | 98.7 | 100.0 | 88.3 | 89.4 | **19.4** | **89.4** |
| legit unknown (home page) | 1500 | 94.4 | 99.9 | 91.7 | 96.7 | **3.7** | **96.0** |
| legit unknown (with path) | 1500 | 0.4 | 1.3 | 0.3 | 4.1 | **0.3** | **4.1** |
| typosquat of top brands | 1500 | 97.7 | 100.0 | 98.9 | 100.0 | **91.1** | **99.9** |

*flagged* = Suspicious or Fake. *Portal default* = all layers with ML_ONLY_CAP=1.

## Look-alike layer alone

- Typosquat detection rate: **87.1%** of 1500 generated misspellings of the top-2000 brands
- Strong look-alike false alarms on 1500 real, unrelated domains (rank 20k-1M): **2.0%**
