# Model Comparison Report

## 1. Full Held-Out Test Set (Unseen Domains)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Rule-based (review baseline) | 0.5206 | 0.6643 | 0.1564 | 0.2531 | 0.4872 |
| Logistic Regression | 0.7887 | 0.8425 | 0.7297 | 0.7821 | 0.8850 |
| Decision Tree | 0.8415 | 0.9083 | 0.7729 | 0.8351 | 0.9235 |
| Random Forest | 0.8925 | 0.9227 | 0.8655 | 0.8932 | 0.9621 |
| XGBoost | 0.9032 | 0.9367 | 0.8727 | 0.9036 | 0.9716 |

## 2. Bare Homepages Only (Unseen Domains)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Rule-based (review baseline) | 0.4709 | 0.8994 | 0.0276 | 0.0536 | 0.5836 |
| Logistic Regression | 0.7153 | 0.8062 | 0.6256 | 0.7045 | 0.7963 |
| Decision Tree | 0.7555 | 0.8710 | 0.6449 | 0.7410 | 0.8466 |
| Random Forest | 0.7931 | 0.8595 | 0.7394 | 0.7950 | 0.8716 |
| XGBoost | 0.7994 | 0.8706 | 0.7402 | 0.8001 | 0.8808 |

## 3. Comparison with Old Model (XGBoost)

| Evaluation Set | Metric | Old XGBoost | Retrained XGBoost |
|---|---|---|---|
| Full Test | Accuracy | 0.808 | 0.9032 |
| Full Test | Precision | 0.7353 | 0.9367 |
| Full Test | Recall | 0.985 | 0.8727 |
| Full Test | F1 | 0.8421 | 0.9036 |
| Full Test | Roc_auc | 0.9636 | 0.9716 |
| Homepages Only | Accuracy | 0.5672 | 0.7994 |
| Homepages Only | Precision | 0.5564 | 0.8706 |
| Homepages Only | Recall | 0.9975 | 0.7402 |
| Homepages Only | F1 | 0.7143 | 0.8001 |
| Homepages Only | Roc_auc | 0.8887 | 0.8808 |
