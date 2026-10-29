"""
Version-independent model runner.

The trained XGBoost model is exported once to a plain JSON file (list of decision trees).
This file then evaluates those trees in pure Python, so prediction works on any computer and any
Python / XGBoost / scikit-learn version. (XGBoost is only needed for TRAINING, not for running the portal.)
"""
import json
import math
import struct


def _f32(v):
    """Round to 32-bit float, the precision XGBoost uses for features and split thresholds."""
    return struct.unpack("f", struct.pack("f", v))[0]


class TreeModel:
    def __init__(self, data):
        self.features = data["features"]
        self.base_margin = data["base_margin"]
        self.trees = data["trees"]          # each tree: parallel lists f (feature), t (threshold), y/n (children), v (leaf)
        for t in self.trees:
            t["t"] = [_f32(v) for v in t["t"]]
        self.meta = data.get("meta", {})

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls(json.load(f))

    def margin(self, x):
        total = self.base_margin
        x = [_f32(v) for v in x]
        for t in self.trees:
            f, thr, yes, no = t["f"], t["t"], t["y"], t["n"]
            node = 0
            while f[node] >= 0:                       # f < 0 marks a leaf
                node = yes[node] if x[f[node]] < thr[node] else no[node]
            total += t["v"][node]
        return total

    def predict_proba_one(self, x):
        """Probability (0-1) that the URL is phishing. `x` = list of feature values in self.features order."""
        m = self.margin(x)
        return 1.0 / (1.0 + math.exp(-m)) if m > -700 else 0.0


def export_from_xgboost(model, features, meta=None):
    """Convert a trained xgboost.XGBClassifier (binary:logistic) into the JSON structure above (full precision)."""
    raw = json.loads(bytes(model.get_booster().save_raw(raw_format="json")))
    learner = raw["learner"]
    trees = []
    for t in learner["gradient_booster"]["model"]["trees"]:
        left, right = t["left_children"], t["right_children"]
        cond, idx = t["split_conditions"], t["split_indices"]
        n = len(left)
        is_leaf = [left[i] == -1 for i in range(n)]
        trees.append({
            "f": [-1 if is_leaf[i] else idx[i] for i in range(n)],
            "t": [0.0 if is_leaf[i] else cond[i] for i in range(n)],
            "y": [0 if is_leaf[i] else left[i] for i in range(n)],     # x < threshold  -> left
            "n": [0 if is_leaf[i] else right[i] for i in range(n)],
            "v": [cond[i] if is_leaf[i] else 0.0 for i in range(n)],   # leaf value is stored in split_conditions
        })
    bs = learner["learner_model_param"]["base_score"]
    bs = float(str(bs).strip("[]").split(",")[0])
    bs = min(max(bs, 1e-6), 1 - 1e-6)
    return {"features": list(features), "base_margin": math.log(bs / (1 - bs)), "trees": trees, "meta": meta or {}}
