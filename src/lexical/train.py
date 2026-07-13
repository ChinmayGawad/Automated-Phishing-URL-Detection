"""Lexical classifier: train and persist an ensemble phishing model.

Uses a stacking ensemble of multiple sklearn models for better generalization:
- RandomForestClassifier (strong on structured features)
- GradientBoostingClassifier (captures non-linear interactions)
- ExtraTreesClassifier (reduces variance vs RF)
- LogisticRegression (linear baseline)

A LogisticRegression meta-learner combines all model outputs.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
    StackingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from .features import FEATURE_NAMES, extract_batch

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "lexical_rf.joblib"


def load_dataset(csv_path: str | Path) -> pd.DataFrame:
    """Load a labeled URL dataset.

    Expected columns: ``url`` and ``label`` where label is 1 for phishing and
    0 for legitimate. Falls back to a tiny built-in sample if the file is
    missing so training always has something to run on.
    """
    csv_path = Path(csv_path)
    if csv_path.exists():
        df = pd.read_csv(csv_path)
    else:
        df = _fallback_dataset()
    df = df.dropna(subset=["url", "label"])
    return df


def _fallback_dataset() -> pd.DataFrame:
    rows = [
        ("http://google.com", 0),
        ("https://www.amazon.com/", 0),
        ("https://github.com/login", 0),
        ("https://bankofamerica.com/secure", 0),
        ("http://192.168.1.1/login", 1),
        ("http://micr0soft-secure-login.com/verify", 1),
        ("http://paypa1.com/account/confirm", 1),
        ("http://secure-bank-update.tk/reset", 1),
        ("http://bit.ly/3xlogin-verify", 1),
        ("https://netflix.com/your-account", 0),
    ]
    return pd.DataFrame(rows, columns=["url", "label"])


def _build_ensemble() -> StackingClassifier:
    """Build the stacking ensemble model (optimized for speed)."""
    estimators = [
        ("rf", RandomForestClassifier(
            n_estimators=300, max_depth=None,
            random_state=42, n_jobs=-1, class_weight="balanced"
        )),
        ("gb", GradientBoostingClassifier(
            n_estimators=150, max_depth=5, learning_rate=0.1,
            random_state=42
        )),
        ("et", ExtraTreesClassifier(
            n_estimators=300, max_depth=None,
            random_state=42, n_jobs=-1, class_weight="balanced"
        )),
    ]
    final_estimator = LogisticRegression(
        C=1.0, max_iter=1000, random_state=42
    )
    return StackingClassifier(
        estimators=estimators,
        final_estimator=final_estimator,
        cv=2,
        stack_method="predict_proba",
        n_jobs=-1,
        passthrough=False,
    )


def train(csv_path: str | Path, model_path: str | Path = DEFAULT_MODEL_PATH,
          test_size: float = 0.2) -> dict:
    df = load_dataset(csv_path)
    X = extract_batch(df["url"].tolist())
    y = df["label"].astype(int).tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )

    print(f"Training ensemble on {len(X_train)} samples ({len(FEATURE_NAMES)} features)...")
    clf = _build_ensemble()
    clf.fit(X_train, y_train)

    metrics: dict = {"n_samples": len(y), "n_features": len(FEATURE_NAMES)}
    if len(set(y_test)) > 1:
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)[:, 1]
        metrics["report"] = classification_report(y_test, y_pred, output_dict=True)
        metrics["auc"] = float(roc_auc_score(y_test, y_proba))

    # Cross-validation
    print("Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X, y, cv=cv, scoring="roc_auc", n_jobs=-1)
    metrics["cv_auc_mean"] = float(cv_scores.mean())
    metrics["cv_auc_std"] = float(cv_scores.std())

    # Save ensemble + individual feature importances
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": clf,
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "model_type": "stacking_ensemble",
    }, model_path)

    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Train lexical phishing ensemble")
    ap.add_argument("--csv", default="data/raw/lexical_urls.csv",
                    help="Path to labeled URL CSV (url,label)")
    ap.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    args = ap.parse_args()
    metrics = train(args.csv, args.model)

    print("\n=== Training Results ===")
    for k, v in metrics.items():
        if k == "report":
            continue
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")
        else:
            print(f"  {k}: {v}")

    if "report" in metrics:
        print("\nClassification Report:")
        print(classification_report_from_dict(metrics["report"]))

    if "cv_auc_mean" in metrics:
        print(f"\n5-fold CV AUC: {metrics['cv_auc_mean']:.4f} +/- {metrics['cv_auc_std']:.4f}")


def classification_report_from_dict(report: dict) -> str:
    out = []
    for k, v in report.items():
        if isinstance(v, dict):
            out.append(f"{k}: precision={v['precision']:.3f} "
                       f"recall={v['recall']:.3f} f1={v['f1-score']:.3f}")
    return "\n".join(out)


if __name__ == "__main__":
    main()
