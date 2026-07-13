"""Lexical inference: load the trained ensemble model and score URLs.

The model is a stacking ensemble (RF + GB + ET + LR meta-learner) that
produces calibrated phishing probabilities from 55 lexical URL features.
"""

from __future__ import annotations

from pathlib import Path

import joblib

from .features import FEATURE_NAMES, extract_features

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "lexical_rf.joblib"


class LexicalModel:
    """Wrapper around the persisted ensemble lexical classifier."""

    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self._artifact = None

    def _ensure_loaded(self) -> None:
        if self._artifact is None:
            if not self.model_path.exists():
                raise FileNotFoundError(
                    f"Lexical model not found at {self.model_path}. "
                    "Run `python -m src.lexical.train` first."
                )
            self._artifact = joblib.load(self.model_path)

    def _validate_features(self, vec: list[float]) -> None:
        """Ensure feature vector matches what the model expects."""
        expected = self._artifact.get("n_features") or self._artifact.get("model").n_features_in_
        if len(vec) != expected:
            raise ValueError(
                f"Feature count mismatch: code produces {len(vec)} features "
                f"but model expects {expected}. "
                "Delete __pycache__ and retrain with `python -m src.lexical.train`."
            )

    def predict_proba(self, url: str) -> float:
        """Return phishing probability in [0, 1] for a single URL."""
        self._ensure_loaded()
        clf = self._artifact["model"]
        vec = extract_features(url).vector()
        self._validate_features(vec)
        return float(clf.predict_proba([vec])[0, 1])

    def predict_proba_batch(self, urls: list[str]) -> list[float]:
        self._ensure_loaded()
        clf = self._artifact["model"]
        vecs = [extract_features(u).vector() for u in urls]
        for vec in vecs:
            self._validate_features(vec)
        return [float(p) for p in clf.predict_proba(vecs)[:, 1]]


def score_url(url: str, model_path: str | Path = DEFAULT_MODEL_PATH) -> float:
    return LexicalModel(model_path).predict_proba(url)
