"""Lexical inference: load the trained model and score URLs.

The trained model (a gradient-boosted classifier) produces a calibrated
phishing probability from the lexical URL features. The artifact also stores an
optimized ``threshold`` (tuned for high phishing recall) which :func:`predict`
uses to emit a hard label.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import joblib

from .features import FEATURE_NAMES, extract_features

# joblib/numpy emit noisy DeprecationWarnings on load in newer numpy; they are
# benign for our persisted artifacts, so silence them.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="joblib")
warnings.filterwarnings("ignore", message=".*Setting the shape on a NumPy array.*")

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "lexical_rf.joblib"

# Default threshold used only when the artifact has none (e.g. older models).
DEFAULT_THRESHOLD = 0.5


class LexicalModel:
    """Wrapper around the persisted lexical classifier."""

    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self._artifact = None
        self._model = None
        self._threshold = DEFAULT_THRESHOLD

    def _ensure_loaded(self) -> None:
        if self._artifact is None:
            if not self.model_path.exists():
                raise FileNotFoundError(
                    f"Lexical model not found at {self.model_path}. "
                    "Run `python -m src.lexical.train` first."
                )
            self._artifact = joblib.load(self.model_path)
            self._model = self._artifact["model"]
            self._threshold = float(self._artifact.get("threshold", DEFAULT_THRESHOLD))

    def threshold(self) -> float:
        self._ensure_loaded()
        return self._threshold

    def _vector(self, url: str) -> list[float]:
        vec = extract_features(url).vector()
        expected = self._artifact.get("n_features") or self._model.n_features_in_
        if len(vec) != expected:
            raise ValueError(
                f"Feature count mismatch: code produces {len(vec)} features "
                f"but model expects {expected}. "
                "Retrain with `python -m src.lexical.train`."
            )
        return vec

    def predict_proba(self, url: str) -> float:
        """Return phishing probability in [0, 1] for a single URL."""
        self._ensure_loaded()
        vec = self._vector(url)
        return float(self._model.predict_proba([vec])[0, 1])

    def predict_proba_batch(self, urls: list[str]) -> list[float]:
        self._ensure_loaded()
        vecs = [self._vector(u) for u in urls]
        return [float(p) for p in self._model.predict_proba(vecs)[:, 1]]

    def predict(self, url: str) -> int:
        """Return a hard label (1 = phishing, 0 = legitimate) using the tuned threshold."""
        return int(self.predict_proba(url) >= self.threshold())


def score_url(url: str, model_path: str | Path = DEFAULT_MODEL_PATH) -> float:
    return LexicalModel(model_path).predict_proba(url)
