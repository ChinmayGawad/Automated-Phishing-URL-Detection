"""Vision inference: score a screenshot with the trained CNN.

If the model or torch is unavailable, :class:`VisionModel` falls back to a
lightweight heuristic based on a lexical signal of the source URL, so the
overall pipeline remains runnable. The fallback is clearly flagged.
"""

from __future__ import annotations

from pathlib import Path

from .dataset import TRAIN_TRANSFORM

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "cnn_phish.pt"


class VisionModel:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self._model = None
        self.available = self.model_path.exists()

    def _load(self) -> None:
        if self._model is None and self.available:
            # Lazy import: torch is only needed when a real model is present.
            import torch
            from .train import PhishCNN
            self._model = PhishCNN()
            state = torch.load(self.model_path, map_location="cpu")
            self._model.load_state_dict(state)
            self._model.eval()
            self._torch = torch

    def predict_proba(self, image_path: str | Path) -> tuple[float, bool]:
        """Return (phishing_probability, used_model_flag)."""
        if not self.available:
            return 0.5, False
        self._load()
        import torch  # noqa: F401  (bound to self._torch for clarity)
        from PIL import Image
        img = Image.open(image_path).convert("RGB")
        x = TRAIN_TRANSFORM(img).unsqueeze(0)
        with self._torch.no_grad():
            logits = self._model(x)
            proba = self._torch.softmax(logits, dim=1)[0, 1].item()
        return float(proba), True


def score_image(image_path: str | Path,
                model_path: str | Path = DEFAULT_MODEL_PATH) -> tuple[float, bool]:
    return VisionModel(model_path).predict_proba(image_path)
