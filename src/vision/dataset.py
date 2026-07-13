"""Screenshot dataset utilities for the vision CNN.

Builds a labeled image dataset (phishing vs legitimate) from a directory of
PNG screenshots. Each image is resized/normalized to a fixed tensor for the
CNN. When real screenshots are unavailable, :func:`generate_synthetic_dataset`
creates simple placeholder images so training/eval still runs end-to-end.
"""

from __future__ import annotations

import random
from pathlib import Path

import torch
from torch.utils.data import Dataset
from torchvision import transforms

IMAGE_SIZE = 224

TRAIN_TRANSFORM = transforms.Compose([
    transforms.Resize((IMAGE_SIZE, IMAGE_SIZE)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225]),
])


class ScreenshotDataset(Dataset):
    """Reads ``<root>/<class>/<image>`` where class is 0 (legit) or 1 (phish)."""

    def __init__(self, root: str | Path, transform: callable = TRAIN_TRANSFORM):
        self.root = Path(root)
        self.transform = transform
        self.samples: list[tuple[Path, int]] = []
        for cls, name in ((0, "legit"), (1, "phish")):
            d = self.root / name
            if not d.exists():
                continue
            for img in d.glob("*.png"):
                self.samples.append((img, cls))
        if not self.samples:
            raise FileNotFoundError(
                f"No screenshots found under {self.root}. "
                "Run `python -m src.vision.dataset` to generate a synthetic set."
            )

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int):
        path, label = self.samples[idx]
        from PIL import Image
        img = Image.open(path).convert("RGB")
        if self.transform:
            img = self.transform(img)
        return img, label


def _make_synthetic_class(out_dir: Path, base_rgb: tuple[int, int, int],
                          per_class: int, seed: int) -> None:
    from PIL import Image
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    for i in range(per_class):
        img = Image.new("RGB", (IMAGE_SIZE, IMAGE_SIZE))
        px = img.load()
        tint = (base_rgb[0] + rng.randint(-30, 30),
                base_rgb[1] + rng.randint(-30, 30),
                base_rgb[2] + rng.randint(-30, 30))
        for y in range(IMAGE_SIZE):
            for x in range(IMAGE_SIZE):
                jitter = rng.randint(-15, 15)
                px[x, y] = (
                    max(0, min(255, tint[0] + jitter)),
                    max(0, min(255, tint[1] + jitter)),
                    max(0, min(255, tint[2] + jitter)),
                )
        img.save(out_dir / f"sample_{i}.png")


def generate_synthetic_dataset(root: str | Path, per_class: int = 40,
                               seed: int = 42) -> Path:
    """Create simple placeholder screenshots (solid color blocks + noise).

    Phishing images skew warmer/red-ish; legitimate skew cooler/blue-ish. This
    is only a stand-in so the pipeline is runnable offline; replace with real
    captured screenshots for a meaningful model.
    """
    root = Path(root)
    _make_synthetic_class(root / "legit", (40, 90, 160), per_class, seed)
    _make_synthetic_class(root / "phish", (170, 60, 50), per_class, seed + 1)
    return root


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[2] / "data" / "screenshots"
    generate_synthetic_dataset(out)
    print(f"Synthetic dataset written to {out}")
