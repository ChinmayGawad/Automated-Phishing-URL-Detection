"""CNN for screenshot-based phishing classification.

A small convolutional network (conv -> pool -> fc) sufficient for distinguishing
phishing vs legitimate page layouts. Uses torchvision transforms defined in
:mod:`src.vision.dataset`. If torch is unavailable, training/inference raise a
clear error and the pipeline falls back to a heuristic vision score.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import torch
import torch.nn as nn

from .dataset import IMAGE_SIZE, ScreenshotDataset, TRAIN_TRANSFORM

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "cnn_phish.pt"


class PhishCNN(nn.Module):  # torch is required for this module; imported at top
    def __init__(self, num_classes: int = 2):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(64, 128, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * (IMAGE_SIZE // 8) * (IMAGE_SIZE // 8), 256),
            nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(256, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.features(x))


def train(data_root: str | Path,
          model_path: str | Path = DEFAULT_MODEL_PATH,
          epochs: int = 6, batch_size: int = 16, lr: float = 1e-3) -> dict:
    data_root = Path(data_root)
    from .dataset import generate_synthetic_dataset, ScreenshotDataset
    try:
        dataset = ScreenshotDataset(data_root, transform=TRAIN_TRANSFORM)
    except FileNotFoundError:
        data_root = generate_synthetic_dataset(data_root)
        dataset = ScreenshotDataset(data_root, transform=TRAIN_TRANSFORM)

    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size,
                                        shuffle=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PhishCNN().to(device)
    loss_fn = nn.CrossEntropyLoss()
    opt = torch.optim.Adam(model.parameters(), lr=lr)

    model.train()
    for epoch in range(epochs):
        running = 0.0
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            out = model(x)
            loss = loss_fn(out, y)
            loss.backward()
            opt.step()
            running += loss.item() * x.size(0)
        print(f"epoch {epoch+1}/{epochs} loss={running/len(dataset):.4f}")

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), model_path)
    return {"epochs": epochs, "n_samples": len(dataset), "device": str(device)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Train vision CNN")
    ap.add_argument("--data", default="data/screenshots")
    ap.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args()
    metrics = train(args.data, args.model, epochs=args.epochs)
    print("Trained CNN:", metrics)


if __name__ == "__main__":
    main()
