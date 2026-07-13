"""Headless screenshot capture for the visual impersonation engine.

Visits a URL with Playwright Chromium and saves a viewport screenshot. This
stage touches untrusted content, so it MUST run inside an isolated,
network-restricted sandbox/container. Never run capture on a production host.

If Playwright/Chromium is unavailable, :func:`capture` raises
``CaptureUnavailable`` so the pipeline can fall back to a heuristic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

VIEWPORT = (1280, 800)
SHOT_TIMEOUT_MS = 20_000
WAIT_MS = 1_500


class CaptureUnavailable(RuntimeError):
    pass


@dataclass
class CaptureResult:
    image_path: Path
    ok: bool
    error: str | None = None


def _launch_browser():
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise CaptureUnavailable(
            "playwright is not installed. Run `pip install playwright && "
            "playwright install chromium`."
        ) from exc
    return sync_playwright


def capture(url: str, out_path: str | Path,
            wait_ms: int = WAIT_MS) -> CaptureResult:
    """Capture a screenshot of ``url`` to ``out_path``.

    Returns a :class:`CaptureResult`. On failure ``ok`` is False and the error
    is recorded rather than raised, so batch capture can continue.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        sp = _launch_browser()
    except CaptureUnavailable as exc:
        return CaptureResult(image_path=out_path, ok=False, error=str(exc))

    try:
        with sp() as pw:
            browser = pw.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            ctx = browser.new_context(viewport={"width": VIEWPORT[0],
                                                "height": VIEWPORT[1]})
            page = ctx.new_page()
            page.goto(url, timeout=SHOT_TIMEOUT_MS, wait_until="domcontentloaded")
            time.sleep(wait_ms / 1000.0)
            page.screenshot(path=str(out_path), full_page=False)
            ctx.close()
            browser.close()
        return CaptureResult(image_path=out_path, ok=True)
    except Exception as exc:  # pragma: no cover - network/remote failures
        return CaptureResult(image_path=out_path, ok=False, error=str(exc))


def capture_batch(urls: list[str], out_dir: str | Path,
                  label: str = "sample") -> list[CaptureResult]:
    out_dir = Path(out_dir)
    results = []
    for i, url in enumerate(urls):
        path = out_dir / f"{label}_{i}.png"
        results.append(capture(url, path))
    return results
