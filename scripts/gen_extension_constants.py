"""Generate JS constant arrays (FEATURE_NAMES, KNOWN_BRANDS, KNOWN_LEGITIMATE_DOMAINS)
from the Python source so the extension stays in lock-step with src/lexical/features.py.

Run: python scripts/gen_extension_constants.py
Emits a snippet to stdout that can be pasted into the extension files.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

FEAT_PY = Path(__file__).resolve().parents[1] / "src" / "lexical" / "features.py"
OUT = Path(__file__).resolve().parents[1] / "extension" / "lib"


def _grab_tuple(name: str, src: str) -> list[str]:
    m = re.search(name + r"\s*=\s*(?:\(|frozenset\(\{)([\s\S]*?)(?:\)|\}\))", src)
    if m is None:
        raise ValueError(f"Could not find {name} in features.py")
    return re.findall(r'"([^"]+)"', m.group(1))


def main() -> None:
    src = FEAT_PY.read_text(encoding="utf-8")
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src.lexical.features import FEATURE_NAMES
    brands = _grab_tuple("KNOWN_BRANDS", src)
    legit = _grab_tuple("KNOWN_LEGITIMATE_DOMAINS", src)

    feat_js = "const FEATURE_NAMES = [\n" + ",\n".join(
        f'  "{n}"' for n in FEATURE_NAMES
    ) + ",\n];"

    brands_js = "const KNOWN_BRANDS = [\n" + ",\n".join(
        f'  "{b}"' for b in brands
    ) + "\n];"

    legit_js = "const KNOWN_LEGITIMATE_DOMAINS = new Set([\n" + ",\n".join(
        f'  "{d}"' for d in legit
    ) + "\n]);"

    (OUT / "_gen_feature_names.js").write_text(feat_js + "\n", encoding="utf-8")
    (OUT / "_gen_known_brands.js").write_text(brands_js + "\n", encoding="utf-8")
    (OUT / "_gen_known_legit.js").write_text(legit_js + "\n", encoding="utf-8")
    print(f"Wrote generated constants: {len(FEATURE_NAMES)} features, "
          f"{len(brands)} brands, {len(legit)} legit domains -> {OUT}")


if __name__ == "__main__":
    main()
