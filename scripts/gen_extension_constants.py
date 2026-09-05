"""Extract constants from Python modules for use in the JS extension.

Generates:
  extension/lib/_gen_feature_names.js
  extension/lib/_gen_known_brands.js  
  extension/lib/_gen_known_legit.js
  extension/lib/_gen_thresholds.js (from HybridConfig)
"""
from __future__ import annotations

import re
from pathlib import Path

FEAT_PY = Path(__file__).resolve().parents[1] / "src" / "lexical" / "features.py"
CONSTANTS_PY = Path(__file__).resolve().parents[1] / "src" / "utils" / "constants.py"
CONFIG_PY = Path(__file__).resolve().parents[1] / "src" / "core" / "config.py"
OUT = Path(__file__).resolve().parents[1] / "extension" / "lib"


def _grab_tuple(name: str, src: str) -> list[str]:
    """Extract quoted strings from a tuple/frozenset/sequence assignment."""
    patterns = [
        rf'{name}\s*=\s*frozenset\(\{{([\s\S]*?)\}}\)',
        rf'{name}\s*=\s*tuple\(\(([\s\S]*?)\)\)',
        rf'{name}\s*=\s*\(([\s\S]*?)\)',
    ]
    for pat in patterns:
        m = re.search(pat, src)
        if m:
            return re.findall(r'"([^"]+)"', m.group(1))
    raise ValueError(f"Could not find {name} in source")


def main() -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    
    from src.lexical.features import FEATURE_NAMES
    
    # Grab brands from constants.py
    brands_src = CONSTANTS_PY.read_text(encoding="utf-8") if CONSTANTS_PY.exists() else ""
    brands = _grab_tuple("KNOWN_BRANDS", brands_src)
    
    # Grab legitimate domains from features.py
    src = FEAT_PY.read_text(encoding="utf-8")
    legit = _grab_tuple("KNOWN_LEGITIMATE_DOMAINS", src)
    
    # Generate JS files
    feat_js = "const FEATURE_NAMES = [\n" + ",\n".join(
        f'  "{n}"' for n in FEATURE_NAMES
    ) + ",\n];"
    
    brands_js = "const KNOWN_BRANDS = [\n" + ",\n".join(
        f'  "{b}"' for b in brands
    ) + "\n];"
    
    legit_js = "const KNOWN_LEGITIMATE_DOMAINS = new Set([\n" + ",\n".join(
        f'  "{d}"' for d in legit
    ) + "\n]);"
    
    # Generate thresholds from config
    thresholds_js = "const THRESHOLDS = {\n"
    if CONFIG_PY.exists():
        cfg_src = CONFIG_PY.read_text(encoding="utf-8")
        for key in ["fast_path_safe", "fast_path_malicious", "safe_threshold", "phishing_threshold"]:
            m = re.search(rf'{key}:\s*float\s*=\s*([\d.]+)', cfg_src)
            if m:
                thresholds_js += f'  {key}: {m.group(1)},\n'
    thresholds_js += "};\n"
    
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "_gen_feature_names.js").write_text(feat_js + "\n", encoding="utf-8")
    (OUT / "_gen_known_brands.js").write_text(brands_js + "\n", encoding="utf-8")
    (OUT / "_gen_known_legit.js").write_text(legit_js + "\n", encoding="utf-8")
    (OUT / "_gen_thresholds.js").write_text(thresholds_js, encoding="utf-8")
    
    print(f"Wrote generated constants: {len(FEATURE_NAMES)} features, "
          f"{len(brands)} brands, {len(legit)} legit domains -> {OUT}")


if __name__ == "__main__":
    main()
