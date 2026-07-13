"""Interactive engine simulator (Streamlit).

Lets you paste a URL and watch the hybrid pipeline work: per-stage scores, the
fused risk matrix, and live weight/threshold sliders that change the final
verdict in real time.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st

from src.core.config import HybridConfig
from src.core.hybrid import analyze
from src.lexical.features import extract_features, FEATURE_NAMES


st.set_page_config(page_title="Phishing Detection Simulator", layout="wide")
st.title("🛡️ Automated Phishing URL Detection — Engine Simulator")

st.markdown(
    "Paste a URL to run it through the hybrid pipeline. Adjust the weights and "
    "thresholds below to see how the final verdict changes. The lexical engine "
    "runs locally with no network; the visual stage is invoked only when the "
    "lexical score is ambiguous."
)

url = st.text_input("URL to analyze", value="http://micr0soft-secure-login.com/verify")

with st.sidebar:
    st.header("Hybrid Core Parameters")
    w_lex = st.slider("Lexical weight", 0.0, 1.0, 0.5, 0.05)
    w_vis = st.slider("Vision weight", 0.0, 1.0, 0.5, 0.05)
    safe_t = st.slider("Safe threshold", 0.0, 1.0, 0.33, 0.01)
    phish_t = st.slider("Phishing threshold", 0.0, 1.0, 0.66, 0.01)
    run_vision = st.checkbox("Enable visual capture stage", value=True)

cfg = HybridConfig(
    w_lexical=w_lex, w_vision=w_vis,
    safe_threshold=safe_t, phishing_threshold=phish_t,
)

if st.button("Run Analysis") or url:
    result = analyze(url, cfg=cfg, run_vision=run_vision)

    col1, col2 = st.columns([1, 2])

    with col1:
        color = {"Safe": "green", "Suspicious": "orange", "Phishing": "red"}[result.verdict]
        st.markdown(f"### Verdict: <span style='color:{color}'>{result.verdict}</span>",
                    unsafe_allow_html=True)
        st.metric("Fused Risk", f"{result.risk:.3f}")
        st.caption("Fast-path" if result.fast_path else "Full hybrid")

    with col2:
        st.subheader("Stage Scores")
        for s in result.stage_scores:
            st.write(f"**{s.name}** — prob={s.probability:.3f} "
                     f"{'✅ used' if s.used else '⚪ not used'}")
            if s.detail:
                st.caption(s.detail)

    st.subheader("Risk Matrix")
    st.bar_chart({"risk": [result.risk]})

    st.subheader("Lexical Feature Breakdown")
    feats = extract_features(url).values
    st.table({name: [feats[name]] for name in FEATURE_NAMES})

    if result.screenshot:
        st.subheader("Captured Screenshot")
        st.image(result.screenshot)

    with st.expander("Pipeline notes"):
        for n in result.notes:
            st.write("- " + n)
