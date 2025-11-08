# ui/streamlit_app.py
# -*- coding: utf-8 -*-

import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is on sys.path for local imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.utils import get_paths  # noqa: E402

# ---------------------------------------------------------
# Page config + minimal CSS
# ---------------------------------------------------------
st.set_page_config(page_title="Loganom AI", layout="wide", page_icon="🛡️")

st.markdown(
    """
    <style>
    .pill {
        display:inline-block;padding:4px 10px;border-radius:999px;
        font-weight:600;font-size:0.85rem;color:white
    }
    .pill-ok { background:#10b981; }      /* emerald */
    .pill-warn { background:#f59e0b; }    /* amber  */
    .pill-bad { background:#ef4444; }     /* red    */
    .dim { color:#6b7280; }               /* gray-500 */
    .shadow { box-shadow: 0 1px 12px rgba(0,0,0,.06); border-radius:12px; padding:16px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def _get_secret(name: str) -> str | None:
    """Prefer environment variables; only read st.secrets if secrets.toml exists."""
    # 1) Env var first (no warnings)
    env_val = os.getenv(name)
    if env_val:
        return env_val

    # 2) Only touch st.secrets if a secrets.toml is present
    candidates = [
        PROJECT_ROOT / ".streamlit" / "secrets.toml",
        Path.home() / ".streamlit" / "secrets.toml",
    ]
    if any(p.exists() for p in candidates):
        try:
            val = st.secrets.get(name)
            if val:
                return str(val)
        except Exception:
            pass
    return None


@st.cache_data(show_spinner=False)
def _scan_status(paths: dict):
    scores_dir = Path(paths.get("scores_dir", "")) if paths else None
    bundles_dir = Path(paths.get("bundles_dir", "")) if paths else None
    models_dir = Path(paths.get("models_dir", "")) if paths else None

    parquet_files = []
    latest_file = None
    latest_ts = None

    if scores_dir and scores_dir.exists():
        parquet_files = list(scores_dir.rglob("*.parquet"))
        if parquet_files:
            latest_file = max(parquet_files, key=lambda p: p.stat().st_mtime)
            latest_ts = datetime.fromtimestamp(latest_file.stat().st_mtime)

    model_path = None
    if models_dir and models_dir.exists():
        # ưu tiên file IF mặc định nếu có
        candidate = models_dir / "isolation_forest.joblib"
        model_path = candidate if candidate.exists() else None

    bundle_count = 0
    if bundles_dir and bundles_dir.exists():
        bundle_count = len(list(bundles_dir.glob("alert_*.zip")))

    llm_ok = bool(_get_secret("DEEPSEEK_API_KEY") or _get_secret("GEMINI_API_KEY"))

    return {
        "scores_dir": scores_dir,
        "scores_count": len(parquet_files),
        "latest_file": latest_file,
        "latest_ts": latest_ts,
        "models_dir": models_dir,
        "model_path": model_path,
        "bundles_dir": bundles_dir,
        "bundle_count": bundle_count,
        "llm_ok": llm_ok,
    }


def _pill(text: str, kind: str = "ok") -> str:
    cls = {"ok": "pill-ok", "warn": "pill-warn", "bad": "pill-bad"}.get(kind, "pill-ok")
    return f'<span class="pill {cls}">{text}</span>'


# ---------------------------------------------------------
# Hero header
# ---------------------------------------------------------
st.markdown("### 🛡️ Loganom AI")
st.caption("Logs → ECS → Features → Isolation Forest Scoring → Alerts/SHAP → Bundle → (LLM)")

# Quick navigation
c1, c2, c3 = st.columns([1, 1, 1])
with c1:
    st.page_link("pages/1_Overview.py", label="Overview", icon="📊")
with c2:
    st.page_link("pages/2_Hosts.py", label="Hosts", icon="🖥️")
with c3:
    st.page_link("pages/3_Alerts.py", label="Alerts", icon="⚠️")

st.divider()

# ---------------------------------------------------------
# Status cards
# ---------------------------------------------------------
paths = get_paths()
status = _scan_status(paths)

m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown('<div class="shadow">', unsafe_allow_html=True)
    st.metric("Scores files", status["scores_count"])
    if status["latest_ts"]:
        st.caption(f"Latest: {status['latest_file'].name} ({status['latest_ts']:%Y-%m-%d %H:%M:%S})")
    else:
        st.caption("Chưa có file .parquet")
    st.markdown("</div>", unsafe_allow_html=True)

with m2:
    st.markdown('<div class="shadow">', unsafe_allow_html=True)
    if status["model_path"]:
        st.markdown(_pill("Model: Ready", "ok"), unsafe_allow_html=True)
        st.caption(str(status["model_path"]))
    else:
        st.markdown(_pill("Model: Missing", "bad"), unsafe_allow_html=True)
        st.caption("models/isolation_forest.joblib")
    st.markdown("</div>", unsafe_allow_html=True)

with m3:
    st.markdown('<div class="shadow">', unsafe_allow_html=True)
    if status["llm_ok"]:
        st.markdown(_pill("LLM: Configured", "ok"), unsafe_allow_html=True)
        st.caption("Đã thấy DEEPSEEK_API_KEY hoặc GEMINI_API_KEY")
    else:
        st.markdown(_pill("LLM: Offline", "warn"), unsafe_allow_html=True)
        st.caption("Thiếu DEEPSEEK_API_KEY / GEMINI_API_KEY")
    st.markdown("</div>", unsafe_allow_html=True)

with m4:
    st.markdown('<div class="shadow">', unsafe_allow_html=True)
    st.metric("Bundles", status["bundle_count"])
    if status["bundles_dir"]:
        st.caption(str(status["bundles_dir"]))
    st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------------------------------------
# Paths summary table
# ---------------------------------------------------------
st.markdown("#### Paths summary")
rows = []
for key in ["DATA_ROOT", "ECS_PARQUET_DIR", "FEATURE_TABLE_PATH", "MODELS_DIR", "MODEL_PATH", "SCORES_PATH", "BUNDLES_DIR"]:
    # get_paths() dùng key lower/underscore; ánh xạ mềm:
    k = key.lower()
    val = paths.get(k) if paths else None
    p = Path(val) if val else None
    exists = p.exists() if p else False
    rows.append(
        {"name": key, "path": str(p) if p else "-", "exists": "✅" if exists else "—"}
    )
df_paths = pd.DataFrame(rows)
st.dataframe(df_paths, use_container_width=True, hide_index=True)

st.divider()
