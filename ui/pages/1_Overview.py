import sys
from pathlib import Path
from datetime import datetime

# Ensure project root is on sys.path for local imports
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from models.utils import get_paths
from explain.thresholding import compute_threshold

st.set_page_config(page_title="Loganom AI", layout="wide")

st.title("Loganom AI")

st.caption("Logs → ECS → Features → IF Scoring → Alerts/SHAP → Bundle → (SOAR)")


paths = get_paths()

st.divider()

# Tổng tiến trình và biểu đồ điểm theo thời gian
scores_path = Path(paths["scores_dir"]) / "scores.parquet"
if not scores_path.exists():
    st.warning("Chưa có điểm bất thường. Hãy chạy: python -m cli.anom_score featurize && python -m cli.anom_score score")
else:
    df = pd.read_parquet(scores_path)
    if "@timestamp" in df.columns:
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["@timestamp"]).sort_values("@timestamp")

    # Metrics tổng quan
    total_events = len(df)
    time_range = (df["@timestamp"].min(), df["@timestamp"].max()) if len(df) else (None, None)
    thr, _ = compute_threshold(df["anom.score"]) if "anom.score" in df.columns and len(df) else (None, 0)
    alert_count = int((df["anom.score"] >= thr).sum()) if thr is not None else 0

    m1, m2, m3 = st.columns(3)
    m1.metric("Events processed", f"{total_events:,}")
    if time_range[0] is not None:
        m2.metric("Time range",
                  f"{time_range[0]:%Y-%m-%d %H:%M} → {time_range[1]:%Y-%m-%d %H:%M}")
    m3.metric("Alerts ≥ threshold", f"{alert_count}")

    # Biểu đồ timeline điểm + ngưỡng
    if total_events > 0 and "anom.score" in df.columns:
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(df["@timestamp"], df["anom.score"], linewidth=1)
        if thr is not None:
            ax.axhline(thr, color="red", linestyle="--", linewidth=1, label=f"threshold={thr:.3f}")
            ax.legend(loc="upper right")
        ax.set_ylabel("Anomaly score")
        ax.set_xlabel("Time")
        st.pyplot(fig)
