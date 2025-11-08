import sys
from pathlib import Path

# Ensure project root is on sys.path for local imports
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from models.utils import get_paths

st.title("LSTM Time-Series Analysis")

paths = get_paths()
lstm_path = Path(paths["scores_dir"]) / "lstm_scores.parquet"

colA, colB = st.columns(2)
with colA:
    if st.button("Reload data"):
        st.experimental_rerun()
with colB:
    if lstm_path.exists():
        import os
        from datetime import datetime
        mtime = datetime.fromtimestamp(os.path.getmtime(lstm_path)).strftime("%Y-%m-%d %H:%M:%S")
        st.caption(f"lstm_scores.parquet last modified: {mtime}")

if not lstm_path.exists():
    st.warning("No LSTM scores found. Run: python -m cli.anom_score train-lstm && python -m cli.anom_score score-lstm")
    st.stop()

df = pd.read_parquet(lstm_path)
if "@timestamp" in df.columns:
    df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["@timestamp"]).sort_values("@timestamp")

st.subheader("Reconstruction Error Timeline (MSE)")
if "lstm.mse" in df.columns:
    fig, ax = plt.subplots(figsize=(10, 3))
    ax.plot(df["@timestamp"], df["lstm.mse"], linewidth=1)
    ax.set_ylabel("MSE")
    ax.set_xlabel("Time")
    st.pyplot(fig)

st.subheader("Detected Anomalies")
if "lstm.anomaly" in df.columns and df["lstm.anomaly"].any():
    st.dataframe(df[df["lstm.anomaly"] == True][["@timestamp", "lstm.mse"]].tail(200))
else:
    st.info("No LSTM anomalies detected.")


