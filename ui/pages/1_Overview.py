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

    # Bộ lọc theo event.action / event.module
    col_filter1, col_filter2 = st.columns(2)
    if "event.action" in df.columns:
        with col_filter1:
            actions = sorted([a for a in df["event.action"].dropna().unique()])
            selected_actions = st.multiselect("event.action (allow/deny/...)", actions, default=actions[:0])
            if selected_actions:
                df = df[df["event.action"].isin(selected_actions)]
    if "event.module" in df.columns:
        with col_filter2:
            modules = sorted([m for m in df["event.module"].dropna().unique()])
            selected_modules = st.multiselect("event.module (fortigate/ips/packetbeat/...)", modules, default=modules[:0])
            if selected_modules:
                df = df[df["event.module"].isin(selected_modules)]

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

    # Biểu đồ drop/allow theo thời gian (FortiGate/Firewall)
    if "event.action" in df.columns and not df.empty:
        df_act = df.copy()
        df_act["event.action"] = df_act["event.action"].astype(str).str.lower()
        deny = df_act[df_act["event.action"].isin(["deny", "drop", "blocked", "reset"])].resample("1T", on="@timestamp").size()
        allow = df_act[df_act["event.action"].isin(["allow", "allowed", "permit"])].resample("1T", on="@timestamp").size()
        if len(deny) or len(allow):
            fig2, ax2 = plt.subplots(figsize=(10, 3))
            if len(deny):
                ax2.plot(deny.index, deny.values, label="deny/drop", color="#ef4444")
            if len(allow):
                ax2.plot(allow.index, allow.values, label="allow", color="#10b981")
            ax2.set_ylabel("Count per minute")
            ax2.set_xlabel("Time")
            ax2.legend()
            st.pyplot(fig2)

    # Bảng IPS alerts (nếu có)
    if "event.module" in df.columns:
        ips_df = df[df["event.module"].astype(str).str.lower() == "ips"]
        if not ips_df.empty:
            st.subheader("IPS alerts")
            cols = [c for c in ["@timestamp", "event.severity", "rule.name", "source.ip", "destination.ip", "anom.score"] if c in ips_df.columns]
            st.dataframe(ips_df[cols].sort_values("@timestamp"), use_container_width=True, hide_index=True)
