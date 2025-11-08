import sys
from pathlib import Path
import pandas as pd
import streamlit as st

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.utils import get_paths

st.set_page_config(page_title="SOAR Actions", layout="wide")
st.title("SOAR Actions (Audit Log)")

paths = get_paths()
audit_path = Path(paths["logs_dir"]) / "actions.jsonl"

col1, col2 = st.columns(2)
with col1:
    if st.button("Reload audit log"):
        st.experimental_rerun()
with col2:
    run_resp = st.button("Run SOAR (dry-run)")

if run_resp:
    try:
        from pipeline.respond import respond
        out = respond(dry_run=True)
        st.success(f"SOAR dry-run completed. Audit: {out}")
    except Exception as e:
        st.error(f"Failed to run SOAR dry-run: {e}")

if not audit_path.exists():
    st.info("No audit log found yet. Click 'Run SOAR (dry-run)' or run `python -m cli.anom_score respond`. ")
    st.stop()

# Load JSONL safely
try:
    df = pd.read_json(audit_path, lines=True)
except ValueError:
    # Fallback manual load
    rows = []
    with open(audit_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                import json
                rows.append(json.loads(line))
            except Exception:
                continue
    df = pd.DataFrame(rows)

if df.empty:
    st.info("Audit log is empty.")
    st.stop()

# Normalize columns
for c in ["time", "row_ts"]:
    if c in df.columns:
        df[c] = pd.to_datetime(df[c], errors="coerce", utc=True)

if "action" in df.columns:
    def _get_cmd(x):
        if isinstance(x, dict):
            return x.get("cmd")
        return None
    df["action.cmd"] = df["action"].apply(_get_cmd)

st.subheader("Filters")
rule_vals = ["<All>"]
if "rule" in df.columns:
    rule_vals += sorted([r for r in df["rule"].dropna().unique().tolist()])
rule_sel = st.selectbox("Rule", rule_vals)
only_applied = st.checkbox("Only applied actions (not dry-run)", value=False)
last_n = st.slider("Rows to display (latest N)", min_value=100, max_value=10000, step=100, value=1000)

df_view = df.copy()
if only_applied and "dry_run" in df_view.columns:
    df_view = df_view[df_view["dry_run"] == False]
if rule_sel != "<All>" and "rule" in df_view.columns:
    df_view = df_view[df_view["rule"] == rule_sel]

df_view = df_view.sort_values("time" if "time" in df_view.columns else df_view.columns[0]).tail(last_n)

st.subheader("Summary by rule")
if "rule" in df_view.columns:
    agg = df_view.groupby("rule").size().reset_index(name="count").sort_values("count", ascending=False)
    st.dataframe(agg, use_container_width=True)
else:
    st.write("No 'rule' column present.")

st.subheader("Audit entries")
cols = [c for c in ["time", "rule", "score", "action.cmd", "return_code", "dry_run", "row_ts"] if c in df_view.columns]
st.dataframe(df_view[cols] if cols else df_view, use_container_width=True)

# Download filtered data
csv = df_view.to_csv(index=False)
st.download_button("Download filtered CSV", data=csv, file_name="soar_audit_filtered.csv", mime="text/csv")