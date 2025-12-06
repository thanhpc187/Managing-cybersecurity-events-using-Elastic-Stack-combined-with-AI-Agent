# pages/3_Alerts.py
# -*- coding: utf-8 -*-

import sys
import os
import json
import zipfile
from pathlib import Path
from datetime import datetime

# Bổ sung project root vào sys.path để import local modules
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from models.utils import get_paths
from pipeline.alerting import select_alerts
from pipeline.bundle import build_bundle_for_alert
from explain.shap_explain import top_shap_for_rows
from ai.agent import analyze_alert
from ai.mitre_mapper import load_mitre_mapping, map_to_mitre

# ---------------------------------------------------------
# Cấu hình trang
# ---------------------------------------------------------
try:
    st.set_page_config(layout="wide", page_title="Loganom AI Demo – Alerts", page_icon="🛡️")
except Exception:
    pass

st.title("Alerts")


# ---------------------------------------------------------
# UI Helpers
# ---------------------------------------------------------
def _risk_color(level: str) -> str:
    lv = (level or "").upper()
    return {
        "HIGH": "#ef4444",    # red-500
        "MEDIUM": "#f59e0b",  # amber-500
        "LOW": "#10b981",     # emerald-500
    }.get(lv, "#6b7280")      # gray-500


def _pill(text: str, bg: str, fg: str = "#ffffff") -> str:
    return f"""
    <span style="
        display:inline-block;padding:2px 10px;border-radius:999px;
        background:{bg};color:{fg};font-weight:600;font-size:0.85rem;">
        {text}
    </span>
    """


def _provider_chip(name: str) -> str:
    n = (name or "").lower()
    label = {"deepseek": "DeepSeek", "gemini": "Gemini", "stub": "Offline"}.get(n, name or "Unknown")
    col = {"deepseek": "#1f2937", "gemini": "#0ea5e9", "stub": "#6b7280"}.get(n, "#6b7280")
    return _pill(f"Provider: {label}", col)


def _split_action_line(s: str):
    """Tách mô tả và phần lệnh sau dấu ':' (nếu có)."""
    if ":" in s:
        left, right = s.split(":", 1)
        return left.strip(), right.strip()
    return s.strip(), ""


def _detect_shell(cmd: str) -> str:
    c = (cmd or "").lower()
    ps_keys = [
        "new-netfirewallrule", "set-adaccountpassword", "start-mpscan",
        "wevtutil", "stop-process", "get-filehash", "set-netfirewallprofile",
    ]
    return "powershell" if any(k in c for k in ps_keys) else "bash"

def _dedup_keep_order(items):
    seen = set()
    out = []
    for it in items:
        if it and it not in seen:
            out.append(it)
            seen.add(it)
    return out


def _to_dataframe(items):
    if not items:
        return pd.DataFrame()
    try:
        return pd.DataFrame(items)
    except Exception:
        return pd.DataFrame([{"value": str(items)}])


def _truncate(s: str, n: int) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def _load_ai_from_bundle(bundle_zip: Path):
    """Đọc ai_analysis.json / ai_analysis.md trong bundle (nếu có)."""
    data = None
    md = None
    if not bundle_zip.exists():
        return data, md
    try:
        with zipfile.ZipFile(bundle_zip, "r") as z:
            if "ai_analysis.json" in z.namelist():
                with z.open("ai_analysis.json") as f:
                    data = json.loads(f.read().decode("utf-8"))
            if "ai_analysis.md" in z.namelist():
                with z.open("ai_analysis.md") as f:
                    md = f.read().decode("utf-8")
    except Exception as e:
        st.warning(f"Không đọc được bundle: {e}")
    return data, md


# ---------------------------------------------------------
# Tải dữ liệu & bảng cảnh báo
# ---------------------------------------------------------
paths = get_paths()
scores_path = Path(paths["scores_dir"]) / "scores.parquet"

colA, colB = st.columns(2)
with colA:
    if st.button("Reload data"):
        st.experimental_rerun()
with colB:
    if scores_path.exists():
        mtime = datetime.fromtimestamp(os.path.getmtime(scores_path)).strftime("%Y-%m-%d %H:%M:%S")
        st.caption(f"scores.parquet last modified: {mtime}")

if not scores_path.exists():
    st.warning("Chưa có điểm bất thường. Chạy pipeline trước (ingest/featurize/train/score).")
    st.stop()

# Chọn các alert
try:
    top, thr = select_alerts(str(scores_path))
except Exception as e:
    st.error(f"Lỗi chọn alerts: {e}")
    st.stop()

# Chuẩn hóa cột thời gian + điền host/user trống = 'unknown'
if not top.empty:
    top["@timestamp"] = pd.to_datetime(top["@timestamp"], utc=True, errors="coerce")
    for col in ["host.name", "user.name", "source.ip", "destination.ip"]:
        if col not in top.columns:
            top[col] = None
    top["host.name"] = top["host.name"].fillna("unknown")
    top["user.name"] = top["user.name"].fillna("unknown")

# Tính MITRE mapping cho bảng alerts
mapping_cfg = load_mitre_mapping()
if not top.empty:
    mitre_tactics = []
    mitre_techs = []
    for _, r in top.iterrows():
        hits = map_to_mitre(r.to_dict(), r.to_dict(), mapping_cfg)
        tactics = _dedup_keep_order([h.get("tactic") for h in hits if h.get("tactic")])
        techs = _dedup_keep_order([h.get("technique") for h in hits if h.get("technique")])
        mitre_tactics.append(", ".join(tactics))
        mitre_techs.append(", ".join(techs))
    top = top.copy()
    top["mitre.tactics"] = mitre_tactics
    top["mitre.techniques"] = mitre_techs

# Bộ lọc event.action / event.module
col_f1, col_f2 = st.columns(2)
if "event.action" in top.columns:
    with col_f1:
        actions = sorted([a for a in top["event.action"].dropna().unique()])
        selected_actions = st.multiselect("Lọc event.action", actions, default=actions[:0])
        if selected_actions:
            top = top[top["event.action"].isin(selected_actions)]
if "event.module" in top.columns:
    with col_f2:
        modules = sorted([m for m in top["event.module"].dropna().unique()])
        selected_modules = st.multiselect("Lọc event.module", modules, default=modules[:0])
        if selected_modules:
            top = top[top["event.module"].isin(selected_modules)]

# Bộ lọc MITRE
col_f3, col_f4 = st.columns(2)
if "mitre.tactics" in top.columns:
    with col_f3:
        tactic_vals = sorted({t.strip() for v in top["mitre.tactics"].dropna() for t in str(v).split(",") if t.strip()})
        chosen_tactics = st.multiselect("Lọc MITRE tactic", tactic_vals, default=[])
        if chosen_tactics:
            top = top[top["mitre.tactics"].apply(lambda x: any(t in str(x) for t in chosen_tactics))]
if "mitre.techniques" in top.columns:
    with col_f4:
        tech_vals = sorted({t.strip() for v in top["mitre.techniques"].dropna() for t in str(v).split(",") if t.strip()})
        chosen_techs = st.multiselect("Lọc MITRE technique", tech_vals, default=[])
        if chosen_techs:
            top = top[top["mitre.techniques"].apply(lambda x: any(t in str(x) for t in chosen_techs))]

st.caption(f"Threshold: {thr:.4f}")

if top.empty:
    st.info("Chưa có alert vượt ngưỡng.")
    st.stop()

# Bảng alerts
cols_show = [c for c in ["@timestamp", "host.name", "user.name", "source.ip", "destination.ip", "anom.score", "mitre.tactics", "mitre.techniques"] if c in top.columns]
st.dataframe(top[cols_show], use_container_width=True, hide_index=True)

# Đồ thị drop/allow (nếu có)
if "event.action" in top.columns:
    top_act = top.copy()
    top_act["event.action"] = top_act["event.action"].astype(str).str.lower()
    deny = top_act[top_act["event.action"].isin(["deny", "drop", "blocked", "reset"])].resample("1T", on="@timestamp").size()
    allow = top_act[top_act["event.action"].isin(["allow", "allowed", "permit"])].resample("1T", on="@timestamp").size()
    if len(deny) or len(allow):
        st.subheader("Firewall drop/allow theo thời gian")
        figd, axd = plt.subplots(figsize=(8, 3))
        if len(deny):
            axd.plot(deny.index, deny.values, label="deny/drop", color="#ef4444")
        if len(allow):
            axd.plot(allow.index, allow.values, label="allow", color="#10b981")
        axd.legend()
        axd.set_ylabel("Count per minute")
        axd.set_xlabel("Time")
        st.pyplot(figd)

# Bảng IPS alert (nếu có)
if "event.module" in top.columns:
    ips_top = top[top["event.module"].astype(str).str.lower() == "ips"]
    if not ips_top.empty:
        st.subheader("IPS alerts (top-N)")
        cols_ips = [c for c in ["@timestamp", "rule.name", "event.severity", "source.ip", "destination.ip", "anom.score"] if c in ips_top.columns]
        st.dataframe(ips_top[cols_ips], use_container_width=True, hide_index=True)

# Chọn 1 alert để xem chi tiết
idx = st.number_input("Chọn alert (chỉ số hàng)", min_value=0, max_value=len(top) - 1, value=0, step=1)
row = top.iloc[int(idx)]

# ---------------------------------------------------------
# SHAP Top Features
# ---------------------------------------------------------
st.subheader("Top SHAP Features")

names, vals = [], []
try:
    payload = joblib.load(Path(paths["models_dir"]) / "isolation_forest.joblib")
    model = payload["model"] if isinstance(payload, dict) and "model" in payload else payload
    feature_cols = payload.get("feature_cols") if isinstance(payload, dict) else None
    if not feature_cols:
        # fallback: chọn các cột numeric trong hàng
        feature_cols = [c for c in row.index if isinstance(row[c], (int, float, float))]

    X = row[feature_cols].fillna(0.0).to_frame().T
    shap_info = top_shap_for_rows(model, X.values, feature_cols, top_k=5)[0]
    feats = shap_info.get("top_features", [])
    names = [f.get("feature", "") for f in feats]
    vals = [f.get("value", 0.0) for f in feats]
except Exception as e:
    st.caption(f"Không tính được SHAP: {e}")

if names:
    fig, ax = plt.subplots(figsize=(6.8, 3.2))
    bars = ax.bar(names, vals)
    ax.set_ylabel("SHAP value")
    ax.tick_params(axis="x", rotation=30)
    # Gắn nhãn giá trị trên đầu cột
    for b in bars:
        v = b.get_height()
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.3f}", ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    st.pyplot(fig)
else:
    st.caption("Không có dữ liệu SHAP để hiển thị.")

# ---------------------------------------------------------
# Ngữ cảnh thô ±5 phút quanh alert
# ---------------------------------------------------------
st.subheader("Raw context (±5 phút)")
ecs_dir = Path(paths["ecs_parquet_dir"])
ctx = None
try:
    parts = list(ecs_dir.rglob("*.parquet"))
    if parts:
        ecs_df = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True)
        ecs_df["@timestamp"] = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")
        t0 = pd.to_datetime(row["@timestamp"], utc=True)
        mask = (ecs_df["@timestamp"] >= t0 - pd.Timedelta(minutes=5)) & (ecs_df["@timestamp"] <= t0 + pd.Timedelta(minutes=5))
        ctx = ecs_df.loc[mask].sort_values("@timestamp").head(200)
        st.dataframe(ctx, use_container_width=True)
    else:
        st.caption("Không tìm thấy dữ liệu ECS.")
except Exception as e:
    st.warning(f"Không tải được ngữ cảnh: {e}")

# ---------------------------------------------------------
# Forensic bundle
# ---------------------------------------------------------
st.subheader("Forensic Bundle")

if st.button("Tạo bundle cho alert đang chọn"):
    try:
        bundle_path = build_bundle_for_alert(row, int(idx) + 1, thr)
        st.success(f"Bundle created: {bundle_path}")
    except Exception as e:
        st.error(f"Lỗi tạo bundle: {e}")

bundle_candidate = Path(paths["bundles_dir"]) / f"alert_{int(idx) + 1}.zip"
if bundle_candidate.exists():
    with open(bundle_candidate, "rb") as f:
        st.download_button("Tải bundle", data=f, file_name=bundle_candidate.name, mime="application/zip")

    st.divider()
    st.subheader("AI Agent Analysis")

    ai_json, ai_md = _load_ai_from_bundle(bundle_candidate)

    # Nếu bundle chưa có AI, chạy nhanh agent offline trên hàng đang chọn để hiển thị gợi ý
    if not ai_json:
        try:
            payload = joblib.load(Path(paths["models_dir"]) / "isolation_forest.joblib")
            model = payload["model"] if isinstance(payload, dict) and "model" in payload else payload
            feature_cols = payload.get("feature_cols") if isinstance(payload, dict) else None
            if not feature_cols:
                feature_cols = [c for c in row.index if isinstance(row[c], (int, float))]
            X = row[feature_cols].fillna(0.0).to_frame().T
            shap_info = top_shap_for_rows(model, X.values, feature_cols, top_k=5)[0]
        except Exception:
            shap_info = {"top_features": []}
        try:
            ai_json = analyze_alert(row.to_dict(), shap_info.get("top_features", []), [], row.to_dict())
        except Exception:
            ai_json = None

    if ai_json:
        risk = ai_json.get("risk_level", "n/a")
        score = ai_json.get("score")
        provider = ai_json.get("provider", "stub")
        t_alert = ai_json.get("alert_time", "")
        reason = ai_json.get("reason", "")
        raw_text = ai_json.get("raw_text", "")
        iocs = ai_json.get("iocs") or []
        actions = ai_json.get("actions") or []

        # Header: risk pill + score + (optional provider) + time
        c1, c2, c3, c4 = st.columns([1.2, 1, 1, 1.2])
        with c1:
            st.markdown(_pill(f"RISK: {risk}", _risk_color(risk)), unsafe_allow_html=True)
        with c2:
            st.metric("Score", f"{score:.3f}" if isinstance(score, (int, float)) else "n/a")
        with c3:
            if str(provider).lower() not in ("stub", "offline", "none", ""):
                st.markdown(_provider_chip(provider), unsafe_allow_html=True)
        with c4:
            st.caption(f"Alert time (UTC): {t_alert}")

        # LLM summary (short) + raw (expand)
        is_offline = str(provider).lower() in ("stub", "offline", "none", "")
        if not is_offline and reason:
            st.markdown("#### Tóm tắt từ LLM")
            st.markdown(reason)

        if (not is_offline) and raw_text:
            with st.expander("Xem toàn văn phản hồi LLM (raw)"):
                st.markdown(raw_text)

        # Tabs: Indicators / Actions / Context / Export
        tabs = st.tabs(["Indicators", "Actions", "Context", "Export"])

        # --- Indicators
        with tabs[0]:
            df_ioc = _to_dataframe(iocs)
            if not df_ioc.empty:
                st.dataframe(df_ioc, use_container_width=True, hide_index=True)
            else:
                st.caption("Không có IOC.")

        # --- Actions
        with tabs[1]:
            if actions:
                all_cmds = []
                for a in actions:
                    desc, cmd = _split_action_line(a)
                    st.write(f"- **{desc}**")
                    if cmd:
                        lang = _detect_shell(cmd)
                        st.code(cmd, language=lang)
                        all_cmds.append(cmd)
                if all_cmds:
                    joined = "\n\n".join(all_cmds).strip().encode("utf-8")
                    st.download_button(
                        "Tải tất cả lệnh (txt)",
                        data=joined,
                        file_name=f"soar_actions_{int(idx)+1}.txt",
                        mime="text/plain",
                    )
            else:
                st.caption("Không có khuyến nghị.")

        # --- Context
        with tabs[2]:
            if isinstance(ctx, pd.DataFrame) and not ctx.empty:
                st.dataframe(ctx, use_container_width=True)
            else:
                st.caption("Không có dữ liệu ngữ cảnh phù hợp.")

        # --- Export
        with tabs[3]:
            md_lines = [
                f"# AI Agent Analysis – Alert #{int(idx)+1}",
                f"- Risk: **{risk}**",
                f"- Score: **{score:.3f}**" if isinstance(score, (int, float)) else "- Score: n/a",
                f"- Provider: **{provider}**",
                f"- Time (UTC): {t_alert}",
                "",
                "##Tóm tắt",
                reason or "_(offline/no analysis)_",
                "",
                "## Indicators",
            ]
            for x in (iocs or []):
                md_lines.append(f"- {x.get('type')}: `{x.get('value')}`")
            md_lines.append("")
            md_lines.append("## Actions")
            for a in (actions or []):
                md_lines.append(f"- {a}")

            md_blob = "\n".join(md_lines).encode("utf-8")
            st.download_button(
                "Tải báo cáo Markdown",
                data=md_blob,
                file_name=f"ai_analysis_{int(idx)+1}.md",
                mime="text/markdown",
            )

        # Nếu bundle có sẵn bản tóm tắt Markdown
        if ai_md:
            st.divider()
            st.caption("Bản tóm tắt (từ bundle)")
            st.markdown(ai_md)

    else:
        st.info("Bundle chưa có phân tích AI.")

else:
    st.caption("Chưa có bundle cho alert đang chọn. Nhấn nút để tạo.")
