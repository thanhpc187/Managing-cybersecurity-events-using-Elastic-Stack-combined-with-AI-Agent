import sys
import os
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# Ensure project root is on sys.path for local imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.utils import get_paths  # noqa: E402
from explain.thresholding import compute_threshold  # noqa: E402
from ai.mitre_mapper import load_mitre_mapping, map_to_mitre  # noqa: E402
from ai.nist_mapper import load_nist_mapping, map_to_nist  # noqa: E402


st.set_page_config(page_title="Báo cáo kết quả", layout="wide", page_icon="📊")
st.title("📊 Báo cáo kết quả SIEM + AI Agent (One-page)")


# ---------------------------------------------------------
# Load data
# ---------------------------------------------------------
paths = get_paths()
scores_path = Path(paths["scores_dir"]) / "scores.parquet"
eval_report_path = Path(paths["scores_dir"]) / "evaluate_report.json"

if not scores_path.exists():
    st.warning("Chưa có dữ liệu scores. Hãy chạy ingest → featurize → train → score trước.")
    st.stop()

df = pd.read_parquet(scores_path)
if "@timestamp" in df.columns:
    df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["@timestamp"]).sort_values("@timestamp")

# Threshold & alerts
thr, _ = compute_threshold(df["anom.score"]) if "anom.score" in df.columns and len(df) else (None, 0)
alerts = df[df["anom.score"] >= thr].copy() if thr is not None else df.head(0)

# Recompute MITRE + NIST mapping
mapping_cfg = load_mitre_mapping()
nist_cfg = load_nist_mapping()
if mapping_cfg is not None:
    mitre_tactics = []
    mitre_techs = []
    nist_funcs = []
    nist_cats = []
    for _, r in alerts.iterrows():
        rec = r.to_dict()
        hits = map_to_mitre(rec, rec, mapping_cfg)
        tactics = sorted({h.get("tactic") for h in hits if h.get("tactic")})
        techs = sorted({h.get("technique") for h in hits if h.get("technique")})
        mitre_tactics.append(", ".join(tactics))
        mitre_techs.append(", ".join(techs))
        nist_hits = map_to_nist(rec, hits, nist_cfg)
        funcs = sorted({h.get("function") for h in nist_hits if h.get("function")})
        cats = sorted({h.get("category") for h in nist_hits if h.get("category")})
        nist_funcs.append(", ".join(funcs))
        nist_cats.append(", ".join(cats))
    alerts["mitre.tactics"] = mitre_tactics
    alerts["mitre.techniques"] = mitre_techs
    alerts["nist.functions"] = nist_funcs
    alerts["nist.categories"] = nist_cats
else:
    alerts["mitre.tactics"] = ""
    alerts["mitre.techniques"] = ""
    alerts["nist.functions"] = ""
    alerts["nist.categories"] = ""

# Risk level fallback
if "risk_level" not in alerts.columns:
    alerts["risk_level"] = None
alerts["risk_level"] = alerts["risk_level"].fillna("")


def _fallback_risk(row):
    if row.get("risk_level"):
        return row["risk_level"]
    tech = str(row.get("mitre.techniques", "")).strip()
    return "MEDIUM" if tech else "LOW"


alerts["risk_level"] = alerts.apply(_fallback_risk, axis=1)


# ---------------------------------------------------------
# MITRE helpers: link + Gemini explanation
# ---------------------------------------------------------
def _technique_url(tech_id: str) -> str:
    """Build MITRE ATT&CK URL from technique id (supports sub-techniques)."""
    tid = (tech_id or "").strip()
    if not tid:
        return ""
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def _collect_mitre_techniques(alerts_df: pd.DataFrame):
    """Extract unique techniques from alerts dataframe."""
    seen = set()
    items = []
    if alerts_df is None or alerts_df.empty:
        return items
    tech_series = alerts_df.get("mitre.techniques")
    if tech_series is None:
        return items
    for raw in tech_series.fillna(""):
        for part in str(raw).split(","):
            t = part.strip()
            if not t:
                continue
            tid = t.split()[0] if " " in t else t
            name = t[len(tid):].strip()
            key = tid.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append({"id": tid, "name": name})
    return items


@st.cache_data(show_spinner=False)
def explain_mitre_with_gemini(tech_id: str, tech_name: str):
    """Call Gemini to explain a MITRE technique (offline-friendly)."""
    gkey = os.getenv("GEMINI_API_KEY")
    if not gkey:
        return "GEMINI_API_KEY chưa được cấu hình, không thể gọi Gemini."
    try:
        import google.generativeai as genai
    except ImportError:
        return "Chưa cài đặt google-generativeai. Cài bằng: pip install google-generativeai"
    prompt = (
        "Giải thích ngắn gọn kỹ thuật MITRE ATT&CK dưới đây bằng tiếng Việt, "
        "nhấn mạnh ý nghĩa, dấu hiệu phát hiện và cách phòng thủ:\n"
        f"- Mã: {tech_id}\n"
        f"- Tên: {tech_name or tech_id}\n"
        "Trả lời súc tích (<= 150 từ)."
    )
    try:
        genai.configure(api_key=gkey)
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
        res = model.generate_content(prompt)
        return (getattr(res, "text", None) or "").strip() or "Không nhận được phản hồi từ Gemini."
    except Exception as e:
        return f"Lỗi khi gọi Gemini: {e}"


def summarize_report_with_gemini(payload: dict):
    """Tóm tắt toàn bộ báo cáo bằng Gemini, có nhắc MITRE nếu có."""
    gkey = os.getenv("GEMINI_API_KEY")
    if not gkey:
        return "GEMINI_API_KEY chưa được cấu hình, không thể gọi Gemini."
    try:
        import google.generativeai as genai
    except ImportError:
        return "Chưa cài đặt google-generativeai. Cài bằng: pip install google-generativeai"

    prompt = (
        "Bạn là chuyên gia SOC. Hãy tóm tắt ngắn gọn (<= 150 từ, tiếng Việt) "
        "về tình trạng báo cáo dưới đây, gồm: khối lượng log, số alert, ngưỡng, "
        "phân bố rủi ro, MITRE kỹ thuật (nếu có), và nhận định tổng quan/rủi ro. "
        "Nếu không có MITRE, nêu rõ. Không dài dòng.\n\n"
        f"Dữ liệu: {json.dumps(payload, ensure_ascii=False)}"
    )
    try:
        genai.configure(api_key=gkey)
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
        res = model.generate_content(prompt)
        return (getattr(res, "text", None) or "").strip() or "Không nhận được phản hồi từ Gemini."
    except Exception as e:
        return f"Lỗi khi gọi Gemini: {e}"

# ---------------------------------------------------------
# 1) Tổng quan dữ liệu
# ---------------------------------------------------------
st.subheader("Tổng quan dữ liệu")
c1, c2, c3 = st.columns(3)
c1.metric("Tổng log (scores)", f"{len(df):,}")
c2.metric("Alerts ≥ threshold", f"{len(alerts):,}")
c3.metric("Ngưỡng (quantile)", f"{thr:.4f}" if thr is not None else "n/a")

st.caption("Nguồn log đã ingest (event.module / event.dataset)")
src_cols = []
if "event.module" in df.columns:
    src_cols.append("event.module")
if "event.dataset" in df.columns:
    src_cols.append("event.dataset")
if src_cols:
    src_counts = df[src_cols].fillna("unknown").value_counts().reset_index(name="count")
    st.dataframe(src_counts, use_container_width=True, hide_index=True)
else:
    st.info("Không có cột event.module/event.dataset trong scores.")

# ---------------------------------------------------------
# 2) Kết luận tổng quan (Gemini)
# ---------------------------------------------------------
st.subheader("Kết luận tổng quan")
summary_payload = {
    "total_events": len(df),
    "alert_count": len(alerts),
    "threshold": thr,
    "risk_counts": alerts["risk_level"].value_counts(dropna=False).to_dict(),
    "mitre_techniques": [x["id"] for x in _collect_mitre_techniques(alerts)],
    "nist_functions": alerts.get("nist.functions", pd.Series([], dtype=str)).value_counts().to_dict()
    if "nist.functions" in alerts.columns
    else {},
}
if "report_summary_ai" not in st.session_state:
    # Auto-generate once on load if có GEMINI_API_KEY
    if os.getenv("GEMINI_API_KEY"):
        st.session_state["report_summary_ai"] = summarize_report_with_gemini(summary_payload)
    else:
        st.session_state["report_summary_ai"] = ""

if st.session_state["report_summary_ai"]:
    st.markdown(st.session_state["report_summary_ai"])
else:
    st.caption("Chưa có GEMINI_API_KEY hoặc chưa sinh tóm tắt.")
    if st.button("Sinh tóm tắt báo cáo bằng Gemini"):
        with st.spinner("Đang gọi Gemini..."):
            st.session_state["report_summary_ai"] = summarize_report_with_gemini(summary_payload)
        st.markdown(st.session_state["report_summary_ai"])

# ---------------------------------------------------------
# 3) Chỉ số phát hiện (nếu có evaluate_report.json)
# ---------------------------------------------------------
st.subheader("Chỉ số phát hiện (Precision/Recall/F1/TPR/FPR/MTTD/MTTR)")
if eval_report_path.exists():
    with open(eval_report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    metrics = report.get("metrics", {})
    counts = report.get("counts", {})
    mcols = st.columns(5)
    mcols[0].metric("Precision", f"{metrics.get('Precision', 0):.3f}")
    mcols[1].metric("Recall/TPR", f"{metrics.get('Recall', 0):.3f}")
    mcols[2].metric("F1", f"{metrics.get('F1', 0):.3f}")
    mcols[3].metric("FPR", f"{metrics.get('FPR', 0):.3f}")
    mcols[4].metric("TPR", f"{metrics.get('TPR', 0):.3f}")
    st.caption(f"Dataset: total={counts.get('total', 0)}, positive={counts.get('positive', 0)}, negative={counts.get('negative', 0)}")
else:
    st.info("Chưa có evaluate_report.json (chưa đánh giá bằng nhãn).")

# ---------------------------------------------------------
# 4) Phân phối rủi ro & anom.score
# ---------------------------------------------------------
st.subheader("Phân phối rủi ro")
risk_counts = alerts["risk_level"].value_counts(dropna=False)
st.bar_chart(risk_counts)

st.subheader("Phân phối anom.score (histogram)")
fig_hist, ax_hist = plt.subplots(figsize=(6, 3))
ax_hist.hist(df["anom.score"], bins=30, color="#3b82f6", alpha=0.8)
ax_hist.set_xlabel("anom.score")
ax_hist.set_ylabel("Count")
st.pyplot(fig_hist)

# ---------------------------------------------------------
# 4) Ánh xạ MITRE ATT&CK
# ---------------------------------------------------------
st.subheader("Ánh xạ MITRE ATT&CK")
tech_counts = alerts["mitre.techniques"].fillna("").str.split(",").explode().str.strip()
tech_counts = tech_counts[tech_counts != ""].value_counts()
if tech_counts.empty:
    st.caption("Chưa có kỹ thuật MITRE nào được gán.")
else:
    st.bar_chart(tech_counts)
    # Với pandas cũ, Series.reset_index không hỗ trợ tham số names
    tech_df = tech_counts.reset_index()
    # Chuẩn hóa tên cột: [Technique, Count]
    if len(tech_df.columns) >= 2:
        tech_df.columns = ["Technique", "Count"]
    st.dataframe(
        tech_df,
        use_container_width=True,
        hide_index=True,
    )

# MITRE technique links + Gemini explanation (tự động)
mitre_list = _collect_mitre_techniques(alerts)
st.subheader("MITRE ATT&CK – giải thích kỹ thuật")
if mitre_list:
    options = [f"{x['id']} – {x['name']}" if x["name"] else x["id"] for x in mitre_list]
    sel = st.selectbox("Chọn kỹ thuật", options)
    current = mitre_list[options.index(sel)]
    url = _technique_url(current["id"])
    st.markdown(f"[{sel}]({url})")

    # Cache trong session để tránh gọi Gemini lặp lại
    if "mitre_exp" not in st.session_state:
        st.session_state["mitre_exp"] = {}

    cached = st.session_state["mitre_exp"].get(current["id"])
    if cached:
        explanation = cached
    else:
        with st.spinner("Đang tạo giải thích MITRE (Gemini hoặc offline)..."):
            explanation = explain_mitre_with_gemini(current["id"], current["name"])
        st.session_state["mitre_exp"][current["id"]] = explanation

    st.markdown("**Giải thích kỹ thuật:**")
    st.markdown(explanation)
else:
    st.caption("Chưa có kỹ thuật MITRE trong dữ liệu alerts.")

# ---------------------------------------------------------
# 5) NIST CSF 2.0
# ---------------------------------------------------------
st.subheader("NIST CSF 2.0")
nist_counts = alerts["nist.functions"].fillna("").str.split(",").explode().str.strip()
nist_counts = nist_counts[nist_counts != ""].value_counts()
if nist_counts.empty:
    st.caption("Chưa có mapping NIST CSF nào được gán.")
else:
    st.bar_chart(nist_counts)
    # Series.reset_index() trong pandas cũ không nhận tham số names
    nist_df = nist_counts.reset_index()
    # Đặt lại tên cột rõ ràng: [Function, Count]
    if len(nist_df.columns) >= 2:
        nist_df.columns = ["Function", "Count"]
    st.dataframe(
        nist_df,
        use_container_width=True,
        hide_index=True,
    )

# ---------------------------------------------------------
# 6) Timeline alert
# ---------------------------------------------------------
st.subheader("Timeline alert")
if not alerts.empty:
    alerts_ts = alerts.set_index("@timestamp").sort_index()
    line = alerts_ts["anom.score"].resample("1min").count()
    fig_tl, ax_tl = plt.subplots(figsize=(10, 3))
    ax_tl.plot(line.index, line.values, linewidth=1)
    ax_tl.set_ylabel("Alerts per minute")
    ax_tl.set_xlabel("Time")
    st.pyplot(fig_tl)
else:
    st.caption("Chưa có alert.")

# ---------------------------------------------------------
# 6) Bảng chi tiết alert + lọc
# ---------------------------------------------------------
st.subheader("Bảng chi tiết alert")
flt_col1, flt_col2, flt_col3 = st.columns(3)
with flt_col1:
    risk_opts = sorted(alerts["risk_level"].dropna().unique())
    sel_risk = st.multiselect("Lọc risk_level", risk_opts, default=[])
with flt_col2:
    tech_opts = sorted({t.strip() for v in alerts.get("mitre.techniques", pd.Series([])).dropna() for t in str(v).split(",") if t.strip()})
    sel_tech = st.multiselect("Lọc MITRE technique", tech_opts, default=[])
with flt_col3:
    nist_opts = sorted({t.strip() for v in alerts.get("nist.functions", pd.Series([])).dropna() for t in str(v).split(",") if t.strip()})
    sel_nist = st.multiselect("Lọc NIST function", nist_opts, default=[])

df_view = alerts.copy()
if sel_risk:
    df_view = df_view[df_view["risk_level"].isin(sel_risk)]
if sel_tech and "mitre.techniques" in df_view.columns:
    df_view = df_view[df_view["mitre.techniques"].apply(lambda x: any(t in str(x) for t in sel_tech))]
if sel_nist and "nist.functions" in df_view.columns:
    df_view = df_view[df_view["nist.functions"].apply(lambda x: any(t in str(x) for t in sel_nist))]

cols_show = [
    c
    for c in [
        "@timestamp",
        "host.name",
        "user.name",
        "source.ip",
        "destination.ip",
        "destination.port",
        "anom.score",
        "risk_level",
        "mitre.techniques",
        "nist.functions",
    ]
    if c in df_view.columns
]
st.dataframe(df_view[cols_show].sort_values("@timestamp"), use_container_width=True, hide_index=True)

st.caption("Chạy pipeline ingest → featurize → train → score để cập nhật báo cáo.")