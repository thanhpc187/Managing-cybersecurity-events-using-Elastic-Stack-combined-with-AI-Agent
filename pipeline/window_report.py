from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from ai.mitre_mapper import load_mitre_mapping, map_to_mitre
from ai.nist_mapper import load_nist_mapping, map_to_nist
from features.build_features import build_features_from_ecs_df
from models.baseline_threshold import load_baseline_threshold, load_baseline_threshold_from_model_meta
from models.infer import score_feature_df
from models.utils import get_paths, write_json
import logging

logger = logging.getLogger(__name__)

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


@dataclass
class WindowReportResult:
    report_dir: Path
    classification: str
    window_start: datetime
    window_end: datetime
    alert_count: int
    validation_failed: bool = False
    validation_reasons: List[str] = None  # type: ignore


REQUIRED_REPORT_KEYS = [
    "window_start",
    "window_end",
    "classification",
    "total_events_ingested",
    "total_rows_scored",
    "baseline_threshold",
    "alert_count",
    "risk_distribution",
    "mitre_counts",
    "nist_counts",
    "top_alerts",
    "notes",
    "warnings",
]


def assert_report_schema(report_obj: Dict[str, Any]) -> None:
    missing = [k for k in REQUIRED_REPORT_KEYS if k not in report_obj]
    if missing:
        raise ValueError(f"report.json missing keys: {', '.join(missing)}")


def _tzinfo(tz_name: str):
    if not tz_name:
        return timezone.utc
    if tz_name.upper() in ("UTC", "Z"):
        return timezone.utc
    if ZoneInfo is None:
        return timezone.utc
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def _parse_dt(s: str, tz_name: str = "UTC") -> datetime:
    """
    Parse datetime string.
    - If string has timezone (Z or offset), respect it.
    - If naive, assume timezone=tz_name, then convert to UTC for ES queries and internal processing.
    """
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tzinfo(tz_name))
    return dt.astimezone(timezone.utc)


def floor_to_window_end(dt: datetime, window_min: int, tz_name: str = "UTC") -> datetime:
    tz = _tzinfo(tz_name)
    dt = dt.astimezone(tz)
    minute = (dt.minute // window_min) * window_min
    floored = dt.replace(minute=minute, second=0, microsecond=0)
    # window boundaries stored in UTC for consistent ES queries and report naming
    return floored.astimezone(timezone.utc)


def slice_time_range(df: pd.DataFrame, start: datetime, end: datetime, ts_col: str = "@timestamp") -> pd.DataFrame:
    if df is None or df.empty or ts_col not in df.columns:
        return pd.DataFrame(columns=df.columns if isinstance(df, pd.DataFrame) else None)
    out = df.copy()
    out[ts_col] = pd.to_datetime(out[ts_col], utc=True, errors="coerce")
    out = out.dropna(subset=[ts_col])
    start_ts = pd.Timestamp(start, tz="UTC")
    end_ts = pd.Timestamp(end, tz="UTC")
    return out[(out[ts_col] >= start_ts) & (out[ts_col] <= end_ts)].copy()


def classify_scores(scores_window: pd.DataFrame, baseline_threshold: float) -> Tuple[str, pd.DataFrame]:
    if scores_window is None or scores_window.empty or "anom.score" not in scores_window.columns:
        return "NORMAL", pd.DataFrame(columns=scores_window.columns if isinstance(scores_window, pd.DataFrame) else None)
    alerts = scores_window[scores_window["anom.score"] >= float(baseline_threshold)].copy()
    return ("ANOMALY" if len(alerts) > 0 else "NORMAL"), alerts


def _load_report_state(state_path: Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {"last_window_end": None}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f) or {"last_window_end": None}
    except Exception:
        return {"last_window_end": None}


def _save_report_state(state_path: Path, state: Dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(state_path, state)


def _list_report_folders(root: Path) -> List[Path]:
    if not root.exists():
        return []
    return sorted([p for p in root.glob("report_*") if p.is_dir()])


def _validate_window(ecs_df: pd.DataFrame, feat_df: pd.DataFrame, scores_df: pd.DataFrame, alerts_df: pd.DataFrame) -> Dict[str, Any]:
    important_ecs = [
        "@timestamp",
        "message",
        "host.name",
        "user.name",
        "source.ip",
        "destination.ip",
        "destination.port",
        "event.action",
        "event.module",
        "event.dataset",
    ]
    ecs_present = [c for c in important_ecs if c in ecs_df.columns]
    ecs_missing = [c for c in important_ecs if c not in ecs_df.columns]
    ecs_non_null = {c: float(ecs_df[c].notna().mean()) for c in ecs_present} if not ecs_df.empty else {}

    required_features = [
        "login_failed",
        "conn_suspicious",
        "action_allow",
        "action_deny",
        "ips_alert",
        "login_failed_count_5m",
        "uniq_dport_per_src_1m",
        "deny_ratio_5m",
        "text_entropy",
        "session.id",
    ]
    feat_present = [c for c in required_features if c in feat_df.columns]
    feat_missing = [c for c in required_features if c not in feat_df.columns]
    feat_nonzero = {}
    for c in feat_present:
        try:
            if pd.api.types.is_numeric_dtype(feat_df[c]):
                feat_nonzero[c] = float((pd.to_numeric(feat_df[c], errors="coerce").fillna(0.0) > 0).mean())
            else:
                feat_nonzero[c] = float(feat_df[c].notna().mean())
        except Exception:
            feat_nonzero[c] = 0.0

    return {
        "ecs": {"rows": int(len(ecs_df)), "important_present": ecs_present, "important_missing": ecs_missing, "non_null": ecs_non_null},
        "features": {"rows": int(len(feat_df)), "required_present": feat_present, "required_missing": feat_missing, "nonzero_rate": feat_nonzero},
        "scores": {"rows": int(len(scores_df)), "alerts": int(len(alerts_df)), "has_anom_score": bool("anom.score" in scores_df.columns)},
    }


def _is_critical_validation_fail(validate_obj: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Define "critical" issues that should return exit code 2 in CLI:
    - Have ECS rows but feature rows are 0
    - Have scored rows but missing anom.score
    - Missing core ECS columns too many
    """
    reasons: List[str] = []
    try:
        ecs_rows = int(validate_obj.get("ecs", {}).get("rows", 0))
        feat_rows = int(validate_obj.get("features", {}).get("rows", 0))
        score_rows = int(validate_obj.get("scores", {}).get("rows", 0))
        has_score = bool(validate_obj.get("scores", {}).get("has_anom_score", False))
        ecs_missing = validate_obj.get("ecs", {}).get("important_missing", []) or []
        if ecs_rows > 0 and feat_rows == 0:
            reasons.append("features_window empty while ecs_window has rows")
        if score_rows > 0 and not has_score:
            reasons.append("scores_window missing anom.score")
        # If missing more than half of important ECS fields, treat as critical
        if isinstance(ecs_missing, list) and len(ecs_missing) >= 6:
            reasons.append(f"missing many important ECS fields: {', '.join(ecs_missing[:10])}")
    except Exception:
        reasons.append("validation check failed unexpectedly")
    return (len(reasons) > 0, reasons)


def _to_report_dir_name(window_end: datetime) -> str:
    return "report_" + window_end.astimezone(timezone.utc).strftime("%Y%m%d_%H%M")


def _load_baseline_threshold_or_fail() -> float:
    try:
        thr, _meta = load_baseline_threshold()
        return float(thr)
    except FileNotFoundError:
        # Fallback: read from model meta if present (still fixed baseline)
        thr2 = load_baseline_threshold_from_model_meta()
        if thr2 is not None:
            logger.warning("baseline_threshold.json missing; using baseline_threshold from model meta.")
            return float(thr2)
        raise FileNotFoundError(
            "Thiếu baseline_threshold.json và model meta không có baseline_threshold. "
            "Hãy copy file data/models/baseline_threshold.json từ máy train baseline, "
            "hoặc chạy lại bước train baseline để tạo threshold cố định."
        )


def _fetch_ecs_source(
    *,
    source: str,
    gte: datetime,
    lte: datetime,
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    es_page_size: int = 1000,
    es_max_docs: int = 20000,
) -> pd.DataFrame:
    if source.lower() in ("elasticsearch", "elastic", "es"):
        from ai.tools.elasticsearch_tool import ElasticsearchTool

        tool = ElasticsearchTool(
            host=elastic_host,
            index_patterns=elastic_index_patterns or [],
            user=elastic_user,
            password=elastic_password,
        )
        records, meta = tool.fetch_time_range_paged(
            gte=gte.astimezone(timezone.utc).isoformat(),
            lte=lte.astimezone(timezone.utc).isoformat(),
            page_size=int(es_page_size),
            max_docs=int(es_max_docs),
            order="asc",
        )
        if meta.get("truncated"):
            logger.warning(f"Elasticsearch results truncated at max_docs={meta.get('fetched')}. Increase max_docs if needed.")
        logger.info(f"Elasticsearch fetched={meta.get('fetched')} pages={meta.get('pages')} range=[{gte},{lte}]")
        return pd.DataFrame(records)

    # parquet source: union ecs_parquet files then slice
    paths = get_paths()
    ecs_dir = Path(paths["ecs_parquet_dir"])
    parts = list(ecs_dir.rglob("*.parquet"))
    if not parts:
        return pd.DataFrame()
    df = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True)
    return slice_time_range(df, gte, lte, ts_col="@timestamp")


def build_window_report(
    *,
    window_start: datetime,
    window_end: datetime,
    warmup_min: int = 60,
    output_dir: Path,
    source: str = "elasticsearch",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    agent: bool = True,
    context_source: str = "elasticsearch",
    max_alerts_analyze: int = 20,
    timezone_name: str = "UTC",
    es_page_size: int = 1000,
    es_max_docs: int = 20000,
) -> WindowReportResult:
    """
    One independent window run:
    - Fetch ECS in [window_start - warmup, window_end]
    - Build rolling features on full range, then slice outputs to [window_start, window_end]
    - Score using existing model, select alerts using fixed baseline_threshold
    - Write report folder + artifacts and optional AI analysis per alert
    """
    baseline_threshold = _load_baseline_threshold_or_fail()
    logger.info(
        f"Window report tz={timezone_name} start={window_start.isoformat()} end={window_end.isoformat()} warmup={warmup_min}m baseline_thr={baseline_threshold:.6f}"
    )

    warm_start = window_start - timedelta(minutes=int(warmup_min))
    ecs_all = _fetch_ecs_source(
        source=source,
        gte=warm_start,
        lte=window_end,
        elastic_host=elastic_host,
        elastic_index_patterns=elastic_index_patterns,
        elastic_user=elastic_user,
        elastic_password=elastic_password,
        es_page_size=es_page_size,
        es_max_docs=es_max_docs,
    )

    # Build features from warmup+window; then slice outputs to [window_start, window_end]
    feat_all = build_features_from_ecs_df(ecs_all) if not ecs_all.empty else pd.DataFrame(columns=["@timestamp"])
    ecs_window = slice_time_range(ecs_all, window_start, window_end, ts_col="@timestamp")
    feat_window = slice_time_range(feat_all, window_start, window_end, ts_col="@timestamp")

    scores_window = score_feature_df(feat_window) if not feat_window.empty else feat_window.copy()
    classification, alerts = classify_scores(scores_window, baseline_threshold)
    logger.info(f"Scored rows={len(scores_window)} alerts={len(alerts)} classification={classification}")

    # Cap alerts for reporting to avoid heavy writes
    alerts_cap = alerts.sort_values("anom.score", ascending=False).head(200) if not alerts.empty else alerts

    # MITRE/NIST mapping per alert (window-only)
    mapping_cfg = load_mitre_mapping()
    nist_cfg = load_nist_mapping()
    mitre_counts: Dict[str, int] = {}
    nist_counts: Dict[str, int] = {}
    risk_distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    top_alerts: List[Dict[str, Any]] = []

    # Optional: build per-alert AI analysis (limited)
    ai_outputs: List[Tuple[str, Dict[str, Any], str]] = []
    if agent and not alerts_cap.empty:
        from ai.agent import analyze_alert
        from ai.tools.elasticsearch_tool import ElasticsearchTool

        es_tool = None
        if context_source.lower() in ("elasticsearch", "elastic", "es"):
            es_tool = ElasticsearchTool(
                host=elastic_host,
                index_patterns=elastic_index_patterns or [],
                user=elastic_user,
                password=elastic_password,
            )

        # Try SHAP (optional dependency)
        try:
            from explain.shap_explain import top_shap_for_rows
            import joblib

            paths = get_paths()
            payload = joblib.load(Path(paths["models_dir"]) / "isolation_forest.joblib")
            model = payload["model"]
            feature_cols = payload["feature_cols"]
            shap_ok = True
        except Exception:
            shap_ok = False
            model = None
            feature_cols = []
            top_shap_for_rows = None  # type: ignore

        # Build a context dataframe (parquet-style) for offline path
        ecs_all_ts = ecs_all.copy()
        if "@timestamp" in ecs_all_ts.columns:
            ecs_all_ts["@timestamp"] = pd.to_datetime(ecs_all_ts["@timestamp"], utc=True, errors="coerce")

        for i, (_, arow) in enumerate(alerts_cap.head(int(max_alerts_analyze)).iterrows(), start=1):
            alert_rec = arow.to_dict()
            # Context rows
            ctx_rows: List[Dict[str, Any]] = []
            if es_tool is not None:
                ctx_rows = es_tool.context_for_alert(alert_rec, window_minutes=5, size=200)
            else:
                t0 = pd.to_datetime(alert_rec.get("@timestamp"), utc=True, errors="coerce")
                if pd.notna(t0) and "@timestamp" in ecs_all_ts.columns:
                    mask = (ecs_all_ts["@timestamp"] >= t0 - timedelta(minutes=5)) & (ecs_all_ts["@timestamp"] <= t0 + timedelta(minutes=5))
                    ctx_rows = ecs_all_ts.loc[mask].tail(200).dropna(axis=1, how="all").to_dict("records")

            # SHAP top features (optional)
            shap_items: List[Dict[str, Any]] = []
            if shap_ok and model is not None and feature_cols and top_shap_for_rows is not None:
                try:
                    X = arow.reindex(feature_cols).fillna(0.0).to_frame().T
                    shap_items = top_shap_for_rows(model, X.values, feature_cols, top_k=5)[0]
                except Exception:
                    shap_items = []

            analysis = analyze_alert(alert_rec, shap_items, ctx_rows, alert_rec)
            md = analysis.get("markdown", "") or ""
            ai_outputs.append((f"ai_alert_{i}", analysis, md))

    # Compute counts + top_alerts
    if not alerts_cap.empty:
        for _, arow in alerts_cap.iterrows():
            rec = arow.to_dict()
            mitre_hits = map_to_mitre(rec, rec, mapping_cfg) if mapping_cfg is not None else []
            nist_hits = map_to_nist(rec, mitre_hits, nist_cfg) if nist_cfg is not None else []
            techs = sorted({h.get("technique") for h in mitre_hits if h.get("technique")})
            funcs = sorted({h.get("function") for h in nist_hits if h.get("function")})
            for t in techs:
                mitre_counts[t] = mitre_counts.get(t, 0) + 1
            for f in funcs:
                nist_counts[f] = nist_counts.get(f, 0) + 1

        # risk distribution (prefer AI outputs if present, else heuristic)
        if ai_outputs:
            for _, analysis, _md in ai_outputs:
                rl = str(analysis.get("risk_level") or "").upper()
                if rl not in risk_distribution:
                    rl = "LOW"
                risk_distribution[rl] += 1
        else:
            # heuristic: MEDIUM if any MITRE, else LOW
            for _, arow in alerts_cap.iterrows():
                rec = arow.to_dict()
                mitre_hits = map_to_mitre(rec, rec, mapping_cfg) if mapping_cfg is not None else []
                risk_distribution["MEDIUM" if mitre_hits else "LOW"] += 1

        # top alerts list for report.json (top 10)
        for _, arow in alerts_cap.sort_values("anom.score", ascending=False).head(10).iterrows():
            rec = arow.to_dict()
            mitre_hits = map_to_mitre(rec, rec, mapping_cfg) if mapping_cfg is not None else []
            nist_hits = map_to_nist(rec, mitre_hits, nist_cfg) if nist_cfg is not None else []
            top_alerts.append(
                {
                    "@timestamp": str(rec.get("@timestamp")),
                    "host.name": rec.get("host.name"),
                    "user.name": rec.get("user.name"),
                    "source.ip": rec.get("source.ip"),
                    "destination.ip": rec.get("destination.ip"),
                    "destination.port": rec.get("destination.port"),
                    "anom.score": float(rec.get("anom.score", 0.0) or 0.0),
                    "mitre": sorted({h.get("technique") for h in mitre_hits if h.get("technique")}),
                    "nist": sorted({h.get("function") for h in nist_hits if h.get("function")}),
                    "risk_level": ("MEDIUM" if mitre_hits else "LOW"),
                }
            )

    # Prepare report directory
    base = output_dir / classification
    report_dir = base / _to_report_dir_name(window_end)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Write artifacts
    ecs_window_path = report_dir / "ecs_window.parquet"
    feat_window_path = report_dir / "features_window.parquet"
    scores_window_path = report_dir / "scores_window.parquet"
    alerts_path = report_dir / "alerts.parquet"
    validate_path = report_dir / "validate_window.json"
    report_json_path = report_dir / "report.json"
    report_md_path = report_dir / "report.md"

    # Ensure timestamp columns are parquet-friendly
    ecs_window.to_parquet(ecs_window_path, index=False)
    feat_window.to_parquet(feat_window_path, index=False)
    scores_window.to_parquet(scores_window_path, index=False)
    alerts_cap.to_parquet(alerts_path, index=False)

    validate_obj = _validate_window(ecs_window, feat_window, scores_window, alerts_cap)
    write_json(validate_path, validate_obj)
    critical_fail, fail_reasons = _is_critical_validation_fail(validate_obj)

    report_obj: Dict[str, Any] = {
        "window_start": window_start.astimezone(timezone.utc).isoformat(),
        "window_end": window_end.astimezone(timezone.utc).isoformat(),
        "classification": classification,
        "total_events_ingested": int(len(ecs_window)),
        "total_rows_scored": int(len(scores_window)),
        "baseline_threshold": float(baseline_threshold),
        "alert_count": int(len(alerts_cap)),
        "risk_distribution": risk_distribution if classification == "ANOMALY" else {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        "mitre_counts": mitre_counts if classification == "ANOMALY" else {},
        "nist_counts": nist_counts if classification == "ANOMALY" else {},
        "top_alerts": top_alerts if classification == "ANOMALY" else [],
        "notes": [],
        "warnings": validate_obj.get("ecs", {}).get("important_missing", []),
    }
    if critical_fail:
        report_obj["warnings"] = (report_obj.get("warnings") or []) + ["CRITICAL_VALIDATION_FAIL"] + fail_reasons
    assert_report_schema(report_obj)
    write_json(report_json_path, report_obj)

    # Markdown report (simple, deterministic)
    lines = []
    lines.append(f"# Window Report: {classification}")
    lines.append(f"- Window: **{report_obj['window_start']} → {report_obj['window_end']}**")
    lines.append(f"- Total events ingested: **{report_obj['total_events_ingested']}**")
    lines.append(f"- Total rows scored: **{report_obj['total_rows_scored']}**")
    lines.append(f"- Baseline threshold: **{report_obj['baseline_threshold']:.6f}**")
    lines.append(f"- Alert count: **{report_obj['alert_count']}**")
    if classification == "ANOMALY":
        if mitre_counts:
            lines.append("## MITRE counts")
            for k, v in sorted(mitre_counts.items(), key=lambda x: (-x[1], x[0])):
                lines.append(f"- {k}: {v}")
        if nist_counts:
            lines.append("## NIST counts")
            for k, v in sorted(nist_counts.items(), key=lambda x: (-x[1], x[0])):
                lines.append(f"- {k}: {v}")
        if top_alerts:
            lines.append("## Top alerts")
            for t in top_alerts:
                lines.append(f"- {t.get('@timestamp')} score={t.get('anom.score'):.3f} src={t.get('source.ip')} dst={t.get('destination.ip')}:{t.get('destination.port')} mitre={','.join(t.get('mitre') or [])}")
    else:
        lines.append("## Kết luận")
        lines.append("- Không có alert vượt baseline threshold trong window này.")
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # Write AI outputs
    if ai_outputs:
        ai_dir = report_dir / "ai"
        ai_dir.mkdir(parents=True, exist_ok=True)
        for name, analysis, md in ai_outputs:
            write_json(ai_dir / f"{name}.json", analysis)
            with open(ai_dir / f"{name}.md", "w", encoding="utf-8") as f:
                f.write(md or "")

    return WindowReportResult(
        report_dir=report_dir,
        classification=classification,
        window_start=window_start,
        window_end=window_end,
        alert_count=int(len(alerts_cap)),
        validation_failed=bool(critical_fail),
        validation_reasons=fail_reasons,
    )


def run_report_once(
    *,
    window_min: int = 15,
    warmup_min: int = 60,
    start: Optional[str] = None,
    end: Optional[str] = None,
    output_dir: Optional[str] = None,
    source: str = "elasticsearch",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    agent: bool = True,
    context_source: str = "elasticsearch",
    max_alerts_analyze: int = 20,
    timezone_name: str = "UTC",
    es_page_size: int = 1000,
    es_max_docs: int = 20000,
) -> WindowReportResult:
    now = datetime.now(timezone.utc)
    if end:
        window_end = _parse_dt(end, tz_name=timezone_name)
    else:
        window_end = floor_to_window_end(now, int(window_min), tz_name=timezone_name)
    if start:
        window_start = _parse_dt(start, tz_name=timezone_name)
    else:
        window_start = window_end - timedelta(minutes=int(window_min))

    paths = get_paths()
    default_reports = Path(paths.get("reports_dir") or (Path(paths["scores_dir"]).resolve().parents[0] / "reports")).resolve()
    out_root = Path(output_dir).resolve() if output_dir else default_reports

    return build_window_report(
        window_start=window_start,
        window_end=window_end,
        warmup_min=warmup_min,
        output_dir=out_root,
        source=source,
        elastic_host=elastic_host,
        elastic_index_patterns=elastic_index_patterns,
        elastic_user=elastic_user,
        elastic_password=elastic_password,
        agent=agent,
        context_source=context_source,
        max_alerts_analyze=max_alerts_analyze,
        timezone_name=timezone_name,
        es_page_size=es_page_size,
        es_max_docs=es_max_docs,
    )


def watch_reports(
    *,
    window_min: int = 15,
    warmup_min: int = 60,
    interval_sec: int = 900,
    output_dir: Optional[str] = None,
    source: str = "elasticsearch",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    agent: bool = True,
    context_source: str = "elasticsearch",
    max_alerts_analyze: int = 20,
    timezone_name: str = "UTC",
    es_page_size: int = 1000,
    es_max_docs: int = 20000,
) -> None:
    paths = get_paths()
    default_reports = Path(paths.get("reports_dir") or (Path(paths["scores_dir"]).resolve().parents[0] / "reports")).resolve()
    out_root = Path(output_dir).resolve() if output_dir else default_reports
    state_path = out_root / "report_state.json"
    state = _load_report_state(state_path)

    last_end = state.get("last_window_end")
    last_end_dt = _parse_dt(last_end) if isinstance(last_end, str) and last_end else None

    while True:
        try:
            now = datetime.now(timezone.utc)
            current_end = floor_to_window_end(now, int(window_min), tz_name=timezone_name)

            # Determine next window_end to process
            if last_end_dt is None:
                next_end = current_end
            else:
                next_end = last_end_dt + timedelta(minutes=int(window_min))
                if next_end > current_end:
                    next_end = None

            if next_end is not None:
                window_start = next_end - timedelta(minutes=int(window_min))
                res = build_window_report(
                    window_start=window_start,
                    window_end=next_end,
                    warmup_min=warmup_min,
                    output_dir=out_root,
                    source=source,
                    elastic_host=elastic_host,
                    elastic_index_patterns=elastic_index_patterns,
                    elastic_user=elastic_user,
                    elastic_password=elastic_password,
                    agent=agent,
                    context_source=context_source,
                    max_alerts_analyze=max_alerts_analyze,
                    timezone_name=timezone_name,
                    es_page_size=es_page_size,
                    es_max_docs=es_max_docs,
                )
                last_end_dt = next_end
                state["last_window_end"] = next_end.astimezone(timezone.utc).isoformat()
                state["window_min"] = int(window_min)
                _save_report_state(state_path, state)
            time.sleep(max(60, int(interval_sec)))
        except KeyboardInterrupt:
            raise
        except Exception:
            time.sleep(max(60, int(interval_sec)))


