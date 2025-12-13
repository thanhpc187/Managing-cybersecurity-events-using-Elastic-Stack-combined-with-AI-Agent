from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from explain.thresholding import compute_threshold
from models.utils import get_paths, write_json


@dataclass
class AgentRunResult:
    processed: int
    skipped: int
    bundles: List[str]
    threshold: Optional[float]


def _alert_fingerprint(row: Dict[str, Any]) -> str:
    """Create a stable-ish fingerprint for de-dup across runs."""
    parts = [
        str(row.get("@timestamp", "")),
        str(row.get("source.ip", "")),
        str(row.get("destination.ip", "")),
        str(row.get("user.name", "")),
        str(row.get("host.name", "")),
        f"{row.get('anom.score', '')}",
    ]
    raw = "|".join(parts).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:24]


def _load_state(state_path: Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {"processed": []}
    try:
        import json

        with open(state_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, dict) and "processed" in obj and isinstance(obj["processed"], list):
            return obj
    except Exception:
        pass
    return {"processed": []}


def _save_state(state_path: Path, state: Dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(state_path, state)


def _load_scores(scores_path: Path) -> pd.DataFrame:
    df = pd.read_parquet(scores_path)
    if "@timestamp" in df.columns:
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["@timestamp"]).sort_values("@timestamp")
    return df


def _select_alerts(df: pd.DataFrame, top_n: int = 10) -> Tuple[pd.DataFrame, Optional[float]]:
    if df is None or df.empty or "anom.score" not in df.columns:
        return df.head(0), None
    thr, _ = compute_threshold(df["anom.score"])
    alerts = df[df["anom.score"] >= thr].copy()
    alerts = alerts.sort_values("anom.score", ascending=False).head(int(top_n))
    return alerts, float(thr) if thr is not None else None


def _gather_context_parquet(
    alert_row: pd.Series,
    window_minutes: int = 5,
    max_rows: int = 500,
) -> pd.DataFrame:
    """
    Gather context events around alert time from local ECS parquet (union).
    Expands window if needed in runner loop.
    """
    paths = get_paths()
    ecs_dir = Path(paths["ecs_parquet_dir"])
    ecs_parts = list(ecs_dir.rglob("*.parquet"))
    if not ecs_parts:
        return pd.DataFrame()
    ecs_df = pd.concat([pd.read_parquet(p) for p in ecs_parts], ignore_index=True)
    if "@timestamp" not in ecs_df.columns:
        return pd.DataFrame()
    ecs_df["@timestamp"] = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")
    ecs_df = ecs_df.dropna(subset=["@timestamp"])

    t0 = pd.to_datetime(alert_row.get("@timestamp"), utc=True, errors="coerce")
    if pd.isna(t0):
        return ecs_df.tail(min(max_rows, len(ecs_df))).copy()
    mask = (ecs_df["@timestamp"] >= t0 - timedelta(minutes=window_minutes)) & (
        ecs_df["@timestamp"] <= t0 + timedelta(minutes=window_minutes)
    )
    out = ecs_df.loc[mask].copy()
    if len(out) > max_rows:
        out = out.tail(max_rows)
    return out


def run_agent_once(
    *,
    top_n: int = 10,
    build_bundles: bool = True,
    state_path: Optional[Path] = None,
    context_source: str = "parquet",  # parquet | elasticsearch
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    context_window_minutes: int = 5,
    context_max_rows: int = 300,
) -> AgentRunResult:
    """
    Process newest alerts (>= threshold) and generate bundles/AI analysis.
    Trigger: this function is called by CLI or watch loop.
    """
    from pipeline.bundle import build_bundle_for_alert

    paths = get_paths()
    scores_path = Path(paths["scores_dir"]) / "scores.parquet"
    if not scores_path.exists():
        raise FileNotFoundError(f"scores not found: {scores_path}. Run score first.")

    # state
    if state_path is None:
        state_path = Path(paths["scores_dir"]) / "agent_state.json"
    state = _load_state(state_path)
    processed_ids = set(state.get("processed") or [])

    df = _load_scores(scores_path)
    alerts, thr = _select_alerts(df, top_n=top_n)

    processed = 0
    skipped = 0
    bundles: List[str] = []

    # Optional ES context tool
    es_tool = None
    if context_source.lower() in ("elasticsearch", "elastic", "es"):
        try:
            from ai.tools.elasticsearch_tool import ElasticsearchTool

            es_tool = ElasticsearchTool(
                host=elastic_host,
                index_patterns=elastic_index_patterns or [],
                user=elastic_user,
                password=elastic_password,
            )
        except Exception:
            es_tool = None

    for i, (_, row) in enumerate(alerts.iterrows(), start=1):
        rec = row.to_dict()
        fid = _alert_fingerprint(rec)
        if fid in processed_ids:
            skipped += 1
            continue

        # Decision loop: gather more context if current window is too small
        ctx_rows: List[Dict[str, Any]] = []
        if es_tool is not None:
            # try 5m, then 15m if too few
            for w in (context_window_minutes, max(15, context_window_minutes * 3)):
                ctx_rows = es_tool.context_for_alert(rec, window_minutes=w, size=context_max_rows)
                if len(ctx_rows) >= 10:
                    break
            # attach minimal context into row for analysis/bundle (bundle still uses parquet slice)
            rec["_agent_context_es"] = ctx_rows[:50]

        # Bundle creation uses local parquet; still valuable for forensic + offline.
        if build_bundles:
            bundle_path = build_bundle_for_alert(row, i, float(thr or 0.0))
            bundles.append(str(bundle_path))

        processed += 1
        processed_ids.add(fid)

    # Save updated state (cap list to avoid unbounded growth)
    state["processed"] = list(processed_ids)[-5000:]
    _save_state(state_path, state)

    return AgentRunResult(processed=processed, skipped=skipped, bundles=bundles, threshold=thr)


def watch_agent(
    *,
    interval_sec: int = 15,
    top_n: int = 10,
    build_bundles: bool = True,
    context_source: str = "parquet",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
) -> None:
    """
    Auto-trigger loop:
    - Watches scores.parquet mtime, runs agent when file changes
    - Also safe to run periodically (idempotent via agent_state.json)
    """
    paths = get_paths()
    scores_path = Path(paths["scores_dir"]) / "scores.parquet"
    last_mtime = None
    while True:
        try:
            if scores_path.exists():
                mtime = scores_path.stat().st_mtime
                if last_mtime is None or mtime != last_mtime:
                    last_mtime = mtime
                    run_agent_once(
                        top_n=top_n,
                        build_bundles=build_bundles,
                        context_source=context_source,
                        elastic_host=elastic_host,
                        elastic_index_patterns=elastic_index_patterns,
                        elastic_user=elastic_user,
                        elastic_password=elastic_password,
                    )
        except KeyboardInterrupt:
            raise
        except Exception:
            # Keep watcher resilient; errors are handled by CLI logs
            pass
        time.sleep(max(5, int(interval_sec)))


