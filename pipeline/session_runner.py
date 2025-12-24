from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from ai.mitre_mapper import load_mitre_mapping, map_to_mitre
from ai.nist_mapper import load_nist_mapping, map_to_nist
from ai.tools.elasticsearch_tool import ElasticsearchTool
from explain.thresholding import compute_threshold
from features.build_features import build_features_from_ecs_df
from models.infer import score_feature_df
from models.train_if import train_model
from models.utils import ensure_dir, get_paths, write_json


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(s: str) -> datetime:
    # Accept ISO with Z
    ss = s.replace("Z", "+00:00")
    return datetime.fromisoformat(ss).astimezone(timezone.utc)


def _floor_to_window_end(ts: datetime, window_minutes: int) -> datetime:
    """
    Return the end boundary of the current window, aligned to window_minutes.
    Example: window=10, 10:07 -> 10:10 end.
    """
    ts = ts.astimezone(timezone.utc)
    minute = (ts.minute // window_minutes) * window_minutes
    floored = ts.replace(minute=minute, second=0, microsecond=0)
    if floored == ts.replace(second=0, microsecond=0) and ts.minute % window_minutes == 0:
        return floored
    return floored + timedelta(minutes=window_minutes)


def _load_state(state_path: Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(state_path: Path, state: Dict[str, Any]) -> None:
    ensure_dir(state_path.parent)
    write_json(state_path, state)


def _window_dir(windows_root: Path, day: str, classification: str, window_id: str) -> Path:
    return windows_root / day / classification.upper() / window_id


def _scan_normal_feature_files(windows_root: Path) -> List[Path]:
    return sorted(windows_root.glob("**/NORMAL/**/features_window.parquet"))


def _train_threshold_from_features(features_path: Path) -> float:
    """
    Train model (writes joblib) and compute a fixed baseline threshold from training scores.
    """
    train_model()
    # Compute baseline threshold from training feature scores.
    df = pd.read_parquet(features_path)
    scored = score_feature_df(df)
    thr, _ = compute_threshold(scored["anom.score"])
    return float(thr)


def _write_baseline_threshold(out_path: Path, thr: float, meta: Dict[str, Any]) -> None:
    payload = {"baseline_threshold": float(thr), "meta": meta}
    ensure_dir(out_path.parent)
    write_json(out_path, payload)


def _load_baseline_threshold(thr_path: Path) -> Optional[float]:
    if not thr_path.exists():
        return None
    try:
        data = json.loads(thr_path.read_text(encoding="utf-8"))
        v = data.get("baseline_threshold")
        return float(v) if v is not None else None
    except Exception:
        return None


def _classify_window(scored_window: pd.DataFrame, threshold: float) -> str:
    if scored_window is None or scored_window.empty:
        return "NORMAL"
    if "anom.score" not in scored_window.columns:
        return "NORMAL"
    return "ANOMALY" if bool((pd.to_numeric(scored_window["anom.score"], errors="coerce") >= float(threshold)).any()) else "NORMAL"


def _compute_mitre_nist_for_alerts(alerts: pd.DataFrame) -> Tuple[Dict[str, int], Dict[str, int]]:
    if alerts is None or alerts.empty:
        return {}, {}
    mcfg = load_mitre_mapping()
    ncfg = load_nist_mapping()
    mitre_counts: Dict[str, int] = {}
    nist_counts: Dict[str, int] = {}
    for _, r in alerts.iterrows():
        rec = r.to_dict()
        hits = map_to_mitre(rec, rec, mcfg)
        techs = {((h.get("technique") or "").strip().upper()) for h in hits if (h.get("technique") or "").strip()}
        for t in techs:
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
        n_hits = map_to_nist(rec, hits, ncfg)
        funcs = {((h.get("function") or "").strip().upper()) for h in n_hits if (h.get("function") or "").strip()}
        for fn in funcs:
            nist_counts[fn] = nist_counts.get(fn, 0) + 1
    return mitre_counts, nist_counts


def run_session(
    *,
    elastic_host: str,
    elastic_index_patterns: List[str],
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    verify_tls: bool = False,
    baseline_start: Optional[str] = None,
    baseline_end: Optional[str] = None,
    baseline_lookback_hours: int = 72,
    window_minutes: int = 10,
    warmup_minutes: int = 20,
    work_hours: int = 8,
    page_size: int = 2000,
    max_docs_per_window: int = 200000,
    sleep_align: bool = True,
    use_gemini_summary: bool = False,
) -> Path:
    """
    One-command session runner:
    - On each program run (a "day"): retrain once at start (baseline + accumulated NORMAL windows).
    - Then process windows every N minutes for work_hours (default 8h) and store NORMAL/ANOMALY artifacts.
    - Classification rule: ANOMALY if >= 1 event exceeds baseline_threshold.
    - Stores enough for next day's retrain by keeping NORMAL window features (and ECS per-window).
    """
    paths = get_paths()
    windows_root = Path(paths["scores_dir"]).resolve().parents[0] / "windows"
    training_root = Path(paths["scores_dir"]).resolve().parents[0] / "training"
    models_root = Path(paths["models_dir"]).resolve()
    state_path = Path(paths["scores_dir"]).resolve().parents[0] / "state" / "session_state.json"
    thr_path = models_root / "baseline_threshold.json"

    ensure_dir(windows_root)
    ensure_dir(training_root)
    ensure_dir(models_root)
    ensure_dir(state_path.parent)

    # Determine today's "day key"
    now = _utcnow()
    day_key = now.strftime("%Y-%m-%d")

    # Load state
    state = _load_state(state_path)
    state_day = str(state.get("day") or "")

    # Build ES tool
    es = ElasticsearchTool(
        host=elastic_host,
        index_patterns=elastic_index_patterns,
        user=elastic_user,
        password=elastic_password,
        verify_tls=verify_tls,
    )

    # If first run or new day -> daily retrain once
    if state_day != day_key or not (models_root / "isolation_forest.joblib").exists():
        # 1) Baseline: if already saved, reuse; else fetch baseline from ES
        baseline_ecs_path = training_root / "baseline_ecs.parquet"
        baseline_feat_path = training_root / "baseline_features.parquet"

        if not baseline_feat_path.exists():
            if baseline_start and baseline_end:
                b_start = _parse_dt(baseline_start)
                b_end = _parse_dt(baseline_end)
            else:
                b_end = now
                b_start = now - timedelta(hours=int(baseline_lookback_hours))

            b_docs = es.fetch_time_range_paged(
                start_ts=_iso(b_start),
                end_ts=_iso(b_end),
                page_size=page_size,
                max_docs=max_docs_per_window,
            )
            b_ecs = pd.DataFrame(b_docs)
            if not b_ecs.empty:
                b_ecs.to_parquet(baseline_ecs_path, index=False)
            b_feat = build_features_from_ecs_df(b_ecs)
            b_feat.to_parquet(baseline_feat_path, index=False)

        # 2) Accumulated NORMAL window features
        normal_files = _scan_normal_feature_files(windows_root)
        normal_feat_path = training_root / "normal_features_accum.parquet"
        if normal_files:
            frames = []
            max_parts = int(os.getenv("NORMAL_FEATURES_MAX_PARTS", "500"))
            for p in normal_files[-max_parts:]:
                try:
                    frames.append(pd.read_parquet(p))
                except Exception:
                    continue
            if frames:
                pd.concat(frames, ignore_index=True).to_parquet(normal_feat_path, index=False)
        else:
            pd.DataFrame(columns=["@timestamp"]).to_parquet(normal_feat_path, index=False)

        # 3) Training dataset = baseline + accumulated normal
        base_df = pd.read_parquet(baseline_feat_path) if baseline_feat_path.exists() else pd.DataFrame()
        norm_df = pd.read_parquet(normal_feat_path) if normal_feat_path.exists() else pd.DataFrame()
        train_df = pd.concat([base_df, norm_df], ignore_index=True) if (not base_df.empty or not norm_df.empty) else base_df

        # Persist to canonical location expected by train_model()
        features_dir = Path(paths["features_dir"]).resolve()
        ensure_dir(features_dir)
        train_features_path = features_dir / "features.parquet"
        train_df.to_parquet(train_features_path, index=False)

        thr = _train_threshold_from_features(train_features_path)
        _write_baseline_threshold(
            thr_path,
            thr,
            meta={
                "trained_at": _iso(now),
                "day": day_key,
                "baseline_features": str(baseline_feat_path),
                "normal_features_parts": int(len(normal_files)),
                "baseline_start": baseline_start,
                "baseline_end": baseline_end,
                "baseline_lookback_hours": int(baseline_lookback_hours),
                "window_minutes": int(window_minutes),
                "warmup_minutes": int(warmup_minutes),
            },
        )
        state["day"] = day_key
        state["trained_at"] = _iso(now)
        state["baseline_threshold_path"] = str(thr_path)
        state["baseline_threshold"] = float(thr)
        state["last_window_end"] = None
        _save_state(state_path, state)

    threshold = _load_baseline_threshold(thr_path)
    if threshold is None:
        raise RuntimeError(f"Missing baseline threshold at {thr_path}. Training step likely failed.")

    # Window loop for this run (one workday)
    iterations = int((int(work_hours) * 60) / int(window_minutes))
    last_end_s = state.get("last_window_end")
    last_end = _parse_dt(last_end_s) if isinstance(last_end_s, str) and last_end_s else None

    for i in range(iterations):
        now_i = _utcnow()
        window_end = _floor_to_window_end(now_i, int(window_minutes))
        window_start = window_end - timedelta(minutes=int(window_minutes))
        if last_end is not None and window_end <= last_end:
            # If we restarted quickly, skip until we move forward.
            window_end = last_end + timedelta(minutes=int(window_minutes))
            window_start = window_end - timedelta(minutes=int(window_minutes))

        # Align sleep to boundary if requested
        if sleep_align:
            # Sleep until we reach the end boundary (so window is complete).
            sleep_for = (window_end - now_i).total_seconds()
            if sleep_for > 0:
                time.sleep(min(sleep_for, 60.0))
                # Recompute boundary after sleeping a bit
                now_i = _utcnow()
                if now_i < window_end:
                    time.sleep(max(0.0, (window_end - now_i).total_seconds()))

        # Fetch warmup + window
        fetch_start = window_start - timedelta(minutes=int(warmup_minutes))
        docs = es.fetch_time_range_paged(
            start_ts=_iso(fetch_start),
            end_ts=_iso(window_end),
            page_size=page_size,
            max_docs=max_docs_per_window,
        )
        ecs_df = pd.DataFrame(docs)

        # Build features with warmup included, then slice to exact 10-minute window
        feat_df = build_features_from_ecs_df(ecs_df, window_start=_iso(window_start), window_end=_iso(window_end))
        scored_df = score_feature_df(feat_df)
        classification = _classify_window(scored_df, threshold)

        # Alerts within the window: rows >= threshold
        alerts = scored_df[pd.to_numeric(scored_df.get("anom.score"), errors="coerce") >= float(threshold)].copy() if not scored_df.empty else scored_df
        mitre_counts, nist_counts = _compute_mitre_nist_for_alerts(alerts)

        # Persist artifacts (enough to retrain tomorrow)
        win_day = window_end.strftime("%Y-%m-%d")
        window_id = f"{window_start.strftime('%Y%m%dT%H%M%SZ')}_{window_end.strftime('%Y%m%dT%H%M%SZ')}"
        out_dir = _window_dir(windows_root, win_day, classification, window_id)
        ensure_dir(out_dir)

        # Save ECS only for the actual window (not warmup) for forensic + retrain if needed
        if not ecs_df.empty and "@timestamp" in ecs_df.columns:
            ecs_df["@timestamp"] = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")
            ecs_window = ecs_df[(ecs_df["@timestamp"] >= window_start) & (ecs_df["@timestamp"] <= window_end)].copy()
        else:
            ecs_window = ecs_df

        ecs_path = out_dir / "ecs_window.parquet"
        feat_path = out_dir / "features_window.parquet"
        scores_path = out_dir / "scores_window.parquet"
        alerts_path = out_dir / "alerts.parquet"

        ecs_window.to_parquet(ecs_path, index=False)
        feat_df.to_parquet(feat_path, index=False)
        scored_df.to_parquet(scores_path, index=False)
        alerts.to_parquet(alerts_path, index=False)

        meta = {
            "day": win_day,
            "window_start": _iso(window_start),
            "window_end": _iso(window_end),
            "warmup_minutes": int(warmup_minutes),
            "baseline_threshold": float(threshold),
            "classification": classification,
            "events_fetched_with_warmup": int(len(ecs_df)),
            "events_in_window": int(len(ecs_window)),
            "rows_scored": int(len(scored_df)),
            "alerts_ge_threshold": int(len(alerts)),
            "mitre_counts": dict(sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)),
            "nist_counts": dict(sorted(nist_counts.items(), key=lambda x: x[1], reverse=True)),
        }
        write_json(out_dir / "window_meta.json", meta)

        # Update state
        last_end = window_end
        state["day"] = day_key
        state["baseline_threshold"] = float(threshold)
        state["last_window_end"] = _iso(window_end)
        state["windows_processed"] = int(state.get("windows_processed") or 0) + 1
        _save_state(state_path, state)

    return windows_root


