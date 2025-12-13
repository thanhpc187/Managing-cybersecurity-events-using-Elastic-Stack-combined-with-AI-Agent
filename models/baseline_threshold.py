from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from models.utils import get_paths, write_json, load_models_config


BASELINE_FILENAME = "baseline_threshold.json"


def _load_model_payload() -> Dict[str, Any]:
    paths = get_paths()
    mp = Path(paths["models_dir"]) / "isolation_forest.joblib"
    if not mp.exists():
        raise FileNotFoundError(f"Model not found: {mp}. Train baseline first.")
    return joblib.load(mp)


def _score_df_with_payload(df: pd.DataFrame, payload: Dict[str, Any]) -> np.ndarray:
    model = payload["model"]
    scaler = payload.get("scaler")
    feature_cols = payload["feature_cols"]
    X = df.copy()
    for c in feature_cols:
        if c not in X.columns:
            X[c] = 0.0
    Xn = X[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
    if scaler is not None:
        Xn = scaler.transform(Xn)
    return -model.decision_function(Xn)


def _contamination_from_payload(payload: Dict[str, Any]) -> Optional[float]:
    try:
        c = payload.get("meta", {}).get("params", {}).get("contamination")
        if c is not None:
            return float(c)
    except Exception:
        pass
    try:
        cfg = load_models_config()
        return float(cfg.get("isolation_forest", {}).get("contamination", 0.05))
    except Exception:
        return None


def baseline_threshold_path() -> Path:
    paths = get_paths()
    return Path(paths["models_dir"]) / BASELINE_FILENAME


def load_baseline_threshold() -> Tuple[float, Dict[str, Any]]:
    p = baseline_threshold_path()
    if not p.exists():
        raise FileNotFoundError(f"Missing baseline threshold file: {p}")
    import json

    with open(p, "r", encoding="utf-8") as f:
        obj = json.load(f)
    thr = float(obj.get("baseline_threshold"))
    return thr, obj


def load_baseline_threshold_from_model_meta() -> Optional[float]:
    """
    Fallback reader when baseline_threshold.json is missing.
    Allowed because it is still a fixed baseline threshold produced at baseline train time.
    """
    try:
        payload = _load_model_payload()
        v = payload.get("meta", {}).get("baseline_threshold")
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def create_baseline_threshold_from_features(
    *,
    baseline_features_path: Path,
    method: Optional[str] = None,
) -> Path:
    """
    Explicit creation of baseline_threshold.json from a user-provided baseline features file.
    This is ONLY allowed when the user points to a known-clean baseline dataset.
    """
    if baseline_features_path is None:
        raise ValueError("baseline_features_path is required")
    if not baseline_features_path.exists():
        raise FileNotFoundError(f"Baseline features not found: {baseline_features_path}")

    payload = _load_model_payload()
    contamination = _contamination_from_payload(payload)
    if contamination is None:
        raise RuntimeError("Cannot infer contamination for baseline threshold computation.")
    q = 1.0 - float(contamination)

    df = pd.read_parquet(baseline_features_path)
    if df.empty:
        raise RuntimeError("Baseline features file is empty; cannot compute baseline threshold.")

    scores = _score_df_with_payload(df, payload)
    thr = float(np.quantile(scores, q))
    obj = {
        "baseline_threshold": thr,
        "method": method or f"p{q:.4f}",
        "computed_from": str(baseline_features_path),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "contamination": float(contamination),
        "note": "Explicitly computed from user-provided baseline features (assumed clean).",
    }
    out_path = baseline_threshold_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(out_path, obj)
    return out_path


