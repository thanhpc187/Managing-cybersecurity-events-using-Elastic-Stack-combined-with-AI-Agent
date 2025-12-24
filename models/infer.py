import os
from pathlib import Path
from typing import Dict, Tuple, List

import pandas as pd
import joblib

from models.utils import get_paths


def _load_model() -> Tuple[object, object, List[str]]:
    paths = get_paths()
    mp = Path(paths["models_dir"]) / "isolation_forest.joblib"
    if not mp.exists():
        raise FileNotFoundError(f"Model not found: {mp}. Run 'python -m cli.anom_score train' first.")
    payload: Dict = joblib.load(mp)
    return payload["model"], payload.get("scaler"), payload["feature_cols"]


def _prepare_features(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    out = df.copy()
    for c in feature_cols:
        if c not in out.columns:
            out[c] = 0.0
    X = out[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return X


def score_features() -> Path:
    """Nếu có features theo partition dt=* thì chấm theo partition, ngược lại chấm features.parquet."""
    paths = get_paths()
    feat_root = Path(paths["features_dir"])
    dt_dirs = sorted([p for p in feat_root.glob("dt=*") if p.is_dir()])
    if dt_dirs:
        return score_features_large()

    model, scaler, feature_cols = _load_model()
    feat_path = feat_root / "features.parquet"
    if not feat_path.exists():
        raise FileNotFoundError(f"Features file not found: {feat_path}. Run featurize first.")
    df = pd.read_parquet(feat_path)
    if df.empty:
        raise RuntimeError("Feature table is empty")

    X = _prepare_features(df, feature_cols)
    X_np = X.values
    if scaler is not None:
        X_np = scaler.transform(X_np)
    scores = -model.decision_function(X_np)

    out = df.copy()
    out["anom.score"] = scores
    out_dir = Path(paths["scores_dir"]); out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "scores.parquet"
    out.to_parquet(out_path, index=False)
    return out_path


def score_features_large() -> Path:
    """
    Chấm điểm theo từng partition ngày:
    data/features/dt=*/part.parquet -> data/scores/dt=*/part.parquet
    Và ghép toàn bộ vào data/scores/scores.parquet cho UI.
    """
    paths = get_paths()
    feat_root = Path(paths["features_dir"])
    scores_root = Path(paths["scores_dir"]); scores_root.mkdir(parents=True, exist_ok=True)
    model, scaler, feature_cols = _load_model()

    for d in sorted([p for p in feat_root.glob("dt=*") if p.is_dir()]):
        parts = list(d.glob("*.parquet"))
        if not parts:
            continue
        df = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True)
        if df.empty:
            continue

        X = _prepare_features(df, feature_cols)
        X_np = X.values
        if scaler is not None:
            X_np = scaler.transform(X_np)
        scores = -model.decision_function(X_np)

        out = df.copy()
        out["anom.score"] = scores
        out_dir = scores_root / d.name; out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "part.parquet"
        try:
            out_path.unlink(missing_ok=True)
        except Exception:
            pass
        out.to_parquet(out_path, index=False)

    # Gộp toàn bộ partition -> scores.parquet (có thể giới hạn số dòng)
    all_parts = sorted(scores_root.glob("dt=*/*.parquet"))
    if all_parts:
        merged = pd.concat([pd.read_parquet(p) for p in all_parts], ignore_index=True)
        max_rows = int(os.getenv("SCORES_MERGE_MAX_ROWS", "2000000"))
        if len(merged) > max_rows:
            merged = merged.sample(max_rows, random_state=42)
        merged.to_parquet(scores_root / "scores.parquet", index=False)

    return scores_root


def score_feature_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Score an in-memory feature dataframe using the saved model payload.

    Returns a copy of df with an added column: anom.score
    """
    if df is None or df.empty:
        return pd.DataFrame()
    model, scaler, feature_cols = _load_model()
    X = _prepare_features(df, feature_cols)
    X_np = X.values
    if scaler is not None:
        X_np = scaler.transform(X_np)
    scores = -model.decision_function(X_np)
    out = df.copy()
    out["anom.score"] = scores
    return out