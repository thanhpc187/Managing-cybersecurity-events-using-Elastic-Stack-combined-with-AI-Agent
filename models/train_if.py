"""Huấn luyện Isolation Forest (Tiếng Việt)

- Đọc bảng đặc trưng `data/features/features.parquet`
- Chọn cột số (loại bỏ các cột định danh)
- Chuẩn hóa bằng RobustScaler, sau đó train IsolationForest
- Lưu payload `data/models/isolation_forest.joblib` gồm: model, scaler, feature_cols, meta
"""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from models.utils import get_paths, load_models_config, ensure_dir
from models.baseline_threshold import baseline_threshold_path


MODEL_FILENAME = "isolation_forest.joblib"


def train_model() -> Path:
    paths = get_paths()
    cfg = load_models_config()

    feat_path = Path(paths["features_dir"]) / "features.parquet"
    df = pd.read_parquet(feat_path)
    if df.empty:
        raise RuntimeError("Feature table is empty; run featurize first")

    # Select feature columns (anything numeric not in identity)
    id_cols = {"@timestamp", "host.name", "user.name", "source.ip", "destination.ip", "session.id"}
    feature_cols = [c for c in df.columns if c not in id_cols and pd.api.types.is_numeric_dtype(df[c])]

    # Drop constant/zero-variance columns to avoid misleading SHAP and improve CBS-only training
    X_all = df[feature_cols].fillna(0.0)
    non_constant_cols = [c for c in feature_cols if X_all[c].nunique(dropna=False) > 1]
    feature_cols = non_constant_cols
    X = X_all[feature_cols]

    # Robust scaling
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    iso_cfg = cfg.get("isolation_forest", {})
    model = IsolationForest(
        n_estimators=iso_cfg.get("n_estimators", 150),
        max_samples=iso_cfg.get("max_samples", "auto"),
        contamination=iso_cfg.get("contamination", 0.05),
        random_state=iso_cfg.get("random_state", 42),
        n_jobs=iso_cfg.get("n_jobs", -1),
    )

    model.fit(X_scaled)

    # Baseline threshold (fixed): computed on the same NORMAL training set scores
    contamination = float(iso_cfg.get("contamination", 0.05))
    q = 1.0 - contamination
    train_scores = -model.decision_function(X_scaled)
    baseline_thr = float(pd.Series(train_scores).quantile(q))

    out_dir = Path(paths["models_dir"]).resolve()
    ensure_dir(out_dir)
    model_path = out_dir / MODEL_FILENAME
    payload = {
        "model": model,
        "feature_cols": feature_cols,
        "scaler": scaler,
        "meta": {
            "algorithm": "IsolationForest",
            "params": iso_cfg,
            "baseline_threshold": baseline_thr,
            "baseline_threshold_method": f"p{q:.4f}",
        },
    }
    joblib.dump(payload, model_path)

    # Persist baseline threshold to a separate file used by window-report mode
    bt_path = baseline_threshold_path()
    bt_obj = {
        "baseline_threshold": baseline_thr,
        "method": f"p{q:.4f}",
        "computed_from": "normal_features (train input)",
        "created_at": pd.Timestamp.utcnow().isoformat() + "Z",
        "contamination": contamination,
    }
    try:
        from models.utils import write_json

        write_json(bt_path, bt_obj)
    except Exception:
        # Keep training resilient even if threshold file cannot be written
        pass
    return model_path


if __name__ == "__main__":
    train_model()
