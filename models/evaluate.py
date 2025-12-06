"""
Đánh giá mô hình Isolation Forest trên tập có nhãn.

Đầu vào:
- scores_path: parquet chứa anom.score và các cột định danh
- labels_path (tuỳ chọn): parquet/csv chứa nhãn; nếu không cung cấp, dùng cột `label` có sẵn trong scores_path

Đầu ra:
- File JSON `data/scores/evaluate_report.json` gồm: TPR, FPR, Precision, Recall, F1, threshold, support
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, List

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

from models.utils import get_paths, load_models_config, write_json
from explain.thresholding import compute_threshold


def _load_scores(scores_path: Optional[str]) -> pd.DataFrame:
    paths = get_paths()
    path = Path(scores_path) if scores_path else Path(paths["scores_dir"]) / "scores.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Scores file not found: {path}")
    return pd.read_parquet(path)


def _load_labels(labels_path: Optional[str]) -> pd.DataFrame:
    if labels_path is None:
        return pd.DataFrame()
    p = Path(labels_path)
    if not p.exists():
        raise FileNotFoundError(f"Labels file not found: {p}")
    if p.suffix.lower() == ".csv":
        return pd.read_csv(p)
    return pd.read_parquet(p)


def _merge_labels(scores: pd.DataFrame, labels: pd.DataFrame, label_col: str) -> pd.Series:
    if label_col in scores.columns:
        return scores[label_col]
    if labels.empty:
        raise ValueError(f"Label column '{label_col}' không có trong scores và không cung cấp labels_path.")
    # Merge ưu tiên các khóa thời gian + IP
    keys = [c for c in ["@timestamp", "source.ip", "destination.ip", "host.name", "session.id"] if c in labels.columns and c in scores.columns]
    if not keys:
        if len(labels) != len(scores):
            raise ValueError("Không thể ghép nhãn: thiếu khóa chung và số bản ghi không khớp.")
        labels = labels.reset_index(drop=True)
        scores = scores.reset_index(drop=True)
        return labels[label_col]
    merged = pd.merge(scores, labels, on=keys, how="left", suffixes=("", "_label"))
    if label_col not in merged.columns:
        raise ValueError(f"Không tìm thấy cột nhãn '{label_col}' sau khi merge.")
    return merged[label_col]


def _compute_metrics(y_true, y_pred) -> Tuple[float, float, float, float, float]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    tpr = tp / (tp + fn + 1e-9)
    fpr = fp / (fp + tn + 1e-9)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, pos_label=1, average="binary", zero_division=0)
    return tpr, fpr, precision, recall, f1


def evaluate_model(
    labels_path: Optional[str] = None,
    scores_path: Optional[str] = None,
    label_col: str = "label",
    positive_label: int = 1,
) -> Path:
    scores_df = _load_scores(scores_path)
    labels_df = _load_labels(labels_path)

    y_true = _merge_labels(scores_df, labels_df, label_col=label_col)
    y_true = (y_true == positive_label).astype(int)

    if "anom.score" not in scores_df.columns:
        raise ValueError("scores_df thiếu cột anom.score")

    thr, _ = compute_threshold(scores_df["anom.score"])
    y_pred = (scores_df["anom.score"] >= thr).astype(int)

    tpr, fpr, precision, recall, f1 = _compute_metrics(y_true, y_pred)

    report = {
        "threshold": float(thr),
        "counts": {
            "total": int(len(y_true)),
            "positive": int(y_true.sum()),
            "negative": int((1 - y_true).sum()),
        },
        "metrics": {
            "TPR": tpr,
            "FPR": fpr,
            "Precision": precision,
            "Recall": recall,
            "F1": f1,
        },
        "label_col": label_col,
        "positive_label": positive_label,
    }

    paths = get_paths()
    out_path = Path(paths["scores_dir"]) / "evaluate_report.json"
    write_json(out_path, report)
    return out_path


if __name__ == "__main__":
    evaluate_model()

