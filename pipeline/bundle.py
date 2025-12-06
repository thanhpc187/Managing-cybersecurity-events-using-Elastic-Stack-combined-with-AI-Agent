import io
import json
from datetime import timedelta
from pathlib import Path
from typing import Dict
import zipfile

import joblib
import pandas as pd

from explain.shap_explain import top_shap_for_rows
from models.utils import get_paths, write_json, sha256_file

from ai.agent import analyze_alert
from pipeline.coc import build_coc


def _load_model_payload():
    paths = get_paths()
    model_path = Path(paths["models_dir"]) / "isolation_forest.joblib"
    return joblib.load(model_path)


def build_bundle_for_alert(alert_row: pd.Series, idx: int, threshold: float) -> Path:
    paths = get_paths()
    ecs_dir = Path(paths["ecs_parquet_dir"])
    features_path = Path(paths["features_dir"]) / "features.parquet"
    scores_path = Path(paths["scores_dir"]) / "scores.parquet"

    # Load ECS union for context
    ecs_parts = list(ecs_dir.rglob("*.parquet"))
    ecs_df = pd.concat([pd.read_parquet(p) for p in ecs_parts], ignore_index=True)
    ecs_df["@timestamp"] = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")

    # Context window ±5m
    t0 = pd.to_datetime(alert_row["@timestamp"], utc=True)
    mask = (ecs_df["@timestamp"] >= t0 - timedelta(minutes=5)) & (ecs_df["@timestamp"] <= t0 + timedelta(minutes=5))
    raw_slice = ecs_df.loc[mask].copy()

    # Features for the single alert row
    feat_row = alert_row.to_dict()

    # SHAP: compute on the single row against model
    payload = _load_model_payload()
    model = payload["model"]
    feature_cols = payload["feature_cols"]
    X = alert_row[feature_cols].fillna(0.0).to_frame().T
    shap_top = top_shap_for_rows(model, X.values, feature_cols, top_k=5)[0]

    # Model meta
    model_meta = {
        "algorithm": payload.get("meta", {}).get("algorithm", "IsolationForest"),
        "params": payload.get("meta", {}).get("params", {}),
        "score_threshold": float(threshold),
        "alert_score": float(alert_row["anom.score"]),
    }

    bundles_dir = Path(paths["bundles_dir"]).resolve()
    bundles_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = bundles_dir / f"alert_{idx}.zip"

    # Prepare files in a temp dir then write into zip
    tmp_dir = bundles_dir / f"tmp_alert_{idx}"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # 1) Raw logs context
    raw_logs_path = tmp_dir / "raw_logs.jsonl"
    with open(raw_logs_path, "w", encoding="utf-8") as f:
        for _, row in raw_slice.iterrows():
            json.dump(row.dropna().to_dict(), f, default=str)
            f.write("\n")

    # 2) Feature row (JSON)
    features_path_json = tmp_dir / "features.json"
    write_json(features_path_json, feat_row)

    # 3) SHAP explanation
    shap_path = tmp_dir / "shap_explanation.json"
    write_json(shap_path, shap_top)

    # 4) Model meta
    model_meta_path = tmp_dir / "model_meta.json"
    write_json(model_meta_path, model_meta)

    # 5) AI agent analysis (JSON + Markdown)
    ai_analysis = analyze_alert(alert_row, shap_top, raw_slice, feat_row)
    ai_json_path = tmp_dir / "ai_analysis.json"
    write_json(ai_json_path, ai_analysis)
    ai_md_path = tmp_dir / "ai_analysis.md"
    with open(ai_md_path, "w", encoding="utf-8") as f:
        f.write(ai_analysis.get("markdown", ""))

    # 6) Evidence manifest (list parquet sources with hashes)
    evidence_manifest = [
        {"path": str(p.resolve()), "sha256": sha256_file(p), "size": p.stat().st_size}
        for p in ecs_parts
    ]
    evidence_manifest_path = tmp_dir / "evidence_manifest.json"
    write_json(evidence_manifest_path, evidence_manifest)

    # 7) Chain-of-custody (COC)
    coc = build_coc(
        tmp_dir,
        input_files=[scores_path, features_path, *ecs_parts],
        extra_outputs=[
            raw_logs_path,
            features_path_json,
            shap_path,
            model_meta_path,
            ai_json_path,
            ai_md_path,
            evidence_manifest_path,
        ],
    )
    coc_path = tmp_dir / "coc.json"
    write_json(coc_path, coc)

    # Bundle manifest (hash every file inside the bundle)
    manifest = {
        "files": {},
        "mitre_attack": ai_analysis.get("mitre_attack", []),
        "threshold": float(threshold),
        "alert_score": float(alert_row.get("anom.score", 0)),
    }
    for p in [
        raw_logs_path,
        features_path_json,
        shap_path,
        model_meta_path,
        ai_json_path,
        ai_md_path,
        evidence_manifest_path,
        coc_path,
    ]:
        manifest["files"][p.name] = {
            "sha256": sha256_file(p),
            "size": p.stat().st_size,
        }
    manifest_path = tmp_dir / "manifest.json"
    write_json(manifest_path, manifest)

    # Write zip
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in [
            raw_logs_path,
            features_path_json,
            shap_path,
            model_meta_path,
            ai_json_path,
            ai_md_path,
            evidence_manifest_path,
            coc_path,
            manifest_path,
        ]:
            zf.write(p, arcname=p.name)

    # Cleanup temp files
    for p in [
        raw_logs_path,
        features_path_json,
        shap_path,
        model_meta_path,
        ai_json_path,
        ai_md_path,
        evidence_manifest_path,
        coc_path,
        manifest_path,
    ]:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    try:
        tmp_dir.rmdir()
    except Exception:
        pass

    return bundle_path


def build_bundles_for_top_alerts(top_alerts: pd.DataFrame, threshold: float) -> None:
    for i, (_, row) in enumerate(top_alerts.iterrows(), start=1):
        build_bundle_for_alert(row, i, threshold)