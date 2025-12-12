"""
CLI commands for anomaly detection pipeline.

Copyright (c) 2024 thanhpc187
See LICENSE file for license information.
Original repository: https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent
"""

import typer
import logging
from pathlib import Path
import shutil
from typing import Optional, List

app = typer.Typer(help="Loganom AI demo CLI")
logger = logging.getLogger(__name__)

def _safe_run_ingest(
    source: str = "files",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    enable_udp: bool = False,
    data_dir: Optional[str] = None,
):
    """Chạy ingest với fallback nếu module không khả dụng."""
    try:
        from pipeline.ingest import ingest_all
        ingest_all(
            source=source,
            elastic_host=elastic_host,
            elastic_index_patterns=elastic_index_patterns,
            elastic_user=elastic_user,
            elastic_password=elastic_password,
            enable_udp=enable_udp,
            data_dir=data_dir,
        )
    except ImportError as e:
        logger.warning(f"Không thể import pipeline.ingest: {e}, thử fallback")
        try:
            from pipeline.build_store import run_ingest
            run_ingest()
        except ImportError as e2:
            logger.error(f"Không thể import pipeline.build_store: {e2}")
            raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi chạy ingest: {e}")
        raise

def _reset_dirs(*dirs: str) -> None:
    """Xóa các thư mục được chỉ định."""
    for d in dirs:
        if not d:
            continue
        p = Path(d)
        if p.exists():
            try:
                shutil.rmtree(p, ignore_errors=True)
                typer.echo(f"[reset] Removed {p}")
            except OSError as e:
                logger.warning(f"Không thể xóa {p}: {e}")

@app.command("ingest")
def cmd_ingest(
    reset: bool = typer.Option(False, help="Remove ECS Parquet before ingest"),
    source: str = typer.Option("files", help="files | elasticsearch"),
    elastic_host: str = typer.Option(None, help="Elasticsearch host (vd http://10.10.20.100:9200)"),
    elastic_index_patterns: str = typer.Option(None, help="Chuỗi phân tách bằng dấu phẩy, vd: siem-*,lab-logs-*"),
    elastic_user: str = typer.Option(None, help="Elastic username"),
    elastic_password: str = typer.Option(None, help="Elastic password"),
    enable_udp: bool = typer.Option(False, help="Bật listener UDP demo cho FortiGate/IPS"),
    data_dir: str = typer.Option(None, help="Thư mục log nguồn (vd sample_data/normal hoặc sample_data/attack)"),
):
    if reset:
        from models.utils import get_paths
        _reset_dirs(get_paths()["ecs_parquet_dir"])
    idx_list = [s.strip() for s in elastic_index_patterns.split(",")] if elastic_index_patterns else None
    _safe_run_ingest(
        source=source,
        elastic_host=elastic_host,
        elastic_index_patterns=idx_list,
        elastic_user=elastic_user,
        elastic_password=elastic_password,
        enable_udp=enable_udp,
        data_dir=data_dir,
    )
    typer.echo("[ingest] Done.")

@app.command("featurize")
def cmd_featurize(reset: bool = typer.Option(False, help="Remove features before building")):
    """Xây dựng bảng features từ ECS data."""
    if reset:
        from models.utils import get_paths
        _reset_dirs(get_paths()["features_dir"])
    try:
        import features.build_features as bf
        func = getattr(bf, "build_feature_table", None) or getattr(bf, "build_feature_table_large", None)
        if not func:
            raise RuntimeError("No build_feature_table(_large) found in features.build_features")
        func()
        typer.echo("[featurize] Done.")
    except ImportError as e:
        logger.error(f"Không thể import features.build_features: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi featurize: {e}")
        raise typer.Exit(code=1)

@app.command("train")
def cmd_train():
    """Huấn luyện Isolation Forest model."""
    try:
        from models.train_if import train_model
        train_model()
        typer.echo("[train] Done.")
    except ImportError as e:
        logger.error(f"Không thể import models.train_if: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi train: {e}")
        raise typer.Exit(code=1)

@app.command("score")
def cmd_score(reset: bool = typer.Option(False, help="Remove scores before scoring")):
    """Chấm điểm bất thường cho features."""
    if reset:
        from models.utils import get_paths
        _reset_dirs(get_paths()["scores_dir"])
    try:
        from models.infer import score_features
        out = score_features()
        typer.echo(f"[score] Wrote: {out}")
    except ImportError as e:
        logger.error(f"Không thể import models.infer: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi score: {e}")
        raise typer.Exit(code=1)

@app.command("evaluate")
def cmd_evaluate(
    labels_path: str = typer.Option(None, help="Đường dẫn file nhãn (parquet/csv)"),
    scores_path: str = typer.Option(None, help="Đường dẫn scores.parquet; mặc định data/scores/scores.parquet"),
    label_col: str = typer.Option("label", help="Tên cột nhãn (1=malicious,0=benign)"),
    positive_label: int = typer.Option(1, help="Giá trị nhãn positive"),
):
    """Đánh giá mô hình trên tập dữ liệu có nhãn (TPR/FPR/Precision/Recall/F1)."""
    try:
        from models.evaluate import evaluate_model
        report_path = evaluate_model(
            labels_path=labels_path,
            scores_path=scores_path,
            label_col=label_col,
            positive_label=positive_label,
        )
        typer.echo(f"[evaluate] Report: {report_path}")
    except ImportError as e:
        logger.error(f"Không thể import models.evaluate: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi evaluate: {e}")
        raise typer.Exit(code=1)

@app.command("respond")
def cmd_respond(apply: bool = typer.Option(False, help="Apply actions (otherwise dry-run)")):
    """Thực thi hoặc mô phỏng các hành động phản ứng (SOAR)."""
    try:
        from pipeline.respond import respond
        out = respond(dry_run=not apply)
        typer.echo(f"[respond] Audit log: {out}")
    except ImportError as e:
        logger.error(f"Không thể import pipeline.respond: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi respond: {e}")
        raise typer.Exit(code=1)

@app.command("validate")
def cmd_validate(
    source: str = typer.Option("parquet", help="parquet | elasticsearch"),
    elastic_host: str = typer.Option(None, help="Elasticsearch host (vd http://10.10.20.100:9200)"),
    elastic_index_patterns: str = typer.Option(None, help="Chuỗi phân tách bằng dấu phẩy, vd: logs-ubuntu.auth-*,logs-network.firewall-*"),
    elastic_user: str = typer.Option(None, help="Elastic username"),
    elastic_password: str = typer.Option(None, help="Elastic password"),
    elastic_size: int = typer.Option(5000, help="Số documents tối đa/query cho mỗi index pattern"),
    max_rows: int = typer.Option(5000, help="Số dòng tối đa để kiểm tra (sample)"),
    ecs_files_limit: int = typer.Option(5, help="Số file ECS parquet tối đa để đọc sample"),
    show_columns: bool = typer.Option(False, help="In toàn bộ danh sách cột (có thể dài)"),
):
    """
    Validate nhanh pipeline trên dữ liệu hiện có:
    - ECS Parquet: kiểm tra cột ECS quan trọng + tỷ lệ non-null + phát hiện field dạng dict.
    - Features: kiểm tra các feature quan trọng có tồn tại và có giá trị khác 0/null.
    - Scores: kiểm tra anom.score, threshold, số alerts và coverage MITRE/NIST trên alerts.
    """
    from models.utils import get_paths, write_json, load_yaml
    from explain.thresholding import compute_threshold
    from ai.mitre_mapper import load_mitre_mapping, map_to_mitre
    from ai.nist_mapper import load_nist_mapping, map_to_nist
    import pandas as pd
    import requests
    from datetime import datetime

    paths = get_paths()
    ecs_root = Path(paths["ecs_parquet_dir"])
    feat_root = Path(paths["features_dir"])
    scores_root = Path(paths["scores_dir"])
    scores_root.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "meta": {
            "ts": datetime.utcnow().isoformat() + "Z",
            "source": source,
            "paths": {
                "ecs_parquet_dir": str(ecs_root),
                "features_dir": str(feat_root),
                "scores_dir": str(scores_root),
            },
        },
        "ecs": {},
        "features": {},
        "scores": {},
        "mitre": {},
        "nist": {},
        "errors": [],
        "warnings": [],
        "suggestions": [],
    }

    typer.echo(f"[validate] ecs_parquet_dir: {ecs_root}")
    typer.echo(f"[validate] features_dir:    {feat_root}")
    typer.echo(f"[validate] scores_dir:      {scores_root}")
    typer.echo(f"[validate] source:          {source}")

    # ---------------- ECS checks ----------------
    ecs_df = pd.DataFrame()
    if source.lower() in ("elasticsearch", "elastic", "es"):
        cfg = load_yaml(Path(__file__).resolve().parents[1] / "config" / "paths.yaml")
        host = elastic_host or cfg.get("elastic_host")
        patterns = None
        if elastic_index_patterns:
            patterns = [s.strip() for s in elastic_index_patterns.split(",") if s.strip()]
        else:
            patterns = cfg.get("elastic_index_patterns") or []
        auth = (elastic_user or cfg.get("elastic_user"), elastic_password or cfg.get("elastic_password")) if (elastic_user or cfg.get("elastic_user")) else None

        records: list[dict] = []
        for pat in patterns:
            url = f"{host.rstrip('/')}/{pat}/_search"
            payload = {"size": int(elastic_size), "query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}
            try:
                resp = requests.get(url, json=payload, auth=auth, timeout=30, verify=False)
                resp.raise_for_status()
                body = resp.json()
                hits = body.get("hits", {}).get("hits", []) or []
                for h in hits:
                    records.append(h.get("_source") or {})
                typer.echo(f"[validate] Elasticsearch {pat}: {len(hits)} docs")
            except Exception as e:
                msg = f"Elasticsearch query failed for {pat}: {e}"
                typer.echo(f"[validate] ERROR: {msg}")
                report["errors"].append(msg)

        if records:
            ecs_df = pd.DataFrame(records)
            if len(ecs_df) > max_rows:
                ecs_df = ecs_df.sample(max_rows, random_state=42)
            typer.echo(f"[validate] ECS sample rows (from Elasticsearch): {len(ecs_df):,}")
        else:
            report["errors"].append("No records fetched from Elasticsearch. Check elastic_host/index_patterns/auth.")
            typer.echo("[validate] ERROR: No records fetched from Elasticsearch.")
    else:
        ecs_files = sorted(ecs_root.rglob("*.parquet"))[: max(1, ecs_files_limit)]
        report["ecs"]["sample_files"] = [str(p) for p in ecs_files]
        if not ecs_files:
            typer.echo("[validate] WARN: No ECS parquet files found.")
            report["warnings"].append("No ECS parquet files found (ecs_parquet_dir empty).")
        else:
            frames = []
            for p in ecs_files:
                try:
                    frames.append(pd.read_parquet(p))
                except Exception as e:
                    msg = f"cannot read {p}: {e}"
                    typer.echo(f"[validate] WARN: {msg}")
                    report["warnings"].append(msg)
            if frames:
                ecs_df = pd.concat(frames, ignore_index=True)
                if len(ecs_df) > max_rows:
                    ecs_df = ecs_df.sample(max_rows, random_state=42)
                typer.echo(f"[validate] ECS sample rows: {len(ecs_df):,} from {len(frames)} file(s)")

    important_ecs = [
        "@timestamp",
        "message",
        "event.original",
        "host.name",
        "host.ip",
        "user.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.transport",
        "event.code",
        "event.action",
        "event.outcome",
        "event.module",
        "event.dataset",
        "network.bytes",
        "network.packets",
        "rule.id",
        "rule.name",
    ]

    if ecs_df is None or ecs_df.empty:
        report["errors"].append("ECS sample is empty; cannot validate.")
    else:
        present = [c for c in important_ecs if c in ecs_df.columns]
        missing = [c for c in important_ecs if c not in ecs_df.columns]
        report["ecs"]["important_present"] = present
        report["ecs"]["important_missing"] = missing
        typer.echo(f"[validate] ECS important columns present: {len(present)}/{len(important_ecs)}")
        if missing:
            typer.echo(f"[validate] WARN missing ECS columns: {', '.join(missing)}")
            report["warnings"].append(f"Missing ECS columns: {', '.join(missing)}")

        # Detect nested dict columns (common from Elasticsearch ingest)
        dict_cols = []
        for c in ecs_df.columns:
            s = ecs_df[c].dropna()
            if not len(s):
                continue
            v = s.iloc[0]
            if isinstance(v, dict):
                dict_cols.append(c)
        report["ecs"]["dict_cols"] = dict_cols[:50]
        if dict_cols:
            typer.echo("[validate] NOTE: found nested dict columns (expected for ES docs; flatten happens in featurize): " + ", ".join(dict_cols[:20]))
            report["suggestions"].append("Detected nested dict ECS fields (event/source/destination/network). Ensure featurize uses flatten_ecs_columns (features/build_features.py).")

        # Non-null coverage for present columns
        nn_cov = {}
        for c in present:
            nn = float(ecs_df[c].notna().mean()) if c in ecs_df.columns else 0.0
            nn_cov[c] = nn
            typer.echo(f"[validate] ECS non-null {c}: {nn:.1%}")
        report["ecs"]["non_null"] = nn_cov

        if show_columns:
            typer.echo("[validate] ECS columns:")
            typer.echo(", ".join(sorted(ecs_df.columns)))

        # Critical ECS checks (fail-fast)
        if "@timestamp" not in ecs_df.columns:
            report["errors"].append("Missing @timestamp in ECS sample.")
        else:
            ts = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")
            bad = float(ts.isna().mean())
            report["ecs"]["timestamp_parse_fail_rate"] = bad
            if bad > 0.2:
                report["errors"].append(f"@timestamp parse failure rate too high: {bad:.1%}")
                report["suggestions"].append("Fix timestamp mapping in ingest/parsers (config/ecs_mapping.yaml or pipeline/ingest.py).")

    # ---------------- Features checks ----------------
    feat_path = feat_root / "features.parquet"
    if not feat_path.exists():
        typer.echo(f"[validate] WARN: features.parquet not found at {feat_path}")
        # fallback: try first partition
        parts = sorted(feat_root.glob("dt=*/*.parquet"))
        if parts:
            feat_path = parts[0]
            typer.echo(f"[validate] Using feature partition sample: {feat_path}")

    feat_df = pd.DataFrame()
    if feat_path.exists():
        feat_df = pd.read_parquet(feat_path)
        if len(feat_df) > max_rows:
            feat_df = feat_df.sample(max_rows, random_state=42)
        typer.echo(f"[validate] Features sample rows: {len(feat_df):,}")

        required_flags = ["login_failed", "conn_suspicious", "action_allow", "action_deny", "ips_alert", "cbs_failed"]
        required_windows = []
        for flag in ["login_failed", "conn_suspicious", "action_allow", "action_deny", "ips_alert"]:
            for w in [1, 5, 15]:
                required_windows.append(f"{flag}_count_{w}m")
        required_uniq = ["uniq_dst_per_src_1m", "uniq_dport_per_src_1m"]
        required_ratios = ["deny_ratio_5m", "login_failed_ratio_5m"]
        required_misc = ["text_entropy", "session.id"]
        required_features = required_flags + required_windows + required_uniq + required_ratios + required_misc

        feat_missing = [c for c in required_features if c not in feat_df.columns]
        if feat_missing:
            typer.echo(f"[validate] WARN missing feature columns: {', '.join(feat_missing[:30])}" + (" ..." if len(feat_missing) > 30 else ""))
            report["warnings"].append(f"Missing feature columns: {', '.join(feat_missing[:50])}")

        # Coverage: for numeric columns, check fraction > 0; for string/id, check non-null
        feat_cov = {}
        for c in [x for x in required_features if x in feat_df.columns]:
            s = feat_df[c]
            try:
                if pd.api.types.is_numeric_dtype(s):
                    cov = float((pd.to_numeric(s, errors="coerce").fillna(0.0) > 0).mean())
                    typer.echo(f"[validate] Feature >0 {c}: {cov:.1%}")
                    feat_cov[c] = {"type": "numeric_gt0", "coverage": cov}
                else:
                    cov = float(s.notna().mean())
                    typer.echo(f"[validate] Feature non-null {c}: {cov:.1%}")
                    feat_cov[c] = {"type": "non_null", "coverage": cov}
            except Exception:
                typer.echo(f"[validate] Feature {c}: (skip)")
        report["features"]["coverage"] = feat_cov

        # Critical feature checks: ensure at least one key feature is non-zero
        critical = ["login_failed_count_5m", "uniq_dport_per_src_1m", "action_allow_count_1m", "action_deny_count_1m"]
        crit_present = [c for c in critical if c in feat_df.columns]
        crit_any = False
        for c in crit_present:
            try:
                crit_any = crit_any or bool((pd.to_numeric(feat_df[c], errors="coerce").fillna(0.0) > 0).any())
            except Exception:
                pass
        if not crit_any:
            report["errors"].append("Critical features appear to be all-zero (rolling/unique). Likely parsing/flatten mismatch.")
            report["suggestions"].append("Check: (1) ingest pulls correct data streams (Ubuntu auth, firewall), (2) flatten_ecs_columns runs in featurize, (3) rolling window counts are canonical names (login_failed_count_5m, ...).")

    # ---------------- Scores + MITRE/NIST checks ----------------
    scores_path = scores_root / "scores.parquet"
    if not scores_path.exists():
        typer.echo(f"[validate] WARN: scores.parquet not found at {scores_path}. Run score step.")
        report["errors"].append("scores.parquet missing (run score step).")
        out_path = scores_root / "validate_report.json"
        write_json(out_path, report)
        raise typer.Exit(code=2)

    s_df = pd.read_parquet(scores_path)
    typer.echo(f"[validate] Scores rows: {len(s_df):,}")
    if "anom.score" not in s_df.columns:
        typer.echo("[validate] ERROR: scores.parquet missing anom.score")
        raise typer.Exit(code=2)

    thr, _ = compute_threshold(s_df["anom.score"])
    alerts = s_df[s_df["anom.score"] >= thr].copy()
    typer.echo(f"[validate] Threshold: {thr:.6f} | Alerts >= thr: {len(alerts):,}")
    report["scores"] = {
        "rows": int(len(s_df)),
        "threshold": float(thr),
        "alerts_ge_threshold": int(len(alerts)),
    }
    if len(alerts) == 0:
        report["errors"].append("No alerts >= threshold. Check model/threshold/scoring or input dataset.")

    cfg = load_mitre_mapping()
    ncfg = load_nist_mapping()
    mitre_counts: dict[str, int] = {}
    nist_counts: dict[str, int] = {}

    # Map coverage trên alerts (toàn bộ nếu nhỏ, hoặc sample nếu rất lớn)
    map_alerts = alerts
    if len(map_alerts) > max_rows:
        map_alerts = map_alerts.sample(max_rows, random_state=42)
        typer.echo(f"[validate] Mapping coverage computed on alert sample: {len(map_alerts):,}/{len(alerts):,}")

    for _, r in map_alerts.iterrows():
        rec = r.to_dict()
        hits = map_to_mitre(rec, rec, cfg)

        # Đếm theo alert (mỗi technique chỉ tính 1 lần/alert)
        techs = {((h.get('technique') or '').strip().upper()) for h in hits if (h.get("technique") or "").strip()}
        for tid in techs:
            mitre_counts[tid] = mitre_counts.get(tid, 0) + 1

        n_hits = map_to_nist(rec, hits, ncfg)
        funcs = {((h.get('function') or '').strip().upper()) for h in n_hits if (h.get("function") or "").strip()}
        for fn in funcs:
            nist_counts[fn] = nist_counts.get(fn, 0) + 1

    if mitre_counts:
        typer.echo("[validate] MITRE techniques hit counts (per-alert, alerts>=threshold):")
        for k, v in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True):
            typer.echo(f"  - {k}: {v}")
        report["mitre"]["counts"] = dict(sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True))
    else:
        typer.echo("[validate] WARN: No MITRE techniques matched on sampled alerts.")
        report["errors"].append("No MITRE techniques matched on alerts>=threshold (rule mismatch or missing features).")

    if nist_counts:
        typer.echo("[validate] NIST functions hit counts (per-alert, alerts>=threshold):")
        for k, v in sorted(nist_counts.items(), key=lambda x: x[1], reverse=True):
            typer.echo(f"  - {k}: {v}")
        report["nist"]["counts"] = dict(sorted(nist_counts.items(), key=lambda x: x[1], reverse=True))
    else:
        typer.echo("[validate] WARN: No NIST CSF mapping matched on sampled alerts (depends on MITRE).")
        report["errors"].append("No NIST CSF mapping matched (depends on MITRE).")

    # Expectation checks for lab scenarios (soft)
    expected_mitre = {"T1110", "T1046", "T1021"}
    missing_mitre = sorted([t for t in expected_mitre if t not in mitre_counts])
    report["mitre"]["expected_missing"] = missing_mitre
    if missing_mitre:
        report["warnings"].append(f"Missing expected MITRE techniques (lab scenarios): {', '.join(missing_mitre)}")
        report["suggestions"].append("If this dataset is a specific scenario (e.g., only brute-force), missing other techniques is OK. Otherwise check port-scan/lateral logs are included in ingest.")

    # Write report JSON
    out_path = scores_root / "validate_report.json"
    write_json(out_path, report)
    typer.echo(f"[validate] Wrote report: {out_path}")

    # Exit code policy
    if report["errors"]:
        typer.echo("[validate] FAIL (see validate_report.json)")
        raise typer.Exit(code=2)
    typer.echo("[validate] PASS")

@app.command("demo")
def cmd_demo(reset: bool = typer.Option(False, help="Reset ecs/features/scores/bundles before run")):
    if reset:
        from models.utils import get_paths
        p = get_paths()
        _reset_dirs(p["ecs_parquet_dir"], p["features_dir"], p["scores_dir"], p.get("bundles_dir", "bundles"))
    cmd_ingest(reset=False)
    cmd_featurize(reset=False)
    cmd_train()
    cmd_score(reset=False)

if __name__ == "__main__":
    app()