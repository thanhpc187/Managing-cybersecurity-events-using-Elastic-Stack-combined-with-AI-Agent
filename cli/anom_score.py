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
        _reset_dirs("data/ecs_parquet")
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
        _reset_dirs("data/features")
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
        _reset_dirs("data/scores")
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

@app.command("demo")
def cmd_demo(reset: bool = typer.Option(False, help="Reset ecs/features/scores/bundles before run")):
    if reset:
        _reset_dirs("data/ecs_parquet", "data/features", "data/scores", "data/bundles")
    cmd_ingest(reset=False)
    cmd_featurize(reset=False)
    cmd_train()
    cmd_score(reset=False)

if __name__ == "__main__":
    app()