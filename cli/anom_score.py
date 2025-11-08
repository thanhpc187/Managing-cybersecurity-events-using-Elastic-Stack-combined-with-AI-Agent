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

app = typer.Typer(help="Loganom AI demo CLI")
logger = logging.getLogger(__name__)

def _safe_run_ingest():
    """Chạy ingest với fallback nếu module không khả dụng."""
    try:
        from pipeline.ingest import ingest_all
        ingest_all()
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
def cmd_ingest(reset: bool = typer.Option(False, help="Remove ECS Parquet before ingest")):
    if reset:
        _reset_dirs("data/ecs_parquet")
    _safe_run_ingest()
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

@app.command("train-lstm")
def cmd_train_lstm():
    """Huấn luyện LSTM Autoencoder model."""
    try:
        from models.lstm_anomaly import train_lstm_model
        out = train_lstm_model()
        typer.echo(f"[train-lstm] Wrote: {out}")
    except ImportError as e:
        logger.error(f"Không thể import models.lstm_anomaly: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi train LSTM: {e}")
        raise typer.Exit(code=1)

@app.command("score-lstm")
def cmd_score_lstm(reset: bool = typer.Option(False, help="Remove LSTM scores before scoring")):
    """Chấm điểm bất thường bằng LSTM model."""
    if reset:
        _reset_dirs("data/scores_lstm", "data/scores/ensemble")
    try:
        from models.lstm_infer import score_lstm_features
        out = score_lstm_features()
        typer.echo(f"[score-lstm] Wrote: {out}")
    except ImportError as e:
        logger.error(f"Không thể import models.lstm_infer: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi score LSTM: {e}")
        raise typer.Exit(code=1)

@app.command("ensemble")
def cmd_ensemble(reset: bool = typer.Option(False, help="Remove ensemble scores before combining")):
    """Kết hợp điểm từ Isolation Forest và LSTM."""
    if reset:
        _reset_dirs("data/scores/ensemble")
    try:
        from models.ensemble import combine_if_lstm
        out = combine_if_lstm()
        typer.echo(f"[ensemble] Wrote: {out}")
    except ImportError as e:
        logger.error(f"Không thể import models.ensemble: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Lỗi khi ensemble: {e}")
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

@app.command("demo-lstm")
def cmd_demo_lstm(reset: bool = typer.Option(False, help="Reset ecs/features/scores before run (LSTM path)")):
    if reset:
        _reset_dirs("data/ecs_parquet", "data/features", "data/scores", "data/bundles", "data/scores_lstm", "data/scores/ensemble")
    cmd_ingest(reset=False)
    cmd_featurize(reset=False)
    cmd_train_lstm()
    cmd_score_lstm(reset=False)
    cmd_ensemble(reset=False)

if __name__ == "__main__":
    app()