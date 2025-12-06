import os
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

# Attempt to load environment variables from a .env file at project root.
# This allows configuration such as SAMPLE_DATA_DIR, TZ, CSV_TIME_COL, etc.
try:
    from dotenv import load_dotenv  # type: ignore
    _ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
    # Do not override explicit OS envs; only fill missing keys from .env
    load_dotenv(dotenv_path=_ENV_PATH, override=False)
except Exception:
    # python-dotenv is optional at runtime; safe to continue without it
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"


def load_yaml(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_paths() -> Dict[str, str]:
    cfg = load_yaml(CONFIG_DIR / "paths.yaml")
    # Convert to absolute paths under project root
    resolved = {}
    for key, rel in cfg.items():
        if isinstance(rel, list):
            resolved[key] = rel
        elif isinstance(rel, (int, float)):
            resolved[key] = rel
        elif isinstance(rel, str) and (rel.startswith("http://") or rel.startswith("https://")):
            resolved[key] = rel
        else:
            resolved[key] = str((PROJECT_ROOT / rel).resolve())
    return resolved


def load_models_config() -> Dict[str, Any]:
    return load_yaml(CONFIG_DIR / "models.yaml")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def list_parquet_files(base_dir: Path) -> List[Path]:
    return list(base_dir.rglob("*.parquet"))


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
