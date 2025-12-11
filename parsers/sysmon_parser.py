from pathlib import Path
from typing import List, Dict

import pandas as pd

from models.utils import get_paths, load_yaml
from parsers.base_reader import read_jsonl, write_partitioned_parquet
from parsers.ecs_mapper import map_record


def _looks_like_ecs(records: List[Dict]) -> bool:
    """Heuristic: synthetic ECS if @timestamp + event.code present."""
    if not records:
        return False
    r0 = records[0]
    return "@timestamp" in r0 and "event.code" in r0


def parse_sysmon() -> Path:
    paths = get_paths()
    raw = Path(paths["raw_data_dir"]) / "sysmon.jsonl"
    ecs_parquet_dir = Path(paths["ecs_parquet_dir"]).resolve()

    records: List[Dict] = read_jsonl(raw)
    if _looks_like_ecs(records):
        df = pd.DataFrame(records)
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        if "event.module" not in df.columns:
            df["event.module"] = "sysmon"
        if "event.dataset" not in df.columns:
            df["event.dataset"] = "sysmon"
    else:
        mapping = load_yaml(Path(__file__).resolve().parents[1] / "config" / "ecs_mapping.yaml")
        cfg = mapping["sysmon"]
        ecs_rows = [map_record(rec, cfg) for rec in records]
        df = pd.DataFrame(ecs_rows)
        df["event.module"] = "sysmon"
        df["event.dataset"] = "sysmon"

    df = df.dropna(subset=["@timestamp"])  # ensure ts present
    write_partitioned_parquet(df, Path(paths["ecs_parquet_dir"]), "sysmon")
    return ecs_parquet_dir


if __name__ == "__main__":
    parse_sysmon()
