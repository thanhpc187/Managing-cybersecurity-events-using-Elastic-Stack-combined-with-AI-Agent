"""
Parser cho Filebeat/Packetbeat/Winlogbeat JSONL -> ECS Parquet.

- Ưu tiên đọc file sample_data/packetbeat*.jsonl hoặc beats/*.jsonl
- Có thể dùng cho dữ liệu lấy từ Elasticsearch (đã ở ECS) bằng cách ghi xuống file tạm và parse lại.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from models.utils import get_paths, load_yaml, CONFIG_DIR
from parsers.base_reader import read_jsonl, write_partitioned_parquet
from parsers.ecs_mapper import map_record


def _load_mapping() -> Dict:
    cfg = load_yaml(CONFIG_DIR / "ecs_mapping.yaml")
    return cfg.get("packetbeat", {})


def _map_records(raw_records: List[Dict]) -> pd.DataFrame:
    mapping = _load_mapping()
    mapped = []
    for r in raw_records:
        ecs = map_record(r, mapping)
        ecs["event.module"] = ecs.get("event.module") or "packetbeat"
        ecs["event.dataset"] = ecs.get("event.dataset") or "packetbeat.flow"
        mapped.append(ecs)
    return pd.DataFrame(mapped)


def parse_beats(path: Optional[Path] = None) -> Optional[Path]:
    """
    Parse Packetbeat/Filebeat JSONL logs.
    - path None: tìm sample_data/packetbeat*.jsonl hoặc sample_data/beats/*.jsonl
    """
    if path is None:
        from models.utils import get_paths
        sample_root = Path(get_paths().get("raw_data_dir", "sample_data"))
        candidates = list(sample_root.glob("**/packetbeat*.jsonl")) + list((sample_root / "beats").glob("*.jsonl"))
        if candidates:
            path = candidates[0]
    if path is None:
        return None
    raw = read_jsonl(Path(path))
    if not raw:
        return None
    df = _map_records(raw)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "packetbeat")
    return out_dir


if __name__ == "__main__":
    parse_beats()

