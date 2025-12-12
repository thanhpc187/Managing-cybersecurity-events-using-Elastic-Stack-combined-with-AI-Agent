from __future__ import annotations

import os
from pathlib import Path

from typing import List, Optional

import pandas as pd
import requests

from models.utils import get_paths, load_yaml
from pipeline.build_store import run_ingest
from parsers.base_reader import write_partitioned_parquet
from parsers.fortigate_parser import parse_fortigate
from parsers.ips_parser import parse_ips
from parsers.beats_parser import parse_beats

try:
    from parsers.csv_parser import parse_csv_file  # type: ignore
except Exception:
    parse_csv_file = None  # type: ignore

try:
    from parsers.log_parser import parse_auth_logs  # type: ignore
except Exception:
    parse_auth_logs = None  # type: ignore

def _ingest_csv_recursive(root: Path) -> None:
    if parse_csv_file is None:
        print("[ingest] CSV parser not available, skip CSV ingest.")
        return
    if not root.exists():
        print(f"[ingest] CSV root not found: {root}")
        return
    files = list(root.rglob("*.csv"))
    if not files:
        print(f"[ingest] No CSV files under: {root}")
        return
    print(f"[ingest] Found {len(files)} CSV file(s)")
    for p in files:
        try:
            parse_csv_file(p)
            print(f"[ingest] CSV ingested: {p}")
        except Exception as e:
            print(f"[ingest] CSV skipped {p}: {e}")

def ingest_from_elastic(
    host: str,
    index_patterns: List[str],
    user: Optional[str] = None,
    password: Optional[str] = None,
    size: int = 5000,
) -> Optional[Path]:
    """Đọc log trực tiếp từ Elasticsearch (giả định đã ở ECS)."""
    if not host:
        raise ValueError("Elasticsearch host is required")
    auth = (user, password) if user else None
    records: List[dict] = []
    for idx in index_patterns:
        url = f"{host.rstrip('/')}/{idx}/_search"
        payload = {"size": size, "query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "asc"}}]}
        try:
            resp = requests.get(url, json=payload, auth=auth, timeout=30, verify=False)
            resp.raise_for_status()
            body = resp.json()
            hits = body.get("hits", {}).get("hits", [])
            for h in hits:
                src = h.get("_source") or {}
                records.append(src)
            print(f"[ingest] Elasticsearch index {idx}: {len(hits)} records")
        except Exception as e:
            print(f"[ingest] Elasticsearch query failed for {idx}: {e}")
    if not records:
        print("[ingest] No records fetched from Elasticsearch.")
        return None
    df = pd.DataFrame(records)

    # Chuẩn hóa cột host: một số log có host là object (dict) với hostname/ip,
    # số khác chỉ có ip; nếu giữ nguyên dạng object, pyarrow sẽ lỗi khi ghi parquet.
    if "host" in df.columns:
        def _extract_host_name(value):
            if isinstance(value, dict):
                if "name" in value:
                    return value["name"]
                if "hostname" in value:
                    return value["hostname"]
            return None

        host_name = df["host"].apply(_extract_host_name)

        # Fallback: nếu có cột hostname riêng thì dùng để lấp chỗ trống
        if "hostname" in df.columns:
            host_name = host_name.fillna(df["hostname"])

        # Fallback: với Windows event, lấy từ winlog.computer_name nếu có
        if "winlog" in df.columns:
            def _from_winlog(value):
                if isinstance(value, dict):
                    return value.get("computer_name")
                return None

            host_name = host_name.fillna(df["winlog"].apply(_from_winlog))

        df["host.name"] = host_name

        def _extract_host_ip(value):
            if isinstance(value, dict) and "ip" in value:
                ip_val = value["ip"]
                # Một số log để ip là list, số khác là string
                if isinstance(ip_val, list) and ip_val:
                    return ip_val[0]
                return ip_val
            return None

        df["host.ip"] = df["host"].apply(_extract_host_ip)

        # Cuối cùng ép cả cột host về string để tránh lỗi Arrow với kiểu object phức tạp
        df["host"] = df["host"].astype(str)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "elastic")
    return out_dir


def ingest_all(
    source: str = "files",
    elastic_host: Optional[str] = None,
    elastic_index_patterns: Optional[List[str]] = None,
    elastic_user: Optional[str] = None,
    elastic_password: Optional[str] = None,
    enable_udp: bool = False,
    data_dir: Optional[str] = None,
) -> Path:
    """
    Ingest pipeline:
    - source="files": dùng sample_data (mặc định)
    - source="elasticsearch": đọc trực tiếp từ Elastic (host/index_patterns)
    """
    paths = get_paths()
    if data_dir:
        os.environ["RAW_DATA_DIR"] = data_dir
        os.environ["SAMPLE_DATA_DIR"] = data_dir
        paths = get_paths()
    out_dir = Path(paths["ecs_parquet_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    if source == "elasticsearch":
        cfg = load_yaml(Path(__file__).resolve().parents[1] / "config" / "paths.yaml")
        host = elastic_host or cfg.get("elastic_host")
        indexes = elastic_index_patterns or cfg.get("elastic_index_patterns") or []
        ingest_from_elastic(host, indexes, user=elastic_user or cfg.get("elastic_user"), password=elastic_password or cfg.get("elastic_password"))
        return out_dir

    # Default: file-based ingest + optional UDP listeners for FortiGate/IPS
    try:
        run_ingest()
    except Exception as e:
        print(f"[ingest] Base ingest error: {e}")
    sample_root = Path(os.getenv("SAMPLE_DATA_DIR", data_dir or "sample_data"))
    if parse_auth_logs:
        try:
            parse_auth_logs(sample_root)
            print("[ingest] Syslog .log ingested (recursive).")
        except Exception as e:
            print(f"[ingest] Syslog .log ingest error: {e}")
    else:
        print("[ingest] Syslog parser not available.")
    _ingest_csv_recursive(sample_root)

    # FortiGate / IPS / Beats
    parse_fortigate(enable_udp=enable_udp)
    parse_ips(enable_udp=enable_udp)
    parse_beats()

    return out_dir

if __name__ == "__main__":
    ingest_all()