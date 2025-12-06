"""
Parser cho FortiGate syslog (UDP 5514 hoặc file log) -> ECS Parquet.

Hỗ trợ định dạng key=value phổ biến của FortiGate:
date=2024-08-01 time=12:34:56 devname=FGT1 devid=FGT001 logid="..." type=traffic subtype=forward
level=notice srcip=10.0.0.10 srcport=12345 dstip=8.8.8.8 dstport=53 proto=udp action=deny policyid=3 service=DNS
msg="..."; sentbyte=120 rcvdbyte=40
"""

from __future__ import annotations

import re
import socket
import socketserver
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from models.utils import get_paths, load_yaml, CONFIG_DIR
from parsers.ecs_mapper import map_record
from parsers.base_reader import write_partitioned_parquet


KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')


def _parse_kv_line(line: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for m in KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2).strip('"')
        data[key] = val
    # Ghép timestamp nếu có date/time
    if "date" in data and "time" in data:
        try:
            data["timestamp"] = datetime.fromisoformat(f"{data['date']} {data['time']}")
        except Exception:
            pass
    return data


def _load_mapping() -> Dict:
    cfg = load_yaml(CONFIG_DIR / "ecs_mapping.yaml")
    return cfg.get("fortigate", {})


def _map_records(raw_records: List[Dict]) -> pd.DataFrame:
    mapping = _load_mapping()
    mapped = []
    for r in raw_records:
        ecs = map_record(r, mapping)
        ecs["event.module"] = "fortigate"
        ecs["event.dataset"] = "fortigate.traffic"
        mapped.append(ecs)
    return pd.DataFrame(mapped)


def parse_fortigate_file(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    raw: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw.append(_parse_kv_line(line))
    if not raw:
        return None
    df = _map_records(raw)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "fortigate")
    return out_dir


def _udp_handler_factory(buffer: List[str]):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request[0].strip()
            try:
                line = data.decode("utf-8", errors="ignore")
            except Exception:
                line = ""
            if line:
                buffer.append(line)

    return Handler


def collect_udp(
    port: int,
    timeout: int = 10,
    max_messages: int = 5000,
) -> List[str]:
    """Thu thập syslog UDP trong thời gian ngắn (demo)."""
    buf: List[str] = []
    handler = _udp_handler_factory(buf)
    with socketserver.UDPServer(("", port), handler) as server:
        server.timeout = timeout
        end_time = datetime.utcnow().timestamp() + timeout
        while datetime.utcnow().timestamp() < end_time and len(buf) < max_messages:
            server.handle_request()
    return buf


def parse_fortigate_udp(port: int = 5514, timeout: int = 10, max_messages: int = 5000) -> Optional[Path]:
    lines = collect_udp(port=port, timeout=timeout, max_messages=max_messages)
    if not lines:
        return None
    raw = [_parse_kv_line(l) for l in lines]
    df = _map_records(raw)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "fortigate")
    return out_dir


def parse_fortigate(path: Optional[Path] = None, enable_udp: bool = False, udp_timeout: int = 10) -> Optional[Path]:
    """
    Parse FortiGate logs từ file (ưu tiên) hoặc UDP listener ngắn.
    - path None: auto tìm sample_data/fortigate*.log hoặc .txt
    - enable_udp=True: mở listener UDP (demo) nếu không có file
    """
    paths = get_paths()
    out_dir = Path(paths["ecs_parquet_dir"])
    if path is None:
        sample_root = Path("sample_data")
        candidates = list(sample_root.glob("fortigate*.log")) + list(sample_root.glob("fortigate*.txt"))
        if candidates:
            path = candidates[0]
    if path:
        return parse_fortigate_file(Path(path))
    if enable_udp:
        try:
            port = int(paths.get("fortigate_syslog_port", 5514))
        except Exception:
            port = 5514
        return parse_fortigate_udp(port=port, timeout=udp_timeout)
    return None


if __name__ == "__main__":
    parse_fortigate()

