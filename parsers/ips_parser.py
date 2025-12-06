"""
Parser cho IPS (Snort/Suricata) syslog/alert log -> ECS Parquet.

Hỗ trợ định dạng phổ biến của Snort/Suricata:
<134>1 2024-05-01T12:00:00Z host - - - [Classification: Attempted Admin Privilege Gain] [Priority: 1] {TCP} 10.0.0.1:1234 -> 10.0.0.2:80 msg
"""

from __future__ import annotations

import re
import socketserver
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from models.utils import get_paths, load_yaml, CONFIG_DIR
from parsers.ecs_mapper import map_record
from parsers.base_reader import write_partitioned_parquet


IPS_RE = re.compile(
    r"""
    (?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)?\s*
    .*?
    \[Classification:\s*(?P<classification>[^\]]+)\]\s*
    \[Priority:\s*(?P<priority>\d+)\]\s*
    \{(?P<proto>[A-Za-z0-9]+)\}\s*
    (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})
    (?::(?P<src_port>\d+))?\s*->\s*
    (?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})
    (?::(?P<dest_port>\d+))?
    """,
    re.VERBOSE,
)


def _parse_line(line: str) -> Dict[str, str]:
    m = IPS_RE.search(line)
    data: Dict[str, str] = {}
    if m:
        data = m.groupdict()
    data["message"] = line.strip()
    # Normalize timestamp
    if data.get("ts"):
        try:
            data["timestamp"] = datetime.fromisoformat(data["ts"].replace("Z", "+00:00"))
        except Exception:
            data["timestamp"] = data["ts"]
    return data


def _load_mapping() -> Dict:
    cfg = load_yaml(CONFIG_DIR / "ecs_mapping.yaml")
    return cfg.get("ips", {})


def _map_records(raw_records: List[Dict]) -> pd.DataFrame:
    mapping = _load_mapping()
    mapped = []
    for r in raw_records:
        ecs = map_record(r, mapping)
        ecs["event.module"] = "ips"
        ecs["event.dataset"] = "ips.alert"
        ecs["rule.name"] = ecs.get("rule.name") or r.get("signature")
        mapped.append(ecs)
    return pd.DataFrame(mapped)


def parse_ips_file(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    raw: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw.append(_parse_line(line))
    if not raw:
        return None
    df = _map_records(raw)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "ips")
    return out_dir


def _udp_handler_factory(buf: List[str]):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request[0].strip()
            try:
                buf.append(data.decode("utf-8", errors="ignore"))
            except Exception:
                pass

    return Handler


def parse_ips_udp(port: int = 514, timeout: int = 10, max_messages: int = 5000) -> Optional[Path]:
    buf: List[str] = []
    handler = _udp_handler_factory(buf)
    with socketserver.UDPServer(("", port), handler) as server:
        server.timeout = timeout
        end = datetime.utcnow().timestamp() + timeout
        while datetime.utcnow().timestamp() < end and len(buf) < max_messages:
            server.handle_request()
    if not buf:
        return None
    raw = [_parse_line(l) for l in buf]
    df = _map_records(raw)
    out_dir = Path(get_paths()["ecs_parquet_dir"])
    write_partitioned_parquet(df, out_dir, "ips")
    return out_dir


def parse_ips(path: Optional[Path] = None, enable_udp: bool = False, udp_timeout: int = 10) -> Optional[Path]:
    """
    Parse IPS alert logs từ file hoặc UDP listener ngắn.
    - path None: tự tìm sample_data/ips*.log hoặc .txt
    - enable_udp=True: mở listener UDP (demo) nếu không có file
    """
    paths = get_paths()
    if path is None:
        sample_root = Path("sample_data")
        candidates = list(sample_root.glob("ips*.log")) + list(sample_root.glob("suricata*.log")) + list(sample_root.glob("snort*.log"))
        if candidates:
            path = candidates[0]
    if path:
        return parse_ips_file(Path(path))
    if enable_udp:
        try:
            port = int(paths.get("ips_syslog_port", 514))
        except Exception:
            port = 514
        return parse_ips_udp(port=port, timeout=udp_timeout)
    return None


if __name__ == "__main__":
    parse_ips()

