from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
from dateutil import tz
from models.utils import get_paths
from parsers.base_reader import write_partitioned_parquet

# Traditional syslog auth format (e.g., "Jan 15 10:31:00 host sshd[pid]: msg")
SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<host>[^\s]+)\s(?P<proc>[^:]+):\s(?P<msg>.*)$"
)

# Windows CBS-like log lines (e.g., "2016-09-28 04:30:31, Info CBS Failed ...")
CBS_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s*'
    r'(?P<level>\w+)\s+'
    r'(?P<component>[A-Za-z0-9_.-]+)\s+'
    r'(?P<message>.*)$'
)

IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
USER_FAIL_RE = re.compile(r"Failed password for (?:invalid user\s+)?(?P<user>[\w\-\.\$]+)")
USER_OK_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>[\w\-\.\$]+)")
MONTH_MAP = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

# Năm mặc định cho syslog (log không có năm)
DEFAULT_SYSLOG_YEAR = int(os.getenv("SYSLOG_DEFAULT_YEAR", datetime.utcnow().year))

def _parse_ts(mon: str, day: str, hhmmss: str) -> Optional[pd.Timestamp]:
    """Parse 'Oct 01 10:02:00' -> UTC Timestamp với năm mặc định từ ENV."""
    try:
        year = DEFAULT_SYSLOG_YEAR
        dt_naive = datetime(year=year, month=MONTH_MAP[mon.title()], day=int(day))
        t = datetime.strptime(hhmmss, "%H:%M:%S").time()
        dt_local = datetime.combine(dt_naive, t)
        tzname = os.getenv("TZ", "UTC")
        local = tz.gettz(tzname) or tz.UTC
        dt_local = dt_local.replace(tzinfo=local)
        return pd.Timestamp(dt_local).tz_convert("UTC")
    except Exception:
        return None

def parse_auth_logs(root: Path = Path("sample_data")) -> Path:
    """
    Quét *.log đệ quy:
    - Syslog auth không có năm -> dùng SYSLOG_DEFAULT_YEAR
    - Windows CBS/CSI có năm đầy đủ -> giữ nguyên
    Ghi ra data/ecs_parquet/syslog_auth/dt=YYYY-MM-DD/
    """
    paths = get_paths()
    out_root = Path(paths["ecs_parquet_dir"]).resolve()
    log_files = list(root.rglob("*.log"))
    if not log_files:
        return out_root

    CHUNK_ROWS = int(os.getenv("CHUNK_ROWS", "200000"))
    buf: List[Dict] = []

    def _flush():
        nonlocal buf
        if not buf:
            return
        df = pd.DataFrame(buf); buf = []
        df = df.dropna(subset=["@timestamp"])
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["@timestamp"])
        if df.empty:
            return
        df["dt"] = df["@timestamp"].dt.strftime("%Y-%m-%d")
        keep_cols = [
            "@timestamp","event.module","event.dataset","event.action","event.outcome",
            "host.name","user.name","process.name","source.ip","message","log.file.path","dt"
        ]
        cols = [c for c in keep_cols if c in df.columns]
        # ghi partition theo dt dưới dataset 'syslog_auth'
        try:
            write_partitioned_parquet(df[cols], out_root, "syslog_auth")
        except TypeError:
            # fallback nếu hàm nhận 2 tham số (base_dir đã gồm dataset)
            write_partitioned_parquet(df[cols], out_root / "syslog_auth")

    for p in log_files:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.rstrip("\n")

                    # 1) Syslog auth
                    m = SYSLOG_RE.match(line)
                    if m:
                        gd = m.groupdict()
                        ts = _parse_ts(gd["mon"], gd["day"], gd["time"])
                        msg = gd.get("msg","")
                        proc = gd.get("proc")
                        outcome = None
                        user = None
                        if "Failed password" in msg or "authentication failure" in msg:
                            outcome = "Failure"
                            uf = USER_FAIL_RE.search(msg)
                            if uf:
                                user = uf.group("user")
                        elif "Accepted " in msg:
                            outcome = "Success"
                            uo = USER_OK_RE.search(msg)
                            if uo:
                                user = uo.group("user")

                        # Re-tag Cisco-like switch/syslog events so they appear as network device logs
                        # Example messages:
                        #   %LINK-3-UPDOWN: Interface Ethernet0/3, changed state to down
                        #   %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet0/3, changed state to down
                        #   %SYS-5-CONFIG_I: Configured from console by vty0
                        msg_u = msg.upper()
                        proc_u = (proc or "").upper()
                        is_auth = (
                            ("sshd" in (proc or "").lower())
                            or ("Failed password" in msg)
                            or ("Accepted " in msg)
                            or ("authentication failure" in msg)
                        )
                        is_switch = any(
                            x in msg_u or x in proc_u
                            for x in ["%LINK-", "%LINEPROTO-", "%SYS-", "%CONFIG_I", "%SEC-"]
                        )

                        event_module = "syslog"
                        event_dataset = "auth"
                        event_action = "user_login"
                        event_outcome = outcome
                        if (not is_auth) and is_switch:
                            event_module = "network"
                            event_dataset = "switch.syslog"
                            if "UPDOWN" in msg_u:
                                event_action = "interface_state"
                                event_outcome = "info"
                            elif "CONFIG" in msg_u:
                                event_action = "config_change"
                                event_outcome = "info"
                            else:
                                event_action = "syslog_event"
                                event_outcome = "info"
                        ip = None
                        ipm = IP_RE.search(msg)
                        if ipm:
                            ip = ipm.group("ip")

                        buf.append({
                            "@timestamp": ts.isoformat() if ts is not None else None,
                            "host.name": gd.get("host"),
                            "process.name": proc,
                            "message": msg,
                            "event.module": event_module,
                            "event.dataset": event_dataset,
                            "event.action": event_action,
                            "event.outcome": event_outcome,
                            "user.name": user,
                            "source.ip": ip,
                            "log.file.path": str(p),
                        })
                        if len(buf) >= CHUNK_ROWS:
                            _flush()
                        continue

                    # 2) Windows CBS/CSI
                    m2 = CBS_RE.match(line)
                    if m2:
                        gd = m2.groupdict()
                        ts = pd.to_datetime(gd["ts"], utc=True, errors="coerce")
                        level = gd.get("level")
                        component = gd.get("component")
                        msg = gd.get("message","")
                        ip = None
                        ipm = IP_RE.search(msg)
                        if ipm:
                            ip = ipm.group("ip")

                        outcome = "Failure" if ("Failed" in msg or "Error" in msg) else None
                        action = "system_update" if (component and ("CBS" in component or "CSI" in component)) else "log_event"

                        buf.append({
                            "@timestamp": ts.isoformat() if pd.notna(ts) else None,
                            "host.name": os.getenv("HOSTNAME", None),
                            "process.name": component,
                            "message": msg,
                            "event.module": "windows",
                            "event.dataset": "cbs",
                            "event.action": action,
                            "event.outcome": outcome or level,
                            "source.ip": ip,
                            "log.file.path": str(p),
                        })
                        if len(buf) >= CHUNK_ROWS:
                            _flush()
                        continue
            _flush()
        except Exception:
            continue

    return out_root

def parse_auth_log() -> Path:
    return parse_auth_logs(Path("sample_data"))