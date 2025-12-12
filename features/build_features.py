"""
Feature engineering for anomaly detection.

Copyright (c) 2024 thanhpc187
See LICENSE file for license information.
Original repository: https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent
"""

from pathlib import Path
from typing import List
import logging
import pandas as pd
import re

from models.utils import get_paths, ensure_dir
from features.windowing import add_time_window_counts
from features.entropy import shannon_entropy
from features.sessionize import sessionize_network

logger = logging.getLogger(__name__)


def _add_rolling_nunique(
    df: pd.DataFrame,
    group_cols: list[str],
    ts_col: str,
    value_col: str,
    windows_min: list[int],
    prefix: str,
) -> pd.DataFrame:
    """Tính rolling số lượng giá trị duy nhất."""
    if df.empty or value_col not in df.columns:
        return df
    out = df.copy()
    out[ts_col] = pd.to_datetime(out[ts_col], utc=True, errors="coerce")
    out = out.dropna(subset=[ts_col]).sort_values(ts_col)
    idx = out.set_index(ts_col)
    for w in windows_min:
        colname = f"{prefix}_{w}m"
        try:
            rolled = (
                idx.groupby(group_cols)[value_col]
                .rolling(f"{w}min")
                .apply(lambda x: x.dropna().nunique(), raw=False)
                .reset_index(level=group_cols, drop=True)
            )
            out[colname] = rolled.values.astype("float64")
        except Exception:
            out[colname] = 0.0
    return out


def _add_time_window_sum(
    df: pd.DataFrame,
    group_cols: list[str],
    ts_col: str,
    value_col: str,
    windows_min: list[int],
) -> pd.DataFrame:
    """Tính rolling sum cho giá trị số (bytes/packets)."""
    if df.empty or value_col not in df.columns:
        return df
    out = df.copy()
    out[ts_col] = pd.to_datetime(out[ts_col], utc=True, errors="coerce")
    out = out.dropna(subset=[ts_col]).sort_values(ts_col)
    out[value_col] = pd.to_numeric(out[value_col], errors="coerce").fillna(0.0)
    idx = out.set_index(ts_col)
    for w in windows_min:
        colname = f"{value_col}_sum_{w}m"
        try:
            rolled = (
                idx.groupby(group_cols)[value_col]
                .rolling(f"{w}min")
                .sum()
                .reset_index(level=group_cols, drop=True)
            )
            out[colname] = rolled.values.astype("float64")
        except Exception:
            out[colname] = 0.0
    return out

def _list_sources(ecs_root: Path) -> List[str]:
    if not ecs_root.exists():
        return []
    return sorted([p.name for p in ecs_root.iterdir() if p.is_dir()])

def _available_dates(ecs_root: Path, sources: List[str]) -> List[str]:
    dts = set()
    for s in sources:
        base = ecs_root / s
        if not base.exists():
            continue
        for p in base.glob("dt=*"):
            if p.is_dir():
                dts.add(p.name.split("=", 1)[1])
    return sorted(dts)

def _read_partition(ecs_root: Path, dt: str, sources: List[str]) -> pd.DataFrame:
    """Đọc tất cả parquet files từ các sources cho một ngày cụ thể."""
    parts = []
    for s in sources:
        parts.extend((ecs_root / s / f"dt={dt}").glob("*.parquet"))
    if not parts:
        return pd.DataFrame()
    
    frames = []
    for p in parts:
        try:
            frames.append(pd.read_parquet(p))
        except (OSError, ValueError) as e:
            logger.warning(f"Không thể đọc {p}: {e}")
            continue
    
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)

def build_feature_table_large(sample_per_day: int = 100_000) -> Path:
    """
    Xây features theo từng ngày (partition) để tiết kiệm RAM; xuất gộp features.parquet nhỏ.
    """
    paths = get_paths()
    ecs_root = Path(paths["ecs_parquet_dir"]).resolve()
    feat_root = Path(paths["features_dir"]).resolve()
    ensure_dir(feat_root)

    sources = _list_sources(ecs_root)
    dates = _available_dates(ecs_root, sources)

    samples = []
    for dt in dates:
        ecs = _read_partition(ecs_root, dt, sources)
        if ecs.empty:
            continue

        # Chuẩn hoá thời gian
        if "@timestamp" in ecs.columns:
            ecs["@timestamp"] = pd.to_datetime(ecs["@timestamp"], utc=True, errors="coerce")
            ecs = ecs.dropna(subset=["@timestamp"]).sort_values("@timestamp")
        else:
            # Không có timestamp thì bỏ qua ngày này
            continue

        # ------------------------------------------------------------------
        # Flatten một số trường ECS lồng nhau (Elastic Agent gửi trực tiếp)
        # ------------------------------------------------------------------
        # Một số nguồn log (đặc biệt khi ingest trực tiếp từ Elasticsearch)
        # có trường dạng dict như: event:{action,code,outcome,...},
        # source:{ip,port}, destination:{ip,port}, network:{bytes,packets,...}.
        # Đoạn dưới sẽ "trải phẳng" các trường này ra dạng event.code,
        # source.ip, destination.port... nếu chưa tồn tại.

        def _flatten_prefix(col: str, keys: list[str]) -> None:
            if col not in ecs.columns:
                return
            ser = ecs[col]
            if not ser.map(lambda v: isinstance(v, dict)).any():
                return
            base = ser.apply(lambda v: v if isinstance(v, dict) else {})
            for k in keys:
                flat_col = f"{col}.{k}"
                if flat_col not in ecs.columns or ecs[flat_col].isna().all():
                    ecs[flat_col] = base.map(lambda d: d.get(k))

        _flatten_prefix("event", ["code", "outcome", "action", "dataset", "module", "severity"])
        _flatten_prefix("source", ["ip", "port"])
        _flatten_prefix("destination", ["ip", "port"])
        _flatten_prefix("network", ["bytes", "packets", "protocol", "transport"])

        # Bổ sung cột thiếu cần thiết cho feature engineering (sau khi flatten)
        required_cols = [
            "event.code",
            "event.outcome",
            "event.action",
            "event.module",
            "event.dataset",
            "event.severity",
            "destination.port",
            "network.protocol",
            "network.transport",
            "process.command_line",
            "process.name",  # process.name cần cho CBS windowing
            "host.name",
            "user.name",
            "source.ip",
            "source.port",  # Cần cho sessionize
            "destination.ip",  # Cần cho sessionize
            "network.bytes",
            "network.packets",
            "rule.id",
            "labels.is_attack",
            "labels.attack_type",
        ]
        for col in required_cols:
            if col not in ecs.columns:
                ecs[col] = None

        # Event flags
        ecs["login_failed"] = (
            (ecs["event.code"].astype(str) == "4625") |
            (ecs["event.outcome"].astype(str).str.lower() == "failure")
        ).fillna(False).astype(int)

        ecs["conn_suspicious"] = (
            (pd.to_numeric(ecs["destination.port"], errors="coerce") == 4444) |
            (ecs["event.outcome"].astype(str) == "S0")
        ).fillna(False).astype(int)

        # Firewall allow/deny flags
        action_lower = ecs["event.action"].astype(str).str.lower()
        ecs["action_allow"] = action_lower.isin(["allow", "allowed", "permit"]).astype(int)
        ecs["action_deny"] = action_lower.isin(["deny", "denied", "drop", "blocked", "reset"]).astype(int)

        # IPS alert flag (Suricata/Snort)
        ecs["ips_alert"] = ecs["event.module"].astype(str).str.lower().eq("ips").astype(int)

        # Entropy: ưu tiên command_line; nếu thiếu, dùng message (CBS thường không có command_line)
        ecs["process.command_line_entropy"] = ecs["process.command_line"].astype(str).apply(shannon_entropy)
        
        # Message entropy (an toàn với cột không tồn tại)
        if "message" in ecs.columns:
            ecs["message_entropy"] = ecs["message"].astype(str).apply(shannon_entropy)
        else:
            ecs["message_entropy"] = 0.0
        
        # Fallback entropy cho mô hình tổng quát: ưu tiên command_line, fallback message
        has_cmd = ecs["process.command_line"].astype(str).str.len() > 0
        ecs["text_entropy"] = ecs["process.command_line_entropy"].where(has_cmd, ecs["message_entropy"])

        # CBS-specific flags from message contents
        # cbs_failed: dòng có Error/Failed/hex code 0x.. trong CBS
        err_re = re.compile(r"(?i)(fail|error|0x[0-9a-f]{2,})")
        
        # Kiểm tra CBS event (an toàn với cột không tồn tại)
        is_cbs = pd.Series([False] * len(ecs), dtype=bool)
        if "event.module" in ecs.columns and "event.dataset" in ecs.columns:
            is_cbs = (
                ecs["event.module"].astype(str).str.lower().eq("windows")
                & ecs["event.dataset"].astype(str).str.lower().eq("cbs")
            )
        
        # Kiểm tra message có chứa error pattern
        has_error = pd.Series([False] * len(ecs), dtype=bool)
        if "message" in ecs.columns:
            has_error = ecs["message"].astype(str).str.contains(err_re, na=False)
        
        ecs["cbs_failed"] = (is_cbs & has_error).astype(int)

        # Sessionize (an toàn với exception)
        try:
            ecs = sessionize_network(ecs)
        except (ValueError, KeyError, AttributeError) as e:
            logger.warning(f"Lỗi sessionize cho dt={dt}: {e}. Gán session.id=None")
            if "session.id" not in ecs.columns:
                ecs["session.id"] = None

        # Rolling counts theo host và user cho các cờ tổng quát
        for flag in ["login_failed", "conn_suspicious", "action_deny", "action_allow", "ips_alert"]:
            ecs = add_time_window_counts(ecs, ["host.name"], "@timestamp", flag, [1, 5, 15])
            ecs = add_time_window_counts(ecs, ["user.name"], "@timestamp", flag, [1, 5, 15])
            ecs = add_time_window_counts(ecs, ["source.ip"], "@timestamp", flag, [1, 5, 15])
            ecs = add_time_window_counts(ecs, ["destination.ip"], "@timestamp", flag, [1, 5, 15])

        # Rolling counts cho CBS theo host và process.name
        for flag in ["cbs_failed"]:
            ecs = add_time_window_counts(ecs, ["host.name"], "@timestamp", flag, [1, 5, 15])
            ecs = add_time_window_counts(ecs, ["process.name"], "@timestamp", flag, [1, 5, 15])

        # Unique IP/port rolling metrics (network visibility)
        ecs = _add_rolling_nunique(ecs, ["source.ip"], "@timestamp", "destination.ip", [1, 5, 15], "uniq_dst_per_src")
        ecs = _add_rolling_nunique(ecs, ["destination.ip"], "@timestamp", "source.ip", [1, 5, 15], "uniq_src_per_dst")
        ecs = _add_rolling_nunique(ecs, ["source.ip"], "@timestamp", "destination.port", [1, 5, 15], "uniq_dport_per_src")

        # Bytes/packets rolling sums
        ecs = _add_time_window_sum(ecs, ["host.name"], "@timestamp", "network.bytes", [1, 5, 15])
        ecs = _add_time_window_sum(ecs, ["host.name"], "@timestamp", "network.packets", [1, 5, 15])
        ecs = _add_time_window_sum(ecs, ["source.ip"], "@timestamp", "network.bytes", [1, 5, 15])
        ecs = _add_time_window_sum(ecs, ["source.ip"], "@timestamp", "network.packets", [1, 5, 15])
        ecs = _add_time_window_sum(ecs, ["destination.ip"], "@timestamp", "network.bytes", [1, 5, 15])
        ecs = _add_time_window_sum(ecs, ["destination.ip"], "@timestamp", "network.packets", [1, 5, 15])

        # Drop/allow ratio (firewall effectiveness)
        for w in [1, 5, 15]:
            allow_col = f"action_allow_count_{w}m"
            deny_col = f"action_deny_count_{w}m"
            if allow_col in ecs.columns and deny_col in ecs.columns:
                ecs[f"deny_ratio_{w}m"] = ecs[deny_col] / (ecs[deny_col] + ecs[allow_col] + 1e-6)
        # Login failed ratio (bruteforce indicator): failed / (failed + allow + deny)
        for w in [1, 5, 15]:
            fail_col = f"login_failed_count_{w}m"
            allow_col = f"action_allow_count_{w}m"
            deny_col = f"action_deny_count_{w}m"
            if fail_col in ecs.columns and allow_col in ecs.columns and deny_col in ecs.columns:
                ecs[f"login_failed_ratio_{w}m"] = ecs[fail_col] / (ecs[fail_col] + ecs[allow_col] + ecs[deny_col] + 1e-6)

        # Chọn cột features đúng tên
        # Base features
        base_features = [
            "login_failed",
            "conn_suspicious",
            "action_allow",
            "action_deny",
            "ips_alert",
            "text_entropy",  # Entropy tổng quát (ưu tiên dùng trong model mới vì phù hợp cả CBS)
            "process.command_line_entropy",  # Giữ để tương thích ngược và cho ablation
            "message_entropy",
            "cbs_failed",
        ]
        
        # Window count features
        window_features = []
        windows = [1, 5, 15]
        flags_for_windowing = ["login_failed", "conn_suspicious", "cbs_failed", "action_allow", "action_deny", "ips_alert"]
        for w in windows:
            for flag in flags_for_windowing:
                col = f"{flag}_count_{w}m"
                if col in ecs.columns:
                    window_features.append(col)
        
        # Ratio & unique metrics
        ratio_features = [c for c in ecs.columns if c.startswith("deny_ratio_")]
        ratio_features += [c for c in ecs.columns if c.startswith("login_failed_ratio_")]
        uniq_features = [c for c in ecs.columns if c.startswith("uniq_")]
        traffic_sums = [c for c in ecs.columns if c.endswith(("_sum_1m", "_sum_5m", "_sum_15m"))]

        feature_cols = base_features + window_features + ratio_features + uniq_features + traffic_sums

        # ID columns
        id_cols = [
            "@timestamp",
            "host.name",
            "user.name",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "session.id",
            "event.action",
            "event.module",
            "event.dataset",
            "event.severity",
            "network.protocol",
            "labels.is_attack",
            "labels.attack_type",
        ]
        for c in id_cols:
            if c not in ecs.columns:
                ecs[c] = None

        feat = ecs[id_cols + feature_cols].copy()

        # Ghi per-partition
        out_dir = feat_root / f"dt={dt}"
        ensure_dir(out_dir)
        out_path = out_dir / "part.parquet"
        try:
            out_path.unlink(missing_ok=True)
            feat.to_parquet(out_path, index=False)
        except OSError as e:
            logger.error(f"Không thể ghi {out_path}: {e}")
            continue

        # Lấy mẫu để ghép ra features.parquet
        if sample_per_day > 0 and len(feat) > 0:
            k = min(sample_per_day, len(feat))
            samples.append(feat.sample(k, random_state=42))

    # Ghi bản gộp nhỏ
    out_all = feat_root / "features.parquet"
    if samples:
        pd.concat(samples, ignore_index=True).to_parquet(out_all, index=False)
    else:
        pd.DataFrame(columns=["@timestamp"]).to_parquet(out_all, index=False)
    return out_all

def build_feature_table() -> Path:
    """Wrapper để CLI gọi; mặc định dùng large-mode."""
    return build_feature_table_large()