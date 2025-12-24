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


# ------------------------------------------------------------------
# Helpers for real-world ECS from Elastic/Logstash
# ------------------------------------------------------------------
def flatten_ecs_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flatten common nested ECS dict columns into dotted columns used by the pipeline.
    This is common when ingesting documents directly from Elasticsearch/Elastic Agent.
    """
    if df is None or df.empty:
        return df

    out = df

    def _flatten_prefix(col: str, keys: list[str]) -> None:
        if col not in out.columns:
            return
        ser = out[col]
        if not ser.map(lambda v: isinstance(v, dict)).any():
            return
        base = ser.apply(lambda v: v if isinstance(v, dict) else {})
        for k in keys:
            flat_col = f"{col}.{k}"
            if flat_col not in out.columns or out[flat_col].isna().all():
                out[flat_col] = base.map(lambda d: d.get(k))

    _flatten_prefix("event", ["code", "outcome", "action", "dataset", "module", "severity"])
    _flatten_prefix("source", ["ip", "port"])
    _flatten_prefix("destination", ["ip", "port"])
    _flatten_prefix("network", ["bytes", "packets", "protocol", "transport"])

    # Normalize ports to numeric to avoid parquet type errors (mixed str/int)
    for pcol in ["source.port", "destination.port"]:
        if pcol in out.columns:
            out[pcol] = pd.to_numeric(out[pcol], errors="coerce")

    return out


def add_basic_security_flags(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add base binary flags used by feature engineering and MITRE mapping:
    - login_failed, conn_suspicious, action_allow, action_deny, ips_alert, cbs_failed
    """
    if df is None or df.empty:
        return df

    out = df

    # login_failed: Windows 4625 OR event.outcome failure OR auth message heuristics (Ubuntu/SSH)
    msg = out["message"].astype(str) if "message" in out.columns else pd.Series([""] * len(out))
    msg_l = msg.str.lower()
    ssh_fail = msg_l.str.contains(r"failed password|authentication failure|invalid user", regex=True, na=False)
    outcome_fail = out["event.outcome"].astype(str).str.lower().eq("failure") if "event.outcome" in out.columns else False
    code_4625 = out["event.code"].astype(str).eq("4625") if "event.code" in out.columns else False
    out["login_failed"] = (code_4625 | outcome_fail | ssh_fail).fillna(False).astype(int)

    # conn_suspicious (demo)
    dport = pd.to_numeric(out["destination.port"], errors="coerce") if "destination.port" in out.columns else pd.Series([None] * len(out))
    out["conn_suspicious"] = ((dport == 4444) | (out["event.outcome"].astype(str) == "S0") if "event.outcome" in out.columns else (dport == 4444)).fillna(False).astype(int)

    # Firewall allow/deny flags (real logs: accept/close/allow/permit)
    action_lower = out["event.action"].astype(str).str.lower() if "event.action" in out.columns else pd.Series([""] * len(out))
    out["action_allow"] = action_lower.isin(["allow", "allowed", "permit", "accept", "close"]).astype(int)
    out["action_deny"] = action_lower.isin(["deny", "denied", "drop", "blocked", "reset"]).astype(int)

    # IPS alert flag (Suricata/Snort)
    out["ips_alert"] = out["event.module"].astype(str).str.lower().eq("ips").astype(int) if "event.module" in out.columns else 0

    # CBS-specific flags from message contents
    err_re = re.compile(r"(?i)(fail|error|0x[0-9a-f]{2,})")
    is_cbs = pd.Series([False] * len(out), dtype=bool)
    if "event.module" in out.columns and "event.dataset" in out.columns:
        is_cbs = (
            out["event.module"].astype(str).str.lower().eq("windows")
            & out["event.dataset"].astype(str).str.lower().eq("cbs")
        )
    has_error = msg.str.contains(err_re, na=False)
    out["cbs_failed"] = (is_cbs & has_error).astype(int)

    return out


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
                idx.groupby(group_cols, dropna=False)[value_col]
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
                idx.groupby(group_cols, dropna=False)[value_col]
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

        # Flatten nested ECS from Elasticsearch/Elastic Agent (event/source/destination/network dicts)
        ecs = flatten_ecs_columns(ecs)

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

        # Event flags (bruteforce/scan/allow-deny/IPS/CBS)
        ecs = add_basic_security_flags(ecs)

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

        # cbs_failed đã được tính trong add_basic_security_flags()

        # Sessionize (an toàn với exception)
        try:
            ecs = sessionize_network(ecs)
        except (ValueError, KeyError, AttributeError) as e:
            logger.warning(f"Lỗi sessionize cho dt={dt}: {e}. Gán session.id=None")
            if "session.id" not in ecs.columns:
                ecs["session.id"] = None

        # Canonical entity key for rolling counts:
        # - Prefer source.ip (network events, bruteforce SSH, scan)
        # - Fallback user.name (Windows 4625 bruteforce)
        # - Fallback host.name
        ecs["_entity_key"] = (
            ecs.get("source.ip", pd.Series([None] * len(ecs))).astype(str).replace({"None": None, "nan": None})
        )
        if "user.name" in ecs.columns:
            ecs["_entity_key"] = ecs["_entity_key"].where(ecs["_entity_key"].notna(), ecs["user.name"].astype(str))
        if "host.name" in ecs.columns:
            ecs["_entity_key"] = ecs["_entity_key"].where(ecs["_entity_key"].notna(), ecs["host.name"].astype(str))
        ecs["_entity_key"] = ecs["_entity_key"].fillna("unknown")

        # Rolling counts cho các cờ tổng quát
        # - Giữ bộ cột "canonical" (không suffix) theo source.ip để phục vụ rule MITRE (vd login_failed_count_5m)
        # - Đồng thời tạo thêm các biến thể có suffix theo host/user/destination để phân tích sâu hơn
        for flag in ["login_failed", "conn_suspicious", "action_deny", "action_allow", "ips_alert"]:
            # Canonical (dùng cho rule/mapping)
            ecs = add_time_window_counts(ecs, ["_entity_key"], "@timestamp", flag, [1, 5, 15], col_suffix=None)
            # Extra variants (không phá cột canonical)
            ecs = add_time_window_counts(ecs, ["host.name"], "@timestamp", flag, [1, 5, 15], col_suffix="host")
            ecs = add_time_window_counts(ecs, ["user.name"], "@timestamp", flag, [1, 5, 15], col_suffix="user")
            ecs = add_time_window_counts(ecs, ["destination.ip"], "@timestamp", flag, [1, 5, 15], col_suffix="dst")

        # Rolling counts cho CBS theo host và process.name (đặt suffix để tránh đè lên canonical của group khác)
        for flag in ["cbs_failed"]:
            ecs = add_time_window_counts(ecs, ["host.name"], "@timestamp", flag, [1, 5, 15], col_suffix="host")
            ecs = add_time_window_counts(ecs, ["process.name"], "@timestamp", flag, [1, 5, 15], col_suffix="proc")

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
        
        # Window count features (canonical + các biến thể theo host/user/dst)
        window_features = []
        windows = [1, 5, 15]
        flags_for_windowing = ["login_failed", "conn_suspicious", "cbs_failed", "action_allow", "action_deny", "ips_alert"]
        for w in windows:
            for flag in flags_for_windowing:
                # canonical (source.ip)
                col = f"{flag}_count_{w}m"
                if col in ecs.columns:
                    window_features.append(col)
                # variants
                for suf in ["host", "user", "dst", "proc"]:
                    vcol = f"{flag}_count_{suf}_{w}m"
                    if vcol in ecs.columns:
                        window_features.append(vcol)
        
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


def build_features_from_ecs_df(
    ecs: pd.DataFrame,
    *,
    window_start: str | None = None,
    window_end: str | None = None,
) -> pd.DataFrame:
    """
    Build features from an in-memory ECS dataframe.

    This is used for "window processing" (e.g., every 10 minutes):
    - You may fetch extra warmup events before window_start so rolling windows are correct.
    - After building features, this function can slice to [window_start, window_end].

    Args:
        ecs: ECS-like dataframe, ideally already containing @timestamp and ECS columns.
        window_start/window_end: optional ISO timestamps to slice output rows.
    Returns:
        Feature dataframe with id columns + engineered numeric features.
    """
    if ecs is None or ecs.empty:
        return pd.DataFrame()

    out = ecs.copy()

    # Timestamp normalization
    if "@timestamp" not in out.columns:
        return pd.DataFrame()
    out["@timestamp"] = pd.to_datetime(out["@timestamp"], utc=True, errors="coerce")
    out = out.dropna(subset=["@timestamp"]).sort_values("@timestamp")
    if out.empty:
        return pd.DataFrame()

    # Flatten nested ECS (common when ingesting from Elasticsearch)
    out = flatten_ecs_columns(out)

    # Ensure required columns exist (after flatten)
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
        "process.name",
        "host.name",
        "user.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "network.bytes",
        "network.packets",
        "rule.id",
        "labels.is_attack",
        "labels.attack_type",
    ]
    for col in required_cols:
        if col not in out.columns:
            out[col] = None

    # Flags
    out = add_basic_security_flags(out)

    # Entropy
    out["process.command_line_entropy"] = out["process.command_line"].astype(str).apply(shannon_entropy)
    if "message" in out.columns:
        out["message_entropy"] = out["message"].astype(str).apply(shannon_entropy)
    else:
        out["message_entropy"] = 0.0
    has_cmd = out["process.command_line"].astype(str).str.len() > 0
    out["text_entropy"] = out["process.command_line_entropy"].where(has_cmd, out["message_entropy"])

    # Sessionize (best-effort)
    try:
        out = sessionize_network(out)
    except (ValueError, KeyError, AttributeError) as e:
        logger.warning(f"sessionize failed: {e}. Setting session.id=None")
        if "session.id" not in out.columns:
            out["session.id"] = None

    # Canonical entity key used by rolling flags (source.ip preferred)
    out["_entity_key"] = out.get("source.ip", pd.Series([None] * len(out))).astype(str).replace({"None": None, "nan": None})
    if "user.name" in out.columns:
        out["_entity_key"] = out["_entity_key"].where(out["_entity_key"].notna(), out["user.name"].astype(str))
    if "host.name" in out.columns:
        out["_entity_key"] = out["_entity_key"].where(out["_entity_key"].notna(), out["host.name"].astype(str))
    out["_entity_key"] = out["_entity_key"].fillna("unknown")

    # Rolling counts for key flags
    for flag in ["login_failed", "conn_suspicious", "action_deny", "action_allow", "ips_alert"]:
        out = add_time_window_counts(out, ["_entity_key"], "@timestamp", flag, [1, 5, 15], col_suffix=None)
        out = add_time_window_counts(out, ["host.name"], "@timestamp", flag, [1, 5, 15], col_suffix="host")
        out = add_time_window_counts(out, ["user.name"], "@timestamp", flag, [1, 5, 15], col_suffix="user")
        out = add_time_window_counts(out, ["destination.ip"], "@timestamp", flag, [1, 5, 15], col_suffix="dst")

    for flag in ["cbs_failed"]:
        out = add_time_window_counts(out, ["host.name"], "@timestamp", flag, [1, 5, 15], col_suffix="host")
        out = add_time_window_counts(out, ["process.name"], "@timestamp", flag, [1, 5, 15], col_suffix="proc")

    # Unique rolling metrics
    out = _add_rolling_nunique(out, ["source.ip"], "@timestamp", "destination.ip", [1, 5, 15], "uniq_dst_per_src")
    out = _add_rolling_nunique(out, ["destination.ip"], "@timestamp", "source.ip", [1, 5, 15], "uniq_src_per_dst")
    out = _add_rolling_nunique(out, ["source.ip"], "@timestamp", "destination.port", [1, 5, 15], "uniq_dport_per_src")

    # Bytes/packets rolling sums
    out = _add_time_window_sum(out, ["host.name"], "@timestamp", "network.bytes", [1, 5, 15])
    out = _add_time_window_sum(out, ["host.name"], "@timestamp", "network.packets", [1, 5, 15])
    out = _add_time_window_sum(out, ["source.ip"], "@timestamp", "network.bytes", [1, 5, 15])
    out = _add_time_window_sum(out, ["source.ip"], "@timestamp", "network.packets", [1, 5, 15])
    out = _add_time_window_sum(out, ["destination.ip"], "@timestamp", "network.bytes", [1, 5, 15])
    out = _add_time_window_sum(out, ["destination.ip"], "@timestamp", "network.packets", [1, 5, 15])

    # Ratios
    for w in [1, 5, 15]:
        allow_col = f"action_allow_count_{w}m"
        deny_col = f"action_deny_count_{w}m"
        if allow_col in out.columns and deny_col in out.columns:
            out[f"deny_ratio_{w}m"] = out[deny_col] / (out[deny_col] + out[allow_col] + 1e-6)

    for w in [1, 5, 15]:
        fail_col = f"login_failed_count_{w}m"
        allow_col = f"action_allow_count_{w}m"
        deny_col = f"action_deny_count_{w}m"
        if fail_col in out.columns and allow_col in out.columns and deny_col in out.columns:
            out[f"login_failed_ratio_{w}m"] = out[fail_col] / (out[fail_col] + out[allow_col] + out[deny_col] + 1e-6)

    # Select feature columns (same logic as large mode)
    base_features = [
        "login_failed",
        "conn_suspicious",
        "action_allow",
        "action_deny",
        "ips_alert",
        "text_entropy",
        "process.command_line_entropy",
        "message_entropy",
        "cbs_failed",
    ]

    window_features: list[str] = []
    windows = [1, 5, 15]
    flags_for_windowing = ["login_failed", "conn_suspicious", "cbs_failed", "action_allow", "action_deny", "ips_alert"]
    for w in windows:
        for flag in flags_for_windowing:
            col = f"{flag}_count_{w}m"
            if col in out.columns:
                window_features.append(col)
            for suf in ["host", "user", "dst", "proc"]:
                vcol = f"{flag}_count_{suf}_{w}m"
                if vcol in out.columns:
                    window_features.append(vcol)

    ratio_features = [c for c in out.columns if c.startswith("deny_ratio_")]
    ratio_features += [c for c in out.columns if c.startswith("login_failed_ratio_")]
    uniq_features = [c for c in out.columns if c.startswith("uniq_")]
    traffic_sums = [c for c in out.columns if c.endswith(("_sum_1m", "_sum_5m", "_sum_15m"))]

    feature_cols = base_features + window_features + ratio_features + uniq_features + traffic_sums

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
        if c not in out.columns:
            out[c] = None

    feat = out[id_cols + feature_cols].copy()

    # Slice to window if requested
    if window_start or window_end:
        ws = pd.to_datetime(window_start, utc=True, errors="coerce") if window_start else None
        we = pd.to_datetime(window_end, utc=True, errors="coerce") if window_end else None
        if ws is not None:
            feat = feat[feat["@timestamp"] >= ws]
        if we is not None:
            feat = feat[feat["@timestamp"] <= we]

    return feat.reset_index(drop=True)