from typing import Any, Dict


def get_by_path(data: Dict[str, Any], path: str) -> Any:
    """
    Safely get value from nested dict using dot-path.
    Supports both nested dicts and flat keys that already contain dots.
    """
    if path in data:
        return data.get(path)
    cur: Any = data
    for key in path.split('.'):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def map_record(raw: Dict[str, Any], mapping_cfg: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    field_map: Dict[str, str] = mapping_cfg.get("map", {})

    for raw_key, ecs_key in field_map.items():
        value = get_by_path(raw, raw_key)
        if value is not None:
            out[ecs_key] = value

    # Prefer explicit timestamp source when present; fallback to any '@timestamp' already in mapped fields
    ts_path = mapping_cfg.get("timestamp")
    ts_value = None
    if ts_path:
        ts_value = get_by_path(raw, ts_path)
    if ts_value is None:
        ts_value = out.get("@timestamp") or get_by_path(raw, "@timestamp")
    out["@timestamp"] = ts_value

    return out
