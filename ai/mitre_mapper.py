"""
MITRE ATT&CK mapper

- Đọc mapping rules từ config/mitre_mapping.yaml
- Kiểm tra conditions trên alert/features để gán tactic/technique
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from models.utils import CONFIG_DIR

_MAPPING_CACHE: Optional[List[Dict[str, Any]]] = None

_NUM_RE = re.compile(r"^\s*(>=|<=|==|>|<)\s*([\-+]?\d+(?:\.\d+)?)\s*$")


def load_mitre_mapping() -> List[Dict[str, Any]]:
    """Load + cache mapping config."""
    global _MAPPING_CACHE
    if _MAPPING_CACHE is not None:
        return _MAPPING_CACHE
    path = CONFIG_DIR / "mitre_mapping.yaml"
    if not path.exists():
        _MAPPING_CACHE = []
        return _MAPPING_CACHE
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
    if not isinstance(data, list):
        data = []
    _MAPPING_CACHE = data
    return _MAPPING_CACHE


def _get_val(obj: Dict[str, Any], key: str) -> Any:
    """
    Lấy giá trị từ dict hỗ trợ cả:
    - Kiểu "phẳng" từ DataFrame (key có dấu chấm, ví dụ "labels.attack_type")
    - Kiểu lồng nhau theo dot-path (record["labels"]["attack_type"])
    """
    if not isinstance(obj, dict):
        return None

    # 1) Thử key phẳng trước (phù hợp với dict từ DataFrame.to_dict)
    if key in obj:
        return obj[key]

    # 2) Nếu không có, thử truy cập lồng nhau theo dot-path
    cur: Any = obj
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_numeric(actual: Any, cond: str) -> bool:
    m = _NUM_RE.match(cond)
    if not m:
        return False
    op, num_s = m.groups()
    try:
        actual_f = float(actual)
        target = float(num_s)
    except Exception:
        return False
    if op == ">":
        return actual_f > target
    if op == ">=":
        return actual_f >= target
    if op == "<":
        return actual_f < target
    if op == "<=":
        return actual_f <= target
    if op == "==":
        return actual_f == target
    return False


def _match_value(actual: Any, cond_val: Any) -> bool:
    """Match condition vs actual value."""
    if cond_val is None:
        return False
    # Numeric comparator in string
    if isinstance(cond_val, str) and _NUM_RE.match(cond_val):
        return _match_numeric(actual, cond_val)
    # List -> membership (case-insensitive for str)
    if isinstance(cond_val, list):
        for v in cond_val:
            if isinstance(v, str) and isinstance(actual, str):
                if actual.lower() == v.lower():
                    return True
            else:
                if actual == v:
                    return True
        return False
    # String equality (case-insensitive)
    if isinstance(cond_val, str):
        if isinstance(actual, str):
            return actual.lower() == cond_val.lower()
        return False
    # Fallback exact match
    return actual == cond_val


def _conditions_pass(rule_conditions: Dict[str, Any], record: Dict[str, Any]) -> bool:
    for field, cond in (rule_conditions or {}).items():
        actual = _get_val(record, field)
        # Nếu field không tồn tại hoặc None, xem như không match
        if actual is None:
            return False
        if not _match_value(actual, cond):
            return False
    return True


def map_to_mitre(alert: Dict[str, Any], features: Optional[Dict[str, Any]], mapping_config: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map alert/features to MITRE techniques based on mapping config.
    Returns list of dicts with rule_id, tactic, technique, subtechnique, description.
    """
    record: Dict[str, Any] = {}
    record.update(features or {})
    record.update(alert or {})

    hits: List[Dict[str, Any]] = []
    for rule in mapping_config or []:
        conditions = rule.get("conditions", {})
        if not isinstance(conditions, dict):
            continue
        if _conditions_pass(conditions, record):
            hits.append(
                {
                    "rule_id": rule.get("id"),
                    "description": rule.get("description"),
                    "tactic": rule.get("tactic"),
                    "technique": rule.get("technique"),
                    "subtechnique": rule.get("subtechnique"),
                }
            )
    return hits


__all__ = ["load_mitre_mapping", "map_to_mitre"]

