"""
NIST CSF 2.0 mapper (nhẹ):

- Đọc mapping rules từ config/nist_csf_mapping.yaml
- Hiện tại hỗ trợ match theo danh sách kỹ thuật MITRE (techniques)
- Trả về danh sách function/category/subcategory mô tả biện pháp NIST liên quan
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from models.utils import CONFIG_DIR

_NIST_MAPPING_CACHE: Optional[List[Dict[str, Any]]] = None


def load_nist_mapping() -> List[Dict[str, Any]]:
    """Load + cache NIST CSF mapping config."""
    global _NIST_MAPPING_CACHE
    if _NIST_MAPPING_CACHE is not None:
        return _NIST_MAPPING_CACHE
    path = CONFIG_DIR / "nist_csf_mapping.yaml"
    if not path.exists():
        _NIST_MAPPING_CACHE = []
        return _NIST_MAPPING_CACHE
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
    if not isinstance(data, list):
        data = []
    _NIST_MAPPING_CACHE = data
    return _NIST_MAPPING_CACHE


def map_to_nist(
    alert: Dict[str, Any],
    mitre_hits: List[Dict[str, Any]],
    mapping_config: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Map alert + (tùy chọn) mitre_hits sang NIST CSF 2.0.
    Ưu tiên match theo danh sách techniques khai báo trong mapping_config.
    """
    mitre_ids = set()
    for h in mitre_hits or []:
        tid = (h.get("technique") or "").strip()
        if tid:
            mitre_ids.add(tid.upper())

    results: List[Dict[str, Any]] = []
    for rule in mapping_config or []:
        tech_list = rule.get("techniques") or []
        if tech_list and mitre_ids.isdisjoint({t.upper() for t in tech_list}):
            continue
        results.append(
            {
                "rule_id": rule.get("id"),
                "description": rule.get("description"),
                "function": rule.get("function"),
                "category": rule.get("category"),
                "subcategory": rule.get("subcategory"),
            }
        )
    return results


__all__ = ["load_nist_mapping", "map_to_nist"]

