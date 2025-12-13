from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import os
from urllib.parse import quote
import requests

from models.utils import load_yaml


class ElasticsearchQueryError(RuntimeError):
    pass


def _iso(ts: Any) -> Optional[str]:
    try:
        if isinstance(ts, str) and ts:
            # Accept already ISO-like strings
            return ts
        if isinstance(ts, datetime):
            return ts.isoformat()
    except Exception:
        pass
    return None


@dataclass
class ElasticsearchTool:
    host: Optional[str]
    index_patterns: List[str]
    user: Optional[str] = None
    password: Optional[str] = None
    timeout_sec: int = 30
    verify_tls: bool = True

    def __post_init__(self) -> None:
        if not self.host:
            # Try config fallback
            cfg = load_yaml(Path(__file__).resolve().parents[2] / "config" / "paths.yaml")
            self.host = cfg.get("elastic_host")
            if not self.index_patterns:
                self.index_patterns = cfg.get("elastic_index_patterns") or []
            if not self.user:
                self.user = cfg.get("elastic_user")
            if not self.password:
                self.password = cfg.get("elastic_password")
        # TLS verify toggle: default True; allow env ELASTIC_VERIFY=false
        v = str(os.getenv("ELASTIC_VERIFY", "true")).strip().lower()
        self.verify_tls = False if v in ("0", "false", "no") else True

    @property
    def _auth(self) -> Optional[Tuple[str, str]]:
        if self.user:
            return (self.user, self.password or "")
        return None

    def _index_expr(self, index: str | List[str]) -> str:
        if isinstance(index, list):
            expr = ",".join([x for x in index if x])
        else:
            expr = index
        # URL-encode the index expression for safe path usage (keep wildcards, commas)
        return quote(expr, safe="*,,-_")

    def search(self, *, index: str | List[str], query: Dict[str, Any], size: int = 200) -> List[Dict[str, Any]]:
        if not self.host:
            return []
        idx = self._index_expr(index)
        # allow_no_indices avoids hard failure when some patterns don't exist yet
        url = f"{self.host.rstrip('/')}/{idx}/_search?allow_no_indices=true&ignore_unavailable=true"
        payload = {
            "size": int(size),
            "query": query,
            "track_total_hits": False,
            "sort": [{"@timestamp": {"order": "desc"}}, {"_id": {"order": "desc"}}],
        }
        try:
            resp = requests.post(url, json=payload, auth=self._auth, timeout=self.timeout_sec, verify=self.verify_tls)
            if resp.status_code >= 400:
                raise ElasticsearchQueryError(f"HTTP {resp.status_code}: {resp.text[:800]}")
            body = resp.json()
        except Exception as e:
            raise ElasticsearchQueryError(f"Elasticsearch search failed: {e}") from e
        hits = body.get("hits", {}).get("hits", []) or []
        out: List[Dict[str, Any]] = []
        for h in hits:
            src = h.get("_source") or {}
            if isinstance(src, dict):
                out.append(src)
        return out

    def search_after_iter(
        self,
        *,
        index: str | List[str],
        query: Dict[str, Any],
        sort: List[Dict[str, Any]],
        page_size: int = 1000,
        max_docs: int = 20000,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Pagination using search_after. Returns (records, meta).
        meta: {fetched, truncated, pages}
        """
        if not self.host:
            return [], {"fetched": 0, "truncated": False, "pages": 0}
        idx = self._index_expr(index)
        url = f"{self.host.rstrip('/')}/{idx}/_search?allow_no_indices=true&ignore_unavailable=true"
        search_after = None
        fetched = 0
        pages = 0
        records: List[Dict[str, Any]] = []
        truncated = False
        while True:
            payload: Dict[str, Any] = {"size": int(page_size), "query": query, "sort": sort}
            if search_after is not None:
                payload["search_after"] = search_after
            try:
                resp = requests.post(url, json=payload, auth=self._auth, timeout=self.timeout_sec, verify=self.verify_tls)
                if resp.status_code >= 400:
                    raise ElasticsearchQueryError(f"HTTP {resp.status_code}: {resp.text[:800]}")
                body = resp.json()
            except Exception as e:
                raise ElasticsearchQueryError(f"Elasticsearch paged search failed: {e}") from e
            hits = body.get("hits", {}).get("hits", []) or []
            pages += 1
            if not hits:
                break
            for h in hits:
                src = h.get("_source") or {}
                if isinstance(src, dict):
                    records.append(src)
                    fetched += 1
                    if fetched >= int(max_docs):
                        truncated = True
                        break
            if truncated:
                break
            search_after = hits[-1].get("sort")
            if not search_after:
                break
        return records, {"fetched": fetched, "truncated": truncated, "pages": pages}

    def context_for_alert(
        self,
        alert: Dict[str, Any],
        *,
        window_minutes: int = 5,
        size: int = 200,
    ) -> List[Dict[str, Any]]:
        """
        Tool: query Elasticsearch for context logs around alert.
        Strategy:
        - time range ±window
        - should match any of: source.ip, destination.ip, user.name, host.name
        """
        if not self.index_patterns:
            return []
        ts_raw = alert.get("@timestamp")
        ts_str = _iso(ts_raw)
        if not ts_str:
            # if cannot parse, fallback to now-ish
            ts_str = datetime.utcnow().isoformat() + "Z"
        try:
            # Parse to datetime for range computation
            t0 = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            t0 = datetime.utcnow()
        gte = (t0 - timedelta(minutes=int(window_minutes))).isoformat()
        lte = (t0 + timedelta(minutes=int(window_minutes))).isoformat()

        should: List[Dict[str, Any]] = []
        for k in ("source.ip", "destination.ip", "user.name", "host.name"):
            v = alert.get(k)
            if v is None or str(v).strip() == "":
                continue
            should.append({"term": {k: v}})

        query: Dict[str, Any] = {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}],
            }
        }
        if should:
            query["bool"]["should"] = should
            query["bool"]["minimum_should_match"] = 1

        merged: List[Dict[str, Any]] = []
        for pat in self.index_patterns:
            try:
                merged.extend(self.search(index=pat, query=query, size=size))
            except Exception:
                continue
        return merged[: int(size)]

    def fetch_time_range(
        self,
        *,
        gte: str,
        lte: str,
        size: int = 10000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch ECS docs in a time range across configured index patterns.
        This is used by 15-minute window reporting with warmup/lookback.
        """
        if not self.index_patterns:
            return []
        query: Dict[str, Any] = {"bool": {"filter": [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}]}}
        # Backward compatible: single-shot, no pagination
        return self.search(index=self.index_patterns, query=query, size=size)

    def fetch_time_range_paged(
        self,
        *,
        gte: str,
        lte: str,
        page_size: int = 1000,
        max_docs: int = 20000,
        order: str = "asc",
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Fetch time range with pagination.
        order: asc recommended for window reporting.
        """
        if not self.index_patterns:
            return [], {"fetched": 0, "truncated": False, "pages": 0}
        query: Dict[str, Any] = {"bool": {"filter": [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}]}}
        # Primary: timestamp + _id tiebreaker (recommended if supported)
        sort_primary = [{"@timestamp": {"order": order}}, {"_id": {"order": order}}]
        try:
            return self.search_after_iter(
                index=self.index_patterns,
                query=query,
                sort=sort_primary,
                page_size=page_size,
                max_docs=max_docs,
            )
        except ElasticsearchQueryError as e:
            # Some ES setups reject sorting on _id. Fallback to timestamp-only pagination.
            sort_fallback = [{"@timestamp": {"order": order}}]
            return self.search_after_iter(
                index=self.index_patterns,
                query=query,
                sort=sort_fallback,
                page_size=page_size,
                max_docs=max_docs,
            )


