from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


@dataclass
class ElasticsearchTool:
    """
    Minimal Elasticsearch helper focused on time-range fetching with pagination.

    Notes:
    - Uses search_after (stateless) pagination.
    - Sorts by @timestamp asc, then _id asc for stable ordering.
    - Supports index patterns (wildcards) by passing them in the URL path.
    """

    host: str
    index_patterns: List[str]
    user: Optional[str] = None
    password: Optional[str] = None
    verify_tls: bool = False
    timeout_s: int = 30

    def _auth(self):
        return (self.user, self.password) if self.user else None

    def _index_path(self) -> str:
        # ES supports comma-separated patterns in the path; ensure URL encoding.
        raw = ",".join([p.strip() for p in self.index_patterns if p and p.strip()])
        return urllib.parse.quote(raw, safe="*,,-_./")

    def _request(
        self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None
    ) -> requests.Response:
        url = f"{self.host.rstrip('/')}/{path.lstrip('/')}"
        resp = requests.request(
            method=method.upper(),
            url=url,
            params=params or {},
            json=json_body,
            auth=self._auth(),
            timeout=self.timeout_s,
            verify=bool(self.verify_tls),
        )
        return resp

    def fetch_time_range_paged(
        self,
        *,
        start_ts: str,
        end_ts: str,
        time_field: str = "@timestamp",
        base_query: Optional[Dict[str, Any]] = None,
        page_size: int = 2000,
        max_docs: int = 200000,
        sleep_s: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """
        Fetch documents within [start_ts, end_ts] inclusive using search_after.

        Args:
            start_ts/end_ts: ISO8601 strings (ideally with Z or timezone offset).
            base_query: additional bool filter/query; will be AND-ed with range query.
            max_docs: hard cap for safety.
        Returns:
            List of _source dicts.
        """
        docs: List[Dict[str, Any]] = []
        search_after: Optional[List[Any]] = None

        # Default query: match_all with time range
        range_q = {"range": {time_field: {"gte": start_ts, "lte": end_ts}}}
        if base_query:
            q = {"bool": {"filter": [range_q, base_query]}}
        else:
            q = {"bool": {"filter": [range_q]}}

        sort_full = [{time_field: {"order": "asc"}}, {"_id": {"order": "asc"}}]
        sort_fallback = [{time_field: {"order": "asc"}}]

        def _page(sort_spec: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[List[Any]]]:
            nonlocal search_after
            body: Dict[str, Any] = {
                "size": int(page_size),
                "query": q,
                "sort": sort_spec,
            }
            if search_after is not None:
                body["search_after"] = search_after

            params = {
                "allow_no_indices": "true",
                "ignore_unavailable": "true",
            }
            idx = self._index_path()
            resp = self._request("POST", f"{idx}/_search", params=params, json_body=body)
            if resp.status_code >= 400:
                # Try to surface ES error body; keep it short-ish.
                try:
                    err = resp.json()
                    err_s = json.dumps(err, ensure_ascii=False)[:2000]
                except Exception:
                    err_s = (resp.text or "")[:2000]
                raise RuntimeError(f"Elasticsearch _search failed ({resp.status_code}): {err_s}")

            data = resp.json()
            hits = (data.get("hits") or {}).get("hits") or []
            out = []
            last_sort = None
            for h in hits:
                out.append(h.get("_source") or {})
                last_sort = h.get("sort")
            return out, last_sort

        while len(docs) < max_docs:
            try:
                batch, last_sort = _page(sort_full)
            except RuntimeError:
                # Retry with fallback sort if ES rejects _id sorting (some data streams / permissions).
                batch, last_sort = _page(sort_fallback)

            if not batch:
                break

            docs.extend(batch)
            search_after = last_sort
            if sleep_s:
                time.sleep(float(sleep_s))

            if len(batch) < page_size:
                break

        return docs[:max_docs]


