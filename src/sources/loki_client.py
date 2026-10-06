"""Loki asynchronous query client with bounded intervals and saturation bisection."""

import logging
import asyncio
from typing import List, Tuple, Dict, Any, Optional
import httpx

logger = logging.getLogger(__name__)


class LokiClient:
    def __init__(
        self,
        base_url: str,
        user: Optional[str] = None,
        password: Optional[str] = None,
        bearer_token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        tls_verify: bool = True,
        timeout_seconds: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.bearer_token = bearer_token
        self.tenant_id = tenant_id
        self.tls_verify = tls_verify
        self.timeout = timeout_seconds

        auth = None
        if user and password:
            auth = httpx.BasicAuth(user, password)

        headers: Dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if tenant_id:
            headers["X-Scope-OrgID"] = tenant_id

        self._client = httpx.AsyncClient(
            auth=auth,
            headers=headers,
            verify=tls_verify,
            timeout=timeout_seconds,
        )

    async def close(self):
        await self._client.aclose()

    async def query_range(
        self,
        query: str,
        start_ns: int,
        end_ns: int,
        limit: int = 1000,
        direction: str = "forward",
    ) -> List[Tuple[int, str]]:
        """Query Loki query_range endpoint, returning list of (loki_ts_ns, raw_line)."""
        url = self.base_url
        if not url.endswith("/loki/api/v1/query_range"):
            if url.endswith("/loki/api/v1"):
                url = f"{url}/query_range"
            else:
                url = f"{url}/loki/api/v1/query_range"

        params = {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": direction,
        }

        try:
            resp = await self._client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("Loki query failed HTTP %s: %s", e.response.status_code, e.response.text[:200])
            raise
        except Exception as e:
            logger.error("Loki query error: %s", e)
            raise

        if data.get("status") != "success":
            err_text = data.get("message") or data.get("error") or str(data.get("status"))
            logger.error("Loki query failed with non-success status: %s", err_text)
            raise RuntimeError(f"Loki returned non-success envelope: {err_text}")

        streams = data.get("data", {}).get("result", [])
        results: List[Tuple[int, str]] = []
        for stream in streams:
            values = stream.get("values", [])
            for ts_str, raw_line in values:
                try:
                    ts_ns = int(ts_str)
                    results.append((ts_ns, raw_line))
                except ValueError:
                    continue

        return results

    async def query_range_safe(
        self,
        query: str,
        start_ns: int,
        end_ns: int,
        limit: int = 1000,
        min_window_ns: int = 2_000_000_000,  # 2 second bisection floor
        max_depth: int = 4,
        _depth: int = 0,
    ) -> Tuple[List[Tuple[int, str]], bool]:
        """Query Loki with automatic interval bisection if results hit the limit.
        
        Returns:
            (records, had_unresolvable_saturation)
        """
        records = await self.query_range(query, start_ns, end_ns, limit=limit, direction="forward")
        if len(records) < limit:
            return records, False

        # Interval saturated: bisect if window > min_window_ns and depth < max_depth
        window_size = end_ns - start_ns
        if window_size <= min_window_ns or _depth >= max_depth:
            logger.warning(
                "Query saturation limit reached in window [%s, %s] with %s entries (depth=%s)",
                start_ns, end_ns, len(records), _depth,
            )
            return records, True

        mid_ns = start_ns + (window_size // 2)
        logger.info(
            "Splitting saturated interval [%s, %s] (depth %s) into [%s, %s] and [%s, %s]",
            start_ns, end_ns, _depth, start_ns, mid_ns, mid_ns, end_ns,
        )

        left_records, left_sat = await self.query_range_safe(
            query, start_ns, mid_ns, limit, min_window_ns, max_depth, _depth + 1
        )
        right_records, right_sat = await self.query_range_safe(
            query, mid_ns, end_ns, limit, min_window_ns, max_depth, _depth + 1
        )

        combined = left_records + right_records
        return combined, (left_sat or right_sat)
