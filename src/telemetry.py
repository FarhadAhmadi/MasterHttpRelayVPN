"""
In-memory telemetry + admin surface for local monitoring.

No external dependencies: everything is standard library only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass
class _HostStats:
    requests: int = 0
    errors: int = 0
    req_bytes: int = 0
    resp_bytes: int = 0
    latency_ms_total: float = 0.0

    def as_dict(self, host: str) -> dict[str, Any]:
        avg_ms = (self.latency_ms_total / self.requests) if self.requests else 0.0
        return {
            "host": host,
            "requests": self.requests,
            "errors": self.errors,
            "req_bytes": self.req_bytes,
            "resp_bytes": self.resp_bytes,
            "avg_latency_ms": round(avg_ms, 2),
        }


class TelemetryStore:
    """Thread-safe enough for asyncio task concurrency on a single loop."""

    def __init__(
        self,
        *,
        max_recent_events: int = 2000,
        hash_hosts: bool = False,
        redact_query: bool = True,
        include_recent_paths: bool = False,
        bucket_seconds: int = 60,
        max_buckets: int = 180,
    ):
        self.started_at = time.time()
        self._lock = asyncio.Lock()
        self._hash_hosts = bool(hash_hosts)
        self._redact_query = bool(redact_query)
        self._include_recent_paths = bool(include_recent_paths)
        self._bucket_seconds = max(10, int(bucket_seconds))
        self._max_buckets = max(10, int(max_buckets))

        self.total_requests = 0
        self.total_errors = 0
        self.total_req_bytes = 0
        self.total_resp_bytes = 0

        self.method_counts: Counter[str] = Counter()
        self.status_counts: Counter[str] = Counter()
        self.route_counts: Counter[str] = Counter()
        self.cache_counts: Counter[str] = Counter()
        self.error_counts: Counter[str] = Counter()

        self._hosts: dict[str, _HostStats] = {}
        self._recent = deque(maxlen=max_recent_events)
        self._buckets = deque(maxlen=self._max_buckets)

    def _norm_host(self, host: str) -> str:
        h = (host or "unknown").lower().strip()
        if not self._hash_hosts:
            return h
        digest = hashlib.sha1(h.encode("utf-8", errors="ignore")).hexdigest()[:12]
        return f"host_{digest}"

    def _norm_path(self, url_or_path: str) -> str:
        if not url_or_path:
            return "/"
        if "://" in url_or_path:
            p = urlsplit(url_or_path)
            path = p.path or "/"
            if p.query and not self._redact_query:
                return f"{path}?{p.query}"
            if p.query and self._redact_query:
                return f"{path}?<redacted>"
            return path
        if "?" in url_or_path:
            path, query = url_or_path.split("?", 1)
            if query and self._redact_query:
                return f"{path}?<redacted>"
        return url_or_path

    def _rollup_bucket(self, now_ts: int, req_bytes: int, resp_bytes: int,
                       errored: bool) -> None:
        bucket_ts = now_ts - (now_ts % self._bucket_seconds)
        if not self._buckets or self._buckets[-1]["ts"] != bucket_ts:
            self._buckets.append({
                "ts": bucket_ts,
                "requests": 0,
                "errors": 0,
                "req_bytes": 0,
                "resp_bytes": 0,
            })
        b = self._buckets[-1]
        b["requests"] += 1
        b["req_bytes"] += req_bytes
        b["resp_bytes"] += resp_bytes
        if errored:
            b["errors"] += 1

    async def record_request(
        self,
        *,
        host: str,
        path: str,
        method: str,
        status: int,
        latency_ms: float,
        req_bytes: int,
        resp_bytes: int,
        route: str,
        cache_hit: bool = False,
        error_name: str = "",
    ) -> None:
        host = self._norm_host(host)
        path = self._norm_path(path)
        method = (method or "GET").upper()
        route = route or "relay"
        status_key = str(int(status)) if isinstance(status, int) else "0"
        req_bytes = max(0, int(req_bytes))
        resp_bytes = max(0, int(resp_bytes))
        latency_ms = max(0.0, float(latency_ms))

        async with self._lock:
            self.total_requests += 1
            self.total_req_bytes += req_bytes
            self.total_resp_bytes += resp_bytes
            self.method_counts[method] += 1
            self.status_counts[status_key] += 1
            self.route_counts[route] += 1
            self.cache_counts["hit" if cache_hit else "miss"] += 1

            if status >= 400:
                self.total_errors += 1
            if error_name:
                self.error_counts[error_name] += 1

            hs = self._hosts.get(host)
            if hs is None:
                hs = _HostStats()
                self._hosts[host] = hs
            hs.requests += 1
            hs.req_bytes += req_bytes
            hs.resp_bytes += resp_bytes
            hs.latency_ms_total += latency_ms
            if status >= 400:
                hs.errors += 1

            now_ts = int(time.time())
            self._rollup_bucket(now_ts, req_bytes, resp_bytes, status >= 400)
            self._recent.append({
                "ts": now_ts,
                "host": host,
                "path": path if self._include_recent_paths else "",
                "method": method,
                "status": status,
                "latency_ms": round(latency_ms, 2),
                "req_bytes": req_bytes,
                "resp_bytes": resp_bytes,
                "route": route,
                "cache_hit": bool(cache_hit),
                "error_name": error_name or "",
            })

    async def snapshot(self, *, top_hosts: int = 30, recent_limit: int = 100) -> dict[str, Any]:
        async with self._lock:
            hosts = [h.as_dict(host) for host, h in self._hosts.items()]
            hosts.sort(key=lambda row: row["resp_bytes"], reverse=True)
            recent = list(self._recent)[-max(1, int(recent_limit)):]

            return {
                "uptime_s": int(time.time() - self.started_at),
                "totals": {
                    "requests": self.total_requests,
                    "errors": self.total_errors,
                    "req_bytes": self.total_req_bytes,
                    "resp_bytes": self.total_resp_bytes,
                    "error_rate_pct": round(
                        (100.0 * self.total_errors / self.total_requests)
                        if self.total_requests else 0.0,
                        2,
                    ),
                },
                "methods": dict(self.method_counts),
                "statuses": dict(self.status_counts),
                "routes": dict(self.route_counts),
                "cache": dict(self.cache_counts),
                "errors": dict(self.error_counts),
                "top_hosts": hosts[:max(1, int(top_hosts))],
                "recent": recent,
                "timeseries": list(self._buckets),
                "privacy": {
                    "hash_hosts": self._hash_hosts,
                    "redact_query": self._redact_query,
                    "include_recent_paths": self._include_recent_paths,
                },
            }

    async def reset(self) -> None:
        async with self._lock:
            self.total_requests = 0
            self.total_errors = 0
            self.total_req_bytes = 0
            self.total_resp_bytes = 0
            self.method_counts.clear()
            self.status_counts.clear()
            self.route_counts.clear()
            self.cache_counts.clear()
            self.error_counts.clear()
            self._hosts.clear()
            self._recent.clear()
            self._buckets.clear()
            self.started_at = time.time()

    async def prometheus_text(self) -> str:
        snap = await self.snapshot(top_hosts=200, recent_limit=1)

        out = []
        out.append("# HELP mhrvpn_requests_total Total proxied HTTP requests")
        out.append("# TYPE mhrvpn_requests_total counter")
        out.append(f"mhrvpn_requests_total {snap['totals']['requests']}")
        out.append("# HELP mhrvpn_request_errors_total Total proxied HTTP requests with status >= 400")
        out.append("# TYPE mhrvpn_request_errors_total counter")
        out.append(f"mhrvpn_request_errors_total {snap['totals']['errors']}")
        out.append("# HELP mhrvpn_request_bytes_total Sum of incoming request payload bytes")
        out.append("# TYPE mhrvpn_request_bytes_total counter")
        out.append(f"mhrvpn_request_bytes_total {snap['totals']['req_bytes']}")
        out.append("# HELP mhrvpn_response_bytes_total Sum of outgoing response payload bytes")
        out.append("# TYPE mhrvpn_response_bytes_total counter")
        out.append(f"mhrvpn_response_bytes_total {snap['totals']['resp_bytes']}")

        out.append("# TYPE mhrvpn_requests_by_method_total counter")
        for method, count in sorted(snap["methods"].items()):
            out.append(f'mhrvpn_requests_by_method_total{{method="{method}"}} {count}')

        out.append("# TYPE mhrvpn_requests_by_status_total counter")
        for status, count in sorted(snap["statuses"].items()):
            out.append(f'mhrvpn_requests_by_status_total{{status="{status}"}} {count}')

        out.append("# TYPE mhrvpn_requests_by_route_total counter")
        for route, count in sorted(snap["routes"].items()):
            out.append(f'mhrvpn_requests_by_route_total{{route="{route}"}} {count}')

        out.append("# TYPE mhrvpn_cache_events_total counter")
        for event_name, count in sorted(snap["cache"].items()):
            out.append(f'mhrvpn_cache_events_total{{kind="{event_name}"}} {count}')

        out.append("# TYPE mhrvpn_host_response_bytes gauge")
        for row in snap["top_hosts"]:
            host = row["host"].replace("\\", "_").replace('"', "_")
            out.append(f'mhrvpn_host_response_bytes{{host="{host}"}} {row["resp_bytes"]}')

        return "\n".join(out) + "\n"

    async def recent_csv(self, *, limit: int = 500) -> bytes:
        rows = await self.snapshot(top_hosts=1, recent_limit=limit)
        out = [
            "ts,host,path,method,status,latency_ms,req_bytes,resp_bytes,route,cache_hit,error_name"
        ]
        for row in rows["recent"]:
            out.append(
                ",".join([
                    str(row.get("ts", "")),
                    str(row.get("host", "")).replace(",", "_"),
                    str(row.get("path", "")).replace(",", "_"),
                    str(row.get("method", "")),
                    str(row.get("status", "")),
                    str(row.get("latency_ms", "")),
                    str(row.get("req_bytes", "")),
                    str(row.get("resp_bytes", "")),
                    str(row.get("route", "")).replace(",", "_"),
                    "1" if row.get("cache_hit") else "0",
                    str(row.get("error_name", "")).replace(",", "_"),
                ])
            )
        return ("\n".join(out) + "\n").encode()

    @staticmethod
    def json_response(payload: dict[str, Any]) -> bytes:
        body = json.dumps(payload, ensure_ascii=True).encode()
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Cache-Control: no-store\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )


class JsonlTelemetryWriter:
    """Append-only JSONL writer with size-based rotation."""

    def __init__(self, path: str, *, max_bytes: int = 5 * 1024 * 1024,
                 backups: int = 3):
        self.path = path
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self.backups = max(1, int(backups))
        self._lock = asyncio.Lock()

    async def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=True) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._write_sync, line)

    def _rotate_sync(self) -> None:
        for idx in range(self.backups, 0, -1):
            old = f"{self.path}.{idx}"
            new = f"{self.path}.{idx + 1}"
            if idx == self.backups and os.path.exists(old):
                try:
                    os.remove(old)
                except OSError:
                    pass
            if os.path.exists(old):
                try:
                    os.replace(old, new)
                except OSError:
                    pass
        if os.path.exists(self.path):
            try:
                os.replace(self.path, f"{self.path}.1")
            except OSError:
                pass

    def _write_sync(self, line: str) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) >= self.max_bytes:
                self._rotate_sync()
        except OSError:
            pass
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
