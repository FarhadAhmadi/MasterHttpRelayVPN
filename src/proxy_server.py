"""
Local HTTP proxy server.

Intercepts the user's browser traffic and forwards everything through
the Apps Script relay (MITM-decrypts HTTPS locally, forwards requests
as JSON to script.google.com fronted through www.google.com).
"""

import asyncio
import base64
import hmac
import json
import logging
import os
import re
import socket
import ssl
import time
import ipaddress
from collections import Counter
from fnmatch import fnmatch
from urllib.parse import urlparse

try:
    import certifi
except Exception:  # optional dependency fallback
    certifi = None

from constants import (
    CACHE_MAX_MB,
    CACHE_TTL_MAX,
    CACHE_TTL_STATIC_LONG,
    CACHE_TTL_STATIC_MED,
    CLIENT_IDLE_TIMEOUT,
    GOOGLE_DIRECT_ALLOW_EXACT,
    GOOGLE_DIRECT_ALLOW_SUFFIXES,
    GOOGLE_DIRECT_EXACT_EXCLUDE,
    GOOGLE_DIRECT_SUFFIX_EXCLUDE,
    GOOGLE_OWNED_EXACT,
    GOOGLE_OWNED_SUFFIXES,
    LARGE_FILE_EXTS,
    MAX_HEADER_BYTES,
    MAX_REQUEST_BODY_BYTES,
    SNI_REWRITE_SUFFIXES,
    STATIC_EXTS,
    TCP_CONNECT_TIMEOUT,
    TRACE_HOST_SUFFIXES,
    UNCACHEABLE_HEADER_NAMES,
)
from domain_fronter import DomainFronter
from telemetry import JsonlTelemetryWriter, TelemetryStore

log = logging.getLogger("Proxy")


def _is_ip_literal(host: str) -> bool:
    """True for IPv4/IPv6 literals (strips brackets around IPv6)."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _parse_content_length(header_block: bytes) -> int:
    """Return Content-Length or 0. Matches only the exact header name."""
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def _has_unsupported_transfer_encoding(header_block: bytes) -> bool:
    """True when the request uses Transfer-Encoding, which we don't stream."""
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() != b"transfer-encoding":
            continue
        encodings = [
            token.strip().lower()
            for token in value.decode(errors="replace").split(",")
            if token.strip()
        ]
        return any(token != "identity" for token in encodings)
    return False


class ResponseCache:
    """Simple LRU response cache — avoids repeated relay calls."""

    def __init__(self, max_mb: int = 50):
        self._store: dict[str, tuple[bytes, float]] = {}
        self._size = 0
        self._max = max_mb * 1024 * 1024
        self.hits = 0
        self.misses = 0

    def get(self, url: str) -> bytes | None:
        entry = self._store.get(url)
        if not entry:
            self.misses += 1
            return None
        raw, expires = entry
        if time.time() > expires:
            self._size -= len(raw)
            del self._store[url]
            self.misses += 1
            return None
        self.hits += 1
        return raw

    def put(self, url: str, raw_response: bytes, ttl: int = 300):
        size = len(raw_response)
        if size > self._max // 4 or size == 0:
            return
        # Evict oldest to make room
        while self._size + size > self._max and self._store:
            oldest = next(iter(self._store))
            self._size -= len(self._store[oldest][0])
            del self._store[oldest]
        if url in self._store:
            self._size -= len(self._store[url][0])
        self._store[url] = (raw_response, time.time() + ttl)
        self._size += size

    def clear(self, *, reset_stats: bool = False) -> None:
        self._store.clear()
        self._size = 0
        if reset_stats:
            self.hits = 0
            self.misses = 0

    @staticmethod
    def parse_ttl(raw_response: bytes, url: str) -> int:
        """Determine cache TTL from response headers and URL."""
        hdr_end = raw_response.find(b"\r\n\r\n")
        if hdr_end < 0:
            return 0
        hdr = raw_response[:hdr_end].decode(errors="replace").lower()

        # Don't cache errors or non-200
        if b"HTTP/1.1 200" not in raw_response[:20]:
            return 0
        if "no-store" in hdr or "private" in hdr or "set-cookie:" in hdr:
            return 0

        # Explicit max-age
        m = re.search(r"max-age=(\d+)", hdr)
        if m:
            return min(int(m.group(1)), CACHE_TTL_MAX)

        # Heuristic by content type / extension
        path = url.split("?")[0].lower()
        for ext in STATIC_EXTS:
            if path.endswith(ext):
                return CACHE_TTL_STATIC_LONG

        ct_m = re.search(r"content-type:\s*([^\r\n]+)", hdr)
        ct = ct_m.group(1) if ct_m else ""
        if "image/" in ct or "font/" in ct:
            return CACHE_TTL_STATIC_LONG
        if "text/css" in ct or "javascript" in ct:
            return CACHE_TTL_STATIC_MED
        if "text/html" in ct or "application/json" in ct:
            return 0  # don't cache dynamic content by default

        return 0


class ProxyServer:
    # Pulled from constants.py so users can override any subset via config.
    _GOOGLE_DIRECT_EXACT_EXCLUDE  = GOOGLE_DIRECT_EXACT_EXCLUDE
    _GOOGLE_DIRECT_SUFFIX_EXCLUDE = GOOGLE_DIRECT_SUFFIX_EXCLUDE
    _GOOGLE_DIRECT_ALLOW_EXACT    = GOOGLE_DIRECT_ALLOW_EXACT
    _GOOGLE_DIRECT_ALLOW_SUFFIXES = GOOGLE_DIRECT_ALLOW_SUFFIXES
    _TRACE_HOST_SUFFIXES          = TRACE_HOST_SUFFIXES
    _DOWNLOAD_DEFAULT_EXTS        = tuple(sorted(LARGE_FILE_EXTS))
    _DOWNLOAD_ACCEPT_MARKERS      = (
        "application/octet-stream",
        "application/zip",
        "application/x-bittorrent",
        "video/",
        "audio/",
    )
    _TELEGRAM_SUFFIXES = (
        "telegram.org",
        "telegram.me",
        "t.me",
        "telegra.ph",
        "tdesktop.com",
    )

    def __init__(self, config: dict):
        self._config = dict(config)
        self._config_path = str(config.get("_config_path", "")).strip()
        self.host = config.get("listen_host", "127.0.0.1")
        self.port = config.get("listen_port", 8080)
        self.socks_enabled = config.get("socks5_enabled", True)
        self.socks_host = config.get("socks5_host", self.host)
        self.socks_port = config.get("socks5_port", 1080)
        if self.socks_enabled and self.socks_host == self.host \
                and int(self.socks_port) == int(self.port):
            raise ValueError(
                f"listen_port and socks5_port must differ on the same host "
                f"(both set to {self.port} on {self.host}). "
                f"Change one of them in config.json."
            )
        self.fronter = DomainFronter(config)
        self.mitm = None
        self._cache = ResponseCache(max_mb=CACHE_MAX_MB)
        self._direct_fail_until: dict[str, float] = {}
        self._direct_fail_score: dict[str, int] = {}
        self._servers: list[asyncio.base_events.Server] = []
        self._client_tasks: set[asyncio.Task] = set()
        self._route_decisions: Counter[str] = Counter()
        self._telegram_counters: Counter[str] = Counter()
        self._telemetry = TelemetryStore(
            max_recent_events=self._cfg_int(
                config, "metrics_max_recent_events", 2000, minimum=200,
            ),
            hash_hosts=bool(config.get("metrics_hash_hosts", False)),
            redact_query=bool(config.get("metrics_redact_query", True)),
            include_recent_paths=bool(config.get("metrics_include_recent_paths", False)),
            bucket_seconds=self._cfg_int(
                config, "metrics_bucket_seconds", 60, minimum=10,
            ),
            max_buckets=self._cfg_int(
                config, "metrics_max_buckets", 180, minimum=10,
            ),
        )
        self._telemetry_jsonl_writer = None
        if bool(config.get("telemetry_jsonl_enabled", False)):
            self._telemetry_jsonl_writer = JsonlTelemetryWriter(
                str(config.get("telemetry_jsonl_path", "logs/telemetry.jsonl")),
                max_bytes=self._cfg_int(
                    config, "telemetry_jsonl_max_bytes", 5 * 1024 * 1024,
                    minimum=64 * 1024,
                ),
                backups=self._cfg_int(
                    config, "telemetry_jsonl_backups", 3, minimum=1,
                ),
            )
        self._admin_enabled = bool(config.get("admin_enabled", True))
        self._admin_host = str(config.get("admin_host", "127.0.0.1"))
        self._admin_port = self._cfg_int(
            config, "admin_port", 9090, minimum=1,
        )
        self._admin_token = str(config.get("admin_token", "")).strip()
        self._admin_token_scopes = self._normalize_admin_token_scopes(
            config.get("admin_token_scopes", {})
        )
        self._proxy_auth_enabled = bool(config.get("proxy_auth_enabled", False))
        self._proxy_username = str(config.get("proxy_username", ""))
        self._proxy_password = str(config.get("proxy_password", ""))
        self._telegram_desktop_mode = bool(config.get("telegram_desktop_mode", False))
        self._self_heal_enabled = bool(config.get("self_heal_enabled", True))
        self._self_heal_window_s = self._cfg_int(
            config, "self_heal_window_s", 120, minimum=10,
        )
        self._self_heal_error_threshold = self._cfg_int(
            config, "self_heal_error_threshold", 5, minimum=2,
        )
        self._host_relay_errors: dict[str, list[float]] = {}
        self._auto_tune_events: Counter[str] = Counter()
        self._tcp_connect_timeout = self._cfg_float(
            config, "tcp_connect_timeout", TCP_CONNECT_TIMEOUT, minimum=1.0,
        )
        self._download_min_size = self._cfg_int(
            config, "chunked_download_min_size", 5 * 1024 * 1024, minimum=0,
        )
        self._download_chunk_size = self._cfg_int(
            config, "chunked_download_chunk_size", 512 * 1024, minimum=64 * 1024,
        )
        self._download_max_parallel = self._cfg_int(
            config, "chunked_download_max_parallel", 8, minimum=1,
        )
        self._download_max_chunks = self._cfg_int(
            config, "chunked_download_max_chunks", 256, minimum=1,
        )
        self._download_extensions, self._download_any_extension = (
            self._normalize_download_extensions(
                config.get(
                    "chunked_download_extensions",
                    list(self._DOWNLOAD_DEFAULT_EXTS),
                )
            )
        )
        self._route_rules_file = str(config.get("route_rules_file", "route_rules.txt"))
        self._route_rules = self._load_route_rules(self._route_rules_file)

        # hosts override — DNS fake-map: domain/suffix → IP
        # Checked before any real DNS lookup; supports exact and suffix matching.
        self._hosts: dict[str, str] = config.get("hosts", {})
        configured_direct_exclude = config.get("direct_google_exclude", [])
        self._direct_google_exclude = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_EXACT_EXCLUDE) +
                list(configured_direct_exclude)
            )
        }
        configured_direct_allow = config.get("direct_google_allow", [])
        self._direct_google_allow = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_ALLOW_EXACT) +
                list(configured_direct_allow)
            )
        }

        # ── Per-host policy ────────────────────────────────────────
        # block_hosts  — refuse traffic entirely (close or 403)
        # bypass_hosts — route directly (no MITM, no relay)
        # Both accept exact hostnames and leading-dot suffix patterns,
        # e.g. ".local" matches any *.local domain.
        self._block_hosts  = self._load_host_rules(config.get("block_hosts", []))
        self._bypass_hosts = self._load_host_rules(config.get("bypass_hosts", []))

        # Route YouTube through the relay when requested; the Google frontend
        # IP can enforce SafeSearch on the SNI-rewrite path.
        if config.get("youtube_via_relay", False):
            self._SNI_REWRITE_SUFFIXES = tuple(
                s for s in SNI_REWRITE_SUFFIXES
                if s not in self._YOUTUBE_SNI_SUFFIXES
            )
            log.info("youtube_via_relay enabled — YouTube routed through relay")
        else:
            self._SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

        if self._telegram_desktop_mode:
            log.info(
                "telegram_desktop_mode enabled — SOCKS IP-literal flows fail fast "
                "on blocked DCs so Telegram can rotate endpoints quicker"
            )

        try:
            from mitm import MITMCertManager
            self.mitm = MITMCertManager()
        except ImportError:
            log.error("Apps Script relay requires the 'cryptography' package.")
            log.error("Run: pip install cryptography")
            raise SystemExit(1)

    # ── Host-policy helpers ───────────────────────────────────────

    @staticmethod
    def _cfg_int(config: dict, key: str, default: int, *, minimum: int = 1) -> int:
        try:
            value = int(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @staticmethod
    def _cfg_float(config: dict, key: str, default: float,
                   *, minimum: float = 0.1) -> float:
        try:
            value = float(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @staticmethod
    def _scope_expand(level: str) -> set[str]:
        if level == "admin":
            return {"read", "write", "admin"}
        if level == "write":
            return {"read", "write"}
        return {"read"}

    @staticmethod
    def _scope_normalize_name(raw: str) -> str:
        token = str(raw).strip().lower()
        if token in {"admin", "owner", "root", "all", "full"}:
            return "admin"
        if token in {"write", "operator", "ops"}:
            return "write"
        return "read"

    @classmethod
    def _normalize_admin_token_scopes(cls, raw) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        if not isinstance(raw, dict):
            return out
        for token, scopes in raw.items():
            key = str(token or "").strip()
            if not key:
                continue
            allowed = set()
            if isinstance(scopes, str):
                allowed |= cls._scope_expand(cls._scope_normalize_name(scopes))
            elif isinstance(scopes, (list, tuple)):
                for item in scopes:
                    allowed |= cls._scope_expand(cls._scope_normalize_name(str(item)))
            if not allowed:
                allowed = {"read"}
            out[key] = allowed
        return out

    def _admin_auth(self, supplied_token: str) -> tuple[bool, set[str]]:
        token = str(supplied_token or "").strip()
        if not self._admin_token and not self._admin_token_scopes:
            return True, {"read", "write", "admin"}
        if token and token in self._admin_token_scopes:
            return True, set(self._admin_token_scopes[token])
        if token and self._admin_token and hmac.compare_digest(token, self._admin_token):
            return True, {"read", "write", "admin"}
        return False, set()

    @staticmethod
    def _admin_has_scope(scopes: set[str], required: str) -> bool:
        if required == "admin":
            return "admin" in scopes
        if required == "write":
            return "write" in scopes or "admin" in scopes
        return "read" in scopes or "write" in scopes or "admin" in scopes

    @classmethod
    def _normalize_download_extensions(cls, raw) -> tuple[tuple[str, ...], bool]:
        values = raw if isinstance(raw, (list, tuple)) else cls._DOWNLOAD_DEFAULT_EXTS
        normalized: list[str] = []
        any_extension = False
        seen: set[str] = set()
        for item in values:
            ext = str(item).strip().lower()
            if not ext:
                continue
            if ext in {"*", ".*"}:
                any_extension = True
                continue
            if not ext.startswith("."):
                ext = "." + ext
            if ext not in seen:
                seen.add(ext)
                normalized.append(ext)
        if not normalized and not any_extension:
            normalized = list(cls._DOWNLOAD_DEFAULT_EXTS)
        return tuple(normalized), any_extension

    def _track_current_task(self) -> asyncio.Task | None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        return task

    def _untrack_task(self, task: asyncio.Task | None) -> None:
        if task is not None:
            self._client_tasks.discard(task)

    @staticmethod
    def _parse_headers_from_block(header_block: bytes) -> dict[str, str]:
        headers = {}
        for raw_line in header_block.split(b"\r\n")[1:]:
            if b":" in raw_line:
                k, v = raw_line.decode(errors="replace").split(":", 1)
                headers[k.strip()] = v.strip()
        return headers

    def _http_proxy_auth_ok(self, headers: dict[str, str]) -> bool:
        if not self._proxy_auth_enabled:
            return True
        if not self._proxy_username and not self._proxy_password:
            return True
        auth = self._header_value(headers, "proxy-authorization")
        if not auth.lower().startswith("basic "):
            return False
        token = auth.split(" ", 1)[1].strip()
        try:
            raw = base64.b64decode(token).decode(errors="replace")
        except Exception:
            return False
        supplied_user, sep, supplied_pass = raw.partition(":")
        if not sep:
            return False
        return (
            hmac.compare_digest(supplied_user, self._proxy_username)
            and hmac.compare_digest(supplied_pass, self._proxy_password)
        )

    @staticmethod
    def _load_route_rules(path: str) -> list[tuple[str, str]]:
        """Load simple route rules from file.

        File format (one per line):
          <pattern> -> <action>
        Example:
          telegram.org -> direct
          *.google.com -> direct
          *.blocked.example -> relay

        Supported actions: direct, relay, block, bypass
        """
        rules: list[tuple[str, str]] = []
        if not path:
            return rules
        try:
            if not os.path.exists(path):
                return rules
            with open(path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "->" not in line:
                        continue
                    pat, action = [x.strip().lower() for x in line.split("->", 1)]
                    if not pat:
                        continue
                    if action not in {"direct", "relay", "block", "bypass"}:
                        continue
                    rules.append((pat, action))
        except Exception as exc:
            log.warning("Could not load route rules file %s: %s", path, exc)
        return rules

    def _route_rule_action(self, host: str) -> str | None:
        if not self._route_rules:
            return None
        h = host.lower().rstrip(".")
        for pat, action in self._route_rules:
            if pat == "*" or fnmatch(h, pat):
                return action
        return None

    @classmethod
    def _is_telegram_host(cls, host: str) -> bool:
        h = host.lower().rstrip(".")
        if not h:
            return False
        if "telegram" in h:
            return True
        return any(h == suffix or h.endswith("." + suffix) for suffix in cls._TELEGRAM_SUFFIXES)

    @classmethod
    def _is_likely_telegram_target(cls, host: str, port: int, client_proto: str) -> bool:
        if cls._is_telegram_host(host):
            return True
        if client_proto == "socks5" and port == 443 and _is_ip_literal(host):
            return True
        return False

    def _record_route_decision(self, route: str, host: str, port: int,
                               client_proto: str) -> None:
        self._route_decisions[route] += 1
        if self._is_likely_telegram_target(host, port, client_proto):
            self._telegram_counters["total"] += 1
            self._telegram_counters[route] += 1

    def _self_heal_relay_error(self, host: str) -> None:
        if not self._self_heal_enabled:
            return
        now = time.time()
        h = host.lower().rstrip(".")
        bucket = self._host_relay_errors.get(h, [])
        bucket.append(now)
        window_start = now - float(self._self_heal_window_s)
        bucket = [ts for ts in bucket if ts >= window_start]
        self._host_relay_errors[h] = bucket
        if len(bucket) < int(self._self_heal_error_threshold):
            return

        # Temporarily avoid direct retries for repeatedly failing targets.
        self._remember_direct_failure(h, ttl=600)
        self._auto_tune_events["host_quarantined"] += 1

        # Gently reduce download parallelism to lower upstream pressure.
        if self._download_max_parallel > 2:
            self._download_max_parallel -= 1
            self._auto_tune_events["download_parallel_reduced"] += 1
            log.warning(
                "Self-heal: reduced chunked_download_max_parallel to %d after repeated errors on %s",
                self._download_max_parallel, h,
            )

        # Reset host window after a tune event to avoid repeated immediate tuning.
        self._host_relay_errors[h] = []

    @staticmethod
    def _load_host_rules(raw) -> tuple[set[str], tuple[str, ...]]:
        """Accept a list of host strings; return (exact_set, suffix_tuple).

        A rule starting with '.' (e.g. ".internal") is a suffix rule.
        Everything else is treated as an exact match. Case-insensitive.
        """
        exact: set[str] = set()
        suffixes: list[str] = []
        for item in raw or []:
            h = str(item).strip().lower().rstrip(".")
            if not h:
                continue
            if h.startswith("."):
                suffixes.append(h)
            else:
                exact.add(h)
        return exact, tuple(suffixes)

    @staticmethod
    def _host_matches_rules(host: str,
                            rules: tuple[set[str], tuple[str, ...]]) -> bool:
        exact, suffixes = rules
        h = host.lower().rstrip(".")
        if h in exact:
            return True
        for s in suffixes:
            if h.endswith(s):
                return True
        return False

    def _is_blocked(self, host: str) -> bool:
        return self._host_matches_rules(host, self._block_hosts)

    def _is_bypassed(self, host: str) -> bool:
        return self._host_matches_rules(host, self._bypass_hosts)

    @staticmethod
    def _header_value(headers: dict | None, name: str) -> str:
        if not headers:
            return ""
        for key, value in headers.items():
            if key.lower() == name:
                return str(value)
        return ""

    def _cache_allowed(self, method: str, url: str,
                       headers: dict | None, body: bytes) -> bool:
        if method.upper() != "GET" or body:
            return False
        for name in UNCACHEABLE_HEADER_NAMES:
            if self._header_value(headers, name):
                return False
        return self.fronter._is_static_asset_url(url)

    @classmethod
    def _should_trace_host(cls, host: str) -> bool:
        h = host.lower().rstrip(".")
        return any(
            token == h or token in h or h.endswith("." + token)
            for token in cls._TRACE_HOST_SUFFIXES
        )

    def _log_response_summary(self, url: str, response: bytes):
        status, headers, body = self.fronter._split_raw_response(response)
        host = (urlparse(url).hostname or "").lower()

        if status >= 300 or self._should_trace_host(host):
            location = headers.get("location", "") or "-"
            server = headers.get("server", "") or "-"
            cf_ray = headers.get("cf-ray", "") or "-"
            content_type = headers.get("content-type", "") or "-"
            body_len = len(body)

            body_hint = "-"
            rate_limited = False

            # Handle text-like responses (HTML, plain text, JSON…)
            if ("text" in content_type.lower() or "json" in content_type.lower()) and body:
                sample = body[:1200].decode(errors="replace").lower()

                # --- Structured HTML title extraction ---
                if "<title>" in sample and "</title>" in sample:
                    title = sample.split("<title>", 1)[1].split("</title>", 1)[0]
                    body_hint = title.strip()[:120] or "-"

                # --- Known content patterns ---
                elif "captcha" in sample:
                    body_hint = "captcha"
                elif "turnstile" in sample:
                    body_hint = "turnstile"
                elif "loading" in sample:
                    body_hint = "loading"

                # --- Rate-limit / quota markers ---
                rate_limit_markers = (
                    "too many",
                    "rate limit",
                    "quota",
                    "quota exceeded",
                    "request limit",
                    "دفعات زیاد",
                    "بیش از حد",
                    "سرویس در طول یک روز",
                )

                if any(m in sample for m in rate_limit_markers):
                    rate_limited = True
                    body_hint = "quota_exceeded"

            log_msg = (
                "RESP ← %s status=%s type=%s len=%s server=%s location=%s cf-ray=%s hint=%s"
            )
            log_args = (
                host or url[:60],
                status,
                content_type,
                body_len,
                server,
                location,
                cf_ray,
                body_hint,
            )

            if rate_limited:
                log.warning("RATE LIMIT detected! " + log_msg, *log_args)
            else:
                log.info(log_msg, *log_args)

    async def start(self):
        http_srv = await asyncio.start_server(self._on_client, self.host, self.port)
        socks_srv = None
        admin_srv = None

        if self.socks_enabled:
            try:
                socks_srv = await asyncio.start_server(
                    self._on_socks_client, self.socks_host, self.socks_port
                )
            except OSError as e:
                log.error("SOCKS5 listener failed on %s:%d: %s",
                          self.socks_host, self.socks_port, e)

        if self._admin_enabled:
            try:
                admin_srv = await asyncio.start_server(
                    self._on_admin_client, self._admin_host, self._admin_port
                )
            except OSError as e:
                log.error("Admin listener failed on %s:%d: %s",
                          self._admin_host, self._admin_port, e)

        self._servers = [s for s in (http_srv, socks_srv, admin_srv) if s]

        log.info(
            "HTTP proxy listening on %s:%d",
            self.host, self.port,
        )
        if socks_srv:
            log.info(
                "SOCKS5 proxy listening on %s:%d",
                self.socks_host, self.socks_port,
            )
        if admin_srv:
            log.info(
                "Admin dashboard listening on http://%s:%d",
                self._admin_host, self._admin_port,
            )

        try:
            async with http_srv:
                if socks_srv:
                    if admin_srv:
                        async with socks_srv, admin_srv:
                            await asyncio.gather(
                                http_srv.serve_forever(),
                                socks_srv.serve_forever(),
                                admin_srv.serve_forever(),
                            )
                    else:
                        async with socks_srv:
                            await asyncio.gather(
                                http_srv.serve_forever(),
                                socks_srv.serve_forever(),
                            )
                elif admin_srv:
                    async with admin_srv:
                        await asyncio.gather(
                            http_srv.serve_forever(),
                            admin_srv.serve_forever(),
                        )
                else:
                    await http_srv.serve_forever()
        except asyncio.CancelledError:
            raise

    async def stop(self):
        """Shut down all listeners and release relay resources."""
        for srv in self._servers:
            try:
                srv.close()
            except Exception:
                pass
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self._servers = []

        current = asyncio.current_task()
        client_tasks = [task for task in self._client_tasks if task is not current]
        for task in client_tasks:
            task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()

        try:
            await self.fronter.close()
        except Exception as exc:
            log.debug("fronter.close: %s", exc)

    # ── client handler ────────────────────────────────────────────

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return

            # Read remaining headers
            header_block = first_line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                header_block += line
                if len(header_block) > MAX_HEADER_BYTES:
                    log.warning("Request header block exceeds cap — closing")
                    return
                if line in (b"\r\n", b"\n", b""):
                    break

            if _has_unsupported_transfer_encoding(header_block):
                log.warning("Unsupported Transfer-Encoding on client request")
                writer.write(
                    b"HTTP/1.1 501 Not Implemented\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            request_line = first_line.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return

            method = parts[0].upper()
            headers = self._parse_headers_from_block(header_block)
            if not self._http_proxy_auth_ok(headers):
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"MasterHttpRelayVPN\"\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_http(header_block, reader, writer)

        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            log.debug("Timeout: %s", addr)
        except Exception as e:
            log.error("Error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _on_socks_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return

            methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10)
            if self._proxy_auth_enabled and (self._proxy_username or self._proxy_password):
                if 0x02 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                # Username/password auth required
                writer.write(b"\x05\x02")
                await writer.drain()
                auth_ver = await asyncio.wait_for(reader.readexactly(1), timeout=10)
                if auth_ver != b"\x01":
                    writer.write(b"\x01\x01")
                    await writer.drain()
                    return
                ulen = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                uname = (await asyncio.wait_for(reader.readexactly(ulen), timeout=10)).decode(
                    errors="replace"
                )
                plen = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                passwd = (await asyncio.wait_for(reader.readexactly(plen), timeout=10)).decode(
                    errors="replace"
                )
                if (
                    hmac.compare_digest(uname, self._proxy_username)
                    and hmac.compare_digest(passwd, self._proxy_password)
                ):
                    writer.write(b"\x01\x00")
                    await writer.drain()
                else:
                    writer.write(b"\x01\x01")
                    await writer.drain()
                    return
            else:
                if 0x00 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()

            req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if atyp == 0x01:
                raw = await asyncio.wait_for(reader.readexactly(4), timeout=10)
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:
                ln = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                host = (await asyncio.wait_for(reader.readexactly(ln), timeout=10)).decode(
                    errors="replace"
                )
            elif atyp == 0x04:
                raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            port_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            port = int.from_bytes(port_raw, "big")

            log.info("SOCKS5 CONNECT → %s:%d", host, port)
            await self._handle_socks_target_tunnel(host, port, reader, writer)

        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            log.debug("SOCKS5 timeout: %s", addr)
        except Exception as e:
            log.error("SOCKS5 error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── CONNECT (HTTPS tunnelling) ────────────────────────────────

    async def _do_connect(self, target: str, reader, writer):
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            log.warning("CONNECT invalid target: %r", target)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        if not host:
            host, port = target, 443

        log.info("CONNECT → %s:%d", host, port)

        await self._handle_http_connect_tunnel(host, port, reader, writer)

    async def _handle_http_connect_tunnel(self, host: str, port: int,
                                          reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter):
        if self._is_blocked(host):
            log.warning("BLOCKED → %s:%d (matches block_hosts)", host, port)
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._handle_target_tunnel(
            host, port, reader, writer, client_proto="http_connect",
        )

    async def _handle_socks_target_tunnel(self, host: str, port: int,
                                          reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter):
        if self._is_blocked(host):
            log.warning("SOCKS5 BLOCKED → %s:%d (matches block_hosts)", host, port)
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await self._handle_target_tunnel(
            host, port, reader, writer, client_proto="socks5",
        )

    async def _handle_target_tunnel(self, host: str, port: int,
                                    reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    *,
                                    client_proto: str = "http_connect"):
        """Route a target connection through the Apps Script relay."""
        # ── Bypass policy ─────────────────────────────────────────
        if self._is_bypassed(host):
            self._record_route_decision("bypass_direct", host, port, client_proto)
            log.info("Bypass tunnel → %s:%d (matches bypass_hosts)", host, port)
            await self._do_direct_tunnel(host, port, reader, writer)
            return

        rule_action = self._route_rule_action(host)
        if rule_action == "block":
            self._record_route_decision("rule_block", host, port, client_proto)
            log.warning("Route rule BLOCK → %s:%d", host, port)
            try:
                if client_proto == "http_connect":
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                else:
                    writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
            except Exception:
                pass
            return
        if rule_action == "bypass":
            self._record_route_decision("rule_bypass_direct", host, port, client_proto)
            await self._do_direct_tunnel(host, port, reader, writer)
            return
        if rule_action == "direct":
            self._record_route_decision("rule_direct_attempt", host, port, client_proto)
            timeout = self._adaptive_direct_timeout(
                host, default=self._tcp_connect_timeout,
            )
            ok = await self._do_direct_tunnel(
                host, port, reader, writer, timeout=timeout,
            )
            if ok:
                self._record_route_decision("rule_direct_ok", host, port, client_proto)
                self._remember_direct_success(host)
                return
            self._remember_direct_failure(host, ttl=300)
            self._record_route_decision("rule_direct_failed_fallback", host, port, client_proto)
        elif rule_action == "relay":
            self._record_route_decision("rule_force_relay", host, port, client_proto)
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            elif port == 80:
                await self._do_plain_http_tunnel(host, port, reader, writer)
            else:
                # Non-http port cannot be relay'd; keep direct tunnel fallback.
                await self._do_direct_tunnel(host, port, reader, writer)
            return

        # Telegram domain/direct preference in telegram_desktop_mode.
        if (
            self._telegram_desktop_mode
            and self._is_telegram_host(host)
            and not _is_ip_literal(host)
        ):
            self._record_route_decision("telegram_domain_direct_attempt", host, port, client_proto)
            timeout = self._adaptive_direct_timeout(
                host, default=self._tcp_connect_timeout, telegram_hint=True,
            )
            ok = await self._do_direct_tunnel(
                host, port, reader, writer, timeout=timeout,
            )
            if ok:
                self._record_route_decision("telegram_domain_direct_ok", host, port, client_proto)
                self._remember_direct_success(host)
                return
            self._record_route_decision("telegram_domain_direct_failed_fallback", host, port, client_proto)
            self._remember_direct_failure(host, ttl=300)

        # ── IP-literal destinations ───────────────────────────────
        # Prefer a direct tunnel first (works for unblocked IPs and keeps
        # TLS end-to-end). If the network blocks the route (common for
        # Telegram data-centers behind DPI), fall back to:
        #   • port 443 → MITM + relay through Apps Script
        #   • port 80  → plain-HTTP relay through Apps Script
        #   • other    → give up (non-HTTP; can't be relayed)
        # We use a shorter connect timeout for IP literals (4 s) because
        # when the route is DPI-dropped, waiting longer doesn't help and
        # clients like Telegram speed up DC-rotation when we fail fast.
        # We remember per-IP failures for a short while so subsequent
        # connects skip the doomed direct attempt.
        if _is_ip_literal(host):
            if not self._direct_temporarily_disabled(host):
                self._record_route_decision("direct_ip_attempt", host, port, client_proto)
                log.info("Direct tunnel → %s:%d (IP literal)", host, port)
                timeout = self._adaptive_direct_timeout(
                    host, default=4.0, telegram_hint=True,
                )
                ok = await self._do_direct_tunnel(
                    host, port, reader, writer, timeout=timeout,
                )
                if ok:
                    self._record_route_decision("direct_ip_ok", host, port, client_proto)
                    self._remember_direct_success(host)
                    return
                self._remember_direct_failure(host, ttl=300)
                self._record_route_decision("direct_ip_failed", host, port, client_proto)
                if port not in (80, 443):
                    log.warning("Direct tunnel failed for %s:%d", host, port)
                    return
                log.warning(
                    "Direct tunnel fallback → %s:%d (switching to relay)",
                    host, port,
                )
            else:
                log.info(
                    "Relay fallback → %s:%d (direct temporarily disabled)",
                    host, port,
                )
            if self._telegram_desktop_mode and client_proto == "socks5":
                self._record_route_decision("tg_failfast_ip_socks", host, port, client_proto)
                log.info(
                    "Telegram desktop mode: skipping MITM/relay fallback for "
                    "SOCKS5 IP-literal %s:%d to force fast DC rotation",
                    host, port,
                )
                return
            if port == 443:
                self._record_route_decision("ip_fallback_mitm", host, port, client_proto)
                await self._do_mitm_connect(host, port, reader, writer)
            elif port == 80:
                self._record_route_decision("ip_fallback_plain_http", host, port, client_proto)
                await self._do_plain_http_tunnel(host, port, reader, writer)
            return

        override_ip = self._sni_rewrite_ip(host)
        if override_ip:
            # SNI-blocked domain: MITM-decrypt from browser, then
            # re-connect to the override IP with SNI=front_domain so
            # the ISP never sees the blocked hostname in the TLS handshake.
            self._record_route_decision("sni_rewrite_tunnel", host, port, client_proto)
            log.info("SNI-rewrite tunnel → %s via %s (SNI: %s)",
                     host, override_ip, self.fronter.sni_host)
            await self._do_sni_rewrite_tunnel(host, port, reader, writer,
                                              connect_ip=override_ip)
        elif self._is_google_domain(host):
            if self._direct_temporarily_disabled(host):
                self._record_route_decision("google_direct_disabled_fallback", host, port, client_proto)
                log.info("Relay fallback → %s (direct tunnel temporarily disabled)", host)
                if port == 443:
                    await self._do_mitm_connect(host, port, reader, writer)
                else:
                    await self._do_plain_http_tunnel(host, port, reader, writer)
                return

            self._record_route_decision("google_direct_attempt", host, port, client_proto)
            log.info("Direct tunnel → %s (Google domain, skipping relay)", host)
            timeout = self._adaptive_direct_timeout(
                host, default=self._tcp_connect_timeout,
            )
            ok = await self._do_direct_tunnel(
                host, port, reader, writer, timeout=timeout,
            )
            if ok:
                self._record_route_decision("google_direct_ok", host, port, client_proto)
                self._remember_direct_success(host)
                return

            self._remember_direct_failure(host)
            self._record_route_decision("google_direct_failed_fallback", host, port, client_proto)
            log.warning("Direct tunnel fallback → %s (switching to relay)", host)
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            else:
                await self._do_plain_http_tunnel(host, port, reader, writer)
        elif port == 443:
            self._record_route_decision("mitm_relay", host, port, client_proto)
            await self._do_mitm_connect(host, port, reader, writer)
        elif port == 80:
            self._record_route_decision("plain_http_relay", host, port, client_proto)
            await self._do_plain_http_tunnel(host, port, reader, writer)
        else:
            # Non-HTTP port (e.g. mtalk:5228 XMPP, IMAP, SMTP, SSH) —
            # payload isn't HTTP, so we can't relay or MITM. Tunnel bytes.
            self._record_route_decision("direct_non_http_attempt", host, port, client_proto)
            log.info("Direct tunnel → %s:%d (non-HTTP port)", host, port)
            timeout = self._adaptive_direct_timeout(
                host, default=self._tcp_connect_timeout,
            )
            ok = await self._do_direct_tunnel(
                host, port, reader, writer, timeout=timeout,
            )
            if not ok:
                self._record_route_decision("direct_non_http_failed", host, port, client_proto)
                log.warning("Direct tunnel failed for %s:%d", host, port)
            else:
                self._record_route_decision("direct_non_http_ok", host, port, client_proto)
                self._remember_direct_success(host)

    # ── Hosts override (fake DNS) ─────────────────────────────────

    # Built-in list of domains that must be reached via Google's frontend IP
    # with SNI rewritten to `front_domain` (default: www.google.com).
    # Source: constants.SNI_REWRITE_SUFFIXES.
    # When youtube_via_relay is enabled the YouTube suffixes are removed so
    # YouTube goes through the Apps Script relay instead.
    _YOUTUBE_SNI_SUFFIXES = frozenset({
        "youtube.com", "youtu.be", "youtube-nocookie.com",
    })
    _SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

    def _sni_rewrite_ip(self, host: str) -> str | None:
        """Return the IP to SNI-rewrite `host` through, or None.

        Order of precedence:
          1. Explicit entry in config `hosts` map (exact or suffix match).
          2. Built-in `_SNI_REWRITE_SUFFIXES` → mapped to config `google_ip`.
        """
        ip = self._hosts_ip(host)
        if ip:
            return ip
        h = host.lower().rstrip(".")
        for suffix in self._SNI_REWRITE_SUFFIXES:
            if h == suffix or h.endswith("." + suffix):
                return self.fronter.connect_host  # configured google_ip
        return None

    def _hosts_ip(self, host: str) -> str | None:
        """Return override IP for host if defined in config 'hosts', else None.

        Supports exact match and suffix match (e.g. 'youtube.com' matches
        'www.youtube.com', 'm.youtube.com', etc.).
        """
        h = host.lower().rstrip(".")
        if h in self._hosts:
            return self._hosts[h]
        # suffix match: check every parent label
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._hosts:
                return self._hosts[parent]
        return None

    # ── Google domain detection ───────────────────────────────────

    # Google-owned domains that may use the raw direct-tunnel shortcut.
    # YouTube/googlevideo SNIs are blocked; they go through
    # _do_sni_rewrite_tunnel via the hosts map instead.
    # Source: constants.GOOGLE_OWNED_SUFFIXES / GOOGLE_OWNED_EXACT.
    _GOOGLE_OWNED_SUFFIXES = GOOGLE_OWNED_SUFFIXES
    _GOOGLE_OWNED_EXACT = GOOGLE_OWNED_EXACT

    def _is_google_domain(self, host: str) -> bool:
        """Return True if host should use the raw direct Google shortcut."""
        h = host.lower().rstrip(".")
        if self._is_direct_google_excluded(h):
            return False
        if not self._is_google_owned_domain(h):
            return False
        return self._is_direct_google_allowed(h)

    def _is_google_owned_domain(self, host: str) -> bool:
        if host in self._GOOGLE_OWNED_EXACT:
            return True
        for suffix in self._GOOGLE_OWNED_SUFFIXES:
            if host.endswith(suffix):
                return True
        return False

    def _is_direct_google_excluded(self, host: str) -> bool:
        if host in self._direct_google_exclude:
            return True
        for suffix in self._GOOGLE_DIRECT_SUFFIX_EXCLUDE:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_exclude:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _is_direct_google_allowed(self, host: str) -> bool:
        if host in self._direct_google_allow:
            return True
        for suffix in self._GOOGLE_DIRECT_ALLOW_SUFFIXES:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_allow:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _direct_temporarily_disabled(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        now = time.time()
        disabled = False
        for key in self._direct_failure_keys(h):
            until = self._direct_fail_until.get(key, 0)
            if until > now:
                disabled = True
            else:
                self._direct_fail_until.pop(key, None)
        return disabled

    def _remember_direct_failure(self, host: str, ttl: int = 600):
        normalized = host.lower().rstrip(".")
        score = min(6, self._direct_fail_score.get(normalized, 0) + 1)
        self._direct_fail_score[normalized] = score
        adaptive_ttl = int(max(60, min(1800, ttl * (1.35 ** (score - 1)))))
        until = time.time() + adaptive_ttl
        for key in self._direct_failure_keys(normalized):
            self._direct_fail_until[key] = until

    def _remember_direct_success(self, host: str) -> None:
        normalized = host.lower().rstrip(".")
        score = self._direct_fail_score.get(normalized, 0)
        if score > 1:
            self._direct_fail_score[normalized] = score - 1
        elif score == 1:
            self._direct_fail_score.pop(normalized, None)

    def _adaptive_direct_timeout(self, host: str, *, default: float,
                                 telegram_hint: bool = False) -> float:
        normalized = host.lower().rstrip(".")
        score = self._direct_fail_score.get(normalized, 0)
        timeout = float(default)
        if score >= 3:
            timeout = max(1.5, timeout * 0.55)
        elif score == 2:
            timeout = max(2.0, timeout * 0.70)
        elif score == 1:
            timeout = max(2.5, timeout * 0.85)
        if telegram_hint:
            timeout = min(timeout, 3.5)
        return timeout

    def _direct_failure_keys(self, host: str) -> tuple[str, ...]:
        keys = [host]
        if host.endswith(".google.com") or host == "google.com":
            keys.append("*.google.com")
        if host.endswith(".googleapis.com") or host == "googleapis.com":
            keys.append("*.googleapis.com")
        if host.endswith(".gstatic.com") or host == "gstatic.com":
            keys.append("*.gstatic.com")
        if host.endswith(".googleusercontent.com") or host == "googleusercontent.com":
            keys.append("*.googleusercontent.com")
        return tuple(dict.fromkeys(keys))

    async def _open_tcp_connection(self, target: str, port: int,
                                   timeout: float = 10.0):
        """Connect with IPv4-first resolution and clearer failure reporting."""
        errors: list[str] = []
        loop = asyncio.get_running_loop()

        # Strip IPv6 brackets (CONNECT may deliver "[::1]" as the hostname).
        # ipaddress.ip_address() rejects the bracketed form, which would
        # otherwise force a DNS lookup for an IP literal and fail.
        lookup_target = target.strip()
        if lookup_target.startswith("[") and lookup_target.endswith("]"):
            lookup_target = lookup_target[1:-1]

        try:
            ipaddress.ip_address(lookup_target)
            candidates = [(0, lookup_target)]
        except ValueError:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(
                        lookup_target,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=timeout,
                )
            except Exception as exc:
                raise OSError(f"dns lookup failed for {lookup_target}: {exc!r}") from exc

            candidates = []
            seen = set()
            for family, _type, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]
                key = (family, ip)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((family, ip))

            candidates.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)

        for family, ip in candidates:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(ip, port, family=family or 0),
                    timeout=timeout,
                )
            except Exception as exc:
                fam = "ipv4" if family == socket.AF_INET else (
                    "ipv6" if family == socket.AF_INET6 else "auto"
                )
                errors.append(f"{ip} ({fam}): {exc!r}")

        raise OSError("; ".join(errors) or f"connect failed for {target}:{port}")

    # ── Direct tunnel (no MITM) ───────────────────────────────────

    async def _do_direct_tunnel(self, host: str, port: int,
                                reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter,
                                connect_ip: str | None = None,
                                timeout: float | None = None):
        """Pipe raw TLS bytes directly to the target server.

        connect_ip overrides DNS: the TCP connection goes to that IP
        while the browser's TLS (SNI=host) is piped through unchanged.
        Without an override we connect to the real hostname so browser-safe
        Google properties (Gemini assets, Play, Accounts, etc.) use their
        normal edge instead of being forced onto the fronting IP.
        """
        target_ip = connect_ip or host
        effective_timeout = (
            self._tcp_connect_timeout if timeout is None else float(timeout)
        )
        try:
            r_remote, w_remote = await self._open_tcp_connection(
                target_ip, port, timeout=effective_timeout,
            )
        except Exception as e:
            log.error("Direct tunnel connect failed (%s via %s): %s",
                      host, target_ip, e)
            return False

        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as e:
                log.debug("Pipe %s ended: %s", label, e)
            finally:
                # Half-close rather than hard-close so the other direction
                # can still flush final bytes (important for TLS close_notify).
                try:
                    if not dst.is_closing() and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    try:
                        dst.close()
                    except Exception:
                        pass

        await asyncio.gather(
            pipe(reader, w_remote, f"client→{host}"),
            pipe(r_remote, writer, f"{host}→client"),
        )
        return True

    # ── SNI-rewrite tunnel ────────────────────────────────────────

    async def _do_sni_rewrite_tunnel(self, host: str, port: int, reader, writer,
                                     connect_ip: str | None = None):
        """MITM-decrypt TLS from browser, then re-encrypt toward connect_ip
        using SNI=front_domain (e.g. www.google.com).

        The ISP only ever sees SNI=www.google.com in the outgoing handshake,
        hiding the blocked hostname (e.g. www.youtube.com).
        """
        target_ip = connect_ip or self.fronter.connect_host
        sni_out   = self.fronter.sni_host  # e.g. "www.google.com"

        # Step 1: MITM — accept TLS from the browser
        ssl_ctx_server = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol  = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx_server, server_side=True,
            )
        except Exception as e:
            log.debug("SNI-rewrite TLS accept failed (%s): %s", host, e)
            return
        writer._transport = new_transport

        # Step 2: open outgoing TLS to target IP with the safe SNI
        ssl_ctx_client = ssl.create_default_context()
        if certifi is not None:
            try:
                ssl_ctx_client.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        if not self.fronter.verify_ssl:
            ssl_ctx_client.check_hostname = False
            ssl_ctx_client.verify_mode = ssl.CERT_NONE
        try:
            r_out, w_out = await asyncio.wait_for(
                asyncio.open_connection(
                    target_ip, port,
                    ssl=ssl_ctx_client,
                    server_hostname=sni_out,
                ),
                timeout=self._tcp_connect_timeout,
            )
        except Exception as e:
            log.error("SNI-rewrite outbound connect failed (%s via %s): %s",
                      host, target_ip, e)
            return

        # Step 3: pipe application-layer bytes between the two TLS sessions
        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as exc:
                log.debug("Pipe %s ended: %s", label, exc)
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(reader, w_out, f"client→{host}"),
            pipe(r_out,  writer, f"{host}→client"),
        )

    # ── MITM CONNECT (apps_script mode) ───────────────────────────

    async def _do_plain_http_tunnel(self, host: str, port: int, reader, writer):
        """Handle plain HTTP over SOCKS5 in apps_script mode."""
        log.info("Plain HTTP relay → %s:%d", host, port)
        await self._relay_http_stream(host, port, reader, writer)

    async def _do_mitm_connect(self, host: str, port: int, reader, writer):
        """Intercept TLS, decrypt HTTP, and relay through Apps Script."""
        ssl_ctx = self.mitm.get_server_context(host)

        # Upgrade the existing connection to TLS (we are the server)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()

        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_side=True,
            )
        except Exception as e:
            # TLS handshake failed. Common causes:
            #   • Telegram Desktop / MTProto over port 443 sends obfuscated
            #     non-TLS bytes — we literally cannot decrypt these, and
            #     since the target IP is blocked we can't direct-tunnel
            #     either. Telegram will rotate to another DC on its own;
            #     failing fast here lets that happen sooner.
            #   • Client CONNECTs but never speaks TLS (some probes).
            if _is_ip_literal(host) and port == 443:
                log.info(
                    "Non-TLS traffic on %s:%d (likely Telegram MTProto / "
                    "obfuscated protocol). This DC appears blocked; the "
                    "client should rotate to another endpoint shortly.",
                    host, port,
                )
            elif port != 443:
                log.debug(
                    "TLS handshake skipped for %s:%d (non-HTTPS): %s",
                    host, port, e,
                )
            else:
                log.debug("TLS handshake failed for %s: %s", host, e)
            # Close the client side so it fails fast and can retry, rather
            # than hanging on a half-open connection.
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass
            return

        # Update writer to use the new TLS transport
        writer._transport = new_transport

        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host: str, port: int, reader, writer):
        """Read decrypted/origin-form HTTP requests and relay them."""
        # Read and relay HTTP requests from the browser (now decrypted)
        while True:
            try:
                first_line = await asyncio.wait_for(
                    reader.readline(), timeout=CLIENT_IDLE_TIMEOUT
                )
                if not first_line:
                    break

                header_block = first_line
                oversized_headers = False
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=10)
                    header_block += line
                    if len(header_block) > MAX_HEADER_BYTES:
                        oversized_headers = True
                        break
                    if line in (b"\r\n", b"\n", b""):
                        break

                # Reject truncated / oversized header blocks cleanly rather
                # than forwarding a half-parsed request to the relay — doing
                # so would send malformed JSON payloads to Apps Script and
                # leave the client hanging until its own timeout fires.
                if oversized_headers:
                    log.warning(
                        "MITM header block exceeds %d bytes — closing (%s)",
                        MAX_HEADER_BYTES, host,
                    )
                    try:
                        writer.write(
                            b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                            b"Connection: close\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                    except Exception:
                        pass
                    break

                # Read body
                body = b""
                if _has_unsupported_transfer_encoding(header_block):
                    log.warning("Unsupported Transfer-Encoding → %s:%d", host, port)
                    writer.write(
                        b"HTTP/1.1 501 Not Implemented\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    break
                length = _parse_content_length(header_block)
                if length > MAX_REQUEST_BODY_BYTES:
                    raise ValueError(f"Request body too large: {length} bytes")
                if length > 0:
                    body = await reader.readexactly(length)

                # Parse the request
                request_line = first_line.decode(errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 2:
                    break

                method = parts[0]
                path = parts[1]
                req_size = len(header_block) + len(body)

                # Parse headers
                headers = {}
                for raw_line in header_block.split(b"\r\n")[1:]:
                    if b":" in raw_line:
                        k, v = raw_line.decode(errors="replace").split(":", 1)
                        headers[k.strip()] = v.strip()

                # Shortening the length of X API URLs to prevent relay errors.
                if (host == "x.com" or host == "twitter.com") and  re.match(r"/i/api/graphql/[^/]+/[^?]+\?variables=", path):
                    path = path.split("&")[0]

                # MITM traffic arrives as origin-form paths; SOCKS/plain HTTP can
                # also send absolute-form requests. Normalize both to full URLs.
                if path.startswith("http://") or path.startswith("https://"):
                    url = path
                elif port == 443:
                    url = f"https://{host}{path}"
                elif port == 80:
                    url = f"http://{host}{path}"
                else:
                    url = f"http://{host}:{port}{path}"

                log.info("MITM → %s %s", method, url)

                # ── CORS: extract relevant request headers ─────────────
                origin = self._header_value(headers, "origin")
                acr_method = self._header_value(
                    headers, "access-control-request-method",
                )
                acr_headers = self._header_value(
                    headers, "access-control-request-headers",
                )

                # CORS preflight — respond directly. Apps Script's
                # UrlFetchApp does not support the OPTIONS method, so
                # forwarding preflights would always fail and break every
                # cross-origin fetch/XHR the browser runs through us.
                if method.upper() == "OPTIONS" and acr_method:
                    log.debug(
                        "CORS preflight → %s (responding locally)",
                        url[:60],
                    )
                    response = self._cors_preflight_response(
                        origin, acr_method, acr_headers,
                    )
                    writer.write(response)
                    await writer.drain()
                    await self._record_telemetry(
                        method=method,
                        url=url,
                        request_bytes=req_size,
                        response=response,
                        started_at=time.perf_counter(),
                        route="cors_preflight",
                        cache_hit=False,
                        error_name="",
                    )
                    continue

                started_at = time.perf_counter()
                if await self._maybe_stream_download(method, url, headers, body, writer):
                    await self._record_telemetry(
                        method=method,
                        url=url,
                        request_bytes=req_size,
                        response=b"",
                        started_at=started_at,
                        route="stream_parallel",
                        cache_hit=False,
                        error_name="",
                        status_override=200,
                    )
                    continue

                # Check local cache first (GET only)
                response = None
                cache_hit = False
                relay_error_name = ""
                if self._cache_allowed(method, url, headers, body):
                    response = self._cache.get(url)
                    if response:
                        log.debug("Cache HIT: %s", url[:60])
                        cache_hit = True

                if response is None:
                    # Relay through Apps Script
                    try:
                        response = await self._relay_smart(method, url, headers, body)
                    except Exception as e:
                        self._self_heal_relay_error(host)
                        log.error("Relay error (%s): %s", url[:60], e)
                        relay_error_name = type(e).__name__
                        err_body = f"Relay error: {e}".encode()
                        response = (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: " + str(len(err_body)).encode() + b"\r\n"
                            b"\r\n" + err_body
                        )

                    # Cache successful GET responses
                    if self._cache_allowed(method, url, headers, body) and response:
                        ttl = ResponseCache.parse_ttl(response, url)
                        if ttl > 0:
                            self._cache.put(url, response, ttl)
                            log.debug("Cached (%ds): %s", ttl, url[:60])

                # Inject permissive CORS headers whenever the browser sent
                # an Origin (cross-origin XHR / fetch). Without this, the
                # browser blocks the response even though the relay fetched
                # it successfully.
                if origin and response:
                    response = self._inject_cors_headers(response, origin)

                self._log_response_summary(url, response)

                writer.write(response)
                await writer.drain()
                await self._record_telemetry(
                    method=method,
                    url=url,
                    request_bytes=req_size,
                    response=response,
                    started_at=started_at,
                    route="relay",
                    cache_hit=cache_hit,
                    error_name=relay_error_name,
                )

            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            except ConnectionError:
                break
            except Exception as e:
                log.error("MITM handler error (%s): %s", host, e)
                break

    # ── CORS helpers ──────────────────────────────────────────────

    @staticmethod
    def _cors_preflight_response(origin: str, acr_method: str,
                                 acr_headers: str) -> bytes:
        """Build a 204 response that satisfies a CORS preflight locally.

        Apps Script's UrlFetchApp does not support OPTIONS, so we have to
        answer preflights here instead of forwarding them.
        """
        allow_origin = origin or "*"
        allow_methods = (
            f"{acr_method}, GET, POST, PUT, DELETE, PATCH, OPTIONS"
            if acr_method else
            "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        allow_headers = acr_headers or "*"
        return (
            "HTTP/1.1 204 No Content\r\n"
            f"Access-Control-Allow-Origin: {allow_origin}\r\n"
            f"Access-Control-Allow-Methods: {allow_methods}\r\n"
            f"Access-Control-Allow-Headers: {allow_headers}\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "Vary: Origin\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode()

    @staticmethod
    def _inject_cors_headers(response: bytes, origin: str) -> bytes:
        """Strip existing Access-Control-* headers and add permissive ones.

        Keeps the body untouched; only rewrites the header block. Using
        the exact browser-supplied Origin (rather than "*") is required
        when the request is credentialed (cookies, Authorization).
        """
        sep = b"\r\n\r\n"
        if sep not in response:
            return response
        header_section, body = response.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        lines = [ln for ln in lines
                 if not ln.lower().startswith("access-control-")]
        allow_origin = origin or "*"
        lines += [
            f"Access-Control-Allow-Origin: {allow_origin}",
            "Access-Control-Allow-Credentials: true",
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers: *",
            "Access-Control-Expose-Headers: *",
            "Vary: Origin",
        ]
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    async def _relay_smart(self, method, url, headers, body):
        """Choose optimal relay strategy based on request type.

        - GET requests for likely-large downloads use parallel-range.
        - All other requests (API calls, HTML, JSON, XHR) go through the
          single-request relay. This avoids injecting a synthetic Range
          header on normal traffic, which some origins honor by returning
          206 — breaking fetch()/XHR on sites like x.com or Cloudflare
          challenge pages.
        """
        if method == "GET" and not body:
            # Respect client's own Range header verbatim.
            if headers:
                for k in headers:
                    if k.lower() == "range":
                        return await self.fronter.relay(
                            method, url, headers, body
                        )
            # Only probe with Range when the URL looks like a big file.
            if self._is_likely_download(url, headers):
                return await self.fronter.relay_parallel(
                    method,
                    url,
                    headers,
                    body,
                    chunk_size=self._download_chunk_size,
                    max_parallel=self._download_max_parallel,
                    max_chunks=self._download_max_chunks,
                    min_size=self._download_min_size,
                )
        return await self.fronter.relay(method, url, headers, body)

    def _is_likely_download(self, url: str, headers: dict) -> bool:
        """Heuristic: is this URL likely a large file download?"""
        path = url.split("?")[0].lower()
        if self._download_any_extension:
            return True
        for ext in self._download_extensions:
            if path.endswith(ext):
                return True
        accept = self._header_value(headers, "accept").lower()
        if any(marker in accept for marker in self._DOWNLOAD_ACCEPT_MARKERS):
            return True
        return False

    async def _maybe_stream_download(self, method: str, url: str,
                                     headers: dict | None, body: bytes,
                                     writer) -> bool:
        if method.upper() != "GET" or body:
            return False
        if headers:
            for key in headers:
                if key.lower() == "range":
                    return False
        effective_headers = headers or {}
        if not self._is_likely_download(url, effective_headers):
            return False
        if not self.fronter.stream_download_allowed(url):
            return False
        return await self.fronter.stream_parallel_download(
            url,
            effective_headers,
            writer,
            chunk_size=self._download_chunk_size,
            max_parallel=self._download_max_parallel,
            max_chunks=self._download_max_chunks,
            min_size=self._download_min_size,
        )

    # ── Plain HTTP forwarding ─────────────────────────────────────

    async def _do_http(self, header_block: bytes, reader, writer):
        body = b""
        started_at = time.perf_counter()
        if _has_unsupported_transfer_encoding(header_block):
            log.warning("Unsupported Transfer-Encoding on plain HTTP request")
            writer.write(
                b"HTTP/1.1 501 Not Implemented\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        length = _parse_content_length(header_block)
        if length > MAX_REQUEST_BODY_BYTES:
            writer.write(b"HTTP/1.1 413 Content Too Large\r\n\r\n")
            await writer.drain()
            return
        if length > 0:
            body = await reader.readexactly(length)

        first_line = header_block.split(b"\r\n")[0].decode(errors="replace")
        log.info("HTTP → %s", first_line)

        # Parse request and relay through Apps Script
        parts = first_line.strip().split(" ", 2)
        method = parts[0] if parts else "GET"
        url = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for raw_line in header_block.split(b"\r\n")[1:]:
            if b":" in raw_line:
                k, v = raw_line.decode(errors="replace").split(":", 1)
                headers[k.strip()] = v.strip()

        # ── CORS preflight over plain HTTP ─────────────────────────────
        origin = self._header_value(headers, "origin")
        acr_method = self._header_value(headers, "access-control-request-method")
        acr_headers = self._header_value(headers, "access-control-request-headers")
        if method.upper() == "OPTIONS" and acr_method:
            log.debug("CORS preflight (HTTP) → %s (responding locally)", url[:60])
            response = self._cors_preflight_response(
                origin, acr_method, acr_headers,
            )
            writer.write(response)
            await writer.drain()
            await self._record_telemetry(
                method=method,
                url=url,
                request_bytes=len(header_block) + len(body),
                response=response,
                started_at=started_at,
                route="cors_preflight",
                cache_hit=False,
                error_name="",
            )
            return

        if await self._maybe_stream_download(method, url, headers, body, writer):
            await self._record_telemetry(
                method=method,
                url=url,
                request_bytes=len(header_block) + len(body),
                response=b"",
                started_at=started_at,
                route="stream_parallel",
                cache_hit=False,
                error_name="",
                status_override=200,
            )
            return

        # Cache check for GET
        response = None
        cache_hit = False
        if self._cache_allowed(method, url, headers, body):
            response = self._cache.get(url)
            if response:
                log.debug("Cache HIT (HTTP): %s", url[:60])
                cache_hit = True

        if response is None:
            try:
                response = await self._relay_smart(method, url, headers, body)
            except Exception as exc:
                self._self_heal_relay_error((urlparse(url).hostname or "unknown"))
                err_body = f"Relay error: {exc}".encode()
                response = (
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(err_body)).encode() + b"\r\n"
                    b"\r\n" + err_body
                )
            # Cache successful GET
            if self._cache_allowed(method, url, headers, body) and response:
                ttl = ResponseCache.parse_ttl(response, url)
                if ttl > 0:
                    self._cache.put(url, response, ttl)

        if origin and response:
            response = self._inject_cors_headers(response, origin)

        self._log_response_summary(url, response)

        writer.write(response)
        await writer.drain()
        await self._record_telemetry(
            method=method,
            url=url,
            request_bytes=len(header_block) + len(body),
            response=response,
            started_at=started_at,
            route="relay",
            cache_hit=cache_hit,
            error_name="",
        )

    async def _record_telemetry(self, *, method: str, url: str,
                                request_bytes: int, response: bytes,
                                started_at: float, route: str,
                                cache_hit: bool, error_name: str,
                                status_override: int | None = None) -> None:
        status, _, body = self.fronter._split_raw_response(response)
        if status_override is not None:
            status = int(status_override)
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower() or "unknown"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        latency_ms = (time.perf_counter() - started_at) * 1000.0
        await self._telemetry.record_request(
            host=host,
            path=path,
            method=method,
            status=status,
            latency_ms=latency_ms,
            req_bytes=request_bytes,
            resp_bytes=len(body),
            route=route,
            cache_hit=cache_hit,
            error_name=error_name,
        )
        if self._telemetry_jsonl_writer is not None:
            event = {
                "ts": int(time.time()),
                "host": host,
                "path": path,
                "method": method.upper(),
                "status": status,
                "latency_ms": round(latency_ms, 2),
                "req_bytes": max(0, int(request_bytes)),
                "resp_bytes": len(body),
                "route": route,
                "cache_hit": bool(cache_hit),
                "error_name": error_name or "",
            }
            try:
                await self._telemetry_jsonl_writer.write(event)
            except Exception as exc:
                log.debug("telemetry jsonl write failed: %s", exc)

    async def _on_admin_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        task = self._track_current_task()
        try:
            first = await asyncio.wait_for(reader.readline(), timeout=10)
            if not first:
                return
            request_line = first.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0].upper(), parts[1]
            header_block = b""
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
                header_block += line
                if len(header_block) > 32768:
                    break
            headers = {}
            for raw_line in header_block.split(b"\r\n"):
                if b":" in raw_line:
                    k, v = raw_line.decode(errors="replace").split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            content_length = 0
            if headers.get("content-length", "").isdigit():
                content_length = int(headers.get("content-length", "0"))
            body_data = b""
            if content_length > 0 and content_length <= 16384:
                body_data = await reader.readexactly(content_length)

            if method not in {"GET", "POST"}:
                writer.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            auth_ok, scopes = self._admin_auth(headers.get("x-admin-token", ""))
            if not auth_ok:
                writer.write(
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            if path == "/" or path.startswith("/?"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                body = self._admin_html().encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
                await writer.drain()
                return

            if path.startswith("/api/summary"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                snap = await self._telemetry.snapshot(top_hosts=30, recent_limit=150)
                snap["relay"] = self.fronter.stats_snapshot()
                snap["cache_store"] = {
                    "entries": len(self._cache._store),
                    "bytes": self._cache._size,
                    "hits": self._cache.hits,
                    "misses": self._cache.misses,
                }
                snap["route_decisions"] = dict(self._route_decisions)
                snap["telegram"] = {
                    "mode_enabled": self._telegram_desktop_mode,
                    "stats": dict(self._telegram_counters),
                }
                snap["self_heal"] = {
                    "enabled": self._self_heal_enabled,
                    "events": dict(self._auto_tune_events),
                    "download_max_parallel": self._download_max_parallel,
                }
                snap["route_rules"] = {
                    "file": self._route_rules_file,
                    "count": len(self._route_rules),
                }
                snap["settings"] = self._admin_runtime_settings()
                writer.write(TelemetryStore.json_response(snap))
                await writer.drain()
                return

            if path.startswith("/api/settings") and not path.startswith("/api/settings/persist"):
                if method == "GET":
                    if not self._admin_has_scope(scopes, "read"):
                        writer.write(
                            b"HTTP/1.1 403 Forbidden\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                        return
                    writer.write(
                        TelemetryStore.json_response(self._admin_runtime_settings())
                    )
                    await writer.drain()
                    return
                if not self._admin_has_scope(scopes, "write"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                payload = {}
                if body_data:
                    try:
                        payload = json.loads(body_data.decode("utf-8", errors="replace"))
                    except Exception:
                        writer.write(
                            b"HTTP/1.1 400 Bad Request\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                        return
                if not isinstance(payload, dict):
                    writer.write(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                errors = self._apply_admin_settings(payload)
                writer.write(TelemetryStore.json_response({
                    "ok": not errors,
                    "errors": errors,
                    "settings": self._admin_runtime_settings(),
                }))
                await writer.drain()
                return

            if path.startswith("/api/settings/persist"):
                if method != "POST":
                    writer.write(
                        b"HTTP/1.1 405 Method Not Allowed\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                if not self._admin_has_scope(scopes, "admin"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                ok, message = self._persist_runtime_settings_to_config()
                writer.write(TelemetryStore.json_response({
                    "ok": ok,
                    "message": message,
                    "settings": self._admin_runtime_settings(),
                }))
                await writer.drain()
                return

            if path.startswith("/api/top-hosts"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                limit = 20
                if "?" in path:
                    try:
                        q = path.split("?", 1)[1]
                        for tok in q.split("&"):
                            k, _, v = tok.partition("=")
                            if k == "limit" and v.isdigit():
                                limit = max(1, min(200, int(v)))
                    except Exception:
                        pass
                snap = await self._telemetry.snapshot(top_hosts=limit, recent_limit=1)
                writer.write(TelemetryStore.json_response({"top_hosts": snap["top_hosts"]}))
                await writer.drain()
                return

            if path.startswith("/api/recent.csv"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                csv_body = await self._telemetry.recent_csv(limit=1000)
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/csv; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Disposition: attachment; filename=\"mhrvpn_recent.csv\"\r\n"
                    b"Content-Length: " + str(len(csv_body)).encode() + b"\r\n\r\n" + csv_body
                )
                await writer.drain()
                return

            if path.startswith("/metrics"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                text = await self._telemetry.prometheus_text()
                if self._route_decisions:
                    lines = [text.rstrip("\n")]
                    lines.append("# TYPE mhrvpn_route_decisions_total counter")
                    for route, count in sorted(self._route_decisions.items()):
                        route_label = str(route).replace("\\", "_").replace('"', "_")
                        lines.append(
                            f'mhrvpn_route_decisions_total{{route="{route_label}"}} {count}'
                        )
                    if self._telegram_counters:
                        lines.append("# TYPE mhrvpn_telegram_route_decisions_total counter")
                        for route, count in sorted(self._telegram_counters.items()):
                            route_label = str(route).replace("\\", "_").replace('"', "_")
                            lines.append(
                                f'mhrvpn_telegram_route_decisions_total{{route="{route_label}"}} {count}'
                            )
                    text = "\n".join(lines) + "\n"
                data = text.encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data
                )
                await writer.drain()
                return

            if path.startswith("/api/cache/clear"):
                if method != "POST":
                    writer.write(
                        b"HTTP/1.1 405 Method Not Allowed\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                if not self._admin_has_scope(scopes, "write"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                self._cache.clear(reset_stats=True)
                writer.write(TelemetryStore.json_response({"ok": True, "cleared": True}))
                await writer.drain()
                return

            if path.startswith("/api/route-rules/reload"):
                if method != "POST":
                    writer.write(
                        b"HTTP/1.1 405 Method Not Allowed\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                if not self._admin_has_scope(scopes, "write"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                self._route_rules = self._load_route_rules(self._route_rules_file)
                writer.write(TelemetryStore.json_response({
                    "ok": True,
                    "file": self._route_rules_file,
                    "count": len(self._route_rules),
                }))
                await writer.drain()
                return

            if path.startswith("/api/reset"):
                if method != "POST":
                    writer.write(
                        b"HTTP/1.1 405 Method Not Allowed\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                if not self._admin_has_scope(scopes, "write"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                _ = body_data
                await self._telemetry.reset()
                self._route_decisions.clear()
                self._telegram_counters.clear()
                writer.write(TelemetryStore.json_response({"ok": True, "reset": True}))
                await writer.drain()
                return

            if path.startswith("/healthz"):
                if not self._admin_has_scope(scopes, "read"):
                    writer.write(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 15\r\n\r\n"
                    b"{\"status\":\"ok\"}"
                )
                await writer.drain()
                return

            writer.write(
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
        except Exception as exc:
            log.debug("Admin client error: %s", exc)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _admin_runtime_settings(self) -> dict[str, object]:
        return {
            "self_heal_enabled": self._self_heal_enabled,
            "telegram_desktop_mode": self._telegram_desktop_mode,
            "download_max_parallel": self._download_max_parallel,
            "metrics_hash_hosts": self._telemetry._hash_hosts,
            "metrics_redact_query": self._telemetry._redact_query,
            "metrics_include_recent_paths": self._telemetry._include_recent_paths,
            "route_rules_file": self._route_rules_file,
            "route_rules_count": len(self._route_rules),
            "config_path": self._config_path or "",
            "config_persist_available": bool(self._config_path),
            "admin_auth_mode": (
                "scoped_tokens"
                if self._admin_token_scopes else
                ("single_token" if self._admin_token else "disabled")
            ),
        }

    def _apply_admin_settings(self, payload: dict[str, object]) -> list[str]:
        errors: list[str] = []
        bool_keys = (
            "self_heal_enabled",
            "telegram_desktop_mode",
            "metrics_hash_hosts",
            "metrics_redact_query",
            "metrics_include_recent_paths",
        )
        for key in bool_keys:
            if key not in payload:
                continue
            value = payload.get(key)
            if not isinstance(value, bool):
                errors.append(f"{key} must be boolean")
                continue
            if key == "self_heal_enabled":
                self._self_heal_enabled = value
            elif key == "telegram_desktop_mode":
                self._telegram_desktop_mode = value
            elif key == "metrics_hash_hosts":
                self._telemetry._hash_hosts = value
            elif key == "metrics_redact_query":
                self._telemetry._redact_query = value
            elif key == "metrics_include_recent_paths":
                self._telemetry._include_recent_paths = value

        if "download_max_parallel" in payload:
            value = payload.get("download_max_parallel")
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                parsed = 0
            if not 1 <= parsed <= 64:
                errors.append("download_max_parallel must be an integer between 1 and 64")
            else:
                self._download_max_parallel = parsed
        return errors

    def _persist_runtime_settings_to_config(self) -> tuple[bool, str]:
        if not self._config_path:
            return False, "config path not set"
        updates = {
            "self_heal_enabled": self._self_heal_enabled,
            "telegram_desktop_mode": self._telegram_desktop_mode,
            "chunked_download_max_parallel": self._download_max_parallel,
            "metrics_hash_hosts": self._telemetry._hash_hosts,
            "metrics_redact_query": self._telemetry._redact_query,
            "metrics_include_recent_paths": self._telemetry._include_recent_paths,
        }
        try:
            on_disk = {}
            if os.path.exists(self._config_path):
                with open(self._config_path, "r", encoding="utf-8") as f:
                    parsed = json.load(f)
                    if isinstance(parsed, dict):
                        on_disk = parsed
            on_disk.update(updates)
            tmp_path = self._config_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(on_disk, f, indent=2)
                f.write("\n")
            os.replace(tmp_path, self._config_path)
            self._config.update(updates)
            return True, f"saved to {self._config_path}"
        except Exception as exc:
            return False, str(exc)

    @staticmethod
    def _admin_html() -> str:
        return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MasterHttpRelayVPN Admin Panel</title>
  <style>
    :root{--bg:#071021;--bg2:#0d172c;--card:#111d35;--stroke:#223555;--text:#e2ebff;--muted:#8fa7cf;--accent:#39c6ff;--accent2:#5ee1a2;--warn:#f6b949;--bad:#ff6b7d;}
    *{box-sizing:border-box}body{margin:0;color:var(--text);font-family:system-ui,Segoe UI,Arial;background:radial-gradient(circle at 8% 0,#162a4e 0,#071021 45%,#050c18 100%);}
    .wrap{max-width:1400px;margin:0 auto;padding:16px}
    .top{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center}
    h1{margin:0;font-size:23px;letter-spacing:.3px}
    .label{color:var(--muted);font-size:12px}
    .chip{padding:6px 10px;border:1px solid var(--stroke);border-radius:999px;background:#0c1830}
    .toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
    .toolbar input,.toolbar select,.settings input,.settings select{background:#091327;border:1px solid var(--stroke);color:var(--text);padding:7px 10px;border-radius:8px}
    button{background:#183157;border:1px solid #2a4a77;color:var(--text);padding:7px 11px;border-radius:8px;cursor:pointer}
    button:hover{background:#21406f}.ghost{background:#101b33;border-color:var(--stroke)}
    .grid{margin-top:10px;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
    .card{background:linear-gradient(180deg,var(--card),#0f1b33);border:1px solid var(--stroke);border-radius:12px;padding:12px}
    .value{font-size:21px;font-weight:700;margin-top:3px}
    .panes{margin-top:10px;display:grid;grid-template-columns:2.3fr 1fr;gap:10px}
    .subgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
    table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:6px;border-bottom:1px solid #213557}th{color:var(--muted);font-weight:600}
    .mono{font-family:Consolas,ui-monospace,monospace}
    .status-ok{color:var(--accent2)}.status-bad{color:var(--bad)}
    .footer{margin-top:10px;font-size:12px;color:var(--muted)}
    a{color:var(--accent)}
    svg{width:100%;height:190px;background:#091327;border-radius:8px}
    .legend{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
    .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:middle}
    .settings label{display:block;font-size:12px;color:var(--muted);margin-bottom:3px}
    .settings-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:8px 0}
    .switches{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:8px}
    .switches label{display:flex;align-items:center;gap:6px;color:var(--text)}
    #toast{position:fixed;right:14px;bottom:14px;background:#102241;border:1px solid var(--stroke);padding:9px 12px;border-radius:8px;opacity:0;transition:opacity .2s ease}
    #toast.show{opacity:1}
    @media(max-width:1180px){.panes{grid-template-columns:1fr}.subgrid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <h1>MasterHttpRelayVPN Admin Panel</h1>
      <div class="chip">Uptime: <span id="uptime">-</span></div>
    </div>
    <div class="toolbar">
      <input id="hostFilter" placeholder="Filter host..." />
      <select id="refreshMs">
        <option value="1000">1s refresh</option><option value="2000" selected>2s refresh</option>
        <option value="5000">5s refresh</option><option value="10000">10s refresh</option>
      </select>
      <label class="label"><input id="autoRefresh" type="checkbox" checked /> auto refresh</label>
      <label class="label"><input id="chartReq" type="checkbox" checked /> requests</label>
      <label class="label"><input id="chartErr" type="checkbox" checked /> errors</label>
      <label class="label"><input id="chartDown" type="checkbox" checked /> download</label>
      <button class="ghost" id="btnRefresh">Refresh now</button>
      <button class="ghost" id="btnCsv">CSV</button>
      <button class="ghost" id="btnJson">JSON</button>
    </div>
    <div class="grid" id="cards"></div>
    <div class="card" style="margin-top:10px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <strong>Traffic Timeline</strong>
        <span class="label" id="chartSummary">-</span>
      </div>
      <svg id="chart" viewBox="0 0 980 190"></svg>
      <div class="legend">
        <span><span class="dot" style="background:#39c6ff"></span>requests</span>
        <span><span class="dot" style="background:#ff6b7d"></span>errors</span>
        <span><span class="dot" style="background:#5ee1a2"></span>download bytes</span>
      </div>
    </div>
    <div class="panes">
      <div class="subgrid">
        <div class="card"><strong>Top Hosts</strong><table id="hosts"></table></div>
        <div class="card"><strong>Recent Requests</strong><table id="recent"></table></div>
        <div class="card"><strong>Route Decisions</strong><table id="routes"></table></div>
        <div class="card"><strong>Methods / Status / Errors</strong><table id="mix"></table></div>
        <div class="card">
          <strong>Status Class + Latency</strong>
          <div class="label" style="margin:6px 0 4px">HTTP status classes</div>
          <svg id="statusChart" viewBox="0 0 380 110" style="height:110px"></svg>
          <div class="label" style="margin:8px 0 4px">Latency percentiles (recent)</div>
          <svg id="latencyChart" viewBox="0 0 380 110" style="height:110px"></svg>
        </div>
      </div>
      <div class="card settings">
        <strong>Runtime Settings</strong>
        <div class="settings-row">
          <div><label>Download max parallel</label><input id="s_download_max_parallel" type="number" min="1" max="64" /></div>
          <div><label>Top hosts rows</label><input id="s_top_hosts" type="number" min="5" max="50" value="15" /></div>
        </div>
        <div class="switches">
          <label><input id="s_self_heal_enabled" type="checkbox" />self-heal enabled</label>
          <label><input id="s_telegram_desktop_mode" type="checkbox" />telegram desktop mode</label>
          <label><input id="s_metrics_hash_hosts" type="checkbox" />hash host names</label>
          <label><input id="s_metrics_redact_query" type="checkbox" />redact query string</label>
          <label><input id="s_metrics_include_recent_paths" type="checkbox" />include recent paths</label>
        </div>
        <div class="toolbar" style="margin-top:10px">
          <button id="btnSaveSettings">Save settings</button>
          <button id="btnSaveSettingsDisk">Save to config</button>
          <button class="ghost" id="btnReloadRules">Reload route rules</button>
          <button class="ghost" id="btnClearCache">Clear cache</button>
          <button class="ghost" id="btnReset">Reset telemetry</button>
        </div>
        <div class="footer" id="settingsMeta">-</div>
      </div>
    </div>
    <div class="footer">Prometheus: <a href="/metrics" target="_blank">/metrics</a> | Summary: <a href="/api/summary" target="_blank">/api/summary</a></div>
  </div>
  <div id="toast"></div>
  <script>
    const state={summary:null,timer:null};
    const statusEl=document.getElementById("toast");
    function toast(msg,isErr=false){statusEl.textContent=msg;statusEl.style.borderColor=isErr?"#7a2435":"#225e6a";statusEl.classList.add("show");setTimeout(()=>statusEl.classList.remove("show"),1600);}
    function fbytes(n){if(!n)return "0 B";const u=["B","KB","MB","GB","TB"];let i=0,v=Number(n)||0;while(v>=1024&&i<u.length-1){v/=1024;i++}return v.toFixed(i?1:0)+" "+u[i]}
    function pct(n){return Number(n||0).toFixed(2)+"%"}
    function fmtUptime(s){s=Number(s)||0;const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=s%60;return `${h}h ${m}m ${x}s`}
    function linePath(vals,w,h,pad,maxV){if(!vals.length)return "";const n=vals.length,m=maxV||Math.max(...vals,1);return vals.map((v,i)=>`${i===0?"M":"L"} ${pad+(i*(w-2*pad)/Math.max(1,n-1))} ${h-pad-(v/m)*(h-2*pad)}`).join(" ");}
    function entriesTable(obj,headA,headB,maxRows=10){const rows=Object.entries(obj||{}).sort((a,b)=>b[1]-a[1]).slice(0,maxRows);return `<tr><th>${headA}</th><th>${headB}</th></tr>`+rows.map(r=>`<tr><td class="mono">${r[0]}</td><td>${r[1]}</td></tr>`).join("");}
    function percentile(vals,p){
      if(!vals.length)return 0;
      const a=vals.slice().sort((x,y)=>x-y);
      const i=Math.min(a.length-1,Math.max(0,Math.floor((p/100)*(a.length-1))));
      return a[i];
    }
    function drawChart(ts){
      const svg=document.getElementById("chart"),w=980,h=190,p=14,data=ts||[];
      const req=data.map(x=>x.requests||0),err=data.map(x=>x.errors||0),down=data.map(x=>x.resp_bytes||0);
      const reqOn=document.getElementById("chartReq").checked,errOn=document.getElementById("chartErr").checked,downOn=document.getElementById("chartDown").checked;
      const maxV=Math.max(1,...(reqOn?req:[0]),...(errOn?err:[0]),...(downOn?down:[0]));
      let out="";
      if(reqOn) out+=`<path d="${linePath(req,w,h,p,maxV)}" fill="none" stroke="#39c6ff" stroke-width="2"/>`;
      if(errOn) out+=`<path d="${linePath(err,w,h,p,maxV)}" fill="none" stroke="#ff6b7d" stroke-width="2"/>`;
      if(downOn) out+=`<path d="${linePath(down,w,h,p,maxV)}" fill="none" stroke="#5ee1a2" stroke-width="2"/>`;
      svg.innerHTML=out||`<text x="20" y="30" fill="#8fa7cf">enable at least one series</text>`;
      const last=data[data.length-1]||{};
      document.getElementById("chartSummary").textContent=`last bucket: req ${last.requests||0}, err ${last.errors||0}, down ${fbytes(last.resp_bytes||0)}`;
    }
    function drawStatusClassChart(statuses){
      const svg=document.getElementById("statusChart");
      const classes={"2xx":0,"3xx":0,"4xx":0,"5xx":0,"other":0};
      Object.entries(statuses||{}).forEach(([code,count])=>{
        const c=String(code||"");
        if(c.startsWith("2")) classes["2xx"]+=Number(count)||0;
        else if(c.startsWith("3")) classes["3xx"]+=Number(count)||0;
        else if(c.startsWith("4")) classes["4xx"]+=Number(count)||0;
        else if(c.startsWith("5")) classes["5xx"]+=Number(count)||0;
        else classes.other+=Number(count)||0;
      });
      const keys=Object.keys(classes), vals=keys.map(k=>classes[k]), maxV=Math.max(1,...vals);
      const colors={"2xx":"#5ee1a2","3xx":"#39c6ff","4xx":"#f6b949","5xx":"#ff6b7d","other":"#8fa7cf"};
      const barW=56,gap=16,baseY=98;
      svg.innerHTML=keys.map((k,i)=>{
        const h=Math.max(2,Math.round((vals[i]/maxV)*72)),x=14+i*(barW+gap),y=baseY-h;
        return `<rect x="${x}" y="${y}" width="${barW}" height="${h}" rx="6" fill="${colors[k]}"/>`+
               `<text x="${x+barW/2}" y="108" text-anchor="middle" fill="#8fa7cf" font-size="11">${k}</text>`+
               `<text x="${x+barW/2}" y="${y-4}" text-anchor="middle" fill="#e2ebff" font-size="10">${vals[i]}</text>`;
      }).join("");
    }
    function drawLatencyChart(recent){
      const svg=document.getElementById("latencyChart");
      const vals=(recent||[]).map(r=>Number(r.latency_ms)||0).filter(v=>v>0);
      const p50=percentile(vals,50),p90=percentile(vals,90),p99=percentile(vals,99),mx=Math.max(1,p50,p90,p99);
      const rows=[["p50",p50,"#39c6ff"],["p90",p90,"#f6b949"],["p99",p99,"#ff6b7d"]];
      const barW=72,gap=28,baseY=98;
      svg.innerHTML=rows.map((r,i)=>{
        const h=Math.max(2,Math.round((r[1]/mx)*72)),x=24+i*(barW+gap),y=baseY-h;
        return `<rect x="${x}" y="${y}" width="${barW}" height="${h}" rx="6" fill="${r[2]}"/>`+
               `<text x="${x+barW/2}" y="108" text-anchor="middle" fill="#8fa7cf" font-size="11">${r[0]}</text>`+
               `<text x="${x+barW/2}" y="${y-4}" text-anchor="middle" fill="#e2ebff" font-size="10">${r[1].toFixed(1)}ms</text>`;
      }).join("")+`<text x="260" y="15" fill="#8fa7cf" font-size="10">n=${vals.length}</text>`;
    }
    function syncSettingControls(s){
      if(!s)return;
      ["self_heal_enabled","telegram_desktop_mode","metrics_hash_hosts","metrics_redact_query","metrics_include_recent_paths"].forEach(k=>{
        const el=document.getElementById("s_"+k); if(el) el.checked=!!s[k];
      });
      document.getElementById("s_download_max_parallel").value=s.download_max_parallel||8;
      document.getElementById("settingsMeta").textContent=`route rules: ${s.route_rules_file||"-"} (${s.route_rules_count||0} rules) | auth: ${s.admin_auth_mode||"-"} | config: ${s.config_path||"not available"}`;
    }
    function render(summary){
      state.summary=summary;
      const t=summary.totals||{}, cache=summary.cache_store||{}, relay=summary.relay||{}, tg=summary.telegram?.stats||{}, uptime=summary.uptime_s||0;
      const reqRate=uptime? (t.requests/uptime).toFixed(2) : "0.00";
      const cacheTotal=(cache.hits||0)+(cache.misses||0), cacheHitRate=cacheTotal?(100*(cache.hits||0)/cacheTotal):0;
      document.getElementById("uptime").textContent=fmtUptime(uptime);
      const cards=[
        ["Requests",t.requests||0],["Errors",`${t.errors||0} (${pct(t.error_rate_pct)})`],["Req/s avg",reqRate],["Upload",fbytes(t.req_bytes||0)],
        ["Download",fbytes(t.resp_bytes||0)],["Cache entries",cache.entries||0],["Cache hit rate",pct(cacheHitRate)],["Route rules",summary.route_rules?.count||0],
        ["Relay fails",relay.failures||0],["Telegram decisions",tg.total||0]
      ];
      document.getElementById("cards").innerHTML=cards.map(c=>`<div class="card"><div class="label">${c[0]}</div><div class="value">${c[1]}</div></div>`).join("");
      drawChart(summary.timeseries||[]);
      const filter=(document.getElementById("hostFilter").value||"").toLowerCase();
      const hostLimit=Math.max(5,Math.min(50,Number(document.getElementById("s_top_hosts").value)||15));
      const hosts=(summary.top_hosts||[]).filter(h=>!filter||String(h.host||"").toLowerCase().includes(filter)).slice(0,hostLimit);
      document.getElementById("hosts").innerHTML="<tr><th>Host</th><th>Req</th><th>Err</th><th>Down</th><th>Avg ms</th></tr>"+hosts.map(h=>`<tr><td class="mono">${h.host}</td><td>${h.requests}</td><td class="${h.errors?'status-bad':''}">${h.errors}</td><td>${fbytes(h.resp_bytes)}</td><td>${h.avg_latency_ms}</td></tr>`).join("");
      const recent=(summary.recent||[]).slice().reverse().slice(0,18);
      document.getElementById("recent").innerHTML="<tr><th>Time</th><th>Request</th><th>Status</th><th>Route</th></tr>"+recent.map(r=>`<tr><td>${new Date((r.ts||0)*1000).toLocaleTimeString()}</td><td class="mono">${r.method||\"?\"} ${r.host||\"\"}${r.path?\" \"+r.path:\"\"}</td><td class="${Number(r.status)>=400?"status-bad":"status-ok"}">${r.status||0}</td><td>${r.route||\"-\"}</td></tr>`).join("");
      document.getElementById("routes").innerHTML=entriesTable(summary.route_decisions||{},"Route","Count",14);
      document.getElementById("mix").innerHTML=entriesTable(summary.methods||{},"Method","Count",6)+`<tr><td colspan="2">&nbsp;</td></tr>`+entriesTable(summary.statuses||{},"Status","Count",8)+`<tr><td colspan="2">&nbsp;</td></tr>`+entriesTable(summary.errors||{},"Error","Count",8);
      drawStatusClassChart(summary.statuses||{});
      drawLatencyChart(summary.recent||[]);
      syncSettingControls(summary.settings||{});
    }
    async function load(){
      const res=await fetch("/api/summary",{cache:"no-store"});
      if(!res.ok){toast("Could not load summary",true);return;}
      render(await res.json());
    }
    async function postJson(url,body){
      const res=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});
      let data={};try{data=await res.json()}catch(_){}
      if(!res.ok){throw new Error("HTTP "+res.status);}
      return data;
    }
    async function saveSettings(){
      const payload={
        self_heal_enabled:document.getElementById("s_self_heal_enabled").checked,
        telegram_desktop_mode:document.getElementById("s_telegram_desktop_mode").checked,
        metrics_hash_hosts:document.getElementById("s_metrics_hash_hosts").checked,
        metrics_redact_query:document.getElementById("s_metrics_redact_query").checked,
        metrics_include_recent_paths:document.getElementById("s_metrics_include_recent_paths").checked,
        download_max_parallel:Number(document.getElementById("s_download_max_parallel").value)||8
      };
      try{
        const out=await postJson("/api/settings",payload);
        if(out.errors&&out.errors.length){toast(out.errors.join("; "),true);}else{toast("Settings saved");}
        await load();
      }catch(_){toast("Save failed",true);}
    }
    async function saveSettingsDisk(){
      try{
        const out=await postJson("/api/settings/persist",{});
        if(out.ok){toast("Config saved");}else{toast(out.message||"Config save failed",true);}
        await load();
      }catch(_){toast("Config save failed",true);}
    }
    async function reloadRouteRules(){try{const d=await postJson("/api/route-rules/reload",{});toast(`Route rules loaded: ${d.count||0}`);await load();}catch(_){toast("Reload failed",true);}}
    async function clearCache(){if(!confirm("Clear cache entries and cache counters?"))return;try{await postJson("/api/cache/clear",{});toast("Cache cleared");await load();}catch(_){toast("Cache clear failed",true);}}
    async function resetStats(){if(!confirm("Reset all telemetry counters?"))return;try{await postJson("/api/reset",{});toast("Telemetry reset");await load();}catch(_){toast("Reset failed",true);}}
    function downloadCsv(){window.open("/api/recent.csv","_blank");}
    function downloadJson(){if(!state.summary)return;const blob=new Blob([JSON.stringify(state.summary,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="mhrvpn_summary.json";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000);}
    function schedule(){if(state.timer)clearInterval(state.timer);const ms=Number(document.getElementById("refreshMs").value)||2000;state.timer=setInterval(()=>{if(document.getElementById("autoRefresh").checked)load();},ms);}
    document.getElementById("btnRefresh").addEventListener("click",load);
    document.getElementById("btnCsv").addEventListener("click",downloadCsv);
    document.getElementById("btnJson").addEventListener("click",downloadJson);
    document.getElementById("btnSaveSettings").addEventListener("click",saveSettings);
    document.getElementById("btnSaveSettingsDisk").addEventListener("click",saveSettingsDisk);
    document.getElementById("btnReloadRules").addEventListener("click",reloadRouteRules);
    document.getElementById("btnClearCache").addEventListener("click",clearCache);
    document.getElementById("btnReset").addEventListener("click",resetStats);
    document.getElementById("hostFilter").addEventListener("input",()=>state.summary&&render(state.summary));
    document.getElementById("s_top_hosts").addEventListener("input",()=>state.summary&&render(state.summary));
    document.getElementById("refreshMs").addEventListener("change",schedule);
    ["chartReq","chartErr","chartDown"].forEach(id=>document.getElementById(id).addEventListener("change",()=>state.summary&&drawChart(state.summary.timeseries||[])));
    load();schedule();
  </script>
</body>
</html>"""
