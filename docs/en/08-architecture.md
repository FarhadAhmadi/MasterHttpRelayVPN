# 8) Architecture

## Main Components

- `main.py` — startup, config loading, CLI
- `src/proxy_server.py` — listeners, protocol handling, routing decisions
- `src/domain_fronter.py` — relay engine and request strategies
- `src/h2_transport.py` — HTTP/2 transport (optional)
- `src/mitm.py` — local MITM certificate handling
- `src/telemetry.py` — in-memory telemetry store

## Flow Summary

1. Client connects to local proxy.
2. Proxy identifies CONNECT/HTTP/SOCKS behavior.
3. Routing picks direct / relay / SNI-rewrite path.
4. Relay engine sends to Apps Script as needed.
5. Response returns to client.
6. Telemetry records metrics and route decisions.

