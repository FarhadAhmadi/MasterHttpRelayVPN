# 1) Overview

MasterHttpRelayVPN is a local proxy that forwards traffic through a Google Apps Script relay path.

At a high level:

1. Browser/app connects to local proxy (HTTP/SOCKS5).
2. HTTPS can be decrypted locally (MITM mode with local CA cert).
3. Requests are relayed through Apps Script endpoints.
4. Responses are reconstructed and returned to the client.

## Core Purpose

- Improve connectivity in restrictive network environments.
- Provide a single local proxy endpoint for browser/desktop apps.
- Offer observability and controls via built-in dashboard/API.

## v1 Highlights

- HTTP + SOCKS5 listeners
- MITM cert generation and install helper
- Apps Script relay mode
- Optional HTTP/2 transport and batching
- Parallel range downloads
- Admin dashboard + JSON API + Prometheus metrics
- Telegram Desktop compatibility mode

