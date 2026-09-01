# chime-backend

Self-hosted real-time chat backend for the **Chime** app — written in **pure C11** with **zero external dependencies** (SQLite is vendored). One binary, one database file, done.

```
clang/gcc ──► chime-server ──► HTTP/1.1 + WebSocket (RFC 6455)
                               SQLite (WAL, prepared statements)
```

## Why C?

- ~1.2 MB static-capable binary, ~10 MB RSS idle, no runtime, no node_modules
- Single-threaded epoll event loop — thousands of concurrent sockets
- Every safety-critical piece is hand-auditable in `src/` (~3.5k lines)

## Features

- **Auth**: username + password, PBKDF2-HMAC-SHA256 (120k iterations, per-user salt), HMAC-signed bearer tokens (30-day TTL), constant-time comparisons
- **Realtime**: RFC 6455 WebSocket — presence, typing indicators, seen receipts, live message fan-out, `client_ref` acks, multi-device copy
- **Chats**: 1-1 DMs (find-or-create), group chats, member management, history pagination, unread counts
- **Security**: prepared statements everywhere, per-IP + per-user sliding-window rate limits, frame/message size caps, UTF-8 validation, control-char rejection, extension-less SQLite (`SQLITE_OMIT_LOAD_EXTENSION`, `SQLITE_DQS=0`), no tokens in logs
- **Reliability**: fatal-signal crash handler with stack traces (`crash.log`), graceful shutdown, idle sweeps + heartbeat pings, backpressure kill switch
- **Observability**: `/health` endpoint, leveled logs, client crash-report sink (`POST /api/client-logs`)

## Build

```bash
make            # -> ./chime-server   (only needs a C compiler)
make selftest   # NIST/RFC crypto vectors
make test       # full end-to-end smoke suite (22 checks)
make static     # fully static binary
```

That's it. No pkg-config, no libsqlite3-dev — the SQLite amalgamation is vendored in `vendor/`.

## Run

```bash
./chime-server -p 8080 -b 0.0.0.0 -d /var/lib/chime/chime.db --data /var/lib/chime
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-p` | 8080 | TCP port |
| `-b` | 0.0.0.0 | Bind address |
| `-d` | chime.db | SQLite database file |
| `--data` | . | Directory for `chime.log` + `crash.log` |
| `-v` | — | Verbose (repeat for debug) |

👉 **Deploying to a VPS? Follow [DEPLOY_VPS.md](DEPLOY_VPS.md)** — copy-paste ready: build, systemd, nginx + TLS, firewall, backups.

## API

REST (JSON, `Authorization: Bearer <token>`):

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/register` | `{username, password, display_name?}` → `{token, user}` |
| POST | `/api/login` | `{username, password}` → `{token, user}` |
| GET | `/api/me` | current user |
| GET | `/api/users?q=` | search / recent users |
| GET | `/api/chats` | chat list (+last message, unread, peer) |
| POST | `/api/dm` | `{peer_id}` → find-or-create DM |
| POST | `/api/groups` | `{name, members:[ids]}` |
| POST | `/api/groups/:id/members` | `{user_id}` |
| GET | `/api/chats/:id/messages?before=&limit=` | history (≤100) |
| POST | `/api/client-logs` | crash/log sink from the app |
| GET | `/health` | liveness + stats |

WebSocket: `GET /ws?token=<token>` (or `wss://` behind nginx). Client → server:

```jsonc
{"type":"msg.send","chat_id":1,"body":"hello","client_ref":"uuid"}  // → msg.sent ack + msg.new fan-out
{"type":"typing","chat_id":1,"on":true}                             // → relayed to others
{"type":"msg.seen","chat_id":1,"msg_id":42}                         // → seen broadcast
```

Server → client events: `hello`, `presence`, `msg.new`, `msg.sent`, `typing`, `seen`, `chat.new`, `error`.

## Repo layout

```
src/            chime.h · server.c (epoll) · http.c · ws.c (RFC 6455) · api.c
                realtime.c · db.c · auth.c · sha256.c · json.c · ratelimit.c
                crash.c · log.c · util.c · main.c
vendor/sqlite/  amalgamation (public domain)
scripts/        smoke.sh · ws_min.py · crypto_selftest.c
deploy/         chime.service · nginx-chime.conf
```

## License

MIT © 2026 — see [LICENSE](LICENSE).
