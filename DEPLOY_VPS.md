# Deploy Chime backend on a VPS (Ubuntu / Debian)

From zero to a TLS-secured chat server in ~10 minutes. Tested layout: Ubuntu 22.04/24.04, any 1 vCPU / 1 GB VPS.

## 0. DNS (optional but recommended)

Point an `A` record at your VPS IP, e.g. `chat.example.com → 203.0.113.10`.
No domain? Skip TLS steps and use `http://YOUR_IP:8080` directly (fine for testing).

## 1. Install toolchain

```bash
sudo apt update
sudo apt install -y build-essential git nginx certbot python3-certbot-nginx
```

## 2. Create an unprivileged user + get the code

```bash
sudo useradd -r -m -d /opt/chime -s /usr/sbin/nologin chime || true
sudo -iu chime   # or: sudo su -s /bin/bash chime
cd /opt/chime
git clone <your-repo-url> backend && cd backend
make             # → ./chime-server
./scripts/smoke.sh && echo "binary verified ✔"
```

## 3. First manual run (sanity check)

```bash
mkdir -p /opt/chime/data
/opt/chime/backend/chime-server -p 8080 -b 127.0.0.1 \
  -d /opt/chime/data/chime.db --data /opt/chime/data
# another terminal:
curl -s localhost:8080/health   # {"ok":true,...}
```

Stop it (Ctrl+C) and continue to systemd.

## 4. systemd service (auto-start + restart on crash)

```bash
sudo cp /opt/chime/backend/deploy/chime.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now chime
systemctl status chime --no-pager
journalctl -u chime -f          # live logs (Ctrl+C to exit)
```

Crash stack traces land in `/opt/chime/data/crash.log`; the service restarts automatically (`Restart=on-failure`).

## 5. nginx reverse proxy + TLS

```bash
sudo cp /opt/chime/backend/deploy/nginx-chime.conf /etc/nginx/sites-available/chime
sudo ln -sf /etc/nginx/sites-available/chime /etc/nginx/sites-enabled/chime
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# TLS (needs the DNS record from step 0):
sudo certbot --nginx -d chat.example.com
```

Your endpoints are now:

- REST: `https://chat.example.com/api/...`
- WebSocket: `wss://chat.example.com/ws`

## 6. Firewall

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

The C server itself listens on `127.0.0.1:8080` — never expose it directly; let nginx (TLS + HTTP/2) face the internet.

## 7. In the Chime app

Open Chime → server address → `https://chat.example.com` → register → chat. 🎐

## 8. Backups (the whole DB is one file)

```bash
# crontab -e  (root)
17 4 * * * sqlite3 /opt/chime/data/chime.db ".backup /opt/chime/backups/$(date +\%F).db" && find /opt/chime/backups -mtime +14 -delete
```

(`apt install sqlite3` for the CLI, or copy the file while `systemctl stop chime`.)

## Updating

```bash
sudo -iu chime; cd /opt/chime/backend
git pull && make
exit
sudo systemctl restart chime
```

## Troubleshooting

| Symptom | Check |
|---|---|
| App can't connect | `curl localhost:8080/health` on the VPS; then nginx: `curl https://chat.example.com/health` |
| WS fails, REST works | nginx config missing the `/ws` upgrade block (see deploy/nginx-chime.conf) |
| 429 responses | rate limits kicking in — expected under fuzz/abuse |
| Crash after update | `cat /opt/chime/data/crash.log` — stack trace + signal included |
| Password reset | no admin reset by design; delete the row: `sqlite3 chime.db "DELETE FROM users WHERE username='x';"` (chat history stays) |

## Security notes

- Never run as root — the unit file already drops to the `chime` user.
- Keep `SQLITE_OMIT_LOAD_EXTENSION` + `DQS=0` compile flags (already in the Makefile).
- Rate limits per IP: 10 auth req/min, 240 API req/min. Per user: 40 WS msgs/10 s.
- Tokens expire after 30 days; rotating `meta.token_secret` in the DB logs everyone out.
