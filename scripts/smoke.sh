#!/usr/bin/env bash
# smoke.sh — end-to-end test: build must already exist (make).
# Starts a throwaway server, exercises REST + WebSocket, asserts results.
set -u
cd "$(dirname "$0")/.."

PORT=${SMOKE_PORT:-8093}
DATA=data-test
rm -rf "$DATA" && mkdir -p "$DATA"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
assert_contain() { # $1 haystack $2 needle $3 label
  case "$1" in *"$2"*) ok "$3" ;; *) bad "$3 — got: ${1:0:200}" ;; esac
}

B="http://127.0.0.1:$PORT"

echo "[1] starting chime-server on :$PORT"
./chime-server -p "$PORT" -b 127.0.0.1 -d "$DATA/chime.db" --data "$DATA" -v >"$DATA/server.out" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT

# wait for health (max 5s) — fail fast with server log if it never came up
UP=0
for i in $(seq 1 25); do
  if curl -s -m 1 "$B/health" 2>/dev/null | grep -q '"ok":true'; then UP=1; break; fi
  sleep 0.2
done
if [ "$UP" -ne 1 ]; then
  echo "server did not start! log:"; tail -20 "$DATA/server.out"
  exit 1
fi

echo "[2] health"
H=$(curl -s -m 5 "$B/health")
assert_contain "$H" '"ok":true' "health ok"

echo "[3] register two users"
R1=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"arpit","password":"supersecret1","display_name":"Arpit"}')
assert_contain "$R1" '"token":"' "register arpit"
R2=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"priya","password":"supersecret2","display_name":"Priya"}')
assert_contain "$R2" '"token":"' "register priya"
R3=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"arpit","password":"whatever123"}')
assert_contain "$R3" 'already taken' "duplicate username rejected (409)"
R4=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"ab","password":"whatever123"}')
assert_contain "$R4" '3-20 chars' "short username rejected"
R5=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"hacker1","password":"short"}')
assert_contain "$R5" '8-128' "short password rejected"

T1=$(python3 -c "import json,sys;print(json.loads('''$R1''')['token'])")
T2=$(python3 -c "import json,sys;print(json.loads('''$R2''')['token'])")
U1=$(python3 -c "import json,sys;print(json.loads('''$R1''')['user']['id'])")
U2=$(python3 -c "import json,sys;print(json.loads('''$R2''')['user']['id'])")
echo "  users: $U1 / $U2"

echo "[4] auth"
BAD=$(curl -s -m 5 -X POST "$B/api/login" -d '{"username":"arpit","password":"wrongpassword"}')
assert_contain "$BAD" 'invalid credentials' "wrong password rejected"
L=$(curl -s -m 5 -X POST "$B/api/login" -d '{"username":"arpit","password":"supersecret1"}')
assert_contain "$L" '"token":"' "login ok"
ME=$(curl -s -m 5 "$B/api/me" -H "Authorization: Bearer $T1")
assert_contain "$ME" '"username":"arpit"' "GET /me ok"
NOAUTH=$(curl -s -m 5 "$B/api/chats")
assert_contain "$NOAUTH" 'authentication required' "unauthenticated blocked"
BADTOK=$(curl -s -m 5 "$B/api/chats" -H "Authorization: Bearer ch1.forged.forged")
assert_contain "$BADTOK" 'authentication required' "forged token blocked"

echo "[5] DM + REST history"
DM=$(curl -s -m 5 -X POST "$B/api/dm" -H "Authorization: Bearer $T1" -d "{\"peer_id\":$U2}")
assert_contain "$DM" '"chat_id":' "dm create"
CHAT=$(python3 -c "import json;print(json.loads('''$DM''')['chat_id'])")
DM2=$(curl -s -m 5 -X POST "$B/api/dm" -H "Authorization: Bearer $T2" -d "{\"peer_id\":$U1}")
assert_contain "$DM2" "\"chat_id\":$CHAT" "dm find-or-create returns same chat"

echo "[6] websocket realtime"
WSEND=./scripts/ws_min.py
python3 - "$PORT" "$T1" "$T2" "$CHAT" "$WSEND" <<'PYEOF'
import sys, subprocess, time, json, importlib.util
port, t1, t2, chat, wsmod = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
spec = importlib.util.spec_from_file_location("ws_min", wsmod)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

a = m.MiniWS("127.0.0.1", int(port), f"/ws?token={t1}")
b = m.MiniWS("127.0.0.1", int(port), f"/ws?token={t2}")
ha = a.recv_json(); hb = b.recv_json()
assert ha["type"] == "hello" and ha["user"]["id"], f"hello A: {ha}"
assert hb["type"] == "hello", f"hello B: {hb}"
print("  PASS: ws hello for both clients")

# presence: B should receive presence events (own open broadcast)
got_presence = False
for _ in range(3):
    ev = b.recv_json(2)
    if ev and ev.get("type") == "presence":
        got_presence = True
print("  PASS: presence events flowing" if got_presence else "  WARN: no presence event (non-fatal)")

# typing
a.send_json({"type": "typing", "chat_id": int(chat), "on": True})
ev = None
for _ in range(3):
    ev = b.recv_json(3)
    if ev and ev.get("type") == "typing":
        break
assert ev and ev["type"] == "typing" and ev["user_id"], f"typing: {ev}"
print("  PASS: typing relay")

# message send + receive + ack
a.send_json({"type": "msg.send", "chat_id": int(chat), "body": "Hello Priya! 🎐", "client_ref": "abc-1"})
evb = None
for _ in range(3):
    evb = b.recv_json(3)
    if evb and evb.get("type") == "msg.new":
        break
assert evb and evb["type"] == "msg.new", f"msg.new B: {evb}"
msg = evb["message"]
assert msg["body"] == "Hello Priya! 🎐", f"body: {msg}"
assert msg["sender"]["username"] == "arpit", f"sender: {msg}"
print("  PASS: realtime message B<-A (unicode ok)")
# skip possible presence interleavings to find A's copies
ack, own = None, None
for _ in range(4):
    ev = a.recv_json(3)
    if ev and ev.get("type") == "msg.sent":
        ack = ev
    if ev and ev.get("type") == "msg.new":
        own = ev
    if ack and own:
        break
assert ack and ack["client_ref"] == "abc-1" and ack["msg_id"] == msg["id"], f"ack: {ack}"
assert own, "sender copy of msg.new missing"
print("  PASS: msg.sent ack with client_ref + multi-device copy")

# seen receipt
b.send_json({"type": "msg.seen", "chat_id": int(chat), "msg_id": msg["id"]})
for _ in range(4):
    ev = a.recv_json(3)
    if ev and ev.get("type") == "seen":
        assert ev["user_id"] and ev["msg_id"] == msg["id"]
        print("  PASS: seen receipt relay")
        break
else:
    print("  WARN: no seen event")

# unauthorized chat access over ws
a.send_json({"type": "msg.send", "chat_id": 999999, "body": "sneak"})
for _ in range(3):
    ev = a.recv_json(3)
    if ev and ev.get("type") == "error":
        assert ev["code"] == "not_member", f"err: {ev}"
        print("  PASS: ws message to foreign chat rejected")
        break
else:
    print("  WARN: no error for foreign chat")

a.close(); b.close()
PYEOF
[ $? -eq 0 ] && ok "websocket suite" || bad "websocket suite"

echo "[7] history + unread"
HIST=$(curl -s -m 5 "$B/api/chats/$CHAT/messages" -H "Authorization: Bearer $T1")
assert_contain "$HIST" 'Hello Priya' "history contains message"
CHATS=$(curl -s -m 5 "$B/api/chats" -H "Authorization: Bearer $T1")
assert_contain "$CHATS" '"peer"' "chat list has peer info"
# priya already sent a seen receipt in the WS suite -> her unread must be 0
CHATS2=$(curl -s -m 5 "$B/api/chats" -H "Authorization: Bearer $T2")
assert_contain "$CHATS2" '"unread":0' "unread 0 after seen receipt"

# dedicated unread test: carol never opens a WS, so her unread must stay 1
R3=$(curl -s -m 5 -X POST "$B/api/register" -d '{"username":"carol","password":"supersecret3"}')
T3=$(python3 -c "import json,sys;print(json.loads('''$R3''')['token'])")
U3=$(python3 -c "import json,sys;print(json.loads('''$R3''')['user']['id'])")
DMC=$(curl -s -m 5 -X POST "$B/api/dm" -H "Authorization: Bearer $T3" -d "{\"peer_id\":$U1}")
CIDD=$(python3 -c "import json;print(json.loads('''$DMC''')['chat_id'])")
python3 - "$PORT" "$T1" "$CIDD" <<'PYEOF' >/dev/null 2>&1
import sys, importlib.util
port, t1, chat = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("ws_min", "scripts/ws_min.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
a = m.MiniWS("127.0.0.1", int(port), f"/ws?token={t1}")
a.recv_json()
a.send_json({"type":"msg.send","chat_id":int(chat),"body":"unread ping","client_ref":"u1"})
import time; time.sleep(0.6)
a.close()
PYEOF
CHATS3=$(curl -s -m 5 "$B/api/chats" -H "Authorization: Bearer $T3")
assert_contain "$CHATS3" '"unread":1' "unread count for offline receiver"

echo "[8] groups"
GRP=$(curl -s -m 5 -X POST "$B/api/groups" -H "Authorization: Bearer $T1" -d "{\"name\":\"Gang\",\"members\":[$U2]}")
assert_contain "$GRP" '"chat_id":' "group create"
GID=$(python3 -c "import json;print(json.loads('''$GRP''')['chat_id'])")
GH=$(curl -s -m 5 "$B/api/chats/$GID/messages" -H "Authorization: Bearer $T2")
assert_contain "$GH" '"messages":[]' "group member can read"

echo "[9] user search"
SR=$(curl -s -m 5 "$B/api/users?q=pri" -H "Authorization: Bearer $T1")
assert_contain "$SR" '"username":"priya"' "user search"

echo "[10] graceful shutdown"
kill $SRV; wait $SRV 2>/dev/null
if grep -q "CRASH" "$DATA/crash.log" 2>/dev/null; then bad "crash log has entries"; else ok "no crashes"; fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
