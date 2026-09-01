/* realtime.c — WebSocket event layer: presence, typing, seen, message relay. */
#include "chime.h"

/* ---------- broadcast helpers ---------- */

static void send_to_user(int64_t uid, const char *payload) {
    size_t len = strlen(payload);
    for (Conn *c = g_conns; c; c = c->next) {
        if (c->mode == CONN_WS && c->user_id == uid && !c->ws_closing)
            ws_send_text(c, payload, len);
    }
}

static void broadcast_chat(int64_t chat_id, const char *payload) {
    size_t len = strlen(payload);
    for (Conn *c = g_conns; c; c = c->next) {
            if (c->mode != CONN_WS || c->user_id <= 0 || c->ws_closing) continue;
        if (!shared_is_member(chat_id, c->user_id)) continue;
        ws_send_text(c, payload, len);
    }
}

static void broadcast_presence(int64_t uid, int online) {
    char payload[96];
    snprintf(payload, sizeof payload,
             "{\"type\":\"presence\",\"user_id\":%lld,\"online\":%s}",
             (long long)uid, online ? "true" : "false");
    size_t len = strlen(payload);
    for (Conn *c = g_conns; c; c = c->next) {
        if (c->mode == CONN_WS && c->user_id > 0 && !c->ws_closing)
            ws_send_text(c, payload, len);
    }
}

void rt_notify_chat_new(int64_t chat_id) {
    char payload[128];
    snprintf(payload, sizeof payload,
             "{\"type\":\"chat.new\",\"chat_id\":%lld}", (long long)chat_id);
    broadcast_chat(chat_id, payload);
}

/* ---------- lifecycle ---------- */

void rt_on_open(Conn *c) {
    /* hello with own identity + online list */
    Buf b; buf_init(&b);
    buf_printf(&b, "{\"type\":\"hello\",\"user\":");
    shared_user_json(&b, c->user_id);
    buf_printf(&b, ",\"online\":[");
    int first = 1;
    int64_t seen[256]; int ns = 0;
    for (Conn *o = g_conns; o; o = o->next) {
        if (o == c || o->mode != CONN_WS || o->user_id <= 0) continue;
        int dup = 0;
        for (int i = 0; i < ns; i++) if (seen[i] == o->user_id) { dup = 1; break; }
        if (dup) continue;
        if (ns < 256) seen[ns++] = o->user_id;
        if (!first) buf_append(&b, ",", 1);
        first = 0;
        buf_printf(&b, "%lld", (long long)o->user_id);
    }
    buf_printf(&b, "]}");
    ws_send_text(c, b.data ? b.data : "{}", b.len);
    buf_free(&b);

    /* announce presence (clients dedupe per user) */
    broadcast_presence(c->user_id, 1);
    logi("rt online uid=%lld (%s) users=%d", (long long)c->user_id, c->username, online_user_count());
}

void rt_on_close(Conn *c) {
    if (c->user_id <= 0) return;
    Stmt s;
    if (db_prep(&s, "UPDATE users SET last_seen=?2 WHERE id=?1")) return;
    db_bind_i64(&s, 1, c->user_id);
    db_bind_i64(&s, 2, now_sec());
    db_step(&s); db_fin(&s);

    if (!user_online(c->user_id))
        broadcast_presence(c->user_id, 0);
    logi("rt offline uid=%lld users=%d", (long long)c->user_id, online_user_count());
}

/* ---------- inbound events ---------- */

static void ev_msg_send(Conn *c, JV *j) {
    int64_t chat_id = jv_int(jv_get(j, "chat_id"));
    JV *bjv = jv_get(j, "body");
    const char *body = jv_str(bjv);
    JV *ref = jv_get(j, "client_ref");
    const char *client_ref = ref ? jv_str(ref) : NULL;

    if (chat_id <= 0 || !body || !bjv || bjv->t != JV_STR ||
        body[0] == '\0' || bjv->slen > MAX_MSG_BODY) {
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"bad_body\"}");
        return;
    }
    if (!utf8_valid(body, bjv->slen) || has_forbidden_ctrl(body, bjv->slen)) {
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"bad_body\"}");
        return;
    }
    if (!shared_is_member(chat_id, c->user_id)) {
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"not_member\"}");
        return;
    }

    /* rate limit per user */
    char ukey[32];
    snprintf(ukey, sizeof ukey, "u:%lld", (long long)c->user_id);
    if (!rl_check("ws", ukey, 40, 10000)) {
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"rate_limited\"}");
        return;
    }

    int64_t msg_id = 0;
    Stmt s;
    if (db_prep(&s, "INSERT INTO messages(chat_id, sender_id, body, created_at) VALUES(?1,?2,?3,?4)")) {
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"db\"}");
        return;
    }
    db_bind_i64(&s, 1, chat_id);
    db_bind_i64(&s, 2, c->user_id);
    db_bind_text(&s, 3, body, bjv->slen);
    db_bind_i64(&s, 4, now_sec());
    if (db_step(&s) == 0) msg_id = sqlite3_last_insert_rowid(g_db);
    db_fin(&s);
    if (!msg_id) { send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"db\"}"); return; }

    /* sender has obviously read their own message */
    if (db_prep(&s, "UPDATE chat_members SET last_read_msg=MAX(last_read_msg,?3) "
                     "WHERE chat_id=?1 AND user_id=?2")) return;
    db_bind_i64(&s, 1, chat_id);
    db_bind_i64(&s, 2, c->user_id);
    db_bind_i64(&s, 3, msg_id);
    db_step(&s); db_fin(&s);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"type\":\"msg.new\",\"message\":");
    shared_message_json(&b, msg_id);
    buf_append(&b, "}", 1);
    broadcast_chat(chat_id, b.data ? b.data : "{}");
    buf_free(&b);

    if (client_ref) {
        Buf a; buf_init(&a);
        buf_printf(&a, "{\"type\":\"msg.sent\",\"chat_id\":%lld,\"msg_id\":%lld,\"client_ref\":",
                   (long long)chat_id, (long long)msg_id);
        json_escape_buf(&a, client_ref, strlen(client_ref));
        buf_append(&a, "}", 1);
        send_to_user(c->user_id, a.data ? a.data : "{}");
        buf_free(&a);
    }
}

static void ev_typing(Conn *c, JV *j) {
    int64_t chat_id = jv_int(jv_get(j, "chat_id"));
    JV *ov = jv_get(j, "on");
    int on = ov ? (ov->t == JV_BOOL ? ov->b : (int)jv_int(ov)) : 1;
    if (chat_id <= 0) return;
    if (!shared_is_member(chat_id, c->user_id)) return;

    char ukey[32];
    snprintf(ukey, sizeof ukey, "u:%lld", (long long)c->user_id);
    if (!rl_check("typing", ukey, 15, 10000)) return;

    char payload[160];
    snprintf(payload, sizeof payload,
             "{\"type\":\"typing\",\"chat_id\":%lld,\"user_id\":%lld,\"on\":%s}",
             (long long)chat_id, (long long)c->user_id, on ? "true" : "false");

    /* everyone except the typist */
    size_t len = strlen(payload);
    for (Conn *o = g_conns; o; o = o->next) {
        if (o == c || o->mode != CONN_WS || o->user_id <= 0 || o->ws_closing) continue;
        if (!shared_is_member(chat_id, o->user_id)) continue;
        ws_send_text(o, payload, len);
    }
}

static void ev_seen(Conn *c, JV *j) {
    int64_t chat_id = jv_int(jv_get(j, "chat_id"));
    int64_t msg_id = jv_int(jv_get(j, "msg_id"));
    if (chat_id <= 0 || msg_id <= 0) return;
    if (!shared_is_member(chat_id, c->user_id)) return;

    Stmt s;
    if (db_prep(&s, "UPDATE chat_members SET last_read_msg=MAX(last_read_msg,?3) "
                     "WHERE chat_id=?1 AND user_id=?2")) return;
    db_bind_i64(&s, 1, chat_id);
    db_bind_i64(&s, 2, c->user_id);
    db_bind_i64(&s, 3, msg_id);
    db_step(&s); db_fin(&s);

    char payload[160];
    snprintf(payload, sizeof payload,
             "{\"type\":\"seen\",\"chat_id\":%lld,\"user_id\":%lld,\"msg_id\":%lld}",
             (long long)chat_id, (long long)c->user_id, (long long)msg_id);
    broadcast_chat(chat_id, payload);
}

void rt_on_text(Conn *c, char *data, size_t len) {
    c->ping_pending = 0;   /* any traffic proves liveness */
    if (!len || len > MAX_WS_MSG) return;

    const char *err = NULL;
    JV *j = json_parse(data, len, &err);
    if (!j || j->t != JV_OBJ) {
        json_free(j);
        send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"bad_json\"}");
        return;
    }
    const char *type = jv_str(jv_get(j, "type"));
    if (!type) { json_free(j); send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"bad_type\"}"); return; }

    if      (!strcmp(type, "msg.send")) ev_msg_send(c, j);
    else if (!strcmp(type, "typing"))   ev_typing(c, j);
    else if (!strcmp(type, "msg.seen")) ev_seen(c, j);
    else if (!strcmp(type, "ping"))     send_to_user(c->user_id, "{\"type\":\"pong\"}");
    else send_to_user(c->user_id, "{\"type\":\"error\",\"code\":\"unknown_type\"}");

    json_free(j);
}
