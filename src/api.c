/* api.c — REST endpoints + shared entity builders.
 * Every SQL statement uses bound parameters. Every route is rate-limited.
 */
#include "chime.h"
#include <ctype.h>

/* ================= shared builders ================= */

int shared_is_member(int64_t chat_id, int64_t user_id) {
    Stmt s;
    if (db_prep(&s, "SELECT 1 FROM chat_members WHERE chat_id=?1 AND user_id=?2")) return 0;
    db_bind_i64(&s, 1, chat_id);
    db_bind_i64(&s, 2, user_id);
    int r = db_step(&s);
    db_fin(&s);
    return r == 1;
}

void shared_user_json(Buf *b, int64_t uid) {
    Stmt s;
    if (db_prep(&s, "SELECT id, username, display_name FROM users WHERE id=?1")) {
        buf_append(b, "null", 4); return;
    }
    db_bind_i64(&s, 1, uid);
    if (db_step(&s) == 1) {
        buf_printf(b, "{\"id\":%lld,\"username\":",
                   (long long)db_col_i64(&s, 0));
        json_escape_buf(b, (const char*)db_col_text(&s, 1),
                        strlen((const char*)db_col_text(&s, 1)));
        buf_printf(b, ",\"display_name\":");
        const unsigned char *dn = db_col_text(&s, 2);
        json_escape_buf(b, (const char*)dn, strlen((const char*)dn));
        buf_append(b, "}", 1);
    } else {
        buf_append(b, "null", 4);
    }
    db_fin(&s);
}

void shared_message_json(Buf *b, int64_t msg_id) {
    Stmt s;
    if (db_prep(&s, "SELECT id, chat_id, sender_id, body, created_at FROM messages WHERE id=?1")) {
        buf_append(b, "null", 4); return;
    }
    db_bind_i64(&s, 1, msg_id);
    if (db_step(&s) == 1) {
        buf_printf(b, "{\"id\":%lld,\"chat_id\":%lld,\"sender_id\":%lld,\"body\":",
            (long long)db_col_i64(&s, 0), (long long)db_col_i64(&s, 1),
            (long long)db_col_i64(&s, 2));
        const unsigned char *body = db_col_text(&s, 3);
        size_t blen = strlen((const char*)body);
        if (!utf8_valid((const char*)body, blen)) { body = (const unsigned char*)""; blen = 0; }
        json_escape_buf(b, (const char*)body, blen);
        buf_printf(b, ",\"created_at\":%lld,\"sender\":", (long long)db_col_i64(&s, 4));
        int64_t sender = db_col_i64(&s, 2);
        db_fin(&s);
        shared_user_json(b, sender);
        buf_append(b, "}", 1);
        return;
    }
    db_fin(&s);
    buf_append(b, "null", 4);
}

/* ================= small helpers ================= */

static void ok(Buf *out, const char *json) { http_reply_json(out, 200, json); }

static int valid_username(const char *u) {
    size_t n = strlen(u);
    if (n < 3 || n > MAX_USERNAME) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = u[i];
        if (!(isalnum((unsigned char)c) || c == '_')) return 0;
    }
    return 1;
}

static int valid_display(const char *d, size_t len) {
    if (len == 0 || len > (size_t)MAX_DISPLAY * 3) return 0;
    if (!utf8_valid(d, len)) return 0;
    if (has_forbidden_ctrl(d, len)) return 0;
    return 1;
}

/* ================= routes ================= */

static void h_register(Conn *c, HTTPReq *req, Buf *out) {
    (void)c;
    char ipkey[80];
    snprintf(ipkey, sizeof ipkey, "ip:%s", c->ip);
    if (!rl_check("auth", ipkey, 10, 60000)) {
        http_reply_err(out, 429, "slow down, try again in a minute"); return;
    }
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }

    const char *username = jv_str(jv_get(j, "username"));
    const char *password = jv_str(jv_get(j, "password"));
    JV *djv = jv_get(j, "display_name");
    const char *display = djv ? jv_str(djv) : NULL;

    if (!username || !valid_username(username)) { json_free(j); http_reply_err(out, 400, "username must be 3-20 chars: letters, digits, underscore"); return; }
    if (!password || strlen(password) < 8 || strlen(password) > 128) { json_free(j); http_reply_err(out, 400, "password must be 8-128 chars"); return; }
    if (has_forbidden_ctrl(password, strlen(password))) { json_free(j); http_reply_err(out, 400, "password contains control chars"); return; }

    /* copy ALL inputs out of the JSON tree — everything below frees j early */
    char uname[64], dname[MAX_DISPLAY * 3 + 1], pass[129];
    snprintf(uname, sizeof uname, "%s", username);
    snprintf(pass, sizeof pass, "%s", password);
    if (display) {
        if (!valid_display(display, strlen(display))) { json_free(j); http_reply_err(out, 400, "display_name invalid (max 32 chars)"); return; }
        snprintf(dname, sizeof dname, "%s", display);
    } else {
        snprintf(dname, sizeof dname, "%s", uname);
    }
    size_t ulen = strlen(uname), dlen = strlen(dname);
    json_free(j);

    char hash[256];
    if (pw_hash(pass, hash)) { http_reply_err(out, 500, "hash failed"); return; }

    Stmt s;
    if (db_prep(&s, "INSERT INTO users(username, display_name, pass_hash, created_at, last_seen) VALUES(?1,?2,?3,?4,?4)")) {
        http_reply_err(out, 500, "db error"); return;
    }
    int64_t now = now_sec();
    db_bind_text(&s, 1, uname, ulen);
    db_bind_text(&s, 2, dname, dlen);
    db_bind_text(&s, 3, hash, strlen(hash));
    db_bind_i64(&s, 4, now);
    int rc = db_step(&s);
    db_fin(&s);

    if (rc < 0) {
        sqlite3 *d = g_db;
        int ec = sqlite3_extended_errcode(d);
        if (ec == SQLITE_CONSTRAINT_UNIQUE || ec == SQLITE_CONSTRAINT) {
            http_reply_err(out, 409, "username already taken");
        } else {
            http_reply_err(out, 500, "db error");
        }
        return;
    }
    int64_t uid = sqlite3_last_insert_rowid(g_db);

    char token[256];
    if (token_mint(uid, token, sizeof token)) { http_reply_err(out, 500, "token error"); return; }
    logi("registered user=%s uid=%lld ip=%s", uname, (long long)uid, c->ip);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"token\":");
    json_escape_buf(&b, token, strlen(token));
    buf_printf(&b, ",\"user\":{\"id\":%lld,\"username\":", (long long)uid);
    json_escape_buf(&b, uname, ulen);
    buf_printf(&b, ",\"display_name\":");
    json_escape_buf(&b, dname, dlen);
    buf_printf(&b, "}}");
    http_reply_json(out, 201, b.data);
    buf_free(&b);
}

static void h_login(Conn *c, HTTPReq *req, Buf *out) {
    char ipkey[80];
    snprintf(ipkey, sizeof ipkey, "ip:%s", c->ip);
    if (!rl_check("auth", ipkey, 10, 60000)) {
        http_reply_err(out, 429, "slow down, try again in a minute"); return;
    }
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }
    const char *username = jv_str(jv_get(j, "username"));
    const char *password = jv_str(jv_get(j, "password"));
    if (!username || !password) { json_free(j); http_reply_err(out, 400, "username and password required"); return; }

    Stmt s;
    int64_t uid = 0;
    char hash[256] = "";
    if (db_prep(&s, "SELECT id, pass_hash FROM users WHERE username=?1")) {
        json_free(j); http_reply_err(out, 500, "db error"); return;
    }
    db_bind_text(&s, 1, username, strlen(username));
    if (db_step(&s) == 1) {
        uid = db_col_i64(&s, 0);
        const unsigned char *h = db_col_text(&s, 1);
        snprintf(hash, sizeof hash, "%s", h ? (const char*)h : "");
    }
    db_fin(&s);

    /* always run a verify to keep timing uniform for unknown users */
    if (uid <= 0) {
        pw_verify(password, "pbkdf2-sha256$120000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        json_free(j);
        logw("login failed user=%s ip=%s", username, c->ip);
        http_reply_err(out, 401, "invalid credentials");
        return;
    }
    if (pw_verify(password, hash)) {
        json_free(j);
        logw("login failed user=%s ip=%s", username, c->ip);
        http_reply_err(out, 401, "invalid credentials");
        return;
    }
    json_free(j);

    Stmt u;
    if (db_prep(&u, "UPDATE users SET last_seen=?2 WHERE id=?1")) { http_reply_err(out, 500, "db error"); return; }
    db_bind_i64(&u, 1, uid);
    db_bind_i64(&u, 2, now_sec());
    db_step(&u); db_fin(&u);

    char token[256];
    if (token_mint(uid, token, sizeof token)) { http_reply_err(out, 500, "token error"); return; }
    logi("login uid=%lld ip=%s", (long long)uid, c->ip);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"token\":");
    json_escape_buf(&b, token, strlen(token));
    buf_printf(&b, ",\"user\":");
    shared_user_json(&b, uid);
    buf_append(&b, "}", 1);
    ok(out, b.data);
    buf_free(&b);
}

static void h_me(Conn *c, HTTPReq *req, Buf *out) {
    (void)req;
    Buf b; buf_init(&b);
    buf_printf(&b, "{\"user\":");
    shared_user_json(&b, c->user_id);
    buf_append(&b, "}", 1);
    ok(out, b.data);
    buf_free(&b);
}

static void h_users(Conn *c, HTTPReq *req, Buf *out) {
    Stmt s;
    char q[200] = "";
    query_param(req->query, "q", q, sizeof q);
    Buf b; buf_init(&b);
    buf_printf(&b, "{\"users\":[");

    if (q[0]) {
        /* escape LIKE wildcards */
        char esc[401]; size_t oi = 0;
        for (size_t i = 0; q[i] && oi + 2 < sizeof esc; i++) {
            if (q[i] == '\\' || q[i] == '%' || q[i] == '_') esc[oi++] = '\\';
            esc[oi++] = q[i];
        }
        esc[oi] = 0;
        char like[804];
        snprintf(like, sizeof like, "%%%s%%", esc);
        if (db_prep(&s, "SELECT id, username, display_name FROM users "
                        "WHERE id != ?1 AND (username LIKE ?2 ESCAPE '\\' "
                        "OR display_name LIKE ?2 ESCAPE '\\') "
                        "ORDER BY username LIMIT 20")) { buf_free(&b); http_reply_err(out,500,"db"); return; }
        db_bind_i64(&s, 1, c->user_id);
        db_bind_text(&s, 2, like, strlen(like));
    } else {
        if (db_prep(&s, "SELECT id, username, display_name FROM users "
                        "WHERE id != ?1 ORDER BY last_seen DESC LIMIT 20")) {
            buf_free(&b); http_reply_err(out,500,"db"); return;
        }
        db_bind_i64(&s, 1, c->user_id);
    }

    int first = 1;
    while (db_step(&s) == 1) {
        if (!first) buf_append(&b, ",", 1);
        first = 0;
        buf_printf(&b, "{\"id\":%lld,\"username\":", (long long)db_col_i64(&s, 0));
        json_escape_buf(&b, (const char*)db_col_text(&s, 1), strlen((const char*)db_col_text(&s, 1)));
        buf_printf(&b, ",\"display_name\":");
        json_escape_buf(&b, (const char*)db_col_text(&s, 2), strlen((const char*)db_col_text(&s, 2)));
        buf_append(&b, "}", 1);
    }
    db_fin(&s);
    buf_printf(&b, "]}");
    ok(out, b.data);
    buf_free(&b);
}

/* one chat entry for the chat list */
static void chat_entry_json(Buf *b, int64_t chat_id, int64_t me) {
    Stmt s;
    if (db_prep(&s, "SELECT type, name, created_at FROM chats WHERE id=?1")) return;
    db_bind_i64(&s, 1, chat_id);
    if (db_step(&s) != 1) { db_fin(&s); return; }
    const char *type = (const char*)db_col_text(&s, 0);
    const unsigned char *name = db_col_text(&s, 1);
    int64_t created = db_col_i64(&s, 2);
    char ctype[8]; snprintf(ctype, sizeof ctype, "%s", type);
    char cname[193]; snprintf(cname, sizeof cname, "%s", name ? (const char*)name : "");
    db_fin(&s);

    buf_printf(b, "{\"id\":%lld,\"type\":", (long long)chat_id);
    json_escape_buf(b, ctype, strlen(ctype));

    if (!strcmp(ctype, "dm")) {
        /* peer info */
        Stmt p;
        if (db_prep(&p, "SELECT u.id FROM chat_members m JOIN users u ON u.id=m.user_id "
                         "WHERE m.chat_id=?1 AND m.user_id != ?2")) return;
        db_bind_i64(&p, 1, chat_id);
        db_bind_i64(&p, 2, me);
        int64_t peer = 0;
        if (db_step(&p) == 1) peer = db_col_i64(&p, 0);
        db_fin(&p);
        buf_printf(b, ",\"name\":null,\"peer\":");
        shared_user_json(b, peer);
    } else {
        buf_printf(b, ",\"name\":");
        json_escape_buf(b, cname, strlen(cname));
        buf_printf(b, ",\"peer\":null");
    }

    /* last message */
    Stmt lm;
    int64_t last_id = 0;
    if (db_prep(&lm, "SELECT id FROM messages WHERE chat_id=?1 ORDER BY id DESC LIMIT 1")) return;
    db_bind_i64(&lm, 1, chat_id);
    if (db_step(&lm) == 1) last_id = db_col_i64(&lm, 0);
    db_fin(&lm);
    buf_printf(b, ",\"last_message\":");
    if (last_id) shared_message_json(b, last_id); else buf_append(b, "null", 4);

    /* unread */
    Stmt u;
    if (db_prep(&u, "SELECT COUNT(*) FROM messages WHERE chat_id=?1 "
                     "AND id > (SELECT last_read_msg FROM chat_members WHERE chat_id=?1 AND user_id=?2) "
                     "AND sender_id != ?2")) return;
    db_bind_i64(&u, 1, chat_id);
    db_bind_i64(&u, 2, me);
    int64_t unread = 0;
    if (db_step(&u) == 1) unread = db_col_i64(&u, 0);
    db_fin(&u);
    buf_printf(b, ",\"unread\":%lld,\"created_at\":%lld}", (long long)unread, (long long)created);
}

static void h_chats(Conn *c, HTTPReq *req, Buf *out) {
    (void)req;
    Stmt s;
    if (db_prep(&s, "SELECT chat_id FROM chat_members WHERE user_id=?1 ORDER BY chat_id DESC")) {
        http_reply_err(out, 500, "db"); return;
    }
    db_bind_i64(&s, 1, c->user_id);
    int64_t ids[512]; int n = 0;
    while (db_step(&s) == 1 && n < 512) ids[n++] = db_col_i64(&s, 0);
    db_fin(&s);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"chats\":[");
    for (int i = 0; i < n; i++) {
        if (i) buf_append(&b, ",", 1);
        chat_entry_json(&b, ids[i], c->user_id);
    }
    buf_printf(&b, "]}");
    ok(out, b.data);
    buf_free(&b);
}

static void h_dm_create(Conn *c, HTTPReq *req, Buf *out) {
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }
    int64_t peer = jv_int(jv_get(j, "peer_id"));
    json_free(j);
    if (peer <= 0 || peer == c->user_id) { http_reply_err(out, 400, "invalid peer_id"); return; }

    /* peer must exist */
    Stmt e;
    if (db_prep(&e, "SELECT 1 FROM users WHERE id=?1")) { http_reply_err(out, 500, "db"); return; }
    db_bind_i64(&e, 1, peer);
    int exists = db_step(&e) == 1;
    db_fin(&e);
    if (!exists) { http_reply_err(out, 404, "user not found"); return; }

    int64_t lo = c->user_id < peer ? c->user_id : peer;
    int64_t hi = c->user_id < peer ? peer : c->user_id;
    char key[48];
    snprintf(key, sizeof key, "%lld:%lld", (long long)lo, (long long)hi);

    /* find existing */
    Stmt f;
    if (db_prep(&f, "SELECT id FROM chats WHERE dm_key=?1")) { http_reply_err(out, 500, "db"); return; }
    db_bind_text(&f, 1, key, strlen(key));
    int64_t existing = 0;
    if (db_step(&f) == 1) existing = db_col_i64(&f, 0);
    db_fin(&f);

    if (existing) {
        Buf b; buf_init(&b);
        buf_printf(&b, "{\"chat_id\":%lld,\"created\":false}", (long long)existing);
        ok(out, b.data); buf_free(&b);
        return;
    }

    sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    int64_t chat_id = 0;
    Stmt i1;
    if (db_prep(&i1, "INSERT INTO chats(type, dm_key, name, created_by, created_at) VALUES('dm',?1,'',?2,?3)")) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        http_reply_err(out, 500, "db"); return;
    }
    db_bind_text(&i1, 1, key, strlen(key));
    db_bind_i64(&i1, 2, c->user_id);
    db_bind_i64(&i1, 3, now_sec());
    if (db_step(&i1) == 0) chat_id = sqlite3_last_insert_rowid(g_db);
    db_fin(&i1);
    if (!chat_id) { sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL); http_reply_err(out, 500, "db"); return; }

    Stmt i2;
    if (db_prep(&i2, "INSERT INTO chat_members(chat_id, user_id, joined_at) VALUES(?1,?2,?3)")) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL); http_reply_err(out, 500, "db"); return;
    }
    db_bind_i64(&i2, 1, chat_id); db_bind_i64(&i2, 3, now_sec());
    db_bind_i64(&i2, 2, c->user_id); db_step(&i2); db_reset(&i2);
    db_bind_i64(&i2, 2, peer); db_step(&i2);
    db_fin(&i2);
    sqlite3_exec(g_db, "COMMIT", NULL, NULL, NULL);

    logi("dm chat=%lld created by=%lld", (long long)chat_id, (long long)c->user_id);
    rt_notify_chat_new(chat_id);   /* pings online members to refresh */

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"chat_id\":%lld,\"created\":true}", (long long)chat_id);
    http_reply_json(out, 201, b.data);
    buf_free(&b);
}

static void h_group_create(Conn *c, HTTPReq *req, Buf *out) {
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }
    JV *njv = jv_get(j, "name");
    const char *name = jv_str(njv);
    if (!name || !valid_display(name, strlen(name)) || strlen(name) > 96) {
        json_free(j); http_reply_err(out, 400, "group name must be 1-32 chars"); return;
    }
    JV *members = jv_get(j, "members");
    if (members && members->t != JV_ARR) { json_free(j); http_reply_err(out, 400, "members must be array"); return; }

    sqlite3_exec(g_db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    int64_t chat_id = 0;
    Stmt i1;
    if (db_prep(&i1, "INSERT INTO chats(type, dm_key, name, created_by, created_at) VALUES('group',NULL,?1,?2,?3)")) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        json_free(j); http_reply_err(out, 500, "db"); return;
    }
    db_bind_text(&i1, 1, name, strlen(name));
    db_bind_i64(&i1, 2, c->user_id);
    db_bind_i64(&i1, 3, now_sec());
    if (db_step(&i1) == 0) chat_id = sqlite3_last_insert_rowid(g_db);
    db_fin(&i1);
    if (!chat_id) { sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL); json_free(j); http_reply_err(out, 500, "db"); return; }

    Stmt i2;
    if (db_prep(&i2, "INSERT OR IGNORE INTO chat_members(chat_id, user_id, joined_at) VALUES(?1,?2,?3)")) {
        sqlite3_exec(g_db, "ROLLBACK", NULL, NULL, NULL);
        json_free(j); http_reply_err(out, 500, "db"); return;
    }
    db_bind_i64(&i2, 1, chat_id);
    db_bind_i64(&i2, 3, now_sec());
    db_bind_i64(&i2, 2, c->user_id);
    db_step(&i2);
    db_reset(&i2);
    int added = 1;
    if (members) {
        for (size_t i = 0; i < members->n && added < 50; i++) {
            int64_t uid = jv_int(members->items[i]);
            if (uid <= 0 || uid == c->user_id) continue;
            /* verify user exists */
            Stmt e;
            if (db_prep(&e, "SELECT 1 FROM users WHERE id=?1")) continue;
            db_bind_i64(&e, 1, uid);
            int ex = db_step(&e) == 1;
            db_fin(&e);
            if (!ex) continue;
            db_bind_i64(&i2, 2, uid);
            if (db_step(&i2) == 0) added++;
            db_reset(&i2);
        }
    }
    db_fin(&i2);
    sqlite3_exec(g_db, "COMMIT", NULL, NULL, NULL);
    json_free(j);

    logi("group chat=%lld '%s' created by=%lld members=%d", (long long)chat_id, name, (long long)c->user_id, added);
    rt_notify_chat_new(chat_id);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"chat_id\":%lld,\"created\":true,\"members\":%d}", (long long)chat_id, added);
    http_reply_json(out, 201, b.data);
    buf_free(&b);
}

static void h_group_add(Conn *c, HTTPReq *req, Buf *out, int64_t chat_id) {
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }
    int64_t uid = jv_int(jv_get(j, "user_id"));
    json_free(j);
    if (uid <= 0) { http_reply_err(out, 400, "invalid user_id"); return; }
    if (!shared_is_member(chat_id, c->user_id)) { http_reply_err(out, 403, "not a member"); return; }

    Stmt t;
    if (db_prep(&t, "SELECT type FROM chats WHERE id=?1")) { http_reply_err(out, 500, "db"); return; }
    db_bind_i64(&t, 1, chat_id);
    int is_group = 0;
    if (db_step(&t) == 1) {
        const unsigned char *ty = db_col_text(&t, 0);
        is_group = ty && !strcmp((const char*)ty, "group");
    }
    db_fin(&t);
    if (!is_group) { http_reply_err(out, 400, "not a group chat"); return; }

    Stmt e;
    if (db_prep(&e, "SELECT 1 FROM users WHERE id=?1")) { http_reply_err(out, 500, "db"); return; }
    db_bind_i64(&e, 1, uid);
    int ex = db_step(&e) == 1;
    db_fin(&e);
    if (!ex) { http_reply_err(out, 404, "user not found"); return; }

    Stmt i;
    if (db_prep(&i, "INSERT OR IGNORE INTO chat_members(chat_id, user_id, joined_at) VALUES(?1,?2,?3)")) {
        http_reply_err(out, 500, "db"); return;
    }
    db_bind_i64(&i, 1, chat_id);
    db_bind_i64(&i, 2, uid);
    db_bind_i64(&i, 3, now_sec());
    int rc = db_step(&i);
    db_fin(&i);

    logi("group chat=%lld added uid=%lld by=%lld", (long long)chat_id, (long long)uid, (long long)c->user_id);
    rt_notify_chat_new(chat_id);

    Buf b; buf_init(&b);
    if (rc == 0) buf_printf(&b, "{\"added\":true,\"chat_id\":%lld}", (long long)chat_id);
    else buf_printf(&b, "{\"added\":false,\"chat_id\":%lld}", (long long)chat_id);
    ok(out, b.data);
    buf_free(&b);
}

static void h_messages(Conn *c, HTTPReq *req, Buf *out, int64_t chat_id) {
    if (!shared_is_member(chat_id, c->user_id)) { http_reply_err(out, 403, "not a member"); return; }

    int64_t before = 0;
    int64_t limit = 50;
    char tmp[32];
    if (!query_param(req->query, "before", tmp, sizeof tmp)) before = strtoll(tmp, NULL, 10);
    if (!query_param(req->query, "limit", tmp, sizeof tmp)) {
        limit = strtoll(tmp, NULL, 10);
        if (limit < 1) limit = 1;
        if (limit > 100) limit = 100;
    }

    Stmt s;
    if (db_prep(&s, "SELECT id FROM messages WHERE chat_id=?1 AND (?2=0 OR id<?2) "
                    "ORDER BY id DESC LIMIT ?3")) {
        http_reply_err(out, 500, "db"); return;
    }
    db_bind_i64(&s, 1, chat_id);
    db_bind_i64(&s, 2, before);
    db_bind_i64(&s, 3, limit);
    int64_t ids[128]; int n = 0;
    while (db_step(&s) == 1 && n < 128) ids[n++] = db_col_i64(&s, 0);
    db_fin(&s);

    Buf b; buf_init(&b);
    buf_printf(&b, "{\"messages\":[");
    for (int i = n - 1; i >= 0; i--) {   /* ascending order */
        if (i != n - 1) buf_append(&b, ",", 1);
        shared_message_json(&b, ids[i]);
    }
    buf_printf(&b, "],\"has_more\":%s}", (n == (int)limit) ? "true" : "false");
    ok(out, b.data);
    buf_free(&b);
}

static void h_client_logs(Conn *c, HTTPReq *req, Buf *out) {
    char ipkey[80];
    snprintf(ipkey, sizeof ipkey, "ip:%s", c->ip);
    if (!rl_check("logs", ipkey, 30, 60000)) { http_reply_err(out, 429, "slow down"); return; }
    const char *err = NULL;
    JV *j = json_parse(req->body ? req->body : "", req->body_len, &err);
    if (!j || j->t != JV_OBJ) { json_free(j); http_reply_err(out, 400, "invalid json"); return; }
    const char *level = jv_str(jv_get(j, "level"));
    const char *tag = jv_str(jv_get(j, "tag"));
    const char *message = jv_str(jv_get(j, "message"));
    if (!message || strlen(message) > 2000) { json_free(j); http_reply_err(out, 400, "message required (<=2000)"); return; }

    Stmt s;
    if (db_prep(&s, "INSERT INTO client_logs(user_id, level, tag, message, created_at) VALUES(?1,?2,?3,?4,?5)")) {
        json_free(j); http_reply_err(out, 500, "db"); return;
    }
    if (c->user_id > 0) db_bind_i64(&s, 1, c->user_id);
    db_bind_text(&s, 2, level ? level : "error", level ? strlen(level) : 5);
    db_bind_text(&s, 3, tag ? tag : "", tag ? strlen(tag) : 0);
    db_bind_text(&s, 4, message, strlen(message));
    db_bind_i64(&s, 5, now_sec());
    db_step(&s);
    db_fin(&s);
    json_free(j);
    if (level && !strcmp(level, "crash"))
        loge("client crash uid=%lld: %s", (long long)c->user_id, message);
    ok(out, "{\"ok\":true}");
}

/* ================= router ================= */

void api_route(Conn *c, HTTPReq *req, Buf *out) {
    /* CORS preflight */
    if (!strcmp(req->method, "OPTIONS")) {
        http_reply_json(out, 204, "");
        return;
    }

    if (!strcmp(req->path, "/health")) {
        Buf b; buf_init(&b);
        buf_printf(&b, "{\"ok\":true,\"service\":\"chime\",\"version\":\"%s\",\"uptime_s\":%lld,\"connections\":%d,\"ws_users\":%d}",
                   CHIME_VERSION, (long long)(now_sec() - g_start_sec),
                   (int)(g_stats.conns_total ? conns_alive() : 0), online_user_count());
        ok(out, b.data); buf_free(&b);
        return;
    }

    /* /api/ endpoints are rate-limited per IP (soft cap) */
    if (!strncmp(req->path, "/api/", 5)) {
        char ipkey[80];
        snprintf(ipkey, sizeof ipkey, "ip:%s", c->ip);
        if (!rl_check("api", ipkey, 240, 60000)) {
            http_reply_err(out, 429, "too many requests"); return;
        }
    } else {
        http_reply_err(out, 404, "not found"); return;
    }

    int64_t uid = 0;
    int authed = req_is_authed(req, &uid);
    c->user_id = uid;   /* handlers use c->user_id */

    if (!strcmp(req->method, "POST") && !strcmp(req->path, "/api/register")) { h_register(c, req, out); return; }
    if (!strcmp(req->method, "POST") && !strcmp(req->path, "/api/login"))    { h_login(c, req, out); return; }

    if (!authed) { http_reply_err(out, 401, "authentication required"); return; }

    if (!strcmp(req->method, "GET")  && !strcmp(req->path, "/api/me"))   { h_me(c, req, out); return; }
    if (!strcmp(req->method, "GET")  && !strcmp(req->path, "/api/users")){ h_users(c, req, out); return; }
    if (!strcmp(req->method, "GET")  && !strcmp(req->path, "/api/chats")){ h_chats(c, req, out); return; }
    if (!strcmp(req->method, "POST") && !strcmp(req->path, "/api/dm"))   { h_dm_create(c, req, out); return; }
    if (!strcmp(req->method, "POST") && !strcmp(req->path, "/api/groups")){ h_group_create(c, req, out); return; }
    if (!strcmp(req->method, "POST") && !strcmp(req->path, "/api/client-logs")) { h_client_logs(c, req, out); return; }

    int64_t chat_id = 0;
    if (!strcmp(req->method, "GET") && !path_int_after(req->path, "/api/chats/", &chat_id)) {
        h_messages(c, req, out, chat_id); return;
    }
    if (!strcmp(req->method, "POST") && !strncmp(req->path, "/api/groups/", 12) &&
        strstr(req->path, "/members")) {
        int64_t gid = 0;
        if (!path_int_after(req->path, "/api/groups/", &gid)) { h_group_add(c, req, out, gid); return; }
    }

    http_reply_err(out, 404, "not found");
}
