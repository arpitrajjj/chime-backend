/* http.c — HTTP/1.1 request parsing, routing entry, reply builders.
 * Connection: close semantics (one request per HTTP connection).
 */
#include "chime.h"
#include <ctype.h>

static void req_reset(HTTPReq *r) {
    memset(r, 0, sizeof *r);
}

/* case-insensitive header line lookup inside head block */
static int header_val(const char *head, size_t headlen, const char *name,
                      char *out, size_t outsz) {
    size_t nlen = strlen(name);
    const char *p = head;
    const char *end = head + headlen;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        size_t linelen = (size_t)(eol - p);
        if (linelen > nlen && p[nlen] == ':' &&
            strncasecmp(p, name, nlen) == 0) {
            const char *v = p + nlen + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            size_t vl = (size_t)(eol - v);
            while (vl && (v[vl-1] == '\r' || v[vl-1] == ' ' || v[vl-1] == '\t')) vl--;
            if (vl >= outsz) vl = outsz - 1;
            memcpy(out, v, vl);
            out[vl] = 0;
            return 0;
        }
        p = eol + 1;
    }
    return -1;
}

int query_param(const char *query, const char *key, char *out, size_t outsz) {
    size_t klen = strlen(key);
    const char *p = query;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > klen && p[klen] == '=' && !strncmp(p, key, klen)) {
            char raw[600];
            if (seg - klen - 1 >= sizeof raw) return -1;
            memcpy(raw, p + klen + 1, seg - klen - 1);
            raw[seg - klen - 1] = 0;
            return url_decode(raw, seg - klen - 1, out, outsz) >= 0 ? 0 : -1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return -1;
}

int path_int_after(const char *path, const char *prefix, int64_t *out) {
    size_t pl = strlen(prefix);
    if (strncmp(path, prefix, pl)) return -1;
    const char *num = path + pl;
    if (!*num) return -1;
    char *end = NULL;
    long long v = strtoll(num, &end, 10);
    if (end == num || v <= 0) return -1;
    if (*end && strcmp(end, "/messages") && strcmp(end, "/members")) return -1;
    *out = v;
    return 0;
}

int req_is_authed(HTTPReq *req, int64_t *uid_out) {
    int64_t uid = token_verify(req->token);
    if (uid <= 0) return 0;
    if (uid_out) *uid_out = uid;
    return 1;
}

void http_reply_json(Buf *out, int status, const char *json_body) {
    const char *reason = status == 200 ? "OK" : status == 201 ? "Created" :
                         status == 204 ? "No Content" : status == 400 ? "Bad Request" :
                         status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" :
                         status == 404 ? "Not Found" : status == 409 ? "Conflict" :
                         status == 413 ? "Payload Too Large" :
                         status == 429 ? "Too Many Requests" :
                         status == 101 ? "Switching Protocols" : "Server Error";
    buf_printf(out,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", status, reason, strlen(json_body), json_body);
}

void http_reply_err(Buf *out, int status, const char *msg) {
    Buf b; buf_init(&b);
    buf_printf(&b, "{\"error\":");
    json_escape_buf(&b, msg, strlen(msg));
    buf_append(&b, "}", 1);
    http_reply_json(out, status, b.data ? b.data : "{}");
    buf_free(&b);
}

/* -------- main entry: called by server.c when data arrives (HTTP mode) -- */
static void http_finish(Conn *c, HTTPReq *req) {
    g_stats.http_reqs++;
    Buf *out = &c->out;
    buf_reserve(out, 256);

    /* WebSocket upgrade? */
    if (req->upgrade_ws) {
        int64_t uid = token_verify(req->token);
        if (uid <= 0) {
            http_reply_err(out, 401, "valid ?token= required for /ws");
            c->want_close = 1;
        } else {
            c->user_id = uid;
            /* resolve username once for logs/presence */
            Stmt s;
            if (db_prep(&s, "SELECT username FROM users WHERE id=?1")) {
                http_reply_err(out, 500, "db error");
                c->want_close = 1;
                free(req->body);
                return;
            }
            db_bind_i64(&s, 1, uid);
            if (db_step(&s) == 1) {
                const unsigned char *un = db_col_text(&s, 0);
                snprintf(c->username, sizeof c->username, "%s",
                         un ? (const char*)un : "");
            }
            db_fin(&s);
            ws_start(c, req);
            rt_on_open(c);
        }
        free(req->body);
        return;
    }

    api_route(c, req, out);
    c->want_close = 1;
    free(req->body);
}

void http_on_readable(Conn *c) {
    /* accumulate until full request present */
    if (c->in.len > MAX_HTTP_HEAD + MAX_HTTP_BODY + 64) {
        Buf *o = &c->out; buf_reserve(o, 128);
        http_reply_err(o, 413, "request too large");
        c->want_close = 1;
        return;
    }
    char *sep = memchr(c->in.data, '\n', c->in.len);
    /* need full head first */
    char *head_end = NULL;
    for (size_t i = 0; i + 3 < c->in.len; i++) {
        if (c->in.data[i] == '\r' && c->in.data[i+1] == '\n' &&
            c->in.data[i+2] == '\r' && c->in.data[i+3] == '\n') {
            head_end = c->in.data + i;
            break;
        }
    }
    (void)sep;
    if (!head_end) {
        if (c->in.len > MAX_HTTP_HEAD) {
            Buf *o = &c->out; buf_reserve(o, 128);
            http_reply_err(o, 431, "headers too large");
            c->want_close = 1;
        }
        return;
    }

    size_t headlen = (size_t)(head_end - c->in.data) + 4;

    HTTPReq req;
    req_reset(&req);

    /* --- request line --- */
    char *line_end = memchr(c->in.data, '\r', headlen);
    if (!line_end) { http_reply_err(&c->out, 400, "bad request"); c->want_close = 1; return; }
    size_t rll = (size_t)(line_end - c->in.data);
    char rl[1200];
    if (rll >= sizeof rl) { http_reply_err(&c->out, 400, "bad request"); c->want_close = 1; return; }
    memcpy(rl, c->in.data, rll); rl[rll] = 0;

    char rawpath[900] = "";
    if (sscanf(rl, "%7s %898s", req.method, rawpath) != 2) {
        http_reply_err(&c->out, 400, "bad request"); c->want_close = 1; return;
    }
    if (strcmp(req.method, "GET") && strcmp(req.method, "POST") && strcmp(req.method, "OPTIONS")) {
        http_reply_err(&c->out, 405, "method not allowed"); c->want_close = 1; return;
    }

    /* split query */
    char *qm = strchr(rawpath, '?');
    if (qm) {
        *qm = 0;
        char rawq[sizeof req.query];
        snprintf(rawq, sizeof rawq, "%s", qm + 1);
        if (url_decode(rawq, strlen(rawq), req.path, sizeof req.path) < 0 ||
            rawpath[0] != '/' ) {
            http_reply_err(&c->out, 400, "bad request"); c->want_close = 1; return;
        }
        /* path had no percent-encoding need; decode separately below */
        snprintf(req.path, sizeof req.path, "%s", rawpath);
        snprintf(req.query, sizeof req.query, "%s", rawq);
    } else {
        snprintf(req.path, sizeof req.path, "%s", rawpath);
        req.query[0] = 0;
    }
    if (strlen(req.path) >= sizeof req.path - 1) {
        http_reply_err(&c->out, 414, "uri too long"); c->want_close = 1; return;
    }

    /* --- headers --- */
    char clen_s[32] = "", conn_hdr[64] = "", upgrade[64] = "";
    header_val(c->in.data, headlen, "Content-Length", clen_s, sizeof clen_s);
    header_val(c->in.data, headlen, "Connection", conn_hdr, sizeof conn_hdr);
    header_val(c->in.data, headlen, "Upgrade", upgrade, sizeof upgrade);
    header_val(c->in.data, headlen, "Authorization", req.token, sizeof req.token);
    header_val(c->in.data, headlen, "Sec-WebSocket-Key", req.ws_key, sizeof req.ws_key);

    /* token from ?token= (for WS) */
    char qtok[512];
    if (!query_param(req.query, "token", qtok, sizeof qtok)) {
        snprintf(req.token, sizeof req.token, "Bearer %s", qtok);
    }

    /* parse bearer */
    if (!strncasecmp(req.token, "Bearer ", 7)) {
        memmove(req.token, req.token + 7, strlen(req.token + 7) + 1);
        char *nl = strstr(req.token, "\r");
        if (nl) *nl = 0;
    } else {
        req.token[0] = 0;
    }

    if (!strcasecmp(upgrade, "websocket") && strstr(conn_hdr, "pgrade")) {
        req.upgrade_ws = 1;
        if (!req.ws_key[0]) {
            http_reply_err(&c->out, 400, "missing Sec-WebSocket-Key");
            c->want_close = 1; return;
        }
    }

    /* --- body --- */
    size_t clen = 0;
    if (clen_s[0]) {
        char *end = NULL;
        long long v = strtoll(clen_s, &end, 10);
        if (!end || *end || v < 0 || v > MAX_HTTP_BODY) {
            http_reply_err(&c->out, 413, "body too large"); c->want_close = 1; return;
        }
        clen = (size_t)v;
    }
    if (c->in.len < headlen + clen) return;   /* wait for full body */

    if (clen) {
        req.body = malloc(clen + 1);
        if (!req.body) { http_reply_err(&c->out, 500, "oom"); c->want_close = 1; return; }
        memcpy(req.body, c->in.data + headlen, clen);
        req.body[clen] = 0;
        req.body_len = clen;
    }

    buf_consume(&c->in, headlen + clen);
    http_finish(c, &req);
}
