/* ws.c — RFC 6455 server-side: handshake, frame codec, fragmentation.
 * Client frames MUST be masked (RFC requirement) — unmasked -> close 1002.
 * Server frames are never masked. Control frames may interleave fragments.
 */
#include "chime.h"

/* ---- handshake ---- */
static void ws_accept_key(const char *client_key, char out[64]) {
    char cat[128];
    snprintf(cat, sizeof cat, "%s%s", client_key, WS_GUID);
    uint8_t dig[20];
    sha1((const uint8_t*)cat, strlen(cat), dig);
    b64_encode(dig, 20, out, 64);
}

void ws_start(Conn *c, HTTPReq *r) {
    char accept[64];
    ws_accept_key(r->ws_key, accept);
    Buf *o = &c->out;
    buf_printf(o,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n", accept);
    c->mode = CONN_WS;
    c->ws_closing = 0;
    c->ping_pending = 0;
    g_stats.ws_total++;
    logi("ws open fd=%d user=%lld ip=%s", c->fd, (long long)c->user_id, c->ip);
    /* any bytes after the handshake in c->in are already WS frames;
       ws_on_readable will process them on the next loop pass. */
}

/* ---- frame writer ---- */
static void ws_frame(Buf *o, int opcode, const char *payload, size_t len) {
    uint8_t hdr[10];
    int hl = 0;
    hdr[hl++] = (uint8_t)(0x80 | opcode);
    if (len < 126) {
        hdr[hl++] = (uint8_t)len;
    } else if (len < 65536) {
        hdr[hl++] = 126;
        hdr[hl++] = (uint8_t)(len >> 8);
        hdr[hl++] = (uint8_t)(len & 0xFF);
    } else {
        hdr[hl++] = 127;
        for (int i = 7; i >= 0; i--) hdr[hl++] = (uint8_t)((uint64_t)len >> (8*i));
    }
    buf_append(o, hdr, (size_t)hl);
    if (len) buf_append(o, payload, len);
}

void ws_send_text(Conn *c, const char *data, size_t len) {
    if (c->ws_closing || c->mode != CONN_WS) return;
    ws_frame(&c->out, 0x1, data, len);
    g_stats.msgs_out++;
    conn_kick(c);   /* crucial: data may land in a foreign conn's buffer */
}

static void ws_send_pong(Conn *c, const char *payload, size_t len) {
    if (len > 125) len = 125;
    ws_frame(&c->out, 0xA, payload, len);
}

void ws_send_close(Conn *c, int code) {
    if (c->ws_closing) return;
    char payload[2] = { (char)(code >> 8), (char)(code & 0xFF) };
    ws_frame(&c->out, 0x8, payload, 2);
    c->ws_closing = 1;
    c->want_close = 1;
}

void ws_send_ping(Conn *c) {
    if (c->ws_closing || c->mode != CONN_WS) return;
    ws_frame(&c->out, 0x9, "hb", 2);
    c->ping_pending = 1;
    conn_kick(c);
}

/* ---- frame reader ----
 * Consumes complete frames from c->in. Text payloads are accumulated in
 * c->frag across continuation frames; complete messages are delivered to
 * rt_on_text(). Returns -1 on protocol error (caller closes).
 */
static int ws_process(Conn *c) {
    Buf *in = &c->in;
    for (;;) {
        if (in->len < 2) return 0;
        uint8_t b0 = (uint8_t)in->data[0];
        uint8_t b1 = (uint8_t)in->data[1];
        int fin  = (b0 & 0x80) != 0;
        int op   = b0 & 0x0F;
        int masked = (b1 & 0x80) != 0;
        uint64_t len = b1 & 0x7F;

        size_t hl = 2;
        if (len == 126) {
            if (in->len < 4) return 0;
            len = ((uint64_t)(uint8_t)in->data[2] << 8) | (uint8_t)in->data[3];
            hl = 4;
        } else if (len == 127) {
            if (in->len < 10) return 0;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | (uint8_t)in->data[2+i];
            hl = 10;
        }
        if (!masked) { ws_send_close(c, 1002); return -1; }
        if (in->len < hl + 4) return 0;
        uint8_t mask[4];
        memcpy(mask, in->data + hl, 4);

        if (len > MAX_WS_MSG) { ws_send_close(c, 1009); return -1; }
        if (in->len < hl + 4 + len) return 0;

        char *payload = in->data + hl + 4;
        for (uint64_t i = 0; i < len; i++) payload[i] ^= mask[i & 3];

        switch (op) {
            case 0x0: /* continuation */
            case 0x1: /* text */
            case 0x2: /* binary */
                if (op == 0x2) { ws_send_close(c, 1003); return -1; }
                if (op == 0x1 && c->frag.len > 0) { ws_send_close(c, 1002); return -1; }
                if (c->frag.len + len > MAX_WS_MSG) { ws_send_close(c, 1009); return -1; }
                buf_append(&c->frag, payload, (size_t)len);
                if (fin) {
                    g_stats.msgs_in++;
                    rt_on_text(c, c->frag.data ? c->frag.data : (char*)"", c->frag.len);
                    c->frag.len = 0;
                    if (c->frag.data) c->frag.data[0] = 0;
                    if (c->want_close) return -1;   /* handler asked to close */
                }
                break;
            case 0x8: /* close */
                ws_send_close(c, 1000);
                return -1;
            case 0x9: /* ping -> pong */
                ws_send_pong(c, payload, (size_t)len);
                break;
            case 0xA: /* pong */
                c->ping_pending = 0;
                break;
            default:
                ws_send_close(c, 1002);
                return -1;
        }
        buf_consume(in, hl + 4 + (size_t)len);
    }
}

void ws_on_readable(Conn *c) {
    if (c->ws_closing) return;
    if (ws_process(c) < 0 && !c->ws_closing)
        ws_send_close(c, 1002);
}
