/* util.c — buffers, encoding, misc helpers */
#include "chime.h"
#include <sys/random.h>

void buf_init(Buf *b) { b->data = NULL; b->len = 0; b->cap = 0; }

void buf_reserve(Buf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    size_t ncap = b->cap ? b->cap : 512;
    while (ncap < b->len + extra + 1) ncap *= 2;
    char *nd = realloc(b->data, ncap);
    if (!nd) { loge("OOM reserve %zu", ncap); abort(); }
    b->data = nd; b->cap = ncap;
}

void buf_append(Buf *b, const void *src, size_t n) {
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->data + b->len, src, n);
    b->len += n;
    b->data[b->len] = 0;
}

void buf_printf(Buf *b, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return; }
    buf_reserve(b, (size_t)need);
    vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)need;
}

void buf_consume(Buf *b, size_t n) {
    if (n >= b->len) { b->len = 0; if (b->data) b->data[0] = 0; return; }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
    b->data[b->len] = 0;
}

void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
int64_t now_sec(void) { return now_ms() / 1000; }

void rand_bytes(uint8_t *out, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r > 0) { got += (size_t)r; continue; }
        if (errno == EINTR) continue;
        /* fallback: /dev/urandom */
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { size_t rd = fread(out + got, 1, n - got, f); fclose(f);
                 if (rd) { got += rd; continue; } }
        loge("rand_bytes failed"); abort();
    }
}

static const char B64_STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64_URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64_gen(const char *tbl, const uint8_t *in, size_t inlen, char *out, size_t outsz) {
    size_t olen = ((inlen + 2) / 3) * 4;
    if (outsz < olen + 1) return -1;
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i+1] << 8 | in[i+2];
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];  out[o++] = tbl[v & 63];
        i += 3;
    }
    if (i + 1 == inlen) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (i + 2 == inlen) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i+1] << 8;
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];  out[o++] = '=';
    }
    out[o] = 0;
    return (int)o;
}

int b64_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz) {
    return b64_gen(B64_STD, in, inlen, out, outsz);
}
int b64url_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz) {
    int n = b64_gen(B64_URL, in, inlen, out, outsz);
    /* url-safe: strip padding */
    if (n > 0) { while (n > 0 && out[n-1] == '=') out[--n] = 0; }
    return n;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

int b64_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz) {
    return b64url_decode(in, inlen, out, outsz); /* val() accepts both alphabets */
}

int b64url_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz) {
    while (inlen && in[inlen-1] == '=') inlen--;
    if (inlen % 4 == 1) return -1;
    size_t need = inlen / 4 * 3 + (inlen % 4 ? (inlen % 4) - 1 : 0);
    if (outsz < need) return -1;
    size_t o = 0; uint32_t acc = 0; int nb = 0;
    for (size_t i = 0; i < inlen; i++) {
        int v = b64_val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        if (++nb == 4) {
            if (o + 3 > need) return -1;
            out[o++] = (uint8_t)(acc >> 16); out[o++] = (uint8_t)(acc >> 8); out[o++] = (uint8_t)acc;
            acc = 0; nb = 0;
        }
    }
    if (nb == 2) { if (o + 1 > need) return -1; out[o++] = (uint8_t)(acc >> 4); }
    else if (nb == 3) { if (o + 2 > need) return -1; out[o++] = (uint8_t)(acc >> 10); out[o++] = (uint8_t)(acc >> 2); }
    return (int)o;
}

int ct_equal(const char *a, const char *b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
    return diff == 0;
}

int url_decode(const char *in, size_t inlen, char *out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        if (o + 1 >= outsz) return -1;
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= inlen) return -1;
            char hx[3] = { in[i+1], in[i+2], 0 };
            char *end = NULL;
            long v = strtol(hx, &end, 16);
            if (end != hx + 2 || v < 0) return -1;
            out[o++] = (char)v; i += 2;
        } else if (c == '+') {
            out[o++] = ' ';
        } else {
            out[o++] = c;
        }
    }
    out[o] = 0;
    return (int)o;
}

int utf8_valid(const char *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = (uint8_t)s[i];
        if (c < 0x80) { i++; continue; }
        int n; uint32_t cp;
        if ((c & 0xE0) == 0xC0) { n = 1; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { n = 2; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { n = 3; cp = c & 0x07; }
        else return 0;
        if (i + (size_t)n >= len) return 0;
        for (int k = 1; k <= n; k++) {
            uint8_t cc = (uint8_t)s[i + (size_t)k];
            if ((cc & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (n == 1 && cp < 0x80) return 0;
        if (n == 2 && cp < 0x800) return 0;
        if (n == 3 && cp < 0x10000) return 0;
        if (cp > 0x10FFFF) return 0;
        i += (size_t)n + 1;
    }
    return 1;
}

int has_forbidden_ctrl(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c < 0x20 && c != '\n' && c != '\t') return 1;
        if (c == 0x7F) return 1;
    }
    return 0;
}

int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t l = strlen(tmp);
    if (!l) return -1;
    if (tmp[l-1] == '/') tmp[l-1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; if (mkdir(tmp, 0755) && errno != EEXIST) return -1; *p = '/'; }
    }
    if (mkdir(tmp, 0755) && errno != EEXIST) return -1;
    return 0;
}
