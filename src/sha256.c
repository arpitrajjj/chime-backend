/* sha256.c — SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, SHA-1 (for WS handshake).
 * Self-contained FIPS 180-4 / RFC 2104 / RFC 2898 / RFC 3174 implementations.
 */
#include "chime.h"

/* ================= SHA-256 ================= */
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef struct {
    uint32_t h[8]; uint8_t buf[64]; size_t buflen; uint64_t total;
} sha256_ctx;

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7) ^ ROR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2],17) ^ ROR32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->h, H0, sizeof H0);
    c->buflen = 0; c->total = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *d, size_t n) {
    c->total += n;
    while (n) {
        if (c->buflen == 0 && n >= 64) {
            sha256_block(c, d); d += 64; n -= 64; continue;
        }
        size_t take = 64 - c->buflen; if (take > n) take = n;
        memcpy(c->buf + c->buflen, d, take);
        c->buflen += take; d += take; n -= take;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) sha256_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ================= HMAC-SHA256 ================= */
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t k[64], pad[64], kh[32];
    if (keylen > 64) { sha256(key, keylen, kh); key = kh; keylen = 32; }
    memset(k, 0, sizeof k);
    memcpy(k, key, keylen);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha256_ctx c; sha256_init(&c); sha256_update(&c, pad, 64); sha256_update(&c, msg, msglen);
    uint8_t inner[32]; sha256_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha256_init(&c); sha256_update(&c, pad, 64); sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* ================= PBKDF2-HMAC-SHA256 ================= */
void pbkdf2_sha256(const uint8_t *pass, size_t passlen,
                   const uint8_t *salt, size_t saltlen,
                   uint32_t iters, uint8_t out[32]) {
    /* single output block (dkLen = 32 = one block) */
    uint8_t saltbuf[64];
    if (saltlen + 4 > sizeof saltbuf) { memset(out, 0, 32); return; }
    memcpy(saltbuf, salt, saltlen);
    saltbuf[saltlen]   = 0; saltbuf[saltlen+1] = 0;
    saltbuf[saltlen+2] = 0; saltbuf[saltlen+3] = 1;

    uint8_t u[32], t[32];
    hmac_sha256(pass, passlen, saltbuf, saltlen + 4, u);
    memcpy(t, u, 32);
    for (uint32_t i = 1; i < iters; i++) {
        hmac_sha256(pass, passlen, u, 32, u);
        for (int j = 0; j < 32; j++) t[j] ^= u[j];
    }
    memcpy(out, t, 32);
}

/* ================= SHA-1 (RFC 3174) — only for WS accept key ================= */
static void sha1_block(uint32_t h[5], const uint8_t *p) {
    uint32_t w[80];
    for (int j = 0; j < 16; j++)
        w[j] = ((uint32_t)p[j*4] << 24) | ((uint32_t)p[j*4+1] << 16) |
               ((uint32_t)p[j*4+2] << 8) | (uint32_t)p[j*4+3];
    for (int j = 16; j < 80; j++) {
        uint32_t v = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16];
        w[j] = ROL32(v, 1);
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    for (int j = 0; j < 80; j++) {
        uint32_t f, k;
        if (j < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (j < 40) { f = b ^ c ^ d;                      k = 0x6ED9EBA1; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d);    k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                      k = 0xCA62C1D6; }
        uint32_t tmp = ROL32(a,5) + f + e + k + w[j];
        e = d; d = c; c = ROL32(b,30); b = a; a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) sha1_block(h, data + i * 64);

    /* tail: message + 0x80 + zeros + 64-bit length, 1 or 2 blocks */
    uint8_t tail[128];
    size_t rem = len - full * 64;
    memcpy(tail, data + full * 64, rem);
    tail[rem] = 0x80;
    size_t tot = rem + 1;
    size_t blocks = (tot <= 56) ? 1 : 2;
    memset(tail + tot, 0, blocks * 64 - tot);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        tail[blocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha1_block(h, tail);
    if (blocks == 2) sha1_block(h, tail + 64);

    for (int j = 0; j < 5; j++) {
        out[j*4]   = (uint8_t)(h[j] >> 24);
        out[j*4+1] = (uint8_t)(h[j] >> 16);
        out[j*4+2] = (uint8_t)(h[j] >> 8);
        out[j*4+3] = (uint8_t)(h[j]);
    }
}
