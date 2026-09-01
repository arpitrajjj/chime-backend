/* crypto_selftest.c — verify sha1/sha256/hmac/pbkdf2 against official vectors. */
#include "../src/chime.h"

static int fails = 0;
static void hexcmp(const char *label, const uint8_t *got, size_t n, const char *want) {
    char hex[257];
    for (size_t i = 0; i < n; i++) snprintf(hex + i*2, 3, "%02x", got[i]);
    if (!strcmp(hex, want)) printf("PASS %s\n", label);
    else { printf("FAIL %s\n  got:  %s\n  want: %s\n", label, hex, want); fails++; }
}

int main(void) {
    uint8_t out[64];

    /* SHA-1 (RFC 3174 / common vectors) */
    sha1((const uint8_t*)"abc", 3, out);
    hexcmp("sha1(abc)", out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    sha1((const uint8_t*)"", 0, out);
    hexcmp("sha1(empty)", out, 20, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha1((const uint8_t*)msg, strlen(msg), out);
        hexcmp("sha1(56-byte)", out, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }
    /* 1,000,000 x 'a' would be slow; 448-bit boundary test instead */
    {
        char big[100]; memset(big, 'a', 99); big[99] = 0;
        sha1((const uint8_t*)big, 99, out);
        hexcmp("sha1(99x'a')", out, 20, "8cd96af217b5198655e73780f35d522eba762244");
    }
    /* RFC 6455 handshake example: key "dGhlIHNhbXBsZSBub25jZQ==" + GUID */
    {
        const char *cat = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        sha1((const uint8_t*)cat, strlen(cat), out);
        char b64[64];
        b64_encode(out, 20, b64, sizeof b64);
        if (!strcmp(b64, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) printf("PASS ws-accept-vector\n");
        else { printf("FAIL ws-accept-vector got %s\n", b64); fails++; }
    }

    /* SHA-256 (FIPS 180-4 vectors) */
    sha256((const uint8_t*)"abc", 3, out);
    hexcmp("sha256(abc)", out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    sha256((const uint8_t*)"", 0, out);
    hexcmp("sha256(empty)", out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256((const uint8_t*)msg, strlen(msg), out);
        hexcmp("sha256(448-bit)", out, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    /* HMAC-SHA256 (RFC 4231 test case 2) */
    {
        const char *key = "Jefe";
        const char *msg = "what do ya want for nothing?";
        hmac_sha256((const uint8_t*)key, 4, (const uint8_t*)msg, strlen(msg), out);
        hexcmp("hmac-rfc4231-tc2", out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
    /* HMAC with long key (>64 bytes forces key hashing), RFC 4231 tc 6 */
    {
        uint8_t key[131]; memset(key, 0xaa, 131);
        const char *msg = "Test Using Larger Than Block-Size Key - Hash Key First";
        hmac_sha256(key, 131, (const uint8_t*)msg, strlen(msg), out);
        hexcmp("hmac-rfc4231-tc6", out, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    /* PBKDF2-HMAC-SHA256 (RFC 7914 vectors) */
    pbkdf2_sha256((const uint8_t*)"passwd", 6, (const uint8_t*)"salt", 4, 1, out);
    hexcmp("pbkdf2-1iter", out, 32, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
    pbkdf2_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 2, out);
    hexcmp("pbkdf2-2iter", out, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    pbkdf2_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 4096, out);
    hexcmp("pbkdf2-4096iter", out, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

    /* b64 roundtrip */
    {
        uint8_t raw[32]; rand_bytes(raw, 32);
        char enc[64]; int n = b64_encode(raw, 32, enc, sizeof enc);
        uint8_t back[32];
        int m = b64_decode(enc, n, back, 32);
        if (m == 32 && !memcmp(raw, back, 32)) printf("PASS b64-roundtrip\n");
        else { printf("FAIL b64-roundtrip\n"); fails++; }
    }

    printf(fails ? "\n%d FAILURES\n" : "\nALL CRYPTO TESTS PASSED\n", fails);
    return fails != 0;
}
