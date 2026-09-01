/* auth.c — password hashing (PBKDF2-HMAC-SHA256) + HMAC-signed tokens.
 *
 * Stored format:  pbkdf2-sha256$<iters>$<b64 salt>$<b64 hash>
 * Token format:   ch1.<b64url payload>.<b64url hmac>
 *   payload = 8B uid (BE) || 8B expiry (BE) || 16B random nonce
 * The HMAC secret (48 random bytes) is generated on first boot and kept in
 * the meta table so tokens survive restarts. Rotating it logs everyone out.
 */
#include "chime.h"

static uint8_t g_secret[48];

int auth_init(void) {
    char *hex = db_meta_get("token_secret");
    if (hex && strlen(hex) == 96) {
        for (int i = 0; i < 48; i++) {
            char hx[3] = { hex[i*2], hex[i*2+1], 0 };
            g_secret[i] = (uint8_t)strtol(hx, NULL, 16);
        }
        free(hex);
        logi("token secret loaded");
        return 0;
    }
    free(hex);
    rand_bytes(g_secret, sizeof g_secret);
    char hexbuf[97];
    for (int i = 0; i < 48; i++) snprintf(hexbuf + i*2, 3, "%02x", g_secret[i]);
    if (db_meta_set("token_secret", hexbuf)) return -1;
    logi("token secret generated");
    return 0;
}

int pw_hash(const char *pass, char out[256]) {
    uint8_t salt[16], hash[32];
    rand_bytes(salt, sizeof salt);
    pbkdf2_sha256((const uint8_t*)pass, strlen(pass), salt, sizeof salt, PBKDF2_ITERS, hash);
    char b64s[32], b64h[64];
    if (b64_encode(salt, sizeof salt, b64s, sizeof b64s) < 0) return -1;
    if (b64_encode(hash, sizeof hash, b64h, sizeof b64h) < 0) return -1;
    snprintf(out, 256, "pbkdf2-sha256$%d$%s$%s", PBKDF2_ITERS, b64s, b64h);
    return 0;
}

int pw_verify(const char *pass, const char *stored) {
    char fmt[32];
    int iters = 0;
    char b64s[64], b64h[64];
    if (sscanf(stored, "%31[^$]$%d$%63[^$]$%63s", fmt, &iters, b64s, b64h) != 4) return -1;
    if (strcmp(fmt, "pbkdf2-sha256") || iters < 10000 || iters > 1000000) return -1;

    uint8_t salt[64], want[32], got[32];
    int slen = b64_decode(b64s, strlen(b64s), salt, sizeof salt);
    int wlen = b64_decode(b64h, strlen(b64h), want, sizeof want);
    if (slen < 8 || wlen != 32) return -1;

    pbkdf2_sha256((const uint8_t*)pass, strlen(pass), salt, (size_t)slen,
                  (uint32_t)iters, got);
    return ct_equal((char*)want, (char*)got, 32) ? 0 : -1;
}

int token_mint(int64_t uid, char *out, size_t outsz) {
    uint8_t payload[32];
    int64_t exp = now_sec() + TOKEN_TTL_SECS;
    memset(payload, 0, sizeof payload);
    for (int i = 0; i < 8; i++) payload[i]     = (uint8_t)(uid >> (56 - 8*i));
    for (int i = 0; i < 8; i++) payload[8+i]   = (uint8_t)(exp >> (56 - 8*i));
    rand_bytes(payload + 16, 16);

    uint8_t sig[32];
    hmac_sha256(g_secret, sizeof g_secret, payload, sizeof payload, sig);

    char pb[64], sb[64];
    int pl = b64url_encode(payload, sizeof payload, pb, sizeof pb);
    int sl = b64url_encode(sig, sizeof sig, sb, sizeof sb);
    if (pl < 0 || sl < 0) return -1;
    if (outsz < (size_t)pl + (size_t)sl + 8) return -1;
    snprintf(out, outsz, "%s%s.%s", TOKEN_PREFIX, pb, sb);
    return 0;
}

int64_t token_verify(const char *tok) {
    if (!tok || strncmp(tok, TOKEN_PREFIX, 4)) return 0;
    const char *rest = tok + 4;
    const char *dot = strchr(rest, '.');
    if (!dot) return 0;
    size_t pl = (size_t)(dot - rest);
    size_t sl = strlen(dot + 1);
    if (pl == 0 || sl == 0 || pl > 64 || sl > 64) return 0;

    uint8_t payload[32], sig[32], want[32];
    if (b64url_decode(rest, pl, payload, sizeof payload) != 32) return 0;
    if (b64url_decode(dot + 1, sl, sig, sizeof sig) != 32) return 0;

    hmac_sha256(g_secret, sizeof g_secret, payload, sizeof payload, want);
    if (!ct_equal((char*)sig, (char*)want, 32)) return 0;

    int64_t uid = 0, exp = 0;
    for (int i = 0; i < 8; i++) uid = (uid << 8) | payload[i];
    for (int i = 0; i < 8; i++) exp = (exp << 8) | payload[8+i];
    if (now_sec() > exp) return 0;
    return uid;
}
