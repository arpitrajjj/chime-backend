/* ratelimit.c — sliding-window limiter with a bounded open-addressing map.
 * Groups ("auth", "api", "ws") x key ("ip:1.2.3.4", "u:42") -> ring buffer
 * of recent event timestamps. Buckets are recycled when stale.
 */
#include "chime.h"

#define RL_TABLE 8192          /* power of two */
#define RL_MAX_EVENTS 64       /* per bucket ring capacity */

typedef struct RLBucket {
    char    key[96];
    int64_t ts[RL_MAX_EVENTS];
    int     head, count;
    int64_t last_touch;
    int     used;
} RLBucket;

static RLBucket *g_tab;
static pthread_mutex_t g_rl_mtx = PTHREAD_MUTEX_INITIALIZER;

static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (uint8_t)*s++; h *= 1099511628211ULL; }
    return h;
}

void rl_init(void) {
    g_tab = calloc(RL_TABLE, sizeof(RLBucket));
    if (!g_tab) { loge("rl_init OOM"); abort(); }
}

void rl_free(void) { free(g_tab); g_tab = NULL; }

static void rl_evict_stale(int64_t now) {
    for (int i = 0; i < RL_TABLE; i++)
        if (g_tab[i].used && now - g_tab[i].last_touch > 300000)
            g_tab[i].used = 0;
}

int rl_check(const char *group, const char *key, int limit, int64_t window_ms) {
    char full[96];
    snprintf(full, sizeof full, "%s|%s", group, key);
    uint64_t h = fnv1a(full) & (RL_TABLE - 1);
    int64_t now = now_ms();

    pthread_mutex_lock(&g_rl_mtx);
    for (int probe = 0; probe < 64; probe++) {
        RLBucket *b = &g_tab[(h + (uint64_t)probe) & (RL_TABLE - 1)];
        if (!b->used) {
            if (probe > RL_TABLE / 2) rl_evict_stale(now);
            memset(b, 0, sizeof *b);
            b->used = 1;
            snprintf(b->key, sizeof b->key, "%s", full);
        }
        if (strcmp(b->key, full)) continue;

        b->last_touch = now;
        if (b->count > limit) b->count = limit;   /* clamp */
        /* drop expired events */
        int kept = 0;
        for (int i = 0; i < b->count; i++) {
            int64_t t = b->ts[(b->head + i) % RL_MAX_EVENTS];
            if (now - t <= window_ms) b->ts[(b->head + kept++) % RL_MAX_EVENTS] = t;
        }
        b->count = kept;

        if (kept >= limit) { pthread_mutex_unlock(&g_rl_mtx); return 0; }

        int slot = (b->head + kept) % RL_MAX_EVENTS;
        b->ts[slot] = now;
        b->count = kept + 1;
        pthread_mutex_unlock(&g_rl_mtx);
        return 1;
    }
    pthread_mutex_unlock(&g_rl_mtx);
    logw("rl table saturated");
    return 1;   /* fail-open under map pressure, but log */
}
