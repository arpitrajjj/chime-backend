/* log.c — leveled logging, stderr + optional file, mutex */
#include "chime.h"

static FILE   *g_fp  = NULL;
static int     g_lvl = LOG_INFO;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

static const char *LNAME[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };

void log_init(int level, const char *path) {
    g_lvl = level;
    if (path) {
        pthread_mutex_lock(&g_mtx);
        g_fp = fopen(path, "ab");
        if (g_fp) setvbuf(g_fp, NULL, _IOLBF, 4096);
        pthread_mutex_unlock(&g_mtx);
        if (!g_fp) fprintf(stderr, "[chime] cannot open log file %s: %s\n", path, strerror(errno));
    }
}

void log_close(void) {
    pthread_mutex_lock(&g_mtx);
    if (g_fp) fclose(g_fp);
    g_fp = NULL;
    pthread_mutex_unlock(&g_mtx);
}

void log_msg(int lvl, const char *fmt, ...) {
    if (lvl < g_lvl) return;
    char ts[32];
    int64_t ms = now_ms();
    time_t t = (time_t)(ms / 1000);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);

    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_mtx);
    fprintf(stderr, "%s %s %s\n", ts, LNAME[lvl], line);
    if (g_fp) fprintf(g_fp, "%s %s %s\n", ts, LNAME[lvl], line);
    pthread_mutex_unlock(&g_mtx);
}
