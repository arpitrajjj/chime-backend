/* main.c — Chime server entrypoint: CLI, wiring, graceful shutdown. */
#include "chime.h"
#include <getopt.h>

Config g_cfg;
volatile sig_atomic_t g_stop = 0;
int64_t g_start_sec = 0;

static void on_term(int sig) { (void)sig; g_stop = 1; }

static void usage(void) {
    fprintf(stderr,
        "chime-server %s — self-hosted realtime chat backend\n"
        "\n"
        "usage: chime-server [options]\n"
        "  -p, --port <n>        TCP port (default 8080)\n"
        "  -b, --bind <addr>     bind address (default 0.0.0.0)\n"
        "  -d, --db <path>       sqlite database file (default chime.db)\n"
        "      --data <dir>      data dir for logs/crash dumps (default .)\n"
        "  -v                    verbose (repeat for debug)\n"
        "  -h, --help            this help\n",
        CHIME_VERSION);
}

int main(int argc, char **argv) {
    g_cfg.port = 8080;
    g_cfg.bind_addr = "0.0.0.0";
    g_cfg.db_path = "chime.db";
    g_cfg.data_dir = ".";
    g_cfg.log_level = LOG_INFO;

    static struct option longopts[] = {
        { "port", required_argument, 0, 'p' },
        { "bind", required_argument, 0, 'b' },
        { "db",   required_argument, 0, 'd' },
        { "data", required_argument, 0, 'D' },
        { "help", no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:d:D:vh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'p': g_cfg.port = atoi(optarg);
                      if (g_cfg.port <= 0 || g_cfg.port > 65535) {
                          fprintf(stderr, "bad port\n"); return 1;
                      }
                      break;
            case 'b': g_cfg.bind_addr = optarg; break;
            case 'd': g_cfg.db_path = optarg; break;
            case 'D': g_cfg.data_dir = optarg; break;
            case 'v': if (g_cfg.log_level > LOG_DEBUG) g_cfg.log_level--; break;
            default:  usage(); return opt == 'h' ? 0 : 1;
        }
    }

    mkdir_p(g_cfg.data_dir);

    char logpath[512], crashpath[512];
    snprintf(logpath, sizeof logpath, "%s/chime.log", g_cfg.data_dir);
    snprintf(crashpath, sizeof crashpath, "%s/crash.log", g_cfg.data_dir);

    log_init(g_cfg.log_level, logpath);
    crash_install(crashpath);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    g_start_sec = now_sec();

    logi("chime-server %s starting (pid %d)", CHIME_VERSION, (int)getpid());
    if (db_open(g_cfg.db_path)) return 1;
    if (db_migrate()) return 1;
    if (auth_init()) return 1;
    rl_init();

    int rc = server_run();

    rl_free();
    db_close();
    log_close();
    return rc == 0 ? 0 : 1;
}
