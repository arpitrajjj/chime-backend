/* crash.c — fatal-signal catcher: logs a stack trace then re-raises.
 *
 * Installs handlers for SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT.
 * The handler is deliberately minimal: async-signal-safe write() of a
 * header, then backtrace_symbols_fd() (technically not async-signal-safe
 * but the process is dying anyway), then restore default disposition and
 * re-raise so core dumps / systemd still observe the real signal.
 */
#include "chime.h"
#include <execinfo.h>

static char g_crash_path[512];
static volatile sig_atomic_t g_in_crash = 0;

static void crash_sig(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    if (g_in_crash) { /* re-entrancy guard */ _exit(127); }
    g_in_crash = 1;

    int fd = open(g_crash_path[0] ? g_crash_path : "/dev/stderr",
                  O_WRONLY | O_CREAT | O_APPEND, 0600);

    char head[512];
    int n = snprintf(head, sizeof head,
        "\n==== CHIME CRASH %lld ====\nsignal: %d (%s)\nfault addr: %p\n"
        "version: %s\nbacktrace:\n",
        (long long)time(NULL), sig,
        sig == SIGSEGV ? "SIGSEGV" : sig == SIGABRT ? "SIGABRT" :
        sig == SIGBUS  ? "SIGBUS"  : sig == SIGFPE  ? "SIGFPE"  : "SIGILL",
        si ? si->si_addr : NULL, CHIME_VERSION);
    if (fd >= 0 && n > 0) { ssize_t wr = write(fd, head, (size_t)n); (void)wr; }
    { ssize_t wr = write(STDERR_FILENO, head, (size_t)n); (void)wr; }

    void *bt[64];
    int frames = backtrace(bt, 64);
    if (fd >= 0) backtrace_symbols_fd(bt, frames, fd);
    backtrace_symbols_fd(bt, frames, STDERR_FILENO);

    if (fd >= 0) {
        const char *end = "==== END ====\n";
        ssize_t wr = write(fd, end, strlen(end)); (void)wr;
        close(fd);
    }

    /* restore default and re-raise for a real core dump */
    signal(sig, SIG_DFL);
    sigset_t ss; sigemptyset(&ss); sigaddset(&ss, sig);
    sigprocmask(SIG_UNBLOCK, &ss, NULL);
    raise(sig);
    _exit(128 + sig);
}

void crash_install(const char *crashlog_path) {
    if (crashlog_path && *crashlog_path)
        snprintf(g_crash_path, sizeof g_crash_path, "%s", crashlog_path);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_sig;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    int sigs[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, NULL);
    logi("crash handler installed -> %s",
         g_crash_path[0] ? g_crash_path : "/dev/stderr");
}
