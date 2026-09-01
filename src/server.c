/* server.c — epoll event loop, acceptor, flushing, idle sweeps.
 *
 * Lifecycle: connections closed mid-batch are parked on a "dead list" and
 * freed after the current epoll batch, so event.data.ptr stays valid for
 * the whole batch (no use-after-free).
 */
#include "chime.h"

Conn *g_conns = NULL;
Stats g_stats = {0, 0, 0, 0, 0};

static int   g_epfd   = -1;
static int   g_listen = -1;
static Conn *g_dead   = NULL;

int user_online(int64_t uid) {
    for (Conn *c = g_conns; c; c = c->next)
        if (c->mode == CONN_WS && c->user_id == uid) return 1;
    return 0;
}

int online_user_count(void) {
    int64_t seen[512]; int n = 0, uniq = 0;
    for (Conn *c = g_conns; c; c = c->next) {
        if (c->mode != CONN_WS || c->user_id <= 0) continue;
        int dup = 0;
        for (int i = 0; i < n; i++) if (seen[i] == c->user_id) { dup = 1; break; }
        if (dup) continue;
        if (n < 512) seen[n++] = c->user_id;
        uniq++;
    }
    return uniq;
}

int conns_alive(void) {
    int n = 0;
    for (Conn *c = g_conns; c; c = c->next) n++;
    return n;
}

/* mark closed: unlink, park on dead list, free after batch */
void conn_close(Conn *c) {
    if (c->fd < 0) return;                 /* already dead */
    if (c->mode == CONN_WS) rt_on_close(c);
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->fd = -1;
    if (c->prev) c->prev->next = c->next;
    else g_conns = c->next;
    if (c->next) c->next->prev = c->prev;
    c->next = g_dead;
    c->prev = NULL;
    g_dead = c;
    logd("close fd marked dead (user=%lld)", (long long)c->user_id);
}

static void reap_dead(void) {
    while (g_dead) {
        Conn *c = g_dead;
        g_dead = c->next;
        buf_free(&c->in);
        buf_free(&c->out);
        buf_free(&c->frag);
        logd("freed conn (was fd=%d)", c->fd);
        free(c);
    }
}

void conn_send_raw(Conn *c, const char *data, size_t n) {
    if (c->fd < 0) return;
    if (c->out.len + n > 4u * 1024 * 1024) {
        logw("backpressure kill fd=%d out=%zu", c->fd, c->out.len);
        conn_close(c);
        return;
    }
    buf_append(&c->out, data, n);
}

static void mod_interest(Conn *c) {
    if (c->fd < 0) return;
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | (c->out.len ? EPOLLOUT : 0);
    ev.data.ptr = c;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

/* re-arm EPOLLOUT for a conn that received data outside its own event */
void conn_kick(Conn *c) {
    if (c->fd >= 0) mod_interest(c);
}

static int flush_conn(Conn *c) {   /* 0 ok, -1 conn dead */
    while (c->out.len > 0) {
        ssize_t w = send(c->fd, c->out.data, c->out.len, MSG_NOSIGNAL);
        if (w > 0) { buf_consume(&c->out, (size_t)w); continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (w < 0 && errno == EINTR) continue;
        conn_close(c);
        return -1;
    }
    return 0;
}

static Conn *conn_new(int fd, const char *ip) {
    Conn *c = calloc(1, sizeof(Conn));
    if (!c) { close(fd); return NULL; }
    c->fd = fd;
    c->mode = CONN_HTTP;
    snprintf(c->ip, sizeof c->ip, "%s", ip ? ip : "?");
    c->born_ms = c->last_ms = now_ms();
    buf_init(&c->in);
    buf_init(&c->out);
    buf_init(&c->frag);

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.ptr = c;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        free(c); close(fd); return NULL;
    }
    c->next = g_conns;
    if (g_conns) g_conns->prev = c;
    g_conns = c;
    g_stats.conns_total++;
    return c;
}

static void do_accept(void) {
    for (;;) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof sa;
        int fd = accept(g_listen, (struct sockaddr*)&sa, &sl);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        set_nonblock(fd);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        char ip[64] = "?";
        inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip);
        conn_new(fd, ip);
    }
}

static void on_readable(Conn *c) {
    if (c->fd < 0) return;
    char tmp[16384];
    int peer_closed = 0;
    for (;;) {
        ssize_t r = recv(c->fd, tmp, sizeof tmp, 0);
        if (r > 0) {
            buf_append(&c->in, tmp, (size_t)r);
            if (c->in.len > MAX_HTTP_HEAD + MAX_HTTP_BODY + MAX_WS_MSG + 128) {
                conn_close(c);
                return;
            }
            if ((size_t)r < sizeof tmp) break;
            continue;
        }
        if (r == 0) { peer_closed = 1; break; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        conn_close(c);
        return;
    }
    if (peer_closed) { conn_close(c); return; }

    if (c->mode == CONN_HTTP) {
        http_on_readable(c);
        /* request may have upgraded us to WS with leftover frame bytes */
        if (c->fd >= 0 && c->mode == CONN_WS && c->in.len > 0)
            ws_on_readable(c);
    } else {
        ws_on_readable(c);
    }
}

static void sweep_idle(void) {
    int64_t now = now_ms();
    Conn *c = g_conns;
    while (c) {
        Conn *next = c->next;
        int64_t idle = now - c->last_ms;
        if (c->mode == CONN_HTTP) {
            if (idle > HTTP_IDLE_SECS * 1000) {
                if (c->out.len == 0) {
                    http_reply_err(&c->out, 408, "timeout");
                    c->want_close = 1;
                } else {
                    conn_close(c);
                }
            }
        } else {
            if (c->ping_pending && idle > WS_DEAD_SECS * 1000) {
                logi("ws dead user=%lld ip=%s", (long long)c->user_id, c->ip);
                conn_close(c);
            } else if (!c->ping_pending && idle > WS_PING_SECS * 1000) {
                ws_send_ping(c);
            }
        }
        c = next;
    }
}

int server_run(void) {
    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { loge("epoll_create1: %s", strerror(errno)); return -1; }

    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen < 0) { loge("socket: %s", strerror(errno)); return -1; }
    int one = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)g_cfg.port);
    if (!strcmp(g_cfg.bind_addr, "0.0.0.0")) sa.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (inet_pton(AF_INET, g_cfg.bind_addr, &sa.sin_addr) != 1) {
        loge("bad bind addr %s", g_cfg.bind_addr); return -1;
    }
    if (bind(g_listen, (struct sockaddr*)&sa, sizeof sa) < 0) {
        loge("bind %s:%d: %s", g_cfg.bind_addr, g_cfg.port, strerror(errno));
        return -1;
    }
    if (listen(g_listen, 128) < 0) { loge("listen: %s", strerror(errno)); return -1; }
    set_nonblock(g_listen);

    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;   /* NULL ptr == listener */
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listen, &ev);

    logi("listening on %s:%d", g_cfg.bind_addr, g_cfg.port);

    struct epoll_event events[256];
    int64_t last_sweep = now_ms();

    while (!g_stop) {
        int n = epoll_wait(g_epfd, events, 256, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            loge("epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (!events[i].data.ptr) { do_accept(); continue; }
            Conn *c = events[i].data.ptr;
            if (c->fd < 0) continue;   /* closed earlier in this batch */
            uint32_t e = events[i].events;
            if (e & (EPOLLHUP | EPOLLERR)) { conn_close(c); continue; }
            if (e & EPOLLIN)  on_readable(c);
            if (c->fd >= 0 && (e & EPOLLOUT)) {
                if (flush_conn(c) == 0 && c->want_close && c->out.len == 0)
                    conn_close(c);
            }
            if (c->fd >= 0) {
                if (c->want_close && c->out.len == 0) conn_close(c);
                else mod_interest(c);
            }
        }
        reap_dead();

        int64_t now = now_ms();
        if (now - last_sweep > 5000) {
            last_sweep = now;
            sweep_idle();
        }
    }

    logi("shutting down: closing %d connections", conns_alive());
    while (g_conns) conn_close(g_conns);
    reap_dead();
    close(g_listen);
    close(g_epfd);
    logi("bye");
    return 0;
}
