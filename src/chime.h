/* chime.h — Chime real-time chat server (C11, epoll, SQLite)
 *
 * Single-threaded event-loop server speaking HTTP/1.1 + RFC 6455 WebSocket.
 * All state lives on the loop thread; SQLite is vendored (vendor/sqlite).
 */
#ifndef CHIME_H
#define CHIME_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sqlite3.h"

#define CHIME_VERSION "1.0.0"

/* ---- protocol / safety limits ---- */
#define MAX_HTTP_HEAD   16384   /* request line + headers            */
#define MAX_HTTP_BODY   32768   /* JSON body cap                     */
#define MAX_WS_MSG      65536   /* assembled websocket message cap   */
#define WS_PING_SECS    30      /* idle ping cadence                 */
#define WS_DEAD_SECS    95      /* no traffic -> drop                */
#define HTTP_IDLE_SECS  30      /* unfinished request -> drop        */
#define TOKEN_TTL_SECS  (30LL * 86400)
#define TOKEN_PREFIX    "ch1."
#define WS_GUID         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define PBKDF2_ITERS    120000
#define MAX_USERNAME    20
#define MAX_DISPLAY     32      /* UTF-8 bytes cap is 3x for safety  */
#define MAX_MSG_BODY    4000

/* ---- log levels ---- */
enum { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERROR = 3 };

typedef struct Config {
    int         port;
    const char *bind_addr;
    const char *db_path;
    const char *data_dir;      /* logs/, crash.log live here */
    int         log_level;
} Config;

extern Config   g_cfg;
extern volatile sig_atomic_t g_stop;

/* ---------- forward decls used before definition ---------- */
struct Conn;
typedef struct HTTPReq HTTPReq;

/* ---------- growable byte buffer (util.c) ---------- */
typedef struct Buf { char *data; size_t len, cap; } Buf;

void  buf_init(Buf *b);
void  buf_reserve(Buf *b, size_t extra);
void  buf_append(Buf *b, const void *src, size_t n);
void  buf_printf(Buf *b, const char *fmt, ...) __attribute__((format(printf,2,3)));
void  buf_consume(Buf *b, size_t n);       /* drop first n bytes */
void  buf_free(Buf *b);

/* misc helpers (util.c) */
int64_t now_ms(void);
int64_t now_sec(void);
void    rand_bytes(uint8_t *out, size_t n);
int     b64_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz);
int     b64_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz);
int     b64url_encode(const uint8_t *in, size_t inlen, char *out, size_t outsz);
int     b64url_decode(const char *in, size_t inlen, uint8_t *out, size_t outsz);
int     ct_equal(const char *a, const char *b, size_t n);   /* constant-time */
int     url_decode(const char *in, size_t inlen, char *out, size_t outsz);
int     utf8_valid(const char *s, size_t len);
int     has_forbidden_ctrl(const char *s, size_t len);      /* C0 minus \n \t */
int     set_nonblock(int fd);
int     mkdir_p(const char *path);

/* ---------- logging (log.c) ---------- */
void log_init(int level, const char *path /* NULL = stderr only */);
void log_close(void);
void log_msg(int lvl, const char *fmt, ...) __attribute__((format(printf,2,3)));
#define logd(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define logi(...) log_msg(LOG_INFO,  __VA_ARGS__)
#define logw(...) log_msg(LOG_WARN,  __VA_ARGS__)
#define loge(...) log_msg(LOG_ERROR, __VA_ARGS__)

/* ---------- crash handler (crash.c) ---------- */
void crash_install(const char *crashlog_path);

/* ---------- crypto (sha256.c) ---------- */
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen, uint8_t out[32]);
void pbkdf2_sha256(const uint8_t *pass, size_t passlen,
                   const uint8_t *salt, size_t saltlen,
                   uint32_t iters, uint8_t out[32]);
void sha1(const uint8_t *data, size_t len, uint8_t out[20]);

/* ---------- JSON (json.c) ---------- */
typedef enum { JV_NULL, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ } JType;

typedef struct JV {
    JType t;
    int b;                       /* bool        */
    double num;                  /* number      */
    char *s; size_t slen;        /* string      */
    struct JV **items; size_t n; /* arr / obj values */
    char **keys;                 /* obj keys        */
} JV;

JV     *json_parse(const char *s, size_t len, const char **err);
void    json_free(JV *v);
JV     *jv_get(const JV *obj, const char *key);
int64_t jv_int(const JV *v);
const char *jv_str(const JV *v);
/* append quoted, escaped JSON string (incl. surrounding quotes) */
void    json_escape_buf(Buf *out, const char *s, size_t len);

/* ---------- rate limiting (ratelimit.c) ---------- */
void rl_init(void);
void rl_free(void);
/* returns 1 if allowed, 0 if rate-limited. group separates buckets. */
int  rl_check(const char *group, const char *key, int limit, int64_t window_ms);

/* ---------- database (db.c) ---------- */
typedef struct Stmt { sqlite3_stmt *st; } Stmt;

int      db_open(const char *path);
void     db_close(void);
int      db_migrate(void);
int      db_prep(Stmt *s, const char *sql);
int      db_bind_i64(Stmt *s, int idx, int64_t v);
int      db_bind_text(Stmt *s, int idx, const char *v, size_t len);
int      db_step(Stmt *s);          /* returns 1 on ROW, 0 on DONE, -1 err */
void     db_reset(Stmt *s);         /* sqlite3_reset, keeps bindings */
int64_t  db_col_i64(Stmt *s, int col);
const unsigned char *db_col_text(Stmt *s, int col);
void     db_fin(Stmt *s);
char    *db_meta_get(const char *key);          /* caller frees */
int      db_meta_set(const char *key, const char *val);
extern sqlite3 *g_db;

/* ---------- auth (auth.c) ---------- */
int      auth_init(void);                                /* load/create HMAC secret */
int      pw_hash(const char *pass, char out[256]);
int      pw_verify(const char *pass, const char *stored);
int      token_mint(int64_t uid, char *out, size_t outsz);
int64_t  token_verify(const char *tok);                  /* uid or 0 */

/* ---------- websocket (ws.c) ---------- */
void ws_start(struct Conn *c, HTTPReq *r);
void ws_on_readable(struct Conn *c);
void ws_send_text(struct Conn *c, const char *data, size_t len);
void ws_send_close(struct Conn *c, int code);
void ws_send_ping(struct Conn *c);

/* ---------- realtime events (realtime.c) ---------- */
void rt_on_open(struct Conn *c);
void rt_on_text(struct Conn *c, char *data, size_t len);
void rt_on_close(struct Conn *c);
void rt_notify_chat_new(int64_t chat_id);

/* ---------- shared JSON builders / membership (api.c) ---------- */
int  shared_is_member(int64_t chat_id, int64_t user_id);
void shared_user_json(Buf *b, int64_t uid);              /* appends obj or null */
void shared_message_json(Buf *b, int64_t msg_id);        /* message + sender    */

/* ---------- http (http.c) ---------- */
struct HTTPReq {
    char   method[8];
    char   path[512];
    char   query[1024];
    char  *body;  size_t body_len;
    char   token[620];
    char   ws_key[80];
    int    upgrade_ws;
};

void http_on_readable(struct Conn *c);
void api_route(struct Conn *c, HTTPReq *req, Buf *out);
void http_reply_json(Buf *out, int status, const char *json_body);
void http_reply_err(Buf *out, int status, const char *msg);
int  query_param(const char *query, const char *key, char *out, size_t outsz);
int  path_int_after(const char *path, const char *prefix, int64_t *out);
int  req_is_authed(HTTPReq *req, int64_t *uid_out);

/* ---------- server core (server.c) ---------- */
typedef enum { CONN_HTTP = 0, CONN_WS = 1 } ConnMode;

typedef struct Conn {
    int      fd;
    ConnMode mode;
    Buf      in, out, frag;        /* frag: ws fragmentation accumulator */
    int      want_close;
    int      ws_closing;           /* we sent CLOSE, awaiting flush */
    int      ping_pending;
    int64_t  user_id;              /* 0 = anonymous */
    char     username[64];
    char     ip[64];
    int64_t  born_ms, last_ms;
    struct Conn *next, *prev;
} Conn;

extern Conn *g_conns;              /* doubly linked, includes all live conns */

int      server_run(void);
void     conn_send_raw(Conn *c, const char *data, size_t n);
void     conn_kick(Conn *c);
void     conn_close(Conn *c);
int      user_online(int64_t uid);
int      online_user_count(void);
int      conns_alive(void);
extern int64_t g_start_sec;
typedef struct Stats { int64_t conns_total, ws_total, msgs_in, msgs_out, http_reqs; } Stats;
extern Stats g_stats;

#endif /* CHIME_H */
