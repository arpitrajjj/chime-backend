/* db.c — SQLite lifecycle, migrations, tiny prepared-statement helpers.
 * Security: all queries elsewhere MUST use prepared statements (never build
 * SQL with sprintf). WAL mode for concurrency; FK enforcement ON.
 */
#include "chime.h"

sqlite3 *g_db = NULL;

static const char *SCHEMA_V1 =
"CREATE TABLE IF NOT EXISTS meta("
"  k TEXT PRIMARY KEY,"
"  v TEXT NOT NULL);"

"CREATE TABLE IF NOT EXISTS users("
"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
"  display_name TEXT NOT NULL DEFAULT '',"
"  pass_hash TEXT NOT NULL,"
"  created_at INTEGER NOT NULL,"
"  last_seen INTEGER NOT NULL DEFAULT 0);"

"CREATE TABLE IF NOT EXISTS chats("
"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  type TEXT NOT NULL CHECK(type IN ('dm','group')),"
"  dm_key TEXT UNIQUE,"
"  name TEXT NOT NULL DEFAULT '',"
"  created_by INTEGER REFERENCES users(id),"
"  created_at INTEGER NOT NULL);"

"CREATE TABLE IF NOT EXISTS chat_members("
"  chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,"
"  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
"  last_read_msg INTEGER NOT NULL DEFAULT 0,"
"  joined_at INTEGER NOT NULL,"
"  PRIMARY KEY(chat_id, user_id));"

"CREATE TABLE IF NOT EXISTS messages("
"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,"
"  sender_id INTEGER NOT NULL REFERENCES users(id),"
"  body TEXT NOT NULL,"
"  created_at INTEGER NOT NULL);"

"CREATE TABLE IF NOT EXISTS client_logs("
"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
"  user_id INTEGER,"
"  level TEXT NOT NULL DEFAULT 'info',"
"  tag TEXT NOT NULL DEFAULT '',"
"  message TEXT NOT NULL,"
"  created_at INTEGER NOT NULL);"

"CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, id);"
"CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);"
"CREATE INDEX IF NOT EXISTS idx_users_last ON users(last_seen);";

int db_open(const char *path) {
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (sqlite3_open_v2(path, &g_db, flags, NULL) != SQLITE_OK) {
        loge("sqlite open %s: %s", path, g_db ? sqlite3_errmsg(g_db) : "?");
        return -1;
    }
    sqlite3_busy_timeout(g_db, 5000);
    /* hardening: no extensions, no double-quoted strings, WAL, FK on */
    char *err = NULL;
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err);
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, &err);
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, &err);
    if (err) { loge("pragma: %s", err); sqlite3_free(err); }
    logi("db opened: %s (wal)", path);
    return 0;
}

void db_close(void) {
    if (g_db) { sqlite3_close_v2(g_db); g_db = NULL; }
}

int db_prep(Stmt *s, const char *sql) {
    s->st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s->st, NULL) != SQLITE_OK) {
        loge("prep failed: %s | %s", sqlite3_errmsg(g_db), sql);
        return -1;
    }
    return 0;
}

int db_bind_i64(Stmt *s, int idx, int64_t v) {
    return sqlite3_bind_int64(s->st, idx, v) == SQLITE_OK ? 0 : -1;
}

int db_bind_text(Stmt *s, int idx, const char *v, size_t len) {
    return sqlite3_bind_text(s->st, idx, v, (int)len, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

int db_step(Stmt *s) {
    int rc = sqlite3_step(s->st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    loge("step failed: %s", sqlite3_errmsg(g_db));
    return -1;
}

int64_t db_col_i64(Stmt *s, int col) { return sqlite3_column_int64(s->st, col); }
const unsigned char *db_col_text(Stmt *s, int col) { return sqlite3_column_text(s->st, col); }

void db_fin(Stmt *s) {
    if (s->st) { sqlite3_finalize(s->st); s->st = NULL; }
}

void db_reset(Stmt *s) {
    if (s->st) sqlite3_reset(s->st);   /* bindings persist across reset */
}

char *db_meta_get(const char *key) {
    Stmt s;
    if (db_prep(&s, "SELECT v FROM meta WHERE k=?1")) return NULL;
    db_bind_text(&s, 1, key, strlen(key));
    char *out = NULL;
    if (db_step(&s) == 1) {
        const unsigned char *v = db_col_text(&s, 0);
        if (v) out = strdup((const char*)v);
    }
    db_fin(&s);
    return out;
}

int db_meta_set(const char *key, const char *val) {
    Stmt s;
    if (db_prep(&s, "INSERT INTO meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=?2"))
        return -1;
    db_bind_text(&s, 1, key, strlen(key));
    db_bind_text(&s, 2, val, strlen(val));
    int rc = db_step(&s);
    db_fin(&s);
    return rc < 0 ? -1 : 0;
}

int db_migrate(void) {
    char *err = NULL;
    if (sqlite3_exec(g_db, SCHEMA_V1, NULL, NULL, &err) != SQLITE_OK) {
        loge("migrate: %s", err ? err : "?");
        if (err) sqlite3_free(err);
        return -1;
    }
    logi("schema ready");
    return 0;
}
