/* json.c — small strict JSON parser + string escaper.
 * Recursive descent, bounded depth, \uXXXX incl. surrogate pairs.
 */
#include "chime.h"

#define JSON_MAX_DEPTH 32
#define JSON_MAX_NODES 4096

typedef struct { const char *p, *end; const char *err; int depth, nodes; } JP;

static void jskip_ws(JP *j) { while (j->p < j->end && (*j->p==' '||*j->p=='\t'||*j->p=='\n'||*j->p=='\r')) j->p++; }

static JV *jnew(JP *j, JType t) {
    if (++j->nodes > JSON_MAX_NODES) { j->err = "too many nodes"; return NULL; }
    JV *v = calloc(1, sizeof(JV));
    if (!v) { j->err = "oom"; return NULL; }
    v->t = t;
    return v;
}

void json_free(JV *v) {
    if (!v) return;
    if (v->t == JV_ARR || v->t == JV_OBJ) {
        for (size_t i = 0; i < v->n; i++) json_free(v->items[i]);
        free(v->items);
        if (v->t == JV_OBJ) {
            for (size_t i = 0; i < v->n; i++) free(v->keys[i]);
            free(v->keys);
        }
    }
    free(v->s);
    free(v);
}

static void utf8_emit(Buf *b, uint32_t cp) {
    char tmp[4];
    if (cp < 0x80) { tmp[0] = (char)cp; buf_append(b, tmp, 1); }
    else if (cp < 0x800) {
        tmp[0] = (char)(0xC0 | (cp >> 6)); tmp[1] = (char)(0x80 | (cp & 0x3F));
        buf_append(b, tmp, 2);
    } else if (cp < 0x10000) {
        tmp[0] = (char)(0xE0 | (cp >> 12)); tmp[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (char)(0x80 | (cp & 0x3F));
        buf_append(b, tmp, 3);
    } else {
        tmp[0] = (char)(0xF0 | (cp >> 18)); tmp[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        tmp[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); tmp[3] = (char)(0x80 | (cp & 0x3F));
        buf_append(b, tmp, 4);
    }
}

static int jhex4(JP *j, uint32_t *out) {
    if (j->p + 4 > j->end) return -1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char c = j->p[i]; v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    j->p += 4;
    *out = v;
    return 0;
}

/* parse string content; j->p sits after opening quote; appends decoded bytes (no quotes) */
static int jstring_raw(JP *j, Buf *out) {
    for (;;) {
        if (j->p >= j->end) { j->err = "unterminated string"; return -1; }
        unsigned char c = (unsigned char)*j->p;
        if (c == '"') { j->p++; return 0; }
        if (c == '\\') {
            j->p++;
            if (j->p >= j->end) { j->err = "bad escape"; return -1; }
            char e = *j->p++;
            switch (e) {
                case '"': buf_append(out, "\"", 1); break;
                case '\\': buf_append(out, "\\", 1); break;
                case '/': buf_append(out, "/", 1); break;
                case 'b': buf_append(out, "\b", 1); break;
                case 'f': buf_append(out, "\f", 1); break;
                case 'n': buf_append(out, "\n", 1); break;
                case 'r': buf_append(out, "\r", 1); break;
                case 't': buf_append(out, "\t", 1); break;
                case 'u': {
                    uint32_t cp;
                    if (jhex4(j, &cp)) { j->err = "bad \\u"; return -1; }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        /* expect low surrogate */
                        if (j->p + 2 <= j->end && j->p[0] == '\\' && j->p[1] == 'u') {
                            j->p += 2;
                            uint32_t lo;
                            if (jhex4(j, &lo)) { j->err = "bad \\u"; return -1; }
                            if (lo < 0xDC00 || lo > 0xDFFF) { j->err = "bad surrogate"; return -1; }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else { j->err = "lone surrogate"; return -1; }
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        j->err = "lone surrogate"; return -1;
                    }
                    utf8_emit(out, cp);
                    break;
                }
                default: j->err = "bad escape"; return -1;
            }
        } else if (c < 0x20) {
            j->err = "raw control char in string"; return -1;
        } else {
            buf_append(out, &c, 1);
            j->p++;
        }
    }
}

static JV *jvalue(JP *j);

static JV *jobj(JP *j) {
    JV *o = jnew(j, JV_OBJ);
    if (!o) return NULL;
    jskip_ws(j);
    if (j->p < j->end && *j->p == '}') { j->p++; return o; }
    for (;;) {
        jskip_ws(j);
        if (j->p >= j->end || *j->p != '"') { j->err = "expected key"; json_free(o); return NULL; }
        j->p++;
        Buf kb; buf_init(&kb);
        if (jstring_raw(j, &kb)) { buf_free(&kb); json_free(o); return NULL; }
        jskip_ws(j);
        if (j->p >= j->end || *j->p != ':') { j->err = "expected ':'"; buf_free(&kb); json_free(o); return NULL; }
        j->p++;
        JV *val = jvalue(j);
        if (!val) { buf_free(&kb); json_free(o); return NULL; }
        char **nk = realloc(o->keys, (o->n + 1) * sizeof(char*));
        JV **ni = realloc(o->items, (o->n + 1) * sizeof(JV*));
        if (!nk || !ni) { j->err = "oom"; free(nk); free(ni); free(kb.data); json_free(val); json_free(o); return NULL; }
        o->keys = nk; o->items = ni;
        o->keys[o->n] = kb.data ? kb.data : strdup("");
        o->items[o->n] = val;
        o->n++;
        jskip_ws(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == '}') { j->p++; return o; }
        j->err = "expected ',' or '}'"; json_free(o); return NULL;
    }
}

static JV *jarr(JP *j) {
    JV *a = jnew(j, JV_ARR);
    if (!a) return NULL;
    jskip_ws(j);
    if (j->p < j->end && *j->p == ']') { j->p++; return a; }
    for (;;) {
        JV *val = jvalue(j);
        if (!val) { json_free(a); return NULL; }
        JV **ni = realloc(a->items, (a->n + 1) * sizeof(JV*));
        if (!ni) { j->err = "oom"; json_free(val); json_free(a); return NULL; }
        a->items = ni;
        a->items[a->n++] = val;
        jskip_ws(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == ']') { j->p++; return a; }
        j->err = "expected ',' or ']'"; json_free(a); return NULL;
    }
}

static JV *jvalue(JP *j) {
    if (++j->depth > JSON_MAX_DEPTH) { j->depth--; j->err = "too deep"; return NULL; }
    jskip_ws(j);
    if (j->p >= j->end) { j->err = "unexpected end"; j->depth--; return NULL; }
    JV *res = NULL;
    char c = *j->p;
    if (c == '{') { j->p++; res = jobj(j); }
    else if (c == '[') { j->p++; res = jarr(j); }
    else if (c == '"') {
        j->p++;
        Buf sb; buf_init(&sb);
        if (jstring_raw(j, &sb)) { buf_free(&sb); j->depth--; return NULL; }
        res = jnew(j, JV_STR);
        if (res) { res->s = sb.data ? sb.data : strdup(""); res->slen = sb.len; }
        else buf_free(&sb);
    }
    else if (c == 't') {
        if (j->p + 4 <= j->end && !strncmp(j->p, "true", 4)) { j->p += 4; res = jnew(j, JV_BOOL); if (res) res->b = 1; }
        else j->err = "bad literal";
    }
    else if (c == 'f') {
        if (j->p + 5 <= j->end && !strncmp(j->p, "false", 5)) { j->p += 5; res = jnew(j, JV_BOOL); }
        else j->err = "bad literal";
    }
    else if (c == 'n') {
        if (j->p + 4 <= j->end && !strncmp(j->p, "null", 4)) { j->p += 4; res = jnew(j, JV_NULL); }
        else j->err = "bad literal";
    }
    else if (c == '-' || (c >= '0' && c <= '9')) {
        const char *st = j->p;
        if (c == '-') j->p++;
        if (j->p < j->end && *j->p == '0') j->p++;
        else if (j->p < j->end && *j->p >= '1' && *j->p <= '9')
            while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
        else j->err = "bad number";
        if (!j->err) {
            if (j->p < j->end && *j->p == '.') { j->p++; if (j->p >= j->end || *j->p < '0' || *j->p > '9') j->err = "bad number"; else while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++; }
            if (!j->err && j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
                j->p++;
                if (j->p < j->end && (*j->p == '+' || *j->p == '-')) j->p++;
                if (j->p >= j->end || *j->p < '0' || *j->p > '9') j->err = "bad number";
                else while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
            }
        }
        if (!j->err) {
            res = jnew(j, JV_NUM);
            if (res) res->num = strtod(st, NULL);
        }
    }
    else j->err = "unexpected char";
    j->depth--;
    return res;
}

JV *json_parse(const char *s, size_t len, const char **err) {
    JP j = { s, s + len, NULL, 0, 0 };
    JV *v = jvalue(&j);
    if (v) {
        jskip_ws(&j);
        if (j.p != j.end) { json_free(v); v = NULL; j.err = "trailing data"; }
    }
    if (err) *err = j.err;
    return v;
}

JV *jv_get(const JV *obj, const char *key) {
    if (!obj || obj->t != JV_OBJ) return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (!strcmp(obj->keys[i], key)) return obj->items[i];
    return NULL;
}

int64_t jv_int(const JV *v) {
    if (!v) return 0;
    if (v->t == JV_NUM) return (int64_t)v->num;
    if (v->t == JV_STR) return strtoll(v->s, NULL, 10);
    return 0;
}

const char *jv_str(const JV *v) {
    return (v && v->t == JV_STR) ? v->s : NULL;
}

void json_escape_buf(Buf *out, const char *s, size_t len) {
    buf_append(out, "\"", 1);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  buf_append(out, "\\\"", 2); break;
            case '\\': buf_append(out, "\\\\", 2); break;
            case '\b': buf_append(out, "\\b", 2); break;
            case '\f': buf_append(out, "\\f", 2); break;
            case '\n': buf_append(out, "\\n", 2); break;
            case '\r': buf_append(out, "\\r", 2); break;
            case '\t': buf_append(out, "\\t", 2); break;
            default:
                if (c < 0x20) buf_printf(out, "\\u%04x", c);
                else buf_append(out, &s[i], 1);
        }
    }
    buf_append(out, "\"", 1);
}
