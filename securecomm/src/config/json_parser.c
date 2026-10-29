/*
 * securecomm/src/config/json_parser.c
 *
 * Lightweight, safe, standalone JSON parser and serializer in pure C.
 */

#define _POSIX_C_SOURCE 200809L
#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Memory Allocation Helpers ───────────────────────────────────── */
static json_value_t *alloc_value(json_type_t type) {
    json_value_t *v = (json_value_t *)calloc(1, sizeof(json_value_t));
    if (v) v->type = type;
    return v;
}

json_value_t *json_create_object(void) { return alloc_value(JSON_OBJECT); }
json_value_t *json_create_array(void)  { return alloc_value(JSON_ARRAY); }
json_value_t *json_create_null(void)   { return alloc_value(JSON_NULL); }

json_value_t *json_create_bool(bool b) {
    json_value_t *v = alloc_value(JSON_BOOL);
    if (v) v->u.boolean = b;
    return v;
}

json_value_t *json_create_number(double num) {
    json_value_t *v = alloc_value(JSON_NUMBER);
    if (v) v->u.number = num;
    return v;
}

json_value_t *json_create_string(const char *str) {
    json_value_t *v = alloc_value(JSON_STRING);
    if (v) v->u.string = str ? strdup(str) : strdup("");
    return v;
}

void json_free(json_value_t *val) {
    if (!val) return;
    if (val->type == JSON_STRING) {
        free(val->u.string);
    } else if (val->type == JSON_ARRAY) {
        for (size_t i = 0; i < val->u.array.count; i++) {
            json_free(val->u.array.items[i]);
        }
        free(val->u.array.items);
    } else if (val->type == JSON_OBJECT) {
        for (size_t i = 0; i < val->u.object.count; i++) {
            free(val->u.object.pairs[i].key);
            json_free(val->u.object.pairs[i].value);
        }
        free(val->u.object.pairs);
    }
    free(val);
}

void json_object_set(json_value_t *obj, const char *key, json_value_t *val) {
    if (!obj || obj->type != JSON_OBJECT || !key || !val) return;
    for (size_t i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.pairs[i].key, key) == 0) {
            json_free(obj->u.object.pairs[i].value);
            obj->u.object.pairs[i].value = val;
            return;
        }
    }
    size_t new_count = obj->u.object.count + 1;
    json_pair_t *new_pairs = (json_pair_t *)realloc(obj->u.object.pairs, new_count * sizeof(json_pair_t));
    if (!new_pairs) return;
    obj->u.object.pairs = new_pairs;
    obj->u.object.pairs[new_count - 1].key = strdup(key);
    obj->u.object.pairs[new_count - 1].value = val;
    obj->u.object.count = new_count;
}

void json_array_append(json_value_t *arr, json_value_t *val) {
    if (!arr || arr->type != JSON_ARRAY || !val) return;
    size_t new_count = arr->u.array.count + 1;
    json_value_t **new_items = (json_value_t **)realloc(arr->u.array.items, new_count * sizeof(json_value_t *));
    if (!new_items) return;
    arr->u.array.items = new_items;
    arr->u.array.items[new_count - 1] = val;
    arr->u.array.count = new_count;
}

json_value_t *json_object_get(const json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT || !key) return NULL;
    for (size_t i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.pairs[i].key, key) == 0) {
            return obj->u.object.pairs[i].value;
        }
    }
    return NULL;
}

const char *json_get_string(const json_value_t *val, const char *default_val) {
    if (!val || val->type != JSON_STRING || !val->u.string) return default_val;
    return val->u.string;
}

int64_t json_get_int(const json_value_t *val, int64_t default_val) {
    if (!val || val->type != JSON_NUMBER) return default_val;
    return (int64_t)val->u.number;
}

double json_get_double(const json_value_t *val, double default_val) {
    if (!val || val->type != JSON_NUMBER) return default_val;
    return val->u.number;
}

bool json_get_bool(const json_value_t *val, bool default_val) {
    if (!val || val->type != JSON_BOOL) return default_val;
    return val->u.boolean;
}

/* ── Parser Implementation ───────────────────────────────────────── */
typedef struct {
    const char *src;
    size_t pos;
    char error[256];
} parse_ctx_t;

static void skip_whitespace(parse_ctx_t *ctx) {
    while (ctx->src[ctx->pos]) {
        char c = ctx->src[ctx->pos];
        if (isspace((unsigned char)c)) {
            ctx->pos++;
        } else if (c == '/' && ctx->src[ctx->pos + 1] == '/') {
            /* Support C++ comments */
            while (ctx->src[ctx->pos] && ctx->src[ctx->pos] != '\n') ctx->pos++;
        } else {
            break;
        }
    }
}

static json_value_t *parse_value(parse_ctx_t *ctx);

static char *parse_string_raw(parse_ctx_t *ctx) {
    if (ctx->src[ctx->pos] != '"') return NULL;
    ctx->pos++; /* Skip opening quote */
    size_t start = ctx->pos;
    size_t cap = 64;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    while (ctx->src[ctx->pos]) {
        char c = ctx->src[ctx->pos++];
        if (c == '"') {
            buf[len] = '\0';
            return buf;
        }
        if (c == '\\') {
            if (!ctx->src[ctx->pos]) break;
            char esc = ctx->src[ctx->pos++];
            if (esc == '"') c = '"';
            else if (esc == '\\') c = '\\';
            else if (esc == '/') c = '/';
            else if (esc == 'n') c = '\n';
            else if (esc == 'r') c = '\r';
            else if (esc == 't') c = '\t';
            else if (esc == 'b') c = '\b';
            else if (esc == 'f') c = '\f';
        }
        if (len + 2 >= cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[len++] = c;
    }
    free(buf);
    snprintf(ctx->error, sizeof(ctx->error), "Unterminated string at offset %zu", start);
    return NULL;
}

static json_value_t *parse_object(parse_ctx_t *ctx) {
    ctx->pos++; /* Skip '{' */
    json_value_t *obj = json_create_object();
    if (!obj) return NULL;

    for (;;) {
        skip_whitespace(ctx);
        if (ctx->src[ctx->pos] == '}') {
            ctx->pos++;
            return obj;
        }
        if (ctx->src[ctx->pos] != '"') {
            snprintf(ctx->error, sizeof(ctx->error), "Expected string key at offset %zu", ctx->pos);
            json_free(obj);
            return NULL;
        }
        char *key = parse_string_raw(ctx);
        if (!key) {
            json_free(obj);
            return NULL;
        }
        skip_whitespace(ctx);
        if (ctx->src[ctx->pos] != ':') {
            snprintf(ctx->error, sizeof(ctx->error), "Expected ':' after key '%s' at offset %zu", key, ctx->pos);
            free(key);
            json_free(obj);
            return NULL;
        }
        ctx->pos++; /* Skip ':' */
        skip_whitespace(ctx);
        json_value_t *val = parse_value(ctx);
        if (!val) {
            free(key);
            json_free(obj);
            return NULL;
        }
        json_object_set(obj, key, val);
        free(key);
        skip_whitespace(ctx);
        if (ctx->src[ctx->pos] == ',') {
            ctx->pos++;
        } else if (ctx->src[ctx->pos] == '}') {
            ctx->pos++;
            return obj;
        } else {
            snprintf(ctx->error, sizeof(ctx->error), "Expected ',' or '}' at offset %zu", ctx->pos);
            json_free(obj);
            return NULL;
        }
    }
}

static json_value_t *parse_array(parse_ctx_t *ctx) {
    ctx->pos++; /* Skip '[' */
    json_value_t *arr = json_create_array();
    if (!arr) return NULL;

    for (;;) {
        skip_whitespace(ctx);
        if (ctx->src[ctx->pos] == ']') {
            ctx->pos++;
            return arr;
        }
        json_value_t *val = parse_value(ctx);
        if (!val) {
            json_free(arr);
            return NULL;
        }
        json_array_append(arr, val);
        skip_whitespace(ctx);
        if (ctx->src[ctx->pos] == ',') {
            ctx->pos++;
        } else if (ctx->src[ctx->pos] == ']') {
            ctx->pos++;
            return arr;
        } else {
            snprintf(ctx->error, sizeof(ctx->error), "Expected ',' or ']' at offset %zu", ctx->pos);
            json_free(arr);
            return NULL;
        }
    }
}

static json_value_t *parse_value(parse_ctx_t *ctx) {
    skip_whitespace(ctx);
    char c = ctx->src[ctx->pos];
    if (c == '{') return parse_object(ctx);
    if (c == '[') return parse_array(ctx);
    if (c == '"') {
        char *str = parse_string_raw(ctx);
        if (!str) return NULL;
        json_value_t *v = alloc_value(JSON_STRING);
        if (v) v->u.string = str;
        else free(str);
        return v;
    }
    if (c == 't' && strncmp(&ctx->src[ctx->pos], "true", 4) == 0) {
        ctx->pos += 4;
        return json_create_bool(true);
    }
    if (c == 'f' && strncmp(&ctx->src[ctx->pos], "false", 5) == 0) {
        ctx->pos += 5;
        return json_create_bool(false);
    }
    if (c == 'n' && strncmp(&ctx->src[ctx->pos], "null", 4) == 0) {
        ctx->pos += 4;
        return json_create_null();
    }
    if (c == '-' || isdigit((unsigned char)c)) {
        char *end = NULL;
        double val = strtod(&ctx->src[ctx->pos], &end);
        if (end && end != &ctx->src[ctx->pos]) {
            ctx->pos = (size_t)(end - ctx->src);
            return json_create_number(val);
        }
    }
    snprintf(ctx->error, sizeof(ctx->error), "Unexpected character '%c' at offset %zu", c, ctx->pos);
    return NULL;
}

json_value_t *json_parse(const char *text, char *out_error, size_t error_max) {
    if (!text) {
        if (out_error && error_max) snprintf(out_error, error_max, "Null text input");
        return NULL;
    }
    parse_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.src = text;
    json_value_t *root = parse_value(&ctx);
    if (!root && out_error && error_max) {
        snprintf(out_error, error_max, "%s", ctx.error);
    }
    return root;
}

/* ── Stringify Implementation ────────────────────────────────────── */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} str_buf_t;

static void buf_append(str_buf_t *sb, const char *s) {
    size_t slen = strlen(s);
    if (sb->len + slen + 1 >= sb->cap) {
        sb->cap = (sb->cap + slen + 256) * 2;
        sb->buf = (char *)realloc(sb->buf, sb->cap);
    }
    memcpy(sb->buf + sb->len, s, slen);
    sb->len += slen;
    sb->buf[sb->len] = '\0';
}

static void buf_indent(str_buf_t *sb, int indent) {
    for (int i = 0; i < indent * 2; i++) buf_append(sb, " ");
}

static void stringify_value(const json_value_t *val, str_buf_t *sb, bool pretty, int depth) {
    if (!val) { buf_append(sb, "null"); return; }
    char tmp[64];
    switch (val->type) {
        case JSON_NULL: buf_append(sb, "null"); break;
        case JSON_BOOL: buf_append(sb, val->u.boolean ? "true" : "false"); break;
        case JSON_NUMBER:
            if (val->u.number == (int64_t)val->u.number) snprintf(tmp, sizeof(tmp), "%lld", (long long)val->u.number);
            else snprintf(tmp, sizeof(tmp), "%g", val->u.number);
            buf_append(sb, tmp);
            break;
        case JSON_STRING:
            buf_append(sb, "\"");
            for (const char *p = val->u.string; *p; p++) {
                if (*p == '"') buf_append(sb, "\\\"");
                else if (*p == '\\') buf_append(sb, "\\\\");
                else if (*p == '\n') buf_append(sb, "\\n");
                else if (*p == '\r') buf_append(sb, "\\r");
                else if (*p == '\t') buf_append(sb, "\\t");
                else { char c[2] = {*p, '\0'}; buf_append(sb, c); }
            }
            buf_append(sb, "\"");
            break;
        case JSON_ARRAY:
            buf_append(sb, "[");
            if (pretty && val->u.array.count > 0) buf_append(sb, "\n");
            for (size_t i = 0; i < val->u.array.count; i++) {
                if (pretty) buf_indent(sb, depth + 1);
                stringify_value(val->u.array.items[i], sb, pretty, depth + 1);
                if (i + 1 < val->u.array.count) buf_append(sb, ",");
                if (pretty) buf_append(sb, "\n");
            }
            if (pretty && val->u.array.count > 0) buf_indent(sb, depth);
            buf_append(sb, "]");
            break;
        case JSON_OBJECT:
            buf_append(sb, "{");
            if (pretty && val->u.object.count > 0) buf_append(sb, "\n");
            for (size_t i = 0; i < val->u.object.count; i++) {
                if (pretty) buf_indent(sb, depth + 1);
                buf_append(sb, "\"");
                buf_append(sb, val->u.object.pairs[i].key);
                buf_append(sb, "\": ");
                stringify_value(val->u.object.pairs[i].value, sb, pretty, depth + 1);
                if (i + 1 < val->u.object.count) buf_append(sb, ",");
                if (pretty) buf_append(sb, "\n");
            }
            if (pretty && val->u.object.count > 0) buf_indent(sb, depth);
            buf_append(sb, "}");
            break;
    }
}

char *json_stringify(const json_value_t *val, bool pretty) {
    str_buf_t sb;
    sb.cap = 1024;
    sb.len = 0;
    sb.buf = (char *)malloc(sb.cap);
    sb.buf[0] = '\0';
    stringify_value(val, &sb, pretty, 0);
    return sb.buf;
}
