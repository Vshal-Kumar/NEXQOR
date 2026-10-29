/*
 * securecomm/src/config/json_parser.h
 *
 * Lightweight, safe, standalone JSON parser and serializer in pure C.
 */

#ifndef SECURECOMM_JSON_PARSER_H
#define SECURECOMM_JSON_PARSER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JSON_NULL = 0,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value_s json_value_t;

typedef struct {
    char *key;
    json_value_t *value;
} json_pair_t;

struct json_value_s {
    json_type_t type;
    union {
        bool boolean;
        double number;
        char *string;
        struct {
            json_value_t **items;
            size_t count;
        } array;
        struct {
            json_pair_t *pairs;
            size_t count;
        } object;
    } u;
};

/* Parse a null-terminated JSON string */
json_value_t *json_parse(const char *text, char *out_error, size_t error_max);

/* Free allocated JSON value tree */
void json_free(json_value_t *val);

/* Property Accessors */
json_value_t *json_object_get(const json_value_t *obj, const char *key);
const char   *json_get_string(const json_value_t *val, const char *default_val);
int64_t       json_get_int(const json_value_t *val, int64_t default_val);
double        json_get_double(const json_value_t *val, double default_val);
bool          json_get_bool(const json_value_t *val, bool default_val);

/* Builders for Serializing */
json_value_t *json_create_object(void);
json_value_t *json_create_array(void);
json_value_t *json_create_string(const char *str);
json_value_t *json_create_number(double num);
json_value_t *json_create_bool(bool b);
json_value_t *json_create_null(void);

void json_object_set(json_value_t *obj, const char *key, json_value_t *val);
void json_array_append(json_value_t *arr, json_value_t *val);

/* Serialize to formatted string (caller must free returned string) */
char *json_stringify(const json_value_t *val, bool pretty);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_JSON_PARSER_H */
