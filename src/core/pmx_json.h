/*
 * pmx_json.h — PRIVATE helpers over cJSON for profile (de)serialization.
 * Not installed / not part of the public API (keeps cJSON out of pmx headers).
 */
#ifndef PMX_INTERNAL_JSON_H
#define PMX_INTERNAL_JSON_H

#include "proximight/pmx_types.h"
#include "cJSON.h"

/* Read helpers with defaults — never crash on a missing/mistyped field. */
const char *pmx_json_str(const cJSON *obj, const char *key, const char *def);
int pmx_json_int(const cJSON *obj, const char *key, int def);
bool pmx_json_bool(const cJSON *obj, const char *key, bool def);

/* Copy a string field into a fixed buffer (bounded). */
void pmx_json_str_into(const cJSON *obj, const char *key, char *dst,
                       size_t dst_size, const char *def);

/* Add a string only when non-empty (keeps files tidy). Returns the added node
 * or NULL. */
cJSON *pmx_json_add_str_if(cJSON *obj, const char *key, const char *val);

#endif /* PMX_INTERNAL_JSON_H */
