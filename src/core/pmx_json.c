#include "pmx_json.h"

#include <string.h>

const char *pmx_json_str(const cJSON *obj, const char *key, const char *def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(it) && it->valuestring != NULL) {
        return it->valuestring;
    }
    return def;
}

int pmx_json_int(const cJSON *obj, const char *key, int def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(it)) {
        return it->valueint;
    }
    return def;
}

bool pmx_json_bool(const cJSON *obj, const char *key, bool def) {
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsBool(it)) {
        return cJSON_IsTrue(it) ? true : false;
    }
    return def;
}

void pmx_json_str_into(const cJSON *obj, const char *key, char *dst,
                       size_t dst_size, const char *def) {
    pmx_strlcpy(dst, pmx_json_str(obj, key, def), dst_size);
}

cJSON *pmx_json_add_str_if(cJSON *obj, const char *key, const char *val) {
    if (val == NULL || val[0] == '\0') {
        return NULL;
    }
    return cJSON_AddStringToObject(obj, key, val);
}
