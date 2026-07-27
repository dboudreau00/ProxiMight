#include "proximight/pmx_rule.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

void pmx_rule_init(pmx_rule *r) {
    if (r == NULL) {
        return;
    }
    memset(r, 0, sizeof(*r));
    r->enabled = true;
    /* DIRECT, not PROXY. A fresh rule has empty patterns, so it matches EVERY
     * connection; defaulting to PROXY with target_kind == NONE resolved to a
     * verdict of "proxy via nothing" (via_count == 0), which the backend treats
     * as un-routable — blocking all traffic machine-wide under fail-closed, or
     * letting it out direct under fail-open, from the instant "Add rule" is
     * clicked and until the user finishes configuring it. Direct makes a new
     * rule inert (it is appended last, so it behaves like the default rule)
     * until the user deliberately gives it an action. */
    r->action = PMX_ACTION_DIRECT;
    r->target_kind = PMX_TARGET_NONE;
    pmx_strlcpy(r->name, "New rule", sizeof(r->name));
}

const char *pmx_action_str(pmx_action a) {
    switch (a) {
    case PMX_ACTION_DIRECT: return "Direct";
    case PMX_ACTION_PROXY:  return "Proxy";
    case PMX_ACTION_BLOCK:  return "Block";
    case PMX_ACTION__COUNT: break;
    }
    return "?";
}

static char lower_c(char c) { return (char)tolower((unsigned char)c); }

static bool ceq(char a, char b, bool ci) {
    return ci ? (lower_c(a) == lower_c(b)) : (a == b);
}

bool pmx_glob_match(const char *pattern, const char *text, bool ci) {
    if (pattern == NULL || text == NULL) {
        return false;
    }
    const char *p = pattern;
    const char *t = text;
    const char *star_p = NULL;
    const char *star_t = NULL;

    while (*t != '\0') {
        if (*p == '*') {
            star_p = p++;
            star_t = t;
        } else if (*p == '?' || ceq(*p, *t, ci)) {
            p++;
            t++;
        } else if (star_p != NULL) {
            p = star_p + 1;
            t = ++star_t;
        } else {
            return false;
        }
    }
    while (*p == '*') {
        p++;
    }
    return *p == '\0';
}

/* Trim spaces and match `text` against one ';'-separated pattern list. */
bool pmx_glob_list_match(const char *list, const char *text, bool ci) {
    if (list == NULL || list[0] == '\0') {
        return true; /* "any" */
    }
    if (text == NULL) {
        text = "";
    }
    const char *start = list;
    while (*start != '\0') {
        const char *sep = strchr(start, ';');
        size_t seg_len = sep ? (size_t)(sep - start) : strlen(start);

        /* Trim leading/trailing spaces of the segment. */
        const char *s = start;
        const char *e = start + seg_len;
        while (s < e && isspace((unsigned char)*s)) s++;
        while (e > s && isspace((unsigned char)*(e - 1))) e--;

        if (e > s) {
            char pat[PMX_MAX_PATTERN];
            size_t n = (size_t)(e - s);
            if (n >= sizeof(pat)) {
                n = sizeof(pat) - 1;
            }
            memcpy(pat, s, n);
            pat[n] = '\0';
            if (pmx_glob_match(pat, text, ci)) {
                return true;
            }
        }
        if (!sep) {
            break;
        }
        start = sep + 1;
    }
    return false;
}

bool pmx_port_spec_match(const char *spec, pmx_port port) {
    if (spec == NULL || spec[0] == '\0') {
        return true;
    }
    const char *s = spec;
    while (*s != '\0') {
        /* skip spaces/commas */
        while (*s == ' ' || *s == ',') s++;
        if (*s == '\0') break;

        char *end = NULL;
        long a = strtol(s, &end, 10);
        if (end == s) {
            s++;
            continue;
        }
        s = end;
        long b = a;
        /* Tolerate spaces around the dash ("8000 - 8080"). Without this the
         * range was never recognized: the spec silently degraded to the two
         * endpoints only, so a Block rule on "8000 - 8080" let :8050 straight
         * out. validate() accepts the same spacing, so the two agree. */
        while (*s == ' ') s++;
        if (*s == '-') {
            s++;
            while (*s == ' ') s++;
            b = strtol(s, &end, 10);
            if (end == s) {
                b = a;
            } else {
                s = end;
            }
        }
        if (a > b) {
            long tmp = a;
            a = b;
            b = tmp;
        }
        if ((long)port >= a && (long)port <= b) {
            return true;
        }
    }
    return false;
}

pmx_status pmx_port_spec_validate(const char *spec) {
    if (spec == NULL || spec[0] == '\0') {
        return PMX_OK;
    }
    const char *s = spec;
    bool saw_number = false;
    while (*s != '\0') {
        while (*s == ' ' || *s == ',') s++;
        if (*s == '\0') break;
        char *end = NULL;
        long a = strtol(s, &end, 10);
        if (end == s || a < 0 || a > 65535) {
            return PMX_ERR_PARSE;
        }
        s = end;
        while (*s == ' ') s++; /* "8000 - 8080" — must agree with match() */
        if (*s == '-') {
            s++;
            while (*s == ' ') s++;
            long b = strtol(s, &end, 10);
            if (end == s || b < 0 || b > 65535) {
                return PMX_ERR_PARSE;
            }
            s = end;
        }
        saw_number = true;
        while (*s == ' ') s++;
        if (*s != '\0' && *s != ',') {
            return PMX_ERR_PARSE;
        }
    }
    return saw_number ? PMX_OK : PMX_ERR_PARSE;
}

bool pmx_host_pattern_needs_names(const char *pattern) {
    if (pattern == NULL) {
        return false;
    }
    /* A numeric IPv4/IPv6 literal is digits, dots, colons and (for a glob)
     * '*'/'?'. Any LETTER means the segment can only match a name. Hex IPv6
     * literals use letters too, so treat a segment containing ':' as numeric. */
    const char *s = pattern;
    while (*s != '\0') {
        const char *seg = s;
        while (*s != '\0' && *s != ';') {
            s++;
        }
        bool has_alpha = false;
        bool has_colon = false;
        for (const char *c = seg; c < s; c++) {
            if (isalpha((unsigned char)*c)) {
                has_alpha = true;
            } else if (*c == ':') {
                has_colon = true;
            }
        }
        if (has_alpha && !has_colon) {
            return true;
        }
        if (*s == ';') {
            s++;
        }
    }
    return false;
}

bool pmx_rule_matches(const pmx_rule *r, const pmx_conn_query *q) {
    if (r == NULL || q == NULL) {
        return false;
    }
    /* Application: pattern may match either the file name or the full path. */
    if (r->app_pattern[0] != '\0') {
        bool app_ok = pmx_glob_list_match(r->app_pattern, q->app_name, true) ||
                      pmx_glob_list_match(r->app_pattern, q->app_path, true);
        if (!app_ok) {
            return false;
        }
    }
    /* Target host. */
    if (r->host_pattern[0] != '\0') {
        if (!pmx_glob_list_match(r->host_pattern, q->host, true)) {
            return false;
        }
    }
    /* Target port. */
    if (r->port_spec[0] != '\0') {
        if (!pmx_port_spec_match(r->port_spec, q->port)) {
            return false;
        }
    }
    return true;
}
