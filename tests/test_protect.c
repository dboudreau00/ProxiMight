/*
 * test_protect.c — at-rest sealing (pmx_protect) and the sealed profile file.
 *
 * On a platform with a provider (DPAPI on Windows) this proves the seal/unseal
 * round-trip, that sealing hides the plaintext, that tampering is rejected, and
 * that a saved profile is sealed on disk with no cleartext password — including
 * the transparent migration of a legacy plaintext profile. On a platform with
 * no provider the crypto asserts are skipped (and seal/unseal must say so).
 */
#include "pmx_test.h"
#include "proximight/pmx_protect.h"
#include "proximight/pmx_profile.h"
#include "proximight/pmx_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The unique proxy password we hunt for (or prove absent) in the raw file. */
#define SECRET "PMX_UNIQUE_SECRET_9f3a1c"

/* Does the byte range [hay, hay+haylen) contain the bytes of NUL-terminated
 * `needle`? A plain strstr would stop at the first NUL in a binary file. */
static int bytes_contain(const unsigned char *hay, size_t haylen,
                         const char *needle) {
    size_t n = strlen(needle);
    if (n == 0 || haylen < n) {
        return 0;
    }
    for (size_t i = 0; i + n <= haylen; i++) {
        if (memcmp(hay + i, needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}

static unsigned char *read_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    *out_len = rd;
    return buf;
}

static void roundtrip(const unsigned char *msg, size_t len, const char *what) {
    void *sealed = NULL;
    size_t sealed_len = 0;
    CHECK(pmx_protect_seal(msg, len, &sealed, &sealed_len) == PMX_OK);
    CHECK(sealed != NULL);
    /* Sealed form must not equal the plaintext, and (for non-empty) must not
     * contain it verbatim. */
    if (len > 0) {
        int identical = (sealed_len == len) &&
                        (memcmp(sealed, msg, len) == 0);
        CHECK(!identical);
    }

    void *plain = NULL;
    size_t plain_len = 0;
    CHECK(pmx_protect_unseal(sealed, sealed_len, &plain, &plain_len) == PMX_OK);
    CHECK(plain_len == len);
    if (len > 0) {
        CHECK(memcmp(plain, msg, len) == 0);
    }
    (void)what;

    pmx_protect_free(sealed);
    pmx_protect_free(plain);
}

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

    if (!pmx_protect_available()) {
        /* No provider wired in: seal/unseal must fail cleanly, not crash. */
        void *o = NULL;
        size_t ol = 123;
        CHECK(pmx_protect_seal("x", 1, &o, &ol) == PMX_ERR_UNSUPPORTED);
        CHECK(o == NULL);
        CHECK(ol == 0);
        printf("pmx_protect has no provider here; crypto asserts skipped\n");
        return pmx_test_report();
    }

    /* ---- seal/unseal round-trips ------------------------------------- */
    roundtrip((const unsigned char *)"hello proxy", 11, "ascii");
    roundtrip((const unsigned char *)"", 0, "empty");
    {
        unsigned char withnul[8] = {'a', 0, 'b', 0, 0, 'c', 'd', 0};
        roundtrip(withnul, sizeof(withnul), "embedded-nul");
    }
    {
        unsigned char big[5000];
        for (size_t i = 0; i < sizeof(big); i++) {
            big[i] = (unsigned char)(i * 31u + 7u);
        }
        roundtrip(big, sizeof(big), "large");
    }

    /* ---- tampering is rejected --------------------------------------- */
    {
        void *sealed = NULL;
        size_t sealed_len = 0;
        CHECK(pmx_protect_seal((const unsigned char *)SECRET, strlen(SECRET),
                               &sealed, &sealed_len) == PMX_OK);
        /* The plaintext secret must not appear in the sealed bytes. */
        CHECK(!bytes_contain((const unsigned char *)sealed, sealed_len, SECRET));

        /* Flip a byte late in the blob (past any header) and expect failure. */
        unsigned char *copy = (unsigned char *)malloc(sealed_len);
        CHECK(copy != NULL);
        if (copy != NULL) {
            memcpy(copy, sealed, sealed_len);
            copy[sealed_len - 1] ^= 0xFF;
            void *plain = NULL;
            size_t plain_len = 0;
            CHECK(pmx_protect_unseal(copy, sealed_len, &plain, &plain_len) !=
                  PMX_OK);
            CHECK(plain == NULL);
            free(copy);
        }
        pmx_protect_free(sealed);
    }

    /* ---- garbage input fails cleanly --------------------------------- */
    {
        unsigned char junk[64];
        memset(junk, 0xA5, sizeof(junk));
        void *plain = NULL;
        size_t plain_len = 0;
        CHECK(pmx_protect_unseal(junk, sizeof(junk), &plain, &plain_len) !=
              PMX_OK);
        CHECK(plain == NULL);
    }

    /* ---- wipe zeros memory ------------------------------------------- */
    {
        unsigned char secret[16];
        memset(secret, 0x5A, sizeof(secret));
        pmx_protect_wipe(secret, sizeof(secret));
        int all_zero = 1;
        for (size_t i = 0; i < sizeof(secret); i++) {
            if (secret[i] != 0) {
                all_zero = 0;
            }
        }
        CHECK(all_zero);
    }

    /* ---- a saved profile is sealed on disk, with no cleartext password  */
    const char *path = "test_protect_profile.pmxprofile";
    remove(path);
    {
        pmx_profile a;
        pmx_profile_seed_defaults(&a);
        pmx_proxy *p = pmx_profile_add_proxy(&a);
        CHECK(p != NULL);
        pmx_strlcpy(p->host, "proxy.example.net", sizeof(p->host));
        p->port = 1080;
        p->use_auth = true;
        pmx_strlcpy(p->username, "alice", sizeof(p->username));
        pmx_strlcpy(p->password, SECRET, sizeof(p->password));
        pmx_id pid = p->id;

        CHECK(pmx_profile_save(&a, path) == PMX_OK);

        size_t flen = 0;
        unsigned char *raw = read_all(path, &flen);
        CHECK(raw != NULL);
        if (raw != NULL) {
            /* Sealed container magic present, and the secret nowhere in it. */
            CHECK(flen >= 8 && memcmp(raw, "PMXSEAL", 7) == 0);
            CHECK(!bytes_contain(raw, flen, SECRET));
            CHECK(!bytes_contain(raw, flen, "alice"));
            free(raw);
        }

        /* Round-trips back through a real load. */
        pmx_profile b;
        pmx_profile_init(&b);
        CHECK(pmx_profile_load(&b, path) == PMX_OK);
        const pmx_proxy *bp = pmx_profile_find_proxy_c(&b, pid);
        CHECK(bp != NULL);
        if (bp != NULL) {
            CHECK_STR_EQ(bp->password, SECRET);
            CHECK_STR_EQ(bp->username, "alice");
        }
        pmx_profile_free(&a);
        pmx_profile_free(&b);
    }
    remove(path);

    /* ---- a corrupt sealed container is rejected, never half-loaded -----
     * The engine keys its "don't clobber the user's profile" guard off this
     * result, so it matters that a damaged file fails loudly rather than
     * looking like an empty or partly-parsed profile. */
    {
        pmx_profile a;
        pmx_profile_seed_defaults(&a);
        CHECK(pmx_profile_save(&a, path) == PMX_OK);
        size_t flen = 0;
        unsigned char *raw = read_all(path, &flen);
        CHECK(raw != NULL && flen > 20);
        if (raw != NULL) {
            /* (a) declared payload length longer than the file */
            unsigned char *bad = (unsigned char *)malloc(flen);
            CHECK(bad != NULL);
            if (bad != NULL) {
                memcpy(bad, raw, flen);
                bad[12] = 0xFF; bad[13] = 0xFF; bad[14] = 0xFF; bad[15] = 0x7F;
                FILE *f = fopen(path, "wb");
                if (f != NULL) { fwrite(bad, 1, flen, f); fclose(f); }
                pmx_profile b;
                pmx_profile_init(&b);
                CHECK(pmx_profile_load(&b, path) == PMX_ERR_PARSE);
                pmx_profile_free(&b);

                /* (b) unknown container version */
                memcpy(bad, raw, flen);
                bad[8] = 0x63; /* version 99 */
                f = fopen(path, "wb");
                if (f != NULL) { fwrite(bad, 1, flen, f); fclose(f); }
                pmx_profile c2;
                pmx_profile_init(&c2);
                CHECK(pmx_profile_load(&c2, path) == PMX_ERR_PARSE);
                pmx_profile_free(&c2);

                /* (c) intact header, corrupt ciphertext -> decrypt must fail,
                 *     and must be reported as CRYPTO, not silently empty. */
                memcpy(bad, raw, flen);
                bad[flen - 1] ^= 0xFF;
                f = fopen(path, "wb");
                if (f != NULL) { fwrite(bad, 1, flen, f); fclose(f); }
                pmx_profile d;
                pmx_profile_init(&d);
                CHECK(pmx_profile_load(&d, path) == PMX_ERR_CRYPTO);
                pmx_profile_free(&d);
                free(bad);
            }
            free(raw);
        }
        pmx_profile_free(&a);
    }
    remove(path);

    /* ---- a legacy plaintext profile is migrated to sealed on load ----- */
    {
        pmx_profile a;
        pmx_profile_seed_defaults(&a);
        pmx_proxy *p = pmx_profile_add_proxy(&a);
        CHECK(p != NULL);
        pmx_strlcpy(p->password, SECRET, sizeof(p->password));

        char *json = NULL;
        CHECK(pmx_profile_to_json(&a, &json) == PMX_OK);
        /* Write it as a legacy plaintext file (bypassing the sealing save). */
        FILE *f = fopen(path, "wb");
        CHECK(f != NULL);
        if (f != NULL) {
            fwrite(json, 1, strlen(json), f);
            fclose(f);
        }
        pmx_profile_string_free(json);

        /* On disk it is plaintext right now. */
        size_t flen = 0;
        unsigned char *raw = read_all(path, &flen);
        CHECK(raw != NULL && bytes_contain(raw, flen, SECRET));
        free(raw);

        /* Loading it parses AND rewrites it sealed. */
        pmx_profile b;
        pmx_profile_init(&b);
        CHECK(pmx_profile_load(&b, path) == PMX_OK);
        CHECK(b.proxy_count == a.proxy_count);

        raw = read_all(path, &flen);
        CHECK(raw != NULL);
        if (raw != NULL) {
            CHECK(flen >= 8 && memcmp(raw, "PMXSEAL", 7) == 0);
            CHECK(!bytes_contain(raw, flen, SECRET));
            free(raw);
        }
        pmx_profile_free(&a);
        pmx_profile_free(&b);
    }
    remove(path);

    return pmx_test_report();
}
