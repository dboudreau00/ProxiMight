/*
 * pmx_protect.c — at-rest data protection.
 *
 * Windows: DPAPI (current-user scope). Elsewhere: no provider (yet).
 * See pmx_protect.h for the threat model and rationale.
 */
#include "proximight/pmx_protect.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h> /* CryptProtectData / CryptUnprotectData; links Crypt32 */

/*
 * Fixed, app-specific secondary entropy mixed into every seal/unseal.
 *
 * This is NOT a secret — it ships inside the binary. Its only job is to
 * namespace ProxiMight's DPAPI blobs so another program's CryptUnprotectData
 * call (running as the same user) cannot trivially decrypt them, and so a blob
 * from a different app can never be mistaken for ours. It must therefore stay
 * byte-for-byte constant forever: change it and every existing profile becomes
 * undecryptable.
 */
static const BYTE PMX_DPAPI_ENTROPY[16] = {
    0x50, 0x6D, 0x78, 0x21, 0x44, 0x50, 0x41, 0x50,
    0x49, 0x2D, 0x76, 0x31, 0x9A, 0x37, 0xC4, 0xE1,
};

bool pmx_protect_available(void) { return true; }

pmx_status pmx_protect_seal(const void *plaintext, size_t len,
                            void **out, size_t *out_len) {
    if (out == NULL || out_len == NULL || (plaintext == NULL && len != 0)) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = NULL;
    *out_len = 0;
    if (len > 0xFFFFFFFFu) { /* DATA_BLOB.cbData is a DWORD */
        return PMX_ERR_INVALID_ARG;
    }

    DATA_BLOB in;
    in.pbData = (BYTE *)plaintext;
    in.cbData = (DWORD)len;
    DATA_BLOB entropy;
    entropy.pbData = (BYTE *)PMX_DPAPI_ENTROPY;
    entropy.cbData = (DWORD)sizeof(PMX_DPAPI_ENTROPY);
    DATA_BLOB sealed;
    memset(&sealed, 0, sizeof(sealed));

    if (!CryptProtectData(&in, L"ProxiMight profile", &entropy, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &sealed)) {
        return PMX_ERR_CRYPTO;
    }

    void *copy = malloc(sealed.cbData ? sealed.cbData : 1u);
    if (copy == NULL) {
        SecureZeroMemory(sealed.pbData, sealed.cbData);
        LocalFree(sealed.pbData);
        return PMX_ERR_NO_MEMORY;
    }
    memcpy(copy, sealed.pbData, sealed.cbData);
    *out = copy;
    *out_len = sealed.cbData;

    /* The output is ciphertext, but scrub the DPAPI buffer anyway. */
    SecureZeroMemory(sealed.pbData, sealed.cbData);
    LocalFree(sealed.pbData);
    return PMX_OK;
}

pmx_status pmx_protect_unseal(const void *blob, size_t len,
                              void **out, size_t *out_len) {
    if (out == NULL || out_len == NULL || (blob == NULL && len != 0)) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = NULL;
    *out_len = 0;
    if (len > 0xFFFFFFFFu) {
        return PMX_ERR_INVALID_ARG;
    }

    DATA_BLOB in;
    in.pbData = (BYTE *)blob;
    in.cbData = (DWORD)len;
    DATA_BLOB entropy;
    entropy.pbData = (BYTE *)PMX_DPAPI_ENTROPY;
    entropy.cbData = (DWORD)sizeof(PMX_DPAPI_ENTROPY);
    DATA_BLOB plain;
    memset(&plain, 0, sizeof(plain));

    if (!CryptUnprotectData(&in, NULL, &entropy, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        return PMX_ERR_CRYPTO;
    }

    void *copy = malloc(plain.cbData ? plain.cbData : 1u);
    if (copy == NULL) {
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
        return PMX_ERR_NO_MEMORY;
    }
    memcpy(copy, plain.pbData, plain.cbData);
    *out = copy;
    *out_len = plain.cbData;

    /* Recovered plaintext — scrub the provider's copy before freeing it. */
    SecureZeroMemory(plain.pbData, plain.cbData);
    LocalFree(plain.pbData);
    return PMX_OK;
}

void pmx_protect_wipe(void *p, size_t n) {
    if (p != NULL) {
        SecureZeroMemory(p, n);
    }
}

#else /* !_WIN32 — no at-rest crypto provider wired in yet */

bool pmx_protect_available(void) { return false; }

pmx_status pmx_protect_seal(const void *plaintext, size_t len,
                            void **out, size_t *out_len) {
    (void)plaintext;
    (void)len;
    if (out != NULL) *out = NULL;
    if (out_len != NULL) *out_len = 0;
    return PMX_ERR_UNSUPPORTED;
}

pmx_status pmx_protect_unseal(const void *blob, size_t len,
                              void **out, size_t *out_len) {
    (void)blob;
    (void)len;
    if (out != NULL) *out = NULL;
    if (out_len != NULL) *out_len = 0;
    return PMX_ERR_UNSUPPORTED;
}

void pmx_protect_wipe(void *p, size_t n) {
    /* volatile pointer so the store isn't optimized away. */
    volatile unsigned char *v = (volatile unsigned char *)p;
    if (v == NULL) {
        return;
    }
    while (n-- > 0) {
        *v++ = 0;
    }
}

#endif

void pmx_protect_free(void *p) { free(p); }
