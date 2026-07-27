/*
 * pmx_protect.h — at-rest data protection (seal/unseal opaque blobs).
 *
 * This is the choke point for encrypting sensitive data before it touches disk
 * (today: the profile, which carries proxy credentials — see pmx_profile.c).
 *
 * The provider is platform crypto — never hand-rolled:
 *   - Windows: DPAPI (CryptProtectData / CryptUnprotectData), current-user
 *     scope. The ciphertext is bound to the logged-in Windows user on this
 *     machine; another user, or the same file on another machine, cannot
 *     decrypt it. No password prompt is involved.
 *   - Other platforms: no provider is wired in yet, so seal/unseal return
 *     PMX_ERR_UNSUPPORTED and pmx_protect_available() is false. Callers must
 *     treat that as "cannot encrypt here" and act accordingly (pmx_profile
 *     falls back to a clearly-logged plaintext write).
 *
 * Threat model, stated honestly: this protects data at rest against another
 * user account and against the file being copied off the machine. It does NOT
 * protect against malware running as the same user while you are logged in —
 * that code can call CryptUnprotectData too. Stronger, password-derived
 * encryption (a KDF unlocked at launch) can layer on top of this same seam.
 */
#ifndef PROXIMIGHT_PMX_PROTECT_H
#define PROXIMIGHT_PMX_PROTECT_H

#include "proximight/pmx_types.h"
#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

/* True if this build has a real at-rest crypto provider (DPAPI on Windows). */
bool pmx_protect_available(void);

/* Seal `len` bytes of `plaintext` into a freshly-allocated opaque blob
 * (*out, *out_len), which the caller frees with pmx_protect_free. The blob is
 * self-describing to the provider (it carries its own salt/MAC); callers add
 * their own framing. `len` may be 0. Returns PMX_ERR_UNSUPPORTED when no
 * provider is available, PMX_ERR_CRYPTO if the provider fails. */
pmx_status pmx_protect_seal(const void *plaintext, size_t len,
                            void **out, size_t *out_len);

/* Reverse of pmx_protect_seal. Fails with PMX_ERR_CRYPTO if the blob was not
 * produced for this user/machine or was tampered with (never crashes on
 * arbitrary input). The recovered plaintext is in *out/*out_len (freed with
 * pmx_protect_free). */
pmx_status pmx_protect_unseal(const void *blob, size_t len,
                              void **out, size_t *out_len);

/* Free a buffer returned by seal/unseal. Safe on NULL. */
void pmx_protect_free(void *p);

/* Best-effort scrub of `n` bytes at `p` that the optimizer may not elide.
 * Used to wipe recovered plaintext (proxy passwords) once it is no longer
 * needed. Safe on NULL. */
void pmx_protect_wipe(void *p, size_t n);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_PROTECT_H */
