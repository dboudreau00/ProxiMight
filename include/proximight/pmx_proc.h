/*
 * pmx_proc.h — run an external program.
 *
 * ProxiMight deliberately does not reimplement things other people's signed,
 * audited binaries already do (tunnel crypto, in particular). It drives them.
 * That makes launching a child process a first-class, and security-relevant,
 * operation:
 *
 *   - Commands are built from a validated config path, never from unvalidated
 *     remote input.
 *   - Captured output goes to the log at debug level; callers must not pass
 *     credentials on the command line (both VPN clients read secrets from the
 *     config file, which is exactly why we hand them a path instead).
 */
#ifndef PROXIMIGHT_PMX_PROC_H
#define PROXIMIGHT_PMX_PROC_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

/* Run `cmdline` to completion (or until timeout_ms elapses, after which the
 * child is terminated). `out`/`out_cap` optionally receive the captured
 * stdout+stderr, NUL-terminated. *exit_code receives the process exit code. */
pmx_status pmx_proc_run(const char *cmdline, int timeout_ms, int *exit_code,
                        char *out, size_t out_cap);

/* A long-running child (an OpenVPN tunnel, for instance). */
typedef struct pmx_proc pmx_proc;

pmx_status pmx_proc_spawn(const char *cmdline, pmx_proc **out);
bool pmx_proc_running(pmx_proc *p);
/* Exit code once it has stopped; -1 while still running. */
int pmx_proc_exit_code(pmx_proc *p);
/* Terminate if still running. */
void pmx_proc_kill(pmx_proc *p);
/* Kill (if needed) and release the handle. */
void pmx_proc_free(pmx_proc *p);

/* True if this process has Administrator/root rights — some operations
 * (installing a WireGuard tunnel service) require it. */
bool pmx_proc_is_elevated(void);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_PROC_H */
