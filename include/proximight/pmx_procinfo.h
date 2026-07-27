/*
 * pmx_procinfo.h — attribute a TCP connection to the owning OS process.
 *
 * This is the piece a per-application proxifier needs to answer "which app
 * opened this connection?". On Windows it reads the system TCP table
 * (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL) and resolves the PID to an
 * image name/path. The WinDivert backend uses it to build a pmx_flow from an
 * intercepted packet's local endpoint.
 *
 * Implemented for Windows (IPv4). Other platforms return PMX_ERR_UNSUPPORTED.
 */
#ifndef PROXIMIGHT_PMX_PROCINFO_H
#define PROXIMIGHT_PMX_PROCINFO_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

typedef struct pmx_proc_info {
    uint32_t pid;
    char name[PMX_MAX_NAME]; /* image base name, e.g. "chrome.exe" */
    char path[PMX_MAX_PATH]; /* full image path                    */
} pmx_proc_info;

/* Resolve a PID to its image name/path. */
pmx_status pmx_procinfo_for_pid(uint32_t pid, pmx_proc_info *out);

/* Find the process owning the TCP connection with this local port (first
 * match). Addresses/ports are host byte order. Convenient for tests and for the
 * common case where the local port uniquely identifies a client socket. */
pmx_status pmx_procinfo_by_local_port(pmx_port local_port, pmx_proc_info *out);

/* Precise 4-tuple match (host byte order; pass 0 for a field to ignore it).
 * Preferred by the redirection backend, which knows the full tuple. */
pmx_status pmx_procinfo_for_tcp(uint32_t local_addr, pmx_port local_port,
                                uint32_t remote_addr, pmx_port remote_port,
                                pmx_proc_info *out);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_PROCINFO_H */
