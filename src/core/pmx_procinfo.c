#include "proximight/pmx_procinfo.h"

#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

pmx_status pmx_procinfo_for_pid(uint32_t pid, pmx_proc_info *out) {
    if (out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->pid = pid;
    if (pid == 0) {
        pmx_strlcpy(out->name, "System", sizeof(out->name));
        return PMX_OK;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (h == NULL) {
        return PMX_ERR_NOT_FOUND;
    }
    WCHAR wpath[1024];
    DWORD wsz = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    pmx_status st = PMX_ERR_NOT_FOUND;
    if (QueryFullProcessImageNameW(h, 0, wpath, &wsz)) {
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out->path, (int)sizeof(out->path),
                            NULL, NULL);
        const char *slash = strrchr(out->path, '\\');
        pmx_strlcpy(out->name, slash ? slash + 1 : out->path, sizeof(out->name));
        st = PMX_OK;
    }
    CloseHandle(h);
    return st;
}

/* Scan the IPv4 owner-PID TCP table; call `match` for each row. Returns the
 * owning PID of the first matching row, or 0. */
static DWORD find_owner(uint32_t local_addr, pmx_port local_port,
                        uint32_t remote_addr, pmx_port remote_port,
                        bool port_only) {
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                            0) != ERROR_INSUFFICIENT_BUFFER) {
        return 0;
    }
    MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (tbl == NULL) {
        return 0;
    }
    DWORD owner = 0;
    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                            0) == NO_ERROR) {
        for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &tbl->table[i];
            uint16_t lp = ntohs((uint16_t)(r->dwLocalPort & 0xFFFF));
            if (lp != local_port) {
                continue;
            }
            if (!port_only) {
                uint16_t rp = ntohs((uint16_t)(r->dwRemotePort & 0xFFFF));
                if (local_addr != 0 && r->dwLocalAddr != htonl(local_addr)) {
                    continue;
                }
                if (remote_port != 0 && rp != remote_port) {
                    continue;
                }
                if (remote_addr != 0 && r->dwRemoteAddr != htonl(remote_addr)) {
                    continue;
                }
            }
            owner = r->dwOwningPid;
            break;
        }
    }
    free(tbl);
    return owner;
}

pmx_status pmx_procinfo_by_local_port(pmx_port local_port, pmx_proc_info *out) {
    if (out == NULL || local_port == 0) {
        return PMX_ERR_INVALID_ARG;
    }
    DWORD pid = find_owner(0, local_port, 0, 0, true);
    if (pid == 0) {
        return PMX_ERR_NOT_FOUND;
    }
    return pmx_procinfo_for_pid((uint32_t)pid, out);
}

pmx_status pmx_procinfo_for_tcp(uint32_t local_addr, pmx_port local_port,
                                uint32_t remote_addr, pmx_port remote_port,
                                pmx_proc_info *out) {
    if (out == NULL || local_port == 0) {
        return PMX_ERR_INVALID_ARG;
    }
    DWORD pid = find_owner(local_addr, local_port, remote_addr, remote_port, false);
    if (pid == 0) {
        /* Fall back to a port-only match (the tuple can race the table). */
        pid = find_owner(0, local_port, 0, 0, true);
    }
    if (pid == 0) {
        return PMX_ERR_NOT_FOUND;
    }
    return pmx_procinfo_for_pid((uint32_t)pid, out);
}

#else /* !_WIN32 */

pmx_status pmx_procinfo_for_pid(uint32_t pid, pmx_proc_info *out) {
    (void)pid;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    return PMX_ERR_UNSUPPORTED;
}
pmx_status pmx_procinfo_by_local_port(pmx_port local_port, pmx_proc_info *out) {
    (void)local_port;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    return PMX_ERR_UNSUPPORTED;
}
pmx_status pmx_procinfo_for_tcp(uint32_t local_addr, pmx_port local_port,
                                uint32_t remote_addr, pmx_port remote_port,
                                pmx_proc_info *out) {
    (void)local_addr;
    (void)local_port;
    (void)remote_addr;
    (void)remote_port;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    return PMX_ERR_UNSUPPORTED;
}

#endif
