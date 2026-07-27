#include "proximight/pmx_proc.h"
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)

#include <windows.h>

struct pmx_proc {
    HANDLE process;
    HANDLE thread;
    int exit_code;
};

/* CreateProcessA mutates its command line argument, so hand it a copy. */
static char *dup_cmdline(const char *cmdline) {
    size_t n = strlen(cmdline) + 1;
    char *c = (char *)malloc(n);
    if (c != NULL) {
        memcpy(c, cmdline, n);
    }
    return c;
}

/* Read everything currently readable from `rd`, appending into out/total. Once
 * the capture buffer is full the rest is read into a sink and discarded — the
 * point is to never leave the child blocked on a full pipe (see pmx_proc_run).
 * Never blocks: it only reads what PeekNamedPipe says is already available. */
static void drain_pipe(HANDLE rd, char *out, size_t out_cap, size_t *total) {
    char sink[512];
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) || avail == 0) {
            return;
        }
        char *dst;
        DWORD want;
        if (out != NULL && *total + 1 < out_cap) {
            dst = out + *total;
            want = (DWORD)(out_cap - 1 - *total);
        } else {
            dst = sink;
            want = (DWORD)sizeof(sink);
        }
        if (avail < want) {
            want = avail;
        }
        DWORD got = 0;
        if (!ReadFile(rd, dst, want, &got, NULL) || got == 0) {
            return;
        }
        if (dst != sink) {
            *total += got;
        }
    }
}

pmx_status pmx_proc_run(const char *cmdline, int timeout_ms, int *exit_code,
                        char *out, size_t out_cap) {
    if (cmdline == NULL || cmdline[0] == '\0') {
        return PMX_ERR_INVALID_ARG;
    }
    if (out != NULL && out_cap > 0) {
        out[0] = '\0';
    }
    if (exit_code != NULL) {
        *exit_code = -1;
    }

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;


    HANDLE rd = NULL, wr = NULL;
    bool capture = (out != NULL && out_cap > 1);
    if (capture && !CreatePipe(&rd, &wr, &sa, 0)) {
        return PMX_ERR_STATE;
    }
    if (capture) {
        /* Our read end must not be inherited by the child. */
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    }

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (capture) {
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = wr;
        si.hStdError = wr;
        si.hStdInput = NULL;
        si.wShowWindow = SW_HIDE;
    } else {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    char *cmd = dup_cmdline(cmdline);
    if (cmd == NULL) {
        if (capture) {
            CloseHandle(rd);
            CloseHandle(wr);
        }
        return PMX_ERR_NO_MEMORY;
    }

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, capture ? TRUE : FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    if (capture) {
        CloseHandle(wr); /* so ReadFile sees EOF when the child exits */
    }
    if (!ok) {
        DWORD e = GetLastError();
        if (capture) {
            CloseHandle(rd);
        }
        if (e == ERROR_ELEVATION_REQUIRED) {
            return PMX_ERR_PERMISSION;
        }
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
            return PMX_ERR_NOT_FOUND;
        }
        return PMX_ERR_STATE;
    }

    /* Drain the pipe WHILE waiting for the child to exit.
     *
     * Waiting first and reading afterwards deadlocks: the pipe buffer is finite
     * (4 KB by default), so a child that writes more than that blocks forever in
     * WriteFile while we block in WaitForSingleObject. It only ended at the
     * timeout, and the child was then killed mid-operation — e.g. `wg show` on a
     * many-peer interface reported the bogus "usually needs Administrator", and
     * a chatty `wireguard.exe /installtunnelservice` was terminated during a
     * privileged service install. Once the capture buffer is full we keep
     * draining into a sink, so the child is never blocked by us. */
    ULONGLONG start_ms = GetTickCount64();
    size_t total = 0;
    pmx_status st = PMX_OK;
    for (;;) {
        if (capture) {
            drain_pipe(rd, out, out_cap, &total);
        }
        if (WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) {
            break;
        }
        if (timeout_ms > 0 &&
            (GetTickCount64() - start_ms) >= (ULONGLONG)timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            st = PMX_ERR_TIMEOUT;
            break;
        }
    }

    if (capture) {
        drain_pipe(rd, out, out_cap, &total); /* whatever landed before exit */
        out[total] = '\0';
        CloseHandle(rd);
    }

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    if (exit_code != NULL) {
        *exit_code = (int)code;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return st;
}

pmx_status pmx_proc_spawn(const char *cmdline, pmx_proc **out) {
    if (cmdline == NULL || out == NULL) {
        return PMX_ERR_INVALID_ARG;
    }
    *out = NULL;

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    char *cmd = dup_cmdline(cmdline);
    if (cmd == NULL) {
        return PMX_ERR_NO_MEMORY;
    }
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
                             NULL, &si, &pi);
    free(cmd);
    if (!ok) {
        DWORD e = GetLastError();
        if (e == ERROR_ELEVATION_REQUIRED) {
            return PMX_ERR_PERMISSION;
        }
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
            return PMX_ERR_NOT_FOUND;
        }
        return PMX_ERR_STATE;
    }

    pmx_proc *p = (pmx_proc *)calloc(1, sizeof(*p));
    if (p == NULL) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return PMX_ERR_NO_MEMORY;
    }
    p->process = pi.hProcess;
    p->thread = pi.hThread;
    p->exit_code = -1;
    *out = p;
    return PMX_OK;
}

bool pmx_proc_running(pmx_proc *p) {
    if (p == NULL || p->process == NULL) {
        return false;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(p->process, &code)) {
        return false;
    }
    if (code == STILL_ACTIVE) {
        return true;
    }
    p->exit_code = (int)code;
    return false;
}

int pmx_proc_exit_code(pmx_proc *p) {
    if (p == NULL) {
        return -1;
    }
    pmx_proc_running(p); /* refresh */
    return p->exit_code;
}

void pmx_proc_kill(pmx_proc *p) {
    if (p == NULL || p->process == NULL) {
        return;
    }
    if (pmx_proc_running(p)) {
        TerminateProcess(p->process, 1);
        WaitForSingleObject(p->process, 3000);
    }
}

void pmx_proc_free(pmx_proc *p) {
    if (p == NULL) {
        return;
    }
    pmx_proc_kill(p);
    if (p->thread != NULL) {
        CloseHandle(p->thread);
    }
    if (p->process != NULL) {
        CloseHandle(p->process);
    }
    free(p);
}

bool pmx_proc_is_elevated(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elev;
    DWORD sz = sizeof(elev);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz)) {
        elevated = (elev.TokenIsElevated != 0);
    }
    CloseHandle(token);
    return elevated;
}

#else /* POSIX — not needed until the macOS backend lands. */

#include <unistd.h>

pmx_status pmx_proc_run(const char *cmdline, int timeout_ms, int *exit_code,
                        char *out, size_t out_cap) {
    (void)cmdline;
    (void)timeout_ms;
    if (exit_code != NULL) {
        *exit_code = -1;
    }
    if (out != NULL && out_cap > 0) {
        out[0] = '\0';
    }
    return PMX_ERR_UNSUPPORTED;
}
pmx_status pmx_proc_spawn(const char *cmdline, pmx_proc **out) {
    (void)cmdline;
    if (out != NULL) {
        *out = NULL;
    }
    return PMX_ERR_UNSUPPORTED;
}
bool pmx_proc_running(pmx_proc *p) { (void)p; return false; }
int pmx_proc_exit_code(pmx_proc *p) { (void)p; return -1; }
void pmx_proc_kill(pmx_proc *p) { (void)p; }
void pmx_proc_free(pmx_proc *p) { (void)p; }
bool pmx_proc_is_elevated(void) { return geteuid() == 0; }

#endif
