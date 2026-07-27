/*
 * test_proc.c — the child-process helper.
 *
 * Uses only commands guaranteed to exist and with no side effects, so the test
 * is deterministic and never touches the network or system state. (Driving a
 * real VPN client is emphatically NOT something a test should do.)
 */
#include "pmx_test.h"
#include "proximight/pmx_proc.h"
#include "proximight/pmx_net.h" /* pmx_sleep_ms */
#include "proximight/pmx_log.h"

#include <string.h>
#include <stdio.h>

int main(void) {
    pmx_log_set_level(PMX_LOG_OFF);

#if defined(_WIN32)
    /* Capture stdout. */
    char out[256];
    int code = -1;
    pmx_status st =
        pmx_proc_run("cmd.exe /c echo proximight-ok", 10000, &code, out,
                     sizeof(out));
    CHECK(st == PMX_OK);
    CHECK_EQ_INT(code, 0);
    CHECK(strstr(out, "proximight-ok") != NULL);

    /* Non-zero exit codes are reported, not swallowed. */
    code = -1;
    st = pmx_proc_run("cmd.exe /c exit 3", 10000, &code, NULL, 0);
    CHECK(st == PMX_OK);
    CHECK_EQ_INT(code, 3);

    /* A child that writes MORE than the pipe buffer (4 KB default) must still
     * complete. Regression: we waited for exit before reading, so the child
     * blocked in WriteFile on a full pipe while we blocked in
     * WaitForSingleObject — a deadlock that only broke at the timeout, killing
     * the child mid-operation. `wg show` on a many-peer interface hit exactly
     * this. Emit ~24 KB via a batch loop and require a clean, prompt exit. */
    {
        char big[8192];
        code = -1;
        st = pmx_proc_run(
            "cmd.exe /c \"for /L %i in (1,1,300) do @echo "
            "0123456789012345678901234567890123456789012345678901234567890123456789\"",
            15000, &code, big, sizeof(big));
        CHECK(st == PMX_OK); /* NOT PMX_ERR_TIMEOUT */
        CHECK_EQ_INT(code, 0);
        /* The capture buffer fills; the excess is drained and discarded so the
         * child can finish. What we kept must be NUL-terminated and non-empty. */
        CHECK(strlen(big) > 0);
        CHECK(strlen(big) < sizeof(big));
        CHECK(strstr(big, "0123456789") != NULL);
    }

    /* Coverage (NOT a regression guard — this one passes against the old code
     * too, because with out == NULL no pipe is created and there is no
     * back-pressure to deadlock on). It exists to keep the non-redirected path
     * exercised. Output to NUL so it can't pollute ctest logs. */
    code = -1;
    st = pmx_proc_run("cmd.exe /c \"for /L %i in (1,1,300) do @echo "
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" >NUL",
                      15000, &code, NULL, 0);
    CHECK(st == PMX_OK);
    CHECK_EQ_INT(code, 0);

    /* A hung child must be terminated at the timeout rather than hanging us. */
    code = -1;
    st = pmx_proc_run("cmd.exe /c ping -n 20 127.0.0.1 >NUL", 1200, &code, NULL, 0);
    CHECK(st == PMX_ERR_TIMEOUT);

    /* A missing executable is an error, not a crash. */
    st = pmx_proc_run("definitely-not-a-real-program-xyz.exe", 3000, &code, NULL, 0);
    CHECK(st != PMX_OK);

    /* Long-running child: spawn, observe, kill. */
    pmx_proc *p = NULL;
    st = pmx_proc_spawn("cmd.exe /c ping -n 30 127.0.0.1 >NUL", &p);
    CHECK(st == PMX_OK);
    CHECK(p != NULL);
    if (p != NULL) {
        CHECK(pmx_proc_running(p));
        pmx_proc_kill(p);
        /* Give Windows a moment to reap it. */
        for (int i = 0; i < 50 && pmx_proc_running(p); i++) {
            pmx_sleep_ms(20);
        }
        CHECK(!pmx_proc_running(p));
        pmx_proc_free(p);
    }

    /* Elevation query must not crash and must agree with itself. */
    bool e1 = pmx_proc_is_elevated();
    bool e2 = pmx_proc_is_elevated();
    CHECK(e1 == e2);
#else
    int code = -1;
    CHECK(pmx_proc_run("true", 1000, &code, NULL, 0) == PMX_ERR_UNSUPPORTED);
    printf("proc: Windows-only for now; skipped\n");
#endif

    return pmx_test_report();
}
