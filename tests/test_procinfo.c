#include "pmx_test.h"
#include "proximight/pmx_net.h"
#include "proximight/pmx_procinfo.h"

#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

int main(void) {
    pmx_net_init();

    /* A loopback listener on an ephemeral port. */
    SOCKET lis = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(lis != INVALID_SOCKET);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    bind(lis, (struct sockaddr *)&a, sizeof(a));
    listen(lis, 1);
    int alen = sizeof(a);
    getsockname(lis, (struct sockaddr *)&a, &alen);
    unsigned short lport = ntohs(a.sin_port);

    /* Connect a client to it and complete the handshake. */
    pmx_socket cli = PMX_INVALID_SOCKET;
    CHECK(pmx_tcp_connect("127.0.0.1", lport, 2000, &cli) == PMX_OK);
    SOCKET srv = accept(lis, NULL, NULL);
    CHECK(srv != INVALID_SOCKET);

    struct sockaddr_in ca;
    int clen = sizeof(ca);
    getsockname((SOCKET)cli, (struct sockaddr *)&ca, &clen);
    unsigned short cport = ntohs(ca.sin_port);

    /* The client socket's local port must resolve back to THIS process. */
    pmx_proc_info info;
    pmx_status st = pmx_procinfo_by_local_port(cport, &info);
    CHECK(st == PMX_OK);
    CHECK_EQ_INT(info.pid, (long)GetCurrentProcessId());
    CHECK(strstr(info.name, "test_procinfo") != NULL);

    /* Precise 4-tuple match should also find us. */
    pmx_proc_info info2;
    st = pmx_procinfo_for_tcp(ntohl(ca.sin_addr.s_addr), cport,
                              ntohl(a.sin_addr.s_addr), lport, &info2);
    CHECK(st == PMX_OK);
    CHECK_EQ_INT(info2.pid, (long)GetCurrentProcessId());

    /* PID -> image path. */
    pmx_proc_info self;
    CHECK(pmx_procinfo_for_pid(GetCurrentProcessId(), &self) == PMX_OK);
    CHECK(self.path[0] != '\0');

    closesocket(srv);
    closesocket(lis);
    pmx_socket_close(cli);
    pmx_net_shutdown();
    return pmx_test_report();
}

#else /* !_WIN32 */

int main(void) {
    /* pmx_procinfo is Windows-only for now; make sure it returns UNSUPPORTED. */
    pmx_proc_info info;
    CHECK(pmx_procinfo_by_local_port(12345, &info) == PMX_ERR_UNSUPPORTED);
    printf("procinfo: Windows-only, skipped detailed checks\n");
    return pmx_test_report();
}

#endif
