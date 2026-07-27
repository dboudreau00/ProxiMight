/*
 * pmx_net.h — minimal cross-platform blocking-socket helpers.
 *
 * Just enough to implement proxy handshakes and the checker: connect with a
 * timeout, read/write exact byte counts, a monotonic millisecond clock. Winsock
 * and BSD sockets are hidden behind this API.
 */
#ifndef PROXIMIGHT_PMX_NET_H
#define PROXIMIGHT_PMX_NET_H

#include "proximight/pmx_error.h"

PMX_BEGIN_DECLS

/* Opaque socket handle. intptr_t holds both a POSIX int fd and a Winsock
 * SOCKET (which is a pointer-sized handle). */
typedef intptr_t pmx_socket;
#define PMX_INVALID_SOCKET ((pmx_socket)-1)

/* Process-wide init/teardown (WSAStartup on Windows). Reference-counted:
 * balanced init/shutdown calls are fine. */
pmx_status pmx_net_init(void);
void pmx_net_shutdown(void);

/* Connect to host:port (host may be a name or IP literal). Applies a total
 * timeout in milliseconds. On success *out holds a connected socket. */
pmx_status pmx_tcp_connect(const char *host, pmx_port port, int timeout_ms,
                           pmx_socket *out);

/* Like pmx_tcp_connect, but binds the local end to `local_port` first
 * (0 = let the OS choose). Useful when the caller must know the connection's
 * source port up front — which is exactly how the redirect layer correlates a
 * connection with the destination it recorded for it. */
pmx_status pmx_tcp_connect_from(const char *host, pmx_port port,
                                pmx_port local_port, int timeout_ms,
                                pmx_socket *out);

/* Send the whole buffer or fail. */
pmx_status pmx_send_all(pmx_socket s, const void *buf, size_t len);

/* Receive exactly `len` bytes (loops), honoring a per-call timeout. */
pmx_status pmx_recv_exact(pmx_socket s, void *buf, size_t len, int timeout_ms);

/* Receive up to `cap` bytes; *received holds the count (may be < cap). */
pmx_status pmx_recv_some(pmx_socket s, void *buf, size_t cap, size_t *received,
                         int timeout_ms);

/* Listen on bind_host:port for TCP. port 0 picks an ephemeral port;
 * *actual_port (optional) receives the port actually bound. */
pmx_status pmx_tcp_listen(const char *bind_host, pmx_port port, pmx_socket *out,
                          pmx_port *actual_port);

/* Block until a client connects. *peer_port (optional) receives the client's
 * source port — used to correlate a redirected connection with the destination
 * the redirect layer recorded for it. Returns PMX_ERR_NET once the listener is
 * closed, which is how the accept loop is unblocked on shutdown. */
pmx_status pmx_tcp_accept(pmx_socket listener, pmx_socket *out,
                          pmx_port *peer_port);

/* Wait until either socket is readable. Returns a bitmask (1 = a, 2 = b),
 * 0 on timeout, -1 on error. */
int pmx_wait_two(pmx_socket a, pmx_socket b, int timeout_ms);

void pmx_socket_close(pmx_socket s);

/* Monotonic clock in milliseconds; only differences are meaningful. */
uint64_t pmx_now_ms(void);

/* Sleep the calling thread. */
void pmx_sleep_ms(int ms);

PMX_END_DECLS

#endif /* PROXIMIGHT_PMX_NET_H */
