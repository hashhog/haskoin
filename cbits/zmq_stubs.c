/* ZeroMQ C API stubs for Haskell.
 *
 * Wraps the publisher half of libzmq's PUB/SUB pattern so Haskoin.Rpc can
 * push 3-frame Bitcoin-Core-compatible messages to a real network socket
 * via the System.ZMQ4 Haskell wrapper.
 *
 * We deliberately do NOT include <zmq.h>: the Debian package providing the
 * shared library (libzmq5) does not always carry the dev headers
 * (libzmq3-dev) on the target machine, and the public ABI is stable enough
 * to declare here. The forward declarations below mirror the prototypes
 * from https://api.zeromq.org and the ZMQ 4.x ABI contract.
 *
 * Linkage: haskoin.cabal adds [:libzmq.so.5] to [extra-libraries], and
 * GHC's runtime linker resolves these symbols against libzmq.so.5 at
 * process startup.
 *
 * Mirrors camlcoin/lib/zmq_stubs.c (commit 23c02ac) — same direct-ABI
 * pattern, adapted for the Haskell FFI shape (plain C entry points,
 * no GC integration; the Haskell side handles ForeignPtr lifetimes).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* ---------- libzmq ABI forward declarations ----------------------------- */
/* These match the ZMQ 4.x C API. Symbols are looked up at link time
 * against libzmq.so.5 via [:libzmq.so.5] in haskoin.cabal. */

extern void *zmq_ctx_new(void);
extern int   zmq_ctx_term(void *context);
extern void *zmq_socket(void *context, int type);
extern int   zmq_close(void *socket);
extern int   zmq_bind(void *socket, const char *endpoint);
extern int   zmq_connect(void *socket, const char *endpoint);
extern int   zmq_setsockopt(void *socket, int option_name,
                            const void *option_value, size_t option_len);
extern int   zmq_send(void *socket, const void *buf, size_t len, int flags);
extern int   zmq_recv(void *socket, void *buf, size_t len, int flags);
extern int   zmq_msg_init(void *msg);
extern int   zmq_msg_init_size(void *msg, size_t size);
extern int   zmq_msg_close(void *msg);
extern void *zmq_msg_data(void *msg);
extern size_t zmq_msg_size(void *msg);
extern int   zmq_msg_recv(void *msg, void *socket, int flags);
extern int   zmq_msg_more(void *msg);
extern int   zmq_errno(void);
extern const char *zmq_strerror(int errnum);

/* Constants from zmq.h (stable ABI). */
#define ZMQ_PUB       1
#define ZMQ_SUB       2
#define ZMQ_SNDMORE   2
#define ZMQ_DONTWAIT  1
#define ZMQ_SNDHWM    23
#define ZMQ_RCVHWM    24
#define ZMQ_LINGER    17
#define ZMQ_SUBSCRIBE 6
#define ZMQ_TCP_KEEPALIVE 34

/* Size of a zmq_msg_t — opaque on the C side, but the libzmq header
 * documents it as 64 bytes on all supported platforms (4.x ABI).
 * We allocate this much for the Haskell-managed message buffer. */
#define HASKOIN_ZMQ_MSG_SIZE 64

/* ---------- Public C entry points (called from Haskell FFI) ------------ */

void *haskoin_zmq_ctx_new(void) {
    return zmq_ctx_new();
}

int haskoin_zmq_ctx_term(void *ctx) {
    if (!ctx) return 0;
    return zmq_ctx_term(ctx);
}

void *haskoin_zmq_pub_socket(void *ctx) {
    if (!ctx) return NULL;
    void *sock = zmq_socket(ctx, ZMQ_PUB);
    if (!sock) return NULL;
    /* Set LINGER=0 so close() returns immediately on shutdown rather
     * than blocking on undelivered messages — matches Bitcoin Core's
     * CZMQNotifier teardown. The Haskell side may override via
     * haskoin_zmq_set_linger, but the safe default is 0. */
    int linger = 0;
    (void)zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));
    return sock;
}

void *haskoin_zmq_sub_socket(void *ctx) {
    if (!ctx) return NULL;
    return zmq_socket(ctx, ZMQ_SUB);
}

int haskoin_zmq_close(void *sock) {
    if (!sock) return 0;
    return zmq_close(sock);
}

int haskoin_zmq_bind(void *sock, const char *endpoint) {
    if (!sock || !endpoint) return -1;
    return zmq_bind(sock, endpoint);
}

int haskoin_zmq_connect(void *sock, const char *endpoint) {
    if (!sock || !endpoint) return -1;
    return zmq_connect(sock, endpoint);
}

int haskoin_zmq_set_sndhwm(void *sock, int hwm) {
    if (!sock) return -1;
    return zmq_setsockopt(sock, ZMQ_SNDHWM, &hwm, sizeof(hwm));
}

int haskoin_zmq_set_rcvhwm(void *sock, int hwm) {
    if (!sock) return -1;
    return zmq_setsockopt(sock, ZMQ_RCVHWM, &hwm, sizeof(hwm));
}

int haskoin_zmq_set_linger(void *sock, int linger) {
    if (!sock) return -1;
    return zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));
}

int haskoin_zmq_set_tcp_keepalive(void *sock, int on) {
    if (!sock) return -1;
    return zmq_setsockopt(sock, ZMQ_TCP_KEEPALIVE, &on, sizeof(on));
}

int haskoin_zmq_subscribe(void *sock, const char *topic, size_t topic_len) {
    if (!sock) return -1;
    return zmq_setsockopt(sock, ZMQ_SUBSCRIBE, topic, topic_len);
}

/* Send a single frame. Caller controls SNDMORE / DONTWAIT through [flags]:
 *   - frame_more  != 0  -> ZMQ_SNDMORE
 *   - non_blocking != 0 -> ZMQ_DONTWAIT
 *
 * Returns the number of bytes queued (>=0) or -1 on failure. The caller
 * (Haskell side) reads zmq_errno() via haskoin_zmq_errno on failure. */
int haskoin_zmq_send_frame(void *sock,
                            const void *buf, size_t len,
                            int frame_more, int non_blocking) {
    if (!sock) return -1;
    int flags = 0;
    if (frame_more) flags |= ZMQ_SNDMORE;
    if (non_blocking) flags |= ZMQ_DONTWAIT;
    return zmq_send(sock, buf, len, flags);
}

/* Send a 3-frame message [topic | body | seq] atomically (single ZMQ
 * thread; the libzmq socket is thread-safe per call but multipart sends
 * must originate from one thread to avoid frame interleaving). The
 * Haskell side serialises this via an MVar around the socket.
 *
 * All three frames use ZMQ_DONTWAIT so a slow / disconnected subscriber
 * cannot stall the publisher; libzmq buffers up to SNDHWM messages and
 * silently drops the rest (Bitcoin Core has the same semantics).
 *
 * Returns 1 on success, 0 if any frame failed. */
int haskoin_zmq_send_three(void *sock,
                            const void *topic, size_t topic_len,
                            const void *body,  size_t body_len,
                            const void *seq,   size_t seq_len) {
    if (!sock) return 0;
    int rc1 = zmq_send(sock, topic, topic_len, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc1 < 0) return 0;
    int rc2 = zmq_send(sock, body, body_len, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc2 < 0) return 0;
    int rc3 = zmq_send(sock, seq, seq_len, ZMQ_DONTWAIT);
    if (rc3 < 0) return 0;
    return 1;
}

/* Receive a single frame into a caller-allocated buffer. Returns the
 * number of bytes received (>=0) or -1 on failure. If the buffer is
 * too small libzmq truncates and the return value is the full message
 * length (caller should check len > buf_len for truncation). */
int haskoin_zmq_recv_into(void *sock, void *buf, size_t buf_len,
                           int non_blocking) {
    if (!sock) return -1;
    int flags = non_blocking ? ZMQ_DONTWAIT : 0;
    return zmq_recv(sock, buf, buf_len, flags);
}

/* Allocate a heap buffer of [HASKOIN_ZMQ_MSG_SIZE] bytes for use as a
 * zmq_msg_t. The Haskell side wraps this in a ForeignPtr with finaliser
 * haskoin_zmq_msg_free. We do not embed the message struct in Haskell
 * itself because its layout is opaque per the ZMQ 4.x ABI contract. */
void *haskoin_zmq_msg_alloc(void) {
    void *m = malloc(HASKOIN_ZMQ_MSG_SIZE);
    if (m) memset(m, 0, HASKOIN_ZMQ_MSG_SIZE);
    return m;
}

void haskoin_zmq_msg_free(void *m) {
    if (m) free(m);
}

int haskoin_zmq_msg_init(void *m) {
    return zmq_msg_init(m);
}

int haskoin_zmq_msg_close(void *m) {
    return zmq_msg_close(m);
}

int haskoin_zmq_msg_recv(void *m, void *sock, int non_blocking) {
    int flags = non_blocking ? ZMQ_DONTWAIT : 0;
    return zmq_msg_recv(m, sock, flags);
}

void *haskoin_zmq_msg_data(void *m) {
    return zmq_msg_data(m);
}

size_t haskoin_zmq_msg_size(void *m) {
    return zmq_msg_size(m);
}

int haskoin_zmq_msg_more(void *m) {
    return zmq_msg_more(m);
}

int haskoin_zmq_errno(void) {
    return zmq_errno();
}

const char *haskoin_zmq_strerror(int errnum) {
    return zmq_strerror(errnum);
}
