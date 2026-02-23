/**
 * Copyright (c) 2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_plugin.h"

#include "na_ip.h"

#include "mercury_atomic.h"
#include "mercury_hash_table.h"
#include "mercury_thread_mutex.h"

#include <lsquic.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/****************/
/* Local Macros */
/****************/

/* Name used in class_name field */
#define NA_LSQUIC_CLASS_NAME "quic"

/* Protocol name used for URI matching */
#define NA_LSQUIC_PROTOCOL_NAME "quic"

/* Custom ALPN for non-HTTP QUIC */
#define NA_LSQUIC_ALPN "mercury"

/* Default max message sizes */
#define NA_LSQUIC_MSG_UNEXPECTED_SIZE (4096)
#define NA_LSQUIC_MSG_EXPECTED_SIZE   (4 * 1024 * 1024)

/* Op status bits */
#define NA_LSQUIC_OP_COMPLETED (1 << 0)
#define NA_LSQUIC_OP_CANCELED  (1 << 1)
#define NA_LSQUIC_OP_QUEUED    (1 << 2)

/* Env vars for TLS certs */
#define NA_LSQUIC_CERT_FILE_ENV "NA_LSQUIC_CERT_FILE"
#define NA_LSQUIC_KEY_FILE_ENV  "NA_LSQUIC_KEY_FILE"

/* UDP recv buffer size */
#define NA_LSQUIC_MAX_UDP_PKT_SIZE (65535)

/* Debug print - set to 0 to disable verbose output */
#define NA_LSQUIC_DEBUG 0
#if NA_LSQUIC_DEBUG
#define NA_LSQUIC_DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define NA_LSQUIC_DBG(...) do {} while (0)
#endif

/* Trace print for debugging - disabled for production */
#define NA_LSQUIC_TRACE(...) do {} while (0)
#define NA_LSQUIC_ERR(...) fprintf(stderr, __VA_ARGS__)

/* Accessor macros */
#define NA_LSQUIC_CLASS(na_class)                                              \
    ((struct na_lsquic_class *) (na_class->plugin_class))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Wire protocol message types */
enum na_lsquic_msg_type {
    NA_LSQUIC_MSG_UNEXPECTED = 1,
    NA_LSQUIC_MSG_EXPECTED   = 2,
    NA_LSQUIC_MSG_RMA_PUT    = 3,
    NA_LSQUIC_MSG_RMA_GET    = 4,
    NA_LSQUIC_MSG_RMA_RESP   = 5
};

/* Wire protocol header (25 bytes) */
struct na_lsquic_msg_hdr {
    uint32_t type;
    uint32_t tag;
    uint8_t dest_id;
    uint64_t payload_length;
    uint64_t source_addr_hash;
} NA_PACKED();

/* Wire protocol RMA header extension (32 bytes) */
struct na_lsquic_rma_hdr {
    uint64_t remote_handle_id;
    uint64_t remote_offset;
    uint64_t local_handle_id;
    uint64_t length;
} NA_PACKED();

/* Address */
struct na_lsquic_addr {
    struct sockaddr_storage ss;   /* Peer address (IP:port) */
    lsquic_conn_t *conn;          /* QUIC connection (lazily created) */
    hg_atomic_int32_t refcount;   /* Reference count */
    bool is_self;                 /* True if this is our own address */
};

/* Msg info stored in op */
struct na_lsquic_msg_info {
    void *buf;
    size_t buf_size;
    void *plugin_data;
    struct na_lsquic_addr *addr;
    na_tag_t tag;
    uint8_t dest_id;
};

/* RMA info stored in op */
struct na_lsquic_rma_info {
    struct na_lsquic_addr *addr;
    uint64_t local_handle_id;
    uint64_t remote_handle_id;
    uint64_t local_offset;
    uint64_t remote_offset;
    uint64_t length;
    uint8_t remote_id;
};

/* Op ID */
struct na_lsquic_op_id {
    struct na_cb_completion_data completion_data; /* Must be accessible */
    union {
        struct na_lsquic_msg_info msg;
        struct na_lsquic_rma_info rma;
    } info;
    STAILQ_ENTRY(na_lsquic_op_id) entry;
    na_class_t *na_class;
    na_context_t *context;
    hg_atomic_int32_t status;
    na_cb_type_t type;
};

/* Memory handle */
struct na_lsquic_mem_handle {
    void *buf;
    size_t buf_size;
    unsigned long flags;
    uint64_t handle_id;
};

/* Received message (queued when no matching recv is posted) */
struct na_lsquic_msg_recv_unexpected {
    STAILQ_ENTRY(na_lsquic_msg_recv_unexpected) entry;
    void *buf;
    size_t buf_size;
    struct na_lsquic_addr *source;
    na_tag_t tag;
};

/* Queued expected message (arrived before recv_expected posted) */
struct na_lsquic_msg_recv_expected {
    STAILQ_ENTRY(na_lsquic_msg_recv_expected) entry;
    void *buf;
    size_t buf_size;
    struct na_lsquic_addr *source;
    na_tag_t tag;
    uint8_t dest_id;
};

/* Private class data */
struct na_lsquic_class {
    lsquic_engine_t *server_engine;   /* Server engine (if listen=true) */
    lsquic_engine_t *client_engine;   /* Client engine (always) */
    int udp_fd;                       /* UDP socket */
    struct sockaddr_storage self_addr; /* Our bound address */
    socklen_t self_addr_len;          /* Length of self address */
    hg_thread_mutex_t engine_lock;    /* Lock for engine access */
    hg_thread_mutex_t queue_lock;     /* Lock for recv queues */

    /* Pending recv queues */
    STAILQ_HEAD(, na_lsquic_op_id) unexpected_recv_queue;
    STAILQ_HEAD(, na_lsquic_op_id) expected_recv_queue;

    /* Pending RMA GET ops (waiting for RMA_RESP) */
    STAILQ_HEAD(, na_lsquic_op_id) rma_get_queue;

    /* Unexpected messages received but not yet matched */
    STAILQ_HEAD(, na_lsquic_msg_recv_unexpected) unexpected_msg_queue;

    /* Expected messages received but not yet matched */
    STAILQ_HEAD(, na_lsquic_msg_recv_expected) expected_msg_queue;

    /* Memory handle map (for RMA) */
    hg_hash_table_t *mem_handle_map;
    hg_atomic_int64_t next_handle_id;

    /* Active client connections */
    STAILQ_HEAD(, na_lsquic_conn_ctx) conn_list;

    /* SSL context for server */
    SSL_CTX *ssl_ctx;

    /* Stream interface (stored for engine creation) */
    struct lsquic_stream_if stream_if;

    /* Message size limits */
    size_t max_unexpected_size;
    size_t max_expected_size;

    /* Context max */
    uint8_t context_max;

    /* Flag: set when lsquic streams are queued but process_conns hasn't run */
    hg_atomic_int32_t needs_progress;

};

/* Per-connection context (returned by on_new_conn / created at connect) */
struct na_lsquic_conn_ctx {
    struct na_lsquic_class *priv;            /* Back-pointer to class */
    struct na_lsquic_addr *addr;             /* Peer address */
    lsquic_conn_t *conn;                     /* Back-pointer to lsquic conn */
    bool in_conn_list;                       /* Whether in priv->conn_list */
    STAILQ_HEAD(, na_lsquic_stream_ctx) pending_sends; /* Queued sends */
    STAILQ_ENTRY(na_lsquic_conn_ctx) entry;  /* Link in class conn_list */
};

/* Per-stream context (returned by on_new_stream) */
struct na_lsquic_stream_ctx {
    STAILQ_ENTRY(na_lsquic_stream_ctx) entry; /* pending_sends queue entry */
    struct na_lsquic_class *priv;              /* Back-pointer to class */
    struct na_lsquic_conn_ctx *conn_ctx;       /* Connection context */
    struct na_lsquic_op_id *op;                /* Associated operation */

    /* Send state (outgoing streams) */
    struct na_lsquic_msg_hdr send_hdr;
    struct na_lsquic_rma_hdr send_rma_hdr;
    const void *send_buf;
    size_t send_buf_size;
    size_t hdr_sent;
    size_t rma_hdr_sent;
    size_t data_sent;

    /* Recv state (incoming streams) */
    struct na_lsquic_msg_hdr recv_hdr;
    struct na_lsquic_rma_hdr recv_rma_hdr;
    size_t hdr_read;
    size_t rma_hdr_read;
    void *recv_buf;
    size_t recv_buf_size;
    size_t data_read;
    bool hdr_complete;
    bool rma_hdr_complete;

    bool is_sender; /* true if we initiated this stream */
};

/********************/
/* Local Prototypes */
/********************/

/* get_protocol_info */
static na_return_t
na_lsquic_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p);

/* check_protocol */
static bool
na_lsquic_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_lsquic_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen);

/* finalize */
static na_return_t
na_lsquic_finalize(na_class_t *na_class);

/* context_create */
static na_return_t
na_lsquic_context_create(na_class_t *na_class, na_context_t *context,
    void **context_p, uint8_t id);

/* context_destroy */
static na_return_t
na_lsquic_context_destroy(na_class_t *na_class, void *context);

/* op_create */
static na_op_id_t *
na_lsquic_op_create(na_class_t *na_class, unsigned long flags);

/* op_destroy */
static void
na_lsquic_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_lsquic_addr_lookup(
    na_class_t *na_class, const char *name, na_addr_t **addr_p);

/* addr_free */
static void
na_lsquic_addr_free(na_class_t *na_class, na_addr_t *addr);

/* addr_self */
static na_return_t
na_lsquic_addr_self(na_class_t *na_class, na_addr_t **addr_p);

/* addr_dup */
static na_return_t
na_lsquic_addr_dup(
    na_class_t *na_class, na_addr_t *addr, na_addr_t **new_addr_p);

/* addr_cmp */
static bool
na_lsquic_addr_cmp(na_class_t *na_class, na_addr_t *addr1, na_addr_t *addr2);

/* addr_is_self */
static bool
na_lsquic_addr_is_self(na_class_t *na_class, na_addr_t *addr);

/* addr_to_string */
static na_return_t
na_lsquic_addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size, na_addr_t *addr);

/* addr_get_serialize_size */
static size_t
na_lsquic_addr_get_serialize_size(na_class_t *na_class, na_addr_t *addr);

/* addr_serialize */
static na_return_t
na_lsquic_addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t *addr);

/* addr_deserialize */
static na_return_t
na_lsquic_addr_deserialize(na_class_t *na_class, na_addr_t **addr_p,
    const void *buf, size_t buf_size, uint64_t flags);

/* msg_get_max_unexpected_size */
static size_t
na_lsquic_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static size_t
na_lsquic_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_max_tag */
static na_tag_t
na_lsquic_msg_get_max_tag(const na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t
na_lsquic_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_lsquic_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size, void *plugin_data,
    na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_lsquic_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_lsquic_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size, void *plugin_data,
    na_addr_t *source_addr, uint8_t source_id, na_tag_t tag,
    na_op_id_t *op_id);

/* mem_handle_create */
static na_return_t
na_lsquic_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t **mem_handle_p);

/* mem_handle_free */
static void
na_lsquic_mem_handle_free(na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_get_serialize_size */
static size_t
na_lsquic_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_serialize */
static na_return_t
na_lsquic_mem_handle_serialize(
    na_class_t *na_class, void *buf, size_t buf_size,
    na_mem_handle_t *mem_handle);

/* mem_handle_deserialize */
static na_return_t
na_lsquic_mem_handle_deserialize(na_class_t *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size);

/* put */
static na_return_t
na_lsquic_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_lsquic_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static int
na_lsquic_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static bool
na_lsquic_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* poll */
static na_return_t
na_lsquic_poll(
    na_class_t *na_class, na_context_t *context, unsigned int *count_p);

/* poll_wait */
static na_return_t
na_lsquic_poll_wait(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms, unsigned int *count_p);

/* cancel */
static na_return_t
na_lsquic_cancel(
    na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/* Internal helpers */
static void
na_lsquic_release(void *arg);

static na_return_t
na_lsquic_create_udp_socket(
    const char *host_name, bool listen, int *fd_p,
    struct sockaddr_storage *addr_p, socklen_t *addr_len_p);

static na_return_t
na_lsquic_setup_ssl_ctx(SSL_CTX **ssl_ctx_p);

static int
na_lsquic_packets_out(void *ctx, const struct lsquic_out_spec *specs,
    unsigned n_specs);

static uint64_t
na_lsquic_hash_addr(const struct sockaddr_storage *ss);

static na_return_t
na_lsquic_get_conn(struct na_lsquic_class *priv,
    struct na_lsquic_addr *dest, lsquic_conn_t **conn_p);

static void
na_lsquic_complete_op(struct na_lsquic_op_id *op, na_return_t ret);

static na_return_t
na_lsquic_msg_send(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id,
    na_tag_t tag, na_op_id_t *op_id, enum na_lsquic_msg_type msg_type,
    na_cb_type_t cb_type);

static void
na_lsquic_process_recv_unexpected(
    struct na_lsquic_class *priv, struct na_lsquic_addr *source,
    na_tag_t tag, void *data, size_t data_size);

static void
na_lsquic_process_recv_expected(
    struct na_lsquic_class *priv, struct na_lsquic_addr *source,
    na_tag_t tag, uint8_t dest_id, void *data, size_t data_size);

static void
na_lsquic_process_rma_put(struct na_lsquic_class *priv,
    const struct na_lsquic_rma_hdr *rma_hdr, void *data, size_t data_size);

static void
na_lsquic_process_rma_get(struct na_lsquic_class *priv,
    struct na_lsquic_stream_ctx *sctx,
    const struct na_lsquic_rma_hdr *rma_hdr);

static void
na_lsquic_process_rma_resp(struct na_lsquic_class *priv,
    const struct na_lsquic_rma_hdr *rma_hdr, void *data, size_t data_size);

static na_return_t
na_lsquic_progress(struct na_lsquic_class *priv);

static unsigned int
na_lsquic_handle_id_hash(hg_hash_table_key_t key);

static int
na_lsquic_handle_id_equal(
    hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/* lsquic stream interface callbacks */
static lsquic_conn_ctx_t *
na_lsquic_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn);

static void
na_lsquic_on_conn_closed(lsquic_conn_t *conn);

static lsquic_stream_ctx_t *
na_lsquic_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream);

static void
na_lsquic_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *ctx);

static void
na_lsquic_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *ctx);

static void
na_lsquic_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *ctx);

static struct ssl_ctx_st *
na_lsquic_get_ssl_ctx(void *peer_ctx, const struct sockaddr *local);

/*******************/
/* Local Variables */
/*******************/

/* Ops table */
const struct na_class_ops NA_PLUGIN_OPS(quic) = {
    NA_LSQUIC_CLASS_NAME,                    /* class_name */
    na_lsquic_get_protocol_info,             /* get_protocol_info */
    na_lsquic_check_protocol,                /* check_protocol */
    na_lsquic_initialize,                    /* initialize */
    na_lsquic_finalize,                      /* finalize */
    NULL,                                    /* cleanup */
    NULL,                                    /* has_opt_feature */
    na_lsquic_context_create,                /* context_create */
    na_lsquic_context_destroy,               /* context_destroy */
    na_lsquic_op_create,                     /* op_create */
    na_lsquic_op_destroy,                    /* op_destroy */
    na_lsquic_addr_lookup,                   /* addr_lookup */
    na_lsquic_addr_free,                     /* addr_free */
    NULL,                                    /* addr_set_remove */
    na_lsquic_addr_self,                     /* addr_self */
    na_lsquic_addr_dup,                      /* addr_dup */
    na_lsquic_addr_cmp,                      /* addr_cmp */
    na_lsquic_addr_is_self,                  /* addr_is_self */
    na_lsquic_addr_to_string,                /* addr_to_string */
    na_lsquic_addr_get_serialize_size,       /* addr_get_serialize_size */
    na_lsquic_addr_serialize,                /* addr_serialize */
    na_lsquic_addr_deserialize,              /* addr_deserialize */
    na_lsquic_msg_get_max_unexpected_size,   /* msg_get_max_unexpected_size */
    na_lsquic_msg_get_max_expected_size,     /* msg_get_max_expected_size */
    NULL,                                    /* msg_get_unexpected_header_size */
    NULL,                                    /* msg_get_expected_header_size */
    na_lsquic_msg_get_max_tag,               /* msg_get_max_tag */
    NULL,                                    /* msg_buf_alloc */
    NULL,                                    /* msg_buf_free */
    NULL,                                    /* msg_init_unexpected */
    na_lsquic_msg_send_unexpected,           /* msg_send_unexpected */
    na_lsquic_msg_recv_unexpected,           /* msg_recv_unexpected */
    NULL,                                    /* msg_multi_recv_unexpected */
    NULL,                                    /* msg_init_expected */
    na_lsquic_msg_send_expected,             /* msg_send_expected */
    na_lsquic_msg_recv_expected,             /* msg_recv_expected */
    na_lsquic_mem_handle_create,             /* mem_handle_create */
    NULL,                                    /* mem_handle_create_segments */
    na_lsquic_mem_handle_free,               /* mem_handle_free */
    NULL,                                    /* mem_handle_get_max_segments */
    NULL,                                    /* mem_register */
    NULL,                                    /* mem_deregister */
    na_lsquic_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
    na_lsquic_mem_handle_serialize,          /* mem_handle_serialize */
    na_lsquic_mem_handle_deserialize,        /* mem_handle_deserialize */
    na_lsquic_put,                           /* put */
    na_lsquic_get,                           /* get */
    na_lsquic_poll_get_fd,                   /* poll_get_fd */
    na_lsquic_poll_try_wait,                 /* poll_try_wait */
    na_lsquic_poll,                          /* poll */
    na_lsquic_poll_wait,                     /* poll_wait */
    na_lsquic_cancel                         /* cancel */
};

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p)
{
    const char *protocol_name =
        (na_info != NULL) ? na_info->protocol_name : NULL;
    na_return_t ret;

    if (protocol_name != NULL &&
        strcmp(protocol_name, NA_LSQUIC_PROTOCOL_NAME)) {
        *na_protocol_info_p = NULL;
        return NA_SUCCESS;
    }

    *na_protocol_info_p = na_protocol_info_alloc(
        NA_LSQUIC_CLASS_NAME, NA_LSQUIC_PROTOCOL_NAME, "udp");
    NA_CHECK_SUBSYS_ERROR(cls, *na_protocol_info_p == NULL, error, ret,
        NA_NOMEM, "Could not allocate protocol info entry");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static bool
na_lsquic_check_protocol(const char *protocol_name)
{
    return !strcmp(NA_LSQUIC_PROTOCOL_NAME, protocol_name);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_create_udp_socket(const char *host_name, bool listen, int *fd_p,
    struct sockaddr_storage *addr_p, socklen_t *addr_len_p)
{
    struct sockaddr *sa = NULL;
    socklen_t salen = 0;
    int fd = -1;
    int flags;
    na_return_t ret;

    if (host_name != NULL && *host_name != '\0') {
        /* Parse host:port string */
        char *host_copy = strdup(host_name);
        NA_CHECK_SUBSYS_ERROR(cls, host_copy == NULL, error, ret, NA_NOMEM,
            "strdup() failed");

        char *port_str = strrchr(host_copy, ':');
        uint16_t port = 0;
        if (port_str != NULL) {
            *port_str = '\0';
            port_str++;
            port = (uint16_t) atoi(port_str);
        }

        /* Resolve hostname to sockaddr */
        ret = na_ip_check_interface(
            host_copy, port, AF_UNSPEC, NULL, &sa, &salen);
        free(host_copy);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
            "Could not resolve host: %s", host_name);
    } else {
        /* Default: bind to INADDR_ANY on any port */
        struct sockaddr_in *sin =
            (struct sockaddr_in *) calloc(1, sizeof(*sin));
        NA_CHECK_SUBSYS_ERROR(cls, sin == NULL, error, ret, NA_NOMEM,
            "calloc() failed");
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = INADDR_ANY;
        sin->sin_port = 0; /* OS picks port */
        sa = (struct sockaddr *) sin;
        salen = sizeof(*sin);
    }

    /* Create UDP socket */
    fd = socket(sa->sa_family, SOCK_DGRAM, 0);
    NA_CHECK_SUBSYS_ERROR(cls, fd < 0, error, ret, NA_IO_ERROR,
        "socket() failed (%s)", strerror(errno));

    /* Increase socket buffer sizes for large QUIC transfers */
    {
        int buf_size = 4 * 1024 * 1024; /* 4 MB */
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    }

    /* Bind */
    if (listen || host_name != NULL) {
        int rc = bind(fd, sa, salen);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, NA_ADDRINUSE,
            "bind() failed (%s)", strerror(errno));
    } else {
        /* Client with no host: bind to any address to get a local port */
        struct sockaddr_in any = {0};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = INADDR_ANY;
        int rc = bind(fd, (struct sockaddr *) &any, sizeof(any));
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, NA_ADDRINUSE,
            "bind() failed (%s)", strerror(errno));
    }

    /* Set non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    NA_CHECK_SUBSYS_ERROR(cls, flags < 0, error, ret, NA_IO_ERROR,
        "fcntl(F_GETFL) failed (%s)", strerror(errno));
    flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    NA_CHECK_SUBSYS_ERROR(cls, flags < 0, error, ret, NA_IO_ERROR,
        "fcntl(F_SETFL) failed (%s)", strerror(errno));

    /* Get bound address */
    *addr_len_p = sizeof(*addr_p);
    {
        int rc = getsockname(fd, (struct sockaddr *) addr_p, addr_len_p);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, NA_IO_ERROR,
            "getsockname() failed (%s)", strerror(errno));
    }

    /* Replace INADDR_ANY with loopback so peers can connect */
    if (addr_p->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) addr_p;
        if (sin->sin_addr.s_addr == INADDR_ANY)
            sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    free(sa);
    *fd_p = fd;

    return NA_SUCCESS;

error:
    free(sa);
    if (fd >= 0)
        close(fd);
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_alpn_select_cb(SSL *ssl NA_UNUSED,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg NA_UNUSED)
{
    /* Our ALPN protocol string in wire format: length-prefixed */
    unsigned char alpn_wire[1 + sizeof(NA_LSQUIC_ALPN) - 1];
    int r;

    alpn_wire[0] = (unsigned char) (sizeof(NA_LSQUIC_ALPN) - 1);
    memcpy(alpn_wire + 1, NA_LSQUIC_ALPN, sizeof(NA_LSQUIC_ALPN) - 1);

    {
        unsigned char *tmp_out = NULL;
        r = SSL_select_next_proto(&tmp_out, outlen, in, inlen,
            alpn_wire, sizeof(alpn_wire));
        *out = tmp_out;
    }
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_setup_ssl_ctx(SSL_CTX **ssl_ctx_p)
{
    SSL_CTX *ctx;
    const char *cert_file;
    const char *key_file;
    na_return_t ret;

    ctx = SSL_CTX_new(TLS_method());
    NA_CHECK_SUBSYS_ERROR(cls, ctx == NULL, error, ret, NA_PROTOCOL_ERROR,
        "SSL_CTX_new() failed");

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, na_lsquic_alpn_select_cb, NULL);

    cert_file = getenv(NA_LSQUIC_CERT_FILE_ENV);
    key_file = getenv(NA_LSQUIC_KEY_FILE_ENV);

    if (cert_file != NULL && key_file != NULL) {
        int rc;

        NA_LOG_SUBSYS_DEBUG(cls, "Using TLS cert: %s, key: %s",
            cert_file, key_file);

        rc = SSL_CTX_use_certificate_chain_file(ctx, cert_file);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 1, error, ret, NA_PROTOCOL_ERROR,
            "SSL_CTX_use_certificate_chain_file() failed");

        rc = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 1, error, ret, NA_PROTOCOL_ERROR,
            "SSL_CTX_use_PrivateKey_file() failed");
    } else {
        /* Generate self-signed cert */
        EVP_PKEY *pkey = NULL;
        RSA *rsa = NULL;
        BIGNUM *bn = NULL;
        X509 *x509 = NULL;
        int rc;

        NA_LOG_SUBSYS_DEBUG(cls,
            "No TLS cert/key provided, generating self-signed");

        /* Generate RSA key using BoringSSL-compatible API */
        rsa = RSA_new();
        NA_CHECK_SUBSYS_ERROR(cls, rsa == NULL, error, ret,
            NA_PROTOCOL_ERROR, "RSA_new() failed");

        bn = BN_new();
        if (bn == NULL) {
            RSA_free(rsa);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTOCOL_ERROR,
                "BN_new() failed");
        }
        BN_set_word(bn, RSA_F4);

        rc = RSA_generate_key_ex(rsa, 2048, bn, NULL);
        BN_free(bn);
        if (rc != 1) {
            RSA_free(rsa);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTOCOL_ERROR,
                "RSA_generate_key_ex() failed");
        }

        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            RSA_free(rsa);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTOCOL_ERROR,
                "EVP_PKEY_new() failed");
        }

        /* EVP_PKEY_assign_RSA takes ownership of rsa */
        EVP_PKEY_assign_RSA(pkey, rsa);

        x509 = X509_new();
        if (x509 == NULL) {
            EVP_PKEY_free(pkey);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTOCOL_ERROR,
                "X509_new() failed");
        }

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 365L * 24 * 60 * 60);
        X509_set_pubkey(x509, pkey);

        /* Self-sign */
        X509_sign(x509, pkey, EVP_sha256());

        rc = SSL_CTX_use_certificate(ctx, x509);
        if (rc != 1) {
            X509_free(x509);
            EVP_PKEY_free(pkey);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTOCOL_ERROR,
                "SSL_CTX_use_certificate() failed");
        }

        rc = SSL_CTX_use_PrivateKey(ctx, pkey);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 1, error, ret, NA_PROTOCOL_ERROR,
            "SSL_CTX_use_PrivateKey() failed");
    }

    *ssl_ctx_p = ctx;
    return NA_SUCCESS;

error:
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_packets_out(void *ctx, const struct lsquic_out_spec *specs,
    unsigned n_specs)
{
    struct na_lsquic_class *priv = (struct na_lsquic_class *) ctx;
    unsigned i;
    static unsigned packets_out_count = 0;
    packets_out_count++;
    NA_LSQUIC_TRACE("[%d] TRACE packets_out #%u n_specs=%u\n",
        getpid(), packets_out_count, n_specs);
    for (i = 0; i < n_specs; i++) {
        struct msghdr msg = {0};
        msg.msg_name = (struct sockaddr *)(uintptr_t) specs[i].dest_sa;
        msg.msg_namelen = (specs[i].dest_sa->sa_family == AF_INET6)
                              ? sizeof(struct sockaddr_in6)
                              : sizeof(struct sockaddr_in);
        msg.msg_iov = specs[i].iov;
        msg.msg_iovlen = specs[i].iovlen;

        ssize_t sent = sendmsg(priv->udp_fd, &msg, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                NA_LSQUIC_TRACE("[%d] TRACE packets_out EAGAIN at i=%u/%u\n",
                    getpid(), i, n_specs);
                return (int) i;
            }
            NA_LSQUIC_TRACE("[%d] TRACE packets_out FAIL errno=%d (%s) at i=%u/%u\n",
                getpid(), errno, strerror(errno), i, n_specs);
            return -1;
        }
    }

    return (int) n_specs;
}

/*---------------------------------------------------------------------------*/
static uint64_t
na_lsquic_hash_addr(const struct sockaddr_storage *ss)
{
    uint64_t hash = 0;

    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) ss;
        hash = ((uint64_t) sin->sin_addr.s_addr << 16) | sin->sin_port;
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) ss;
        const uint8_t *a = sin6->sin6_addr.s6_addr;
        unsigned i;
        for (i = 0; i < 16; i++)
            hash = hash * 31 + a[i];
        hash = (hash << 16) | sin6->sin6_port;
    }

    return hash;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_complete_op(struct na_lsquic_op_id *op, na_return_t ret)
{
    NA_LSQUIC_TRACE("[%d] TRACE complete_op type=%d ret=%d\n",
        getpid(), op->type, ret);

    /* Mark as completed */
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_COMPLETED);

    /* Fill callback info */
    op->completion_data.callback_info.arg = op->completion_data.callback_info.arg;
    op->completion_data.callback_info.type = op->type;
    op->completion_data.callback_info.ret = ret;

    /* Enqueue completion */
    na_cb_completion_add(op->context, &op->completion_data);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_get_conn(struct na_lsquic_class *priv,
    struct na_lsquic_addr *dest, lsquic_conn_t **conn_p)
{
    struct na_lsquic_conn_ctx *conn_ctx;

    /* If this addr already has a connection, reuse */
    if (dest->conn != NULL) {
        *conn_p = dest->conn;
        return NA_SUCCESS;
    }

    /* Search existing connections for one to the same address */
    STAILQ_FOREACH(conn_ctx, &priv->conn_list, entry) {
        if (conn_ctx->addr != NULL &&
            na_lsquic_addr_cmp(NULL, (na_addr_t *) conn_ctx->addr,
                (na_addr_t *) dest)) {
            /* Found existing connection to same address */
            dest->conn = conn_ctx->conn;
            *conn_p = dest->conn;
            return NA_SUCCESS;
        }
    }

    /* Create connection context */
    conn_ctx =
        (struct na_lsquic_conn_ctx *) calloc(1, sizeof(*conn_ctx));
    if (conn_ctx == NULL)
        return NA_NOMEM;

    conn_ctx->priv = priv;
    conn_ctx->addr = dest;
    STAILQ_INIT(&conn_ctx->pending_sends);
    hg_atomic_incr32(&dest->refcount);

    /* Create QUIC connection to peer */
    NA_LSQUIC_TRACE("[%d] TRACE get_conn: creating NEW connection\n", getpid());
    dest->conn = lsquic_engine_connect(priv->client_engine, LSQVER_I001,
        (struct sockaddr *) &priv->self_addr,
        (struct sockaddr *) &dest->ss,
        priv,       /* peer_ctx (for ea_packets_out / ea_get_ssl_ctx) */
        (lsquic_conn_ctx_t *) conn_ctx, /* conn_ctx - avoids on_new_conn */
        NULL,       /* hostname (no SNI for non-HTTP) */
        0,          /* base_plpmtu */
        NULL, 0,    /* session resume */
        NULL, 0     /* token */
    );

    if (dest->conn == NULL) {
        hg_atomic_decr32(&dest->refcount);
        free(conn_ctx);
        return NA_PROTOCOL_ERROR;
    }

    conn_ctx->conn = dest->conn;
    conn_ctx->in_conn_list = true;
    STAILQ_INSERT_TAIL(&priv->conn_list, conn_ctx, entry);

    *conn_p = dest->conn;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static lsquic_conn_ctx_t *
na_lsquic_on_new_conn(void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct na_lsquic_class *priv = (struct na_lsquic_class *) stream_if_ctx;
    struct na_lsquic_conn_ctx *conn_ctx;
    const struct sockaddr *local_sa = NULL, *peer_sa = NULL;

    /* For client connections, conn_ctx was already set via
     * lsquic_engine_connect. Return it as-is. */
    conn_ctx = (struct na_lsquic_conn_ctx *) lsquic_conn_get_ctx(conn);
    if (conn_ctx != NULL) {
        NA_LOG_SUBSYS_DEBUG(msg, "Client connection established");
        return (lsquic_conn_ctx_t *) conn_ctx;
    }


    /* Server-accepted connection: create a new conn context */
    conn_ctx =
        (struct na_lsquic_conn_ctx *) calloc(1, sizeof(*conn_ctx));
    if (conn_ctx == NULL) {
        NA_LOG_SUBSYS_ERROR(msg, "Could not allocate conn context");
        return NULL;
    }

    conn_ctx->priv = priv;
    conn_ctx->conn = conn;
    STAILQ_INIT(&conn_ctx->pending_sends);

    /* Get peer address from the connection */
    lsquic_conn_get_sockaddr(conn, &local_sa, &peer_sa);
    if (peer_sa != NULL) {
        struct na_lsquic_addr *addr =
            (struct na_lsquic_addr *) calloc(1, sizeof(*addr));
        if (addr != NULL) {
            socklen_t sa_len = (peer_sa->sa_family == AF_INET6)
                                   ? sizeof(struct sockaddr_in6)
                                   : sizeof(struct sockaddr_in);
            memcpy(&addr->ss, peer_sa, sa_len);
            hg_atomic_init32(&addr->refcount, 1);
            addr->is_self = false;
            addr->conn = conn;
            conn_ctx->addr = addr;
        }
    }

    /* Add to conn_list so server can send back on this connection */
    conn_ctx->in_conn_list = true;
    STAILQ_INSERT_TAIL(&priv->conn_list, conn_ctx, entry);

    NA_LOG_SUBSYS_DEBUG(msg, "Server accepted new connection");

    return (lsquic_conn_ctx_t *) conn_ctx;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_on_conn_closed(lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *lctx = lsquic_conn_get_ctx(conn);
    struct na_lsquic_conn_ctx *conn_ctx = (struct na_lsquic_conn_ctx *) lctx;

    if (conn_ctx == NULL)
        return;

    NA_LOG_SUBSYS_DEBUG(msg, "Connection closed");

    /* Complete any pending send operations with error */
    {
        struct na_lsquic_stream_ctx *sctx;
        while (!STAILQ_EMPTY(&conn_ctx->pending_sends)) {
            sctx = STAILQ_FIRST(&conn_ctx->pending_sends);
            STAILQ_REMOVE_HEAD(&conn_ctx->pending_sends, entry);
            NA_LSQUIC_TRACE("[%d] TRACE on_conn_closed: canceling pending send type=%u\n",
                getpid(), sctx->send_hdr.type);
            if (sctx->op != NULL) {
                na_lsquic_complete_op(sctx->op, NA_CANCELED);
                sctx->op = NULL;
            }
            free(sctx);
        }
    }

    /* Remove from conn_list if present */
    if (conn_ctx->in_conn_list && conn_ctx->priv != NULL) {
        STAILQ_REMOVE(&conn_ctx->priv->conn_list, conn_ctx,
            na_lsquic_conn_ctx, entry);
    }

    /* Clear connection reference in addr */
    if (conn_ctx->addr != NULL) {
        conn_ctx->addr->conn = NULL;
        if (hg_atomic_decr32(&conn_ctx->addr->refcount) == 0)
            free(conn_ctx->addr);
    }

    free(conn_ctx);
}

/*---------------------------------------------------------------------------*/
static lsquic_stream_ctx_t *
na_lsquic_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct na_lsquic_class *priv = (struct na_lsquic_class *) stream_if_ctx;
    struct na_lsquic_conn_ctx *conn_ctx;
    struct na_lsquic_stream_ctx *sctx;
    lsquic_conn_t *conn;

    if (stream == NULL) {
        /* lsquic calls on_new_stream with NULL when it can't create */
        NA_LSQUIC_ERR("[%d] ERR on_new_stream: NULL stream (stream creation failed)\n",
            getpid());
        return NULL;
    }

    conn = lsquic_stream_conn(stream);
    conn_ctx = (struct na_lsquic_conn_ctx *) lsquic_conn_get_ctx(conn);

    /* Check if this is a send stream (we have pending sends) */
    if (conn_ctx != NULL && !STAILQ_EMPTY(&conn_ctx->pending_sends)) {
        /* Pop the pending send context */
        sctx = STAILQ_FIRST(&conn_ctx->pending_sends);
        STAILQ_REMOVE_HEAD(&conn_ctx->pending_sends, entry);
        sctx->conn_ctx = conn_ctx;
        sctx->is_sender = true;

        /* We want to write on this stream */
        lsquic_stream_wantwrite(stream, 1);
        lsquic_stream_wantread(stream, 0);

        return (lsquic_stream_ctx_t *) sctx;
    }

    /* This is an incoming (receive) stream from the peer */
    sctx = (struct na_lsquic_stream_ctx *) calloc(1, sizeof(*sctx));
    if (sctx == NULL) {
        NA_LOG_SUBSYS_ERROR(msg, "Could not allocate stream context");
        return NULL;
    }

    sctx->priv = priv;
    sctx->conn_ctx = conn_ctx;
    sctx->is_sender = false;
    sctx->hdr_complete = false;
    sctx->hdr_read = 0;
    sctx->data_read = 0;

    /* We want to read on this stream */
    lsquic_stream_wantread(stream, 1);
    lsquic_stream_wantwrite(stream, 0);

    return (lsquic_stream_ctx_t *) sctx;
}

/*---------------------------------------------------------------------------*/
static bool
na_lsquic_msg_type_is_rma(uint32_t type)
{
    return type == NA_LSQUIC_MSG_RMA_PUT || type == NA_LSQUIC_MSG_RMA_GET ||
           type == NA_LSQUIC_MSG_RMA_RESP;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    struct na_lsquic_stream_ctx *sctx = (struct na_lsquic_stream_ctx *) h;
    ssize_t nr;

    if (sctx == NULL)
        return;

    /* Phase 1: Read message header */
    if (!sctx->hdr_complete) {
        size_t remaining = sizeof(sctx->recv_hdr) - sctx->hdr_read;

        nr = lsquic_stream_read(stream,
            (char *) &sctx->recv_hdr + sctx->hdr_read, remaining);
        if (nr <= 0) {
            if (nr == 0)
                lsquic_stream_shutdown(stream, 0);
            return;
        }

        sctx->hdr_read += (size_t) nr;
        if (sctx->hdr_read < sizeof(sctx->recv_hdr))
            return;

        sctx->hdr_complete = true;
        sctx->rma_hdr_read = 0;
        sctx->rma_hdr_complete = !na_lsquic_msg_type_is_rma(
            sctx->recv_hdr.type);
    }

    /* Phase 2: Read RMA header (for RMA message types only) */
    if (!sctx->rma_hdr_complete) {
        size_t remaining =
            sizeof(sctx->recv_rma_hdr) - sctx->rma_hdr_read;

        nr = lsquic_stream_read(stream,
            (char *) &sctx->recv_rma_hdr + sctx->rma_hdr_read, remaining);
        if (nr <= 0)
            return;

        sctx->rma_hdr_read += (size_t) nr;
        if (sctx->rma_hdr_read < sizeof(sctx->recv_rma_hdr))
            return;

        sctx->rma_hdr_complete = true;

        /* For RMA_GET requests, there is no payload - handle immediately */
        if (sctx->recv_hdr.type == NA_LSQUIC_MSG_RMA_GET) {
            lsquic_stream_wantread(stream, 0);
            na_lsquic_process_rma_get(sctx->priv, sctx,
                &sctx->recv_rma_hdr);
            lsquic_stream_close(stream);
            return;
        }
    }

    /* Phase 3: Allocate payload buffer (once, after all headers read) */
    if (sctx->recv_buf == NULL && sctx->recv_buf_size == 0) {
        sctx->recv_buf_size = sctx->recv_hdr.payload_length;
        if (sctx->recv_buf_size > 0) {
            sctx->recv_buf = malloc(sctx->recv_buf_size);
            if (sctx->recv_buf == NULL) {
                NA_LOG_SUBSYS_ERROR(msg,
                    "Could not allocate recv buffer (%zu bytes)",
                    sctx->recv_buf_size);
                lsquic_stream_shutdown(stream, 0);
                return;
            }
        }
        sctx->data_read = 0;
    }

    /* Phase 4: Read payload */
    if (sctx->data_read < sctx->recv_buf_size) {
        size_t remaining = sctx->recv_buf_size - sctx->data_read;

        nr = lsquic_stream_read(stream,
            (char *) sctx->recv_buf + sctx->data_read, remaining);
        if (nr <= 0) {
            if (sctx->recv_buf_size > 100000)
                NA_LSQUIC_DBG("DEBUG[%d]:  on_read stall nr=%zd read=%zu/%zu\n",
                    getpid(), nr, sctx->data_read, sctx->recv_buf_size);
            return;
        }

        sctx->data_read += (size_t) nr;
        if (sctx->data_read < sctx->recv_buf_size) {
            if (sctx->recv_buf_size > 100000)
                NA_LSQUIC_DBG("DEBUG[%d]:  on_read progress type=%u read=%zu/%zu\n",
                    getpid(), sctx->recv_hdr.type, sctx->data_read, sctx->recv_buf_size);
            return;
        }
    }

    /* Message complete - stop reading */
    lsquic_stream_wantread(stream, 0);

    NA_LSQUIC_TRACE("[%d] TRACE on_read COMPLETE type=%u tag=%u data_size=%zu\n",
        getpid(), sctx->recv_hdr.type, sctx->recv_hdr.tag, sctx->data_read);

    /* Dispatch based on message type */
    {
        struct na_lsquic_addr *source = NULL;
        if (sctx->conn_ctx != NULL)
            source = sctx->conn_ctx->addr;

        switch (sctx->recv_hdr.type) {
        case NA_LSQUIC_MSG_UNEXPECTED:
            na_lsquic_process_recv_unexpected(sctx->priv, source,
                sctx->recv_hdr.tag, sctx->recv_buf, sctx->data_read);
            sctx->recv_buf = NULL;
            break;

        case NA_LSQUIC_MSG_EXPECTED:
            NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" recv expected msg tag=%u dest_id=%u size=%zu source=%p\n",
                sctx->recv_hdr.tag, sctx->recv_hdr.dest_id,
                sctx->data_read, (void*)source);
            na_lsquic_process_recv_expected(sctx->priv, source,
                sctx->recv_hdr.tag, sctx->recv_hdr.dest_id,
                sctx->recv_buf, sctx->data_read);
            sctx->recv_buf = NULL;
            break;

        case NA_LSQUIC_MSG_RMA_PUT:
            na_lsquic_process_rma_put(sctx->priv,
                &sctx->recv_rma_hdr, sctx->recv_buf, sctx->data_read);
            sctx->recv_buf = NULL;
            break;

        case NA_LSQUIC_MSG_RMA_RESP:
            na_lsquic_process_rma_resp(sctx->priv,
                &sctx->recv_rma_hdr, sctx->recv_buf, sctx->data_read);
            sctx->recv_buf = NULL;
            break;

        default:
            NA_LOG_SUBSYS_WARNING(msg, "Unknown message type: %u",
                sctx->recv_hdr.type);
            free(sctx->recv_buf);
            sctx->recv_buf = NULL;
            break;
        }
    }

    lsquic_stream_close(stream);
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    struct na_lsquic_stream_ctx *sctx = (struct na_lsquic_stream_ctx *) h;
    ssize_t nw;

    if (sctx == NULL)
        return;

    if (sctx->send_buf_size > 100000) {
        static unsigned ow_count = 0;
        ow_count++;
        NA_LSQUIC_TRACE("[%d] TRACE on_write #%u type=%u hdr=%zu/%zu rma=%zu/%zu data=%zu/%zu\n",
            getpid(), ow_count, sctx->send_hdr.type,
            sctx->hdr_sent, sizeof(sctx->send_hdr),
            sctx->rma_hdr_sent, sizeof(sctx->send_rma_hdr),
            sctx->data_sent, sctx->send_buf_size);
    }

    /* Write message header */
    if (sctx->hdr_sent < sizeof(sctx->send_hdr)) {
        size_t remaining = sizeof(sctx->send_hdr) - sctx->hdr_sent;

        nw = lsquic_stream_write(stream,
            (const char *) &sctx->send_hdr + sctx->hdr_sent, remaining);
        if (nw < 0)
            return;

        sctx->hdr_sent += (size_t) nw;
        if (sctx->hdr_sent < sizeof(sctx->send_hdr))
            return;
    }

    /* Write RMA header (for RMA message types only) */
    if (na_lsquic_msg_type_is_rma(sctx->send_hdr.type)) {
        if (sctx->rma_hdr_sent < sizeof(sctx->send_rma_hdr)) {
            size_t remaining =
                sizeof(sctx->send_rma_hdr) - sctx->rma_hdr_sent;

            nw = lsquic_stream_write(stream,
                (const char *) &sctx->send_rma_hdr + sctx->rma_hdr_sent,
                remaining);
            if (nw < 0)
                return;

            sctx->rma_hdr_sent += (size_t) nw;
            if (sctx->rma_hdr_sent < sizeof(sctx->send_rma_hdr))
                return;
        }
    }

    /* Write payload */
    if (sctx->data_sent < sctx->send_buf_size) {
        size_t remaining = sctx->send_buf_size - sctx->data_sent;

        nw = lsquic_stream_write(stream,
            (const char *) sctx->send_buf + sctx->data_sent, remaining);
        if (nw < 0) {
            NA_LSQUIC_TRACE("[%d] TRACE on_write ERROR nw=%zd type=%u sent=%zu/%zu\n",
                getpid(), nw, sctx->send_hdr.type, sctx->data_sent, sctx->send_buf_size);
            return;
        }

        sctx->data_sent += (size_t) nw;
        if (sctx->send_buf_size > 100000 || nw == 0)
            NA_LSQUIC_TRACE("[%d] TRACE on_write payload nw=%zd sent=%zu/%zu\n",
                getpid(), nw, sctx->data_sent, sctx->send_buf_size);
        if (sctx->data_sent < sctx->send_buf_size) {
            return; /* lsquic will call on_write again when ready */
        }
    }

    /* All data written - flush, stop writing, and close */
    if (sctx->send_buf_size > 100000)
        NA_LSQUIC_TRACE("[%d] TRACE on_write COMPLETE type=%u size=%zu\n",
            getpid(), sctx->send_hdr.type, sctx->data_sent);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_flush(stream);
    lsquic_stream_close(stream);

    /* Complete the send op */
    if (sctx->op != NULL) {
        NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" on_write complete type=%u tag=%u size=%zu\n",
            sctx->send_hdr.type, sctx->send_hdr.tag, sctx->data_sent);
        na_lsquic_complete_op(sctx->op, NA_SUCCESS);
        sctx->op = NULL;
    }
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_on_close(lsquic_stream_t NA_UNUSED *stream,
    lsquic_stream_ctx_t *h)
{
    struct na_lsquic_stream_ctx *sctx = (struct na_lsquic_stream_ctx *) h;

    if (sctx == NULL)
        return;

    NA_LSQUIC_TRACE("[%d] TRACE on_close stream sctx=%p send_buf_size=%zu\n",
        getpid(), (void*)sctx, sctx->send_buf_size);

    /* If this stream had a pending op that wasn't completed (e.g., connection
     * closed while data was still being sent), complete it with an error */
    if (sctx->op != NULL) {
        NA_LSQUIC_ERR("[%d] ERR on_close: incomplete op type=%u sent=%zu/%zu\n",
            getpid(), sctx->send_hdr.type, sctx->data_sent, sctx->send_buf_size);
        na_lsquic_complete_op(sctx->op, NA_CANCELED);
        sctx->op = NULL;
    }

    /* Free recv buffer if still owned */
    free(sctx->recv_buf);

    /* If this is a sender stream, stream context was allocated in msg_send.
     * If this is a receiver stream, it was allocated in on_new_stream. */
    free(sctx);
}

/*---------------------------------------------------------------------------*/
static struct ssl_ctx_st *
na_lsquic_get_ssl_ctx(void *peer_ctx,
    const struct sockaddr NA_UNUSED *local)
{
    struct na_lsquic_class *priv = (struct na_lsquic_class *) peer_ctx;

    return priv->ssl_ctx;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_release(void NA_UNUSED *arg)
{
    /* Op release callback (called after user callback completes).
     * Reset op status to completed so it can be reused. */
    struct na_lsquic_op_id *na_lsquic_op_id =
        (struct na_lsquic_op_id *) arg;

    hg_atomic_set32(&na_lsquic_op_id->status, NA_LSQUIC_OP_COMPLETED);
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_process_recv_unexpected(struct na_lsquic_class *priv,
    struct na_lsquic_addr *source, na_tag_t tag, void *data,
    size_t data_size)
{
    struct na_lsquic_op_id *op;

    NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG("process_recv_unexpected tag=%u size=%zu\n", tag, data_size);

    hg_thread_mutex_lock(&priv->queue_lock);

    /* Try to find a matching recv op in the unexpected queue */
    op = STAILQ_FIRST(&priv->unexpected_recv_queue);
    if (op != NULL) {
        size_t copy_size;

        /* Remove from queue */
        STAILQ_REMOVE_HEAD(&priv->unexpected_recv_queue, entry);

        hg_thread_mutex_unlock(&priv->queue_lock);

        /* Copy data to user buffer */
        copy_size = (data_size < op->info.msg.buf_size)
                        ? data_size
                        : op->info.msg.buf_size;
        if (copy_size > 0 && op->info.msg.buf != NULL)
            memcpy(op->info.msg.buf, data, copy_size);

        /* Fill callback info for unexpected recv */
        op->completion_data.callback_info.info.recv_unexpected.actual_buf_size =
            data_size;
        op->completion_data.callback_info.info.recv_unexpected.tag = tag;

        /* Provide source address (dup for user) */
        if (source != NULL) {
            hg_atomic_incr32(&source->refcount);
            op->completion_data.callback_info.info.recv_unexpected.source =
                (na_addr_t *) source;
        } else {
            op->completion_data.callback_info.info.recv_unexpected.source =
                NULL;
        }

        /* Free data buffer */
        free(data);

        /* Complete the op */
        na_lsquic_complete_op(op, NA_SUCCESS);
    } else {
        /* No matching recv posted - queue the message */
        struct na_lsquic_msg_recv_unexpected *queued =
            (struct na_lsquic_msg_recv_unexpected *) calloc(
                1, sizeof(*queued));
        if (queued == NULL) {
            NA_LOG_SUBSYS_ERROR(msg,
                "Could not allocate unexpected msg queue entry");
            free(data);
            hg_thread_mutex_unlock(&priv->queue_lock);
            return;
        }

        queued->buf = data; /* Takes ownership */
        queued->buf_size = data_size;
        queued->tag = tag;
        if (source != NULL) {
            hg_atomic_incr32(&source->refcount);
            queued->source = source;
        }

        STAILQ_INSERT_TAIL(&priv->unexpected_msg_queue, queued, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_process_recv_expected(struct na_lsquic_class *priv,
    struct na_lsquic_addr *source, na_tag_t tag, uint8_t dest_id,
    void *data, size_t data_size)
{
    struct na_lsquic_op_id *op;
    struct na_lsquic_op_id *match = NULL;

    NA_LSQUIC_TRACE("[%d] TRACE process_recv_expected tag=%u dest_id=%u data_size=%zu\n",
        getpid(), tag, dest_id, data_size);

    hg_thread_mutex_lock(&priv->queue_lock);

    /* Scan expected recv queue for matching op (source, tag, dest_id) */
    STAILQ_FOREACH(op, &priv->expected_recv_queue, entry) {
        if (op->info.msg.tag == tag && op->info.msg.dest_id == dest_id) {
            /* Match source if provided */
            if (op->info.msg.addr == NULL || source == NULL) {
                match = op;
                break;
            }
            if (op->info.msg.addr->ss.ss_family == source->ss.ss_family) {
                if (op->info.msg.addr->ss.ss_family == AF_INET) {
                    struct sockaddr_in *s1 =
                        (struct sockaddr_in *) &op->info.msg.addr->ss;
                    struct sockaddr_in *s2 =
                        (struct sockaddr_in *) &source->ss;
                    if (s1->sin_port == s2->sin_port &&
                        s1->sin_addr.s_addr == s2->sin_addr.s_addr) {
                        match = op;
                        break;
                    }
                } else {
                    struct sockaddr_in6 *s1 =
                        (struct sockaddr_in6 *) &op->info.msg.addr->ss;
                    struct sockaddr_in6 *s2 =
                        (struct sockaddr_in6 *) &source->ss;
                    if (s1->sin6_port == s2->sin6_port &&
                        memcmp(&s1->sin6_addr, &s2->sin6_addr,
                            sizeof(struct in6_addr)) == 0) {
                        match = op;
                        break;
                    }
                }
            }
        }
    }

    if (match != NULL) {
        size_t copy_size;

        NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" process_recv_expected MATCHED tag=%u dest_id=%u\n", tag, dest_id);

        /* Remove from queue */
        STAILQ_REMOVE(&priv->expected_recv_queue, match,
            na_lsquic_op_id, entry);

        hg_thread_mutex_unlock(&priv->queue_lock);

        /* Copy data to user buffer */
        copy_size = (data_size < match->info.msg.buf_size)
                        ? data_size
                        : match->info.msg.buf_size;
        if (copy_size > 0 && match->info.msg.buf != NULL)
            memcpy(match->info.msg.buf, data, copy_size);

        /* Fill callback info */
        match->completion_data.callback_info.info.recv_expected
            .actual_buf_size = data_size;

        free(data);
        na_lsquic_complete_op(match, NA_SUCCESS);
    } else {
        NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" process_recv_expected NO MATCH tag=%u dest_id=%u, queuing\n", tag, dest_id);
        /* No matching recv posted - queue for later matching */
        struct na_lsquic_msg_recv_expected *queued =
            (struct na_lsquic_msg_recv_expected *) calloc(1, sizeof(*queued));
        if (queued != NULL) {
            queued->buf = data;
            queued->buf_size = data_size;
            queued->source = source;
            if (source != NULL)
                hg_atomic_incr32(&source->refcount);
            queued->tag = tag;
            queued->dest_id = dest_id;
            STAILQ_INSERT_TAIL(&priv->expected_msg_queue, queued, entry);
        } else {
            NA_LOG_SUBSYS_WARNING(msg,
                "Could not queue expected message (tag=%u, dest_id=%u)",
                tag, dest_id);
            free(data);
        }
        hg_thread_mutex_unlock(&priv->queue_lock);
    }
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_process_rma_put(struct na_lsquic_class *priv,
    const struct na_lsquic_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_lsquic_mem_handle *mh;

    /* Look up the target memory handle */
    mh = (struct na_lsquic_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) rma_hdr->remote_handle_id);

    if (mh == NULL) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA PUT: unknown handle_id %" PRIu64,
            rma_hdr->remote_handle_id);
        free(data);
        return;
    }

    /* Validate bounds */
    if (rma_hdr->remote_offset + data_size > mh->buf_size) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA PUT: offset+length exceeds buffer (%" PRIu64 "+%zu > %zu)",
            rma_hdr->remote_offset, data_size, mh->buf_size);
        free(data);
        return;
    }

    /* Copy data into the registered buffer */
    memcpy((char *) mh->buf + rma_hdr->remote_offset, data, data_size);
    free(data);
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_process_rma_get(struct na_lsquic_class *priv,
    struct na_lsquic_stream_ctx *sctx,
    const struct na_lsquic_rma_hdr *rma_hdr)
{
    struct na_lsquic_mem_handle *mh;
    NA_LSQUIC_TRACE("[%d] TRACE process_rma_get handle_id=%lu length=%lu\n",
        getpid(), (unsigned long)rma_hdr->remote_handle_id, (unsigned long)rma_hdr->length);
    struct na_lsquic_stream_ctx *resp_sctx;
    struct na_lsquic_conn_ctx *conn_ctx;
    lsquic_conn_t *conn;

    /* Look up the target memory handle */
    mh = (struct na_lsquic_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) rma_hdr->remote_handle_id);

    if (mh == NULL) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA GET: unknown handle_id %" PRIu64,
            rma_hdr->remote_handle_id);
        return;
    }

    /* Validate bounds */
    if (rma_hdr->remote_offset + rma_hdr->length > mh->buf_size) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA GET: offset+length exceeds buffer (%" PRIu64
            "+%" PRIu64 " > %zu)",
            rma_hdr->remote_offset, rma_hdr->length, mh->buf_size);
        return;
    }

    /* Build a response stream context to send data back */
    resp_sctx = (struct na_lsquic_stream_ctx *) calloc(1, sizeof(*resp_sctx));
    if (resp_sctx == NULL) {
        NA_LOG_SUBSYS_ERROR(rma, "Could not allocate RMA response context");
        return;
    }

    resp_sctx->priv = priv;
    resp_sctx->op = NULL; /* No local op - this is a remote-initiated response */
    resp_sctx->is_sender = true;

    /* Data to send is from the local memory handle */
    resp_sctx->send_buf = (const char *) mh->buf + rma_hdr->remote_offset;
    resp_sctx->send_buf_size = rma_hdr->length;
    resp_sctx->hdr_sent = 0;
    resp_sctx->rma_hdr_sent = 0;
    resp_sctx->data_sent = 0;

    /* Fill wire header for response */
    resp_sctx->send_hdr.type = NA_LSQUIC_MSG_RMA_RESP;
    resp_sctx->send_hdr.tag = 0;
    resp_sctx->send_hdr.dest_id = 0;
    resp_sctx->send_hdr.payload_length = rma_hdr->length;
    resp_sctx->send_hdr.source_addr_hash =
        na_lsquic_hash_addr(&priv->self_addr);

    /* Fill RMA header for response (so requester can match) */
    resp_sctx->send_rma_hdr.remote_handle_id = rma_hdr->remote_handle_id;
    resp_sctx->send_rma_hdr.remote_offset = rma_hdr->remote_offset;
    resp_sctx->send_rma_hdr.local_handle_id = rma_hdr->local_handle_id;
    resp_sctx->send_rma_hdr.length = rma_hdr->length;

    /* Send back on the same connection that the request arrived on */
    conn_ctx = sctx->conn_ctx;
    if (conn_ctx == NULL || conn_ctx->addr == NULL ||
        conn_ctx->addr->conn == NULL) {
        NA_LOG_SUBSYS_ERROR(rma,
            "RMA GET: no connection context for response");
        free(resp_sctx);
        return;
    }

    conn = conn_ctx->addr->conn;

    /* Note: engine_lock is held by progress() via trylock, so pending_sends
     * is protected since on_read runs within process_conns */
    STAILQ_INSERT_TAIL(&conn_ctx->pending_sends, resp_sctx, entry);
    lsquic_conn_make_stream(conn);
    hg_atomic_set32(&priv->needs_progress, 1);
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_process_rma_resp(struct na_lsquic_class *priv,
    const struct na_lsquic_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_lsquic_op_id *op;
    struct na_lsquic_op_id *match = NULL;
    struct na_lsquic_mem_handle *local_mh;
    NA_LSQUIC_TRACE("[%d] TRACE process_rma_resp local_handle=%lu remote_handle=%lu size=%zu\n",
        getpid(), (unsigned long)rma_hdr->local_handle_id, (unsigned long)rma_hdr->remote_handle_id, data_size);

    /* Find matching GET op by local_handle_id and remote_handle_id */
    hg_thread_mutex_lock(&priv->queue_lock);
    STAILQ_FOREACH(op, &priv->rma_get_queue, entry) {
        if (op->info.rma.local_handle_id == rma_hdr->local_handle_id &&
            op->info.rma.remote_handle_id == rma_hdr->remote_handle_id &&
            op->info.rma.remote_offset == rma_hdr->remote_offset) {
            match = op;
            break;
        }
    }

    if (match == NULL) {
        hg_thread_mutex_unlock(&priv->queue_lock);
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA RESP: no matching GET op (local_id=%" PRIu64
            ", remote_id=%" PRIu64 ")",
            rma_hdr->local_handle_id, rma_hdr->remote_handle_id);
        free(data);
        return;
    }

    /* Remove from queue */
    STAILQ_REMOVE(&priv->rma_get_queue, match, na_lsquic_op_id, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    /* Look up local memory handle to copy data into */
    local_mh = (struct na_lsquic_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) match->info.rma.local_handle_id);

    if (local_mh == NULL) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA RESP: local handle_id %" PRIu64 " not found",
            match->info.rma.local_handle_id);
        free(data);
        na_lsquic_complete_op(match, NA_FAULT);
        return;
    }

    /* Validate bounds */
    if (match->info.rma.local_offset + data_size > local_mh->buf_size) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA RESP: offset+length exceeds local buffer");
        free(data);
        na_lsquic_complete_op(match, NA_OVERFLOW);
        return;
    }

    /* Copy response data into local buffer */
    memcpy((char *) local_mh->buf + match->info.rma.local_offset,
        data, data_size);
    free(data);

    na_lsquic_complete_op(match, NA_SUCCESS);
}

/*---------------------------------------------------------------------------*/
static unsigned int
na_lsquic_handle_id_hash(hg_hash_table_key_t key)
{
    uint64_t id = (uint64_t) (uintptr_t) key;

    /* Simple hash mixing for uint64 keys */
    return (unsigned int) (id ^ (id >> 16));
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_handle_id_equal(
    hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    return (uintptr_t) key1 == (uintptr_t) key2;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_msg_send(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg,
    const void *buf, size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id, enum na_lsquic_msg_type msg_type,
    na_cb_type_t cb_type)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_addr *dest = (struct na_lsquic_addr *) dest_addr;
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;
    struct na_lsquic_stream_ctx *sctx = NULL;
    struct na_lsquic_conn_ctx *conn_ctx;
    lsquic_conn_t *conn;
    na_return_t ret;

    NA_LSQUIC_TRACE("[%d] TRACE msg_send type=%u tag=%u buf_size=%zu\n",
        getpid(), msg_type, tag, buf_size);

    /* Set up the operation */
    op->context = context;
    op->type = cb_type;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_QUEUED);

    /* Allocate stream context for the send */
    sctx = (struct na_lsquic_stream_ctx *) calloc(1, sizeof(*sctx));
    NA_CHECK_SUBSYS_ERROR(
        msg, sctx == NULL, error, ret, NA_NOMEM, "calloc() failed");

    sctx->priv = priv;
    sctx->op = op;
    sctx->is_sender = true;
    sctx->send_buf = buf;
    sctx->send_buf_size = buf_size;
    sctx->hdr_sent = 0;
    sctx->data_sent = 0;

    NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" msg_send type=%u tag=%u dest_id=%u size=%zu\n",
        (unsigned)msg_type, tag, dest_id, buf_size);

    /* Fill wire header */
    sctx->send_hdr.type = (uint32_t) msg_type;
    sctx->send_hdr.tag = tag;
    sctx->send_hdr.dest_id = dest_id;
    sctx->send_hdr.payload_length = buf_size;
    sctx->send_hdr.source_addr_hash = na_lsquic_hash_addr(&priv->self_addr);

    /* Get or create connection to dest */
    hg_thread_mutex_lock(&priv->engine_lock);

    ret = na_lsquic_get_conn(priv, dest, &conn);
    if (ret != NA_SUCCESS) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        goto error;
    }

    /* Get connection context and queue the send */
    conn_ctx = (struct na_lsquic_conn_ctx *) lsquic_conn_get_ctx(conn);
    if (conn_ctx == NULL) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        ret = NA_PROTOCOL_ERROR;
        goto error;
    }

    STAILQ_INSERT_TAIL(&conn_ctx->pending_sends, sctx, entry);

    /* Request a new stream and run progress to flush data + read ACKs */
    lsquic_conn_make_stream(conn);
    na_lsquic_progress(priv);

    hg_thread_mutex_unlock(&priv->engine_lock);

    return NA_SUCCESS;

error:
    free(sctx);
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_progress(struct na_lsquic_class *priv)
{
    unsigned char pkt_buf[NA_LSQUIC_MAX_UDP_PKT_SIZE];
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nr;
    static unsigned progress_count = 0;
    static unsigned total_pkts_read = 0;
    int pkts_read = 0;
    progress_count++;
    if ((progress_count % 10000) == 0)
        NA_LSQUIC_TRACE("[%d] TRACE progress #%u needs_progress=%d total_pkts=%u\n",
            getpid(), progress_count,
            hg_atomic_get32(&priv->needs_progress), total_pkts_read);

    /* Read-process loop: drain packets and process connections.
     * Multiple iterations help handle retransmissions and ACKs.
     * Caller must hold engine_lock (lsquic is not thread-safe). */
    {
        int iter;
        for (iter = 0; iter < 4; iter++) {
            int got_pkts = 0;

            /* Read incoming UDP packets and feed to engine(s) */
            for (;;) {
                peer_addr_len = sizeof(peer_addr);
                nr = recvfrom(priv->udp_fd, pkt_buf, sizeof(pkt_buf), 0,
                    (struct sockaddr *) &peer_addr, &peer_addr_len);
                if (nr <= 0)
                    break;

                got_pkts = 1;
                pkts_read++;
                total_pkts_read++;
                if (priv->server_engine != NULL) {
                    int rc = lsquic_engine_packet_in(priv->server_engine,
                        pkt_buf, (size_t) nr,
                        (struct sockaddr *) &priv->self_addr,
                        (struct sockaddr *) &peer_addr, priv, 0);
                    if (rc == 0)
                        continue;
                }

                lsquic_engine_packet_in(priv->client_engine,
                    pkt_buf, (size_t) nr,
                    (struct sockaddr *) &priv->self_addr,
                    (struct sockaddr *) &peer_addr, priv, 0);
            }

            /* Process connections on both engines */
            if (priv->server_engine != NULL)
                lsquic_engine_process_conns(priv->server_engine);
            lsquic_engine_process_conns(priv->client_engine);

            /* Send any unsent packets */
            if (priv->server_engine != NULL &&
                lsquic_engine_has_unsent_packets(priv->server_engine))
                lsquic_engine_send_unsent_packets(priv->server_engine);
            if (lsquic_engine_has_unsent_packets(priv->client_engine))
                lsquic_engine_send_unsent_packets(priv->client_engine);

            /* Only iterate if we got packets or have unsent data */
            if (!got_pkts && iter > 0)
                break;
        }
    }

    if ((progress_count % 1000000) == 0)
        NA_LSQUIC_TRACE("[%d] TRACE progress #%u after process (pkts=%d)\n",
            getpid(), progress_count, pkts_read);

    /* Keep needs_progress set if there are unsent packets or any engine
     * has connections needing a tick (retransmit, congestion, etc.) */
    {
        bool need = false;
        int diff;
        if ((priv->server_engine != NULL &&
             lsquic_engine_has_unsent_packets(priv->server_engine)) ||
            lsquic_engine_has_unsent_packets(priv->client_engine))
            need = true;
        if (priv->server_engine != NULL &&
            lsquic_engine_earliest_adv_tick(priv->server_engine, &diff))
            need = true;
        if (lsquic_engine_earliest_adv_tick(priv->client_engine, &diff))
            need = true;
        if ((progress_count % 10000) == 0)
            NA_LSQUIC_TRACE("[%d] TRACE progress #%u set needs_progress=%d pkts_this_call=%d\n",
                getpid(), progress_count, need ? 1 : 0, pkts_read);
        hg_atomic_set32(&priv->needs_progress, need ? 1 : 0);
    }

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_log_buf(void *ctx, const char *buf, size_t len)
{
    (void)ctx;
    NA_LSQUIC_ERR("[%d] LSQUIC: %.*s", getpid(), (int)len, buf);
    return 0;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen)
{
    const struct na_init_info *na_init_info = &na_info->na_init_info;
    struct na_lsquic_class *priv = NULL;
    struct lsquic_engine_api api;
    struct lsquic_engine_settings settings;
    int rc;
    na_return_t ret;

    NA_LOG_SUBSYS_DEBUG(cls, "Initializing lsquic plugin (listen=%d host=%s)",
        listen, na_info->host_name ? na_info->host_name : "(null)");

    /* Initialize lsquic global state */
    rc = lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "lsquic_global_init() failed");

    /* Enable lsquic logging for debugging */
    {
        static struct lsquic_logger_if lsquic_logger = {
            .log_buf = na_lsquic_log_buf,
        };
        lsquic_logger_init(&lsquic_logger, NULL, LLTS_NONE);
        lsquic_set_log_level("alert");
    }

    /* Allocate private class */
    priv = (struct na_lsquic_class *) calloc(1, sizeof(*priv));
    NA_CHECK_SUBSYS_ERROR(cls, priv == NULL, error, ret, NA_NOMEM,
        "Could not allocate lsquic private class");

    priv->udp_fd = -1;
    priv->context_max = na_init_info->max_contexts;
    priv->max_unexpected_size = na_init_info->max_unexpected_size
                                    ? na_init_info->max_unexpected_size
                                    : NA_LSQUIC_MSG_UNEXPECTED_SIZE;
    priv->max_expected_size = na_init_info->max_expected_size
                                  ? na_init_info->max_expected_size
                                  : NA_LSQUIC_MSG_EXPECTED_SIZE;

    /* Initialize queues */
    STAILQ_INIT(&priv->unexpected_recv_queue);
    STAILQ_INIT(&priv->expected_recv_queue);
    STAILQ_INIT(&priv->rma_get_queue);
    STAILQ_INIT(&priv->unexpected_msg_queue);
    STAILQ_INIT(&priv->expected_msg_queue);
    STAILQ_INIT(&priv->conn_list);

    /* Initialize locks */
    rc = hg_thread_mutex_init(&priv->engine_lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_mutex_init() failed");
    rc = hg_thread_mutex_init(&priv->queue_lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_mutex_init() failed");

    /* Initialize atomic handle ID counter */
    hg_atomic_init64(&priv->next_handle_id, 1);
    hg_atomic_init32(&priv->needs_progress, 0);

    /* Initialize memory handle map (for RMA) */
    priv->mem_handle_map = hg_hash_table_new(
        na_lsquic_handle_id_hash, na_lsquic_handle_id_equal);
    NA_CHECK_SUBSYS_ERROR(cls, priv->mem_handle_map == NULL, error, ret,
        NA_NOMEM, "Could not create mem_handle_map");

    /* Create UDP socket */
    ret = na_lsquic_create_udp_socket(na_info->host_name, listen,
        &priv->udp_fd, &priv->self_addr, &priv->self_addr_len);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
        "Could not create UDP socket");

    /* Set up SSL context (needed for both server and client) */
    ret = na_lsquic_setup_ssl_ctx(&priv->ssl_ctx);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
        "Could not set up SSL context");

    /* Set up lsquic stream interface callbacks */
    memset(&priv->stream_if, 0, sizeof(priv->stream_if));
    priv->stream_if.on_new_conn = na_lsquic_on_new_conn;
    priv->stream_if.on_conn_closed = na_lsquic_on_conn_closed;
    priv->stream_if.on_new_stream = na_lsquic_on_new_stream;
    priv->stream_if.on_read = na_lsquic_on_read;
    priv->stream_if.on_write = na_lsquic_on_write;
    priv->stream_if.on_close = na_lsquic_on_close;

    /* Initialize default engine settings */
    lsquic_engine_init_settings(&settings, 0);
    settings.es_idle_timeout = 300; /* seconds */
    /* Allow server-initiated streams to carry large RMA data */
    settings.es_init_max_stream_data_bidi_remote = 16 * 1024 * 1024;
    settings.es_init_max_stream_data_bidi_local = 16 * 1024 * 1024;
    settings.es_init_max_data = 64 * 1024 * 1024;
    settings.es_max_sfcw = 16 * 1024 * 1024;
    settings.es_max_cfcw = 64 * 1024 * 1024;
    settings.es_init_max_streams_bidi = 10000;

    /* Create client engine (always) */
    memset(&api, 0, sizeof(api));
    api.ea_settings = &settings;
    api.ea_stream_if = &priv->stream_if;
    api.ea_stream_if_ctx = priv;
    api.ea_packets_out = na_lsquic_packets_out;
    api.ea_packets_out_ctx = priv;
    api.ea_get_ssl_ctx = na_lsquic_get_ssl_ctx;
    api.ea_alpn = NA_LSQUIC_ALPN;

    priv->client_engine = lsquic_engine_new(0, &api);
    NA_CHECK_SUBSYS_ERROR(cls, priv->client_engine == NULL, error, ret,
        NA_PROTOCOL_ERROR, "lsquic_engine_new(client) failed");

    /* Create server engine if listening */
    if (listen) {
        lsquic_engine_init_settings(&settings, LSENG_SERVER);
        settings.es_idle_timeout = 60;
        settings.es_init_max_stream_data_bidi_remote = 16 * 1024 * 1024;
        settings.es_init_max_stream_data_bidi_local = 16 * 1024 * 1024;
        settings.es_init_max_data = 64 * 1024 * 1024;
        settings.es_max_sfcw = 16 * 1024 * 1024;
        settings.es_max_cfcw = 64 * 1024 * 1024;
        settings.es_init_max_streams_bidi = 10000;

        memset(&api, 0, sizeof(api));
        api.ea_settings = &settings;
        api.ea_stream_if = &priv->stream_if;
        api.ea_stream_if_ctx = priv;
        api.ea_packets_out = na_lsquic_packets_out;
        api.ea_packets_out_ctx = priv;
        api.ea_lookup_cert = NULL; /* Use ea_get_ssl_ctx instead */
        api.ea_get_ssl_ctx = na_lsquic_get_ssl_ctx;
        api.ea_alpn = NA_LSQUIC_ALPN;

        priv->server_engine = lsquic_engine_new(LSENG_SERVER, &api);
        NA_CHECK_SUBSYS_ERROR(cls, priv->server_engine == NULL, error, ret,
            NA_PROTOCOL_ERROR, "lsquic_engine_new(server) failed");
    }

    na_class->plugin_class = (void *) priv;

    NA_LOG_SUBSYS_DEBUG(cls, "Initialized lsquic plugin (listen=%d)", listen);

    return NA_SUCCESS;

error:
    if (priv != NULL) {
        if (priv->client_engine != NULL)
            lsquic_engine_destroy(priv->client_engine);
        if (priv->server_engine != NULL)
            lsquic_engine_destroy(priv->server_engine);
        if (priv->ssl_ctx != NULL)
            SSL_CTX_free(priv->ssl_ctx);
        if (priv->udp_fd >= 0)
            close(priv->udp_fd);
        hg_thread_mutex_destroy(&priv->engine_lock);
        hg_thread_mutex_destroy(&priv->queue_lock);
        free(priv);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_finalize(na_class_t *na_class)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);

    if (priv == NULL)
        return NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(cls, "Finalizing lsquic plugin");

    /* Destroy engines */
    if (priv->server_engine != NULL)
        lsquic_engine_destroy(priv->server_engine);
    if (priv->client_engine != NULL)
        lsquic_engine_destroy(priv->client_engine);

    /* Free SSL context */
    if (priv->ssl_ctx != NULL)
        SSL_CTX_free(priv->ssl_ctx);

    /* Close UDP socket */
    if (priv->udp_fd >= 0)
        close(priv->udp_fd);

    /* Destroy locks */
    hg_thread_mutex_destroy(&priv->engine_lock);
    hg_thread_mutex_destroy(&priv->queue_lock);

    /* Free mem_handle_map */
    if (priv->mem_handle_map != NULL)
        hg_hash_table_free(priv->mem_handle_map);

    /* Free unexpected_msg_queue entries */
    {
        struct na_lsquic_msg_recv_unexpected *queued;
        while (!STAILQ_EMPTY(&priv->unexpected_msg_queue)) {
            queued = STAILQ_FIRST(&priv->unexpected_msg_queue);
            STAILQ_REMOVE_HEAD(&priv->unexpected_msg_queue, entry);
            if (queued->source != NULL)
                hg_atomic_decr32(&queued->source->refcount);
            free(queued->buf);
            free(queued);
        }
    }

    /* Free expected_msg_queue entries */
    {
        struct na_lsquic_msg_recv_expected *queued;
        while (!STAILQ_EMPTY(&priv->expected_msg_queue)) {
            queued = STAILQ_FIRST(&priv->expected_msg_queue);
            STAILQ_REMOVE_HEAD(&priv->expected_msg_queue, entry);
            if (queued->source != NULL)
                hg_atomic_decr32(&queued->source->refcount);
            free(queued->buf);
            free(queued);
        }
    }

    lsquic_global_cleanup();

    free(priv);
    na_class->plugin_class = NULL;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_context_create(na_class_t NA_UNUSED *na_class,
    na_context_t NA_UNUSED *context, void **context_p,
    uint8_t NA_UNUSED id)
{
    /* No per-context state needed yet; store a non-NULL sentinel */
    *context_p = (void *) (uintptr_t) 1;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_context_destroy(na_class_t NA_UNUSED *na_class,
    void NA_UNUSED *context)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_lsquic_op_create(na_class_t *na_class, unsigned long NA_UNUSED flags)
{
    struct na_lsquic_op_id *op = NULL;

    op = (struct na_lsquic_op_id *) calloc(1, sizeof(*op));
    NA_CHECK_SUBSYS_ERROR_NORET(
        op, op == NULL, done, "Could not allocate lsquic operation ID");

    op->na_class = na_class;

    /* Completed by default */
    hg_atomic_init32(&op->status, NA_LSQUIC_OP_COMPLETED);

    /* Set op release callbacks */
    op->completion_data.plugin_callback = na_lsquic_release;
    op->completion_data.plugin_callback_args = op;

done:
    return (na_op_id_t *) op;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;

    NA_CHECK_SUBSYS_WARNING(op,
        !(hg_atomic_get32(&op->status) & NA_LSQUIC_OP_COMPLETED),
        "Attempting to destroy OP ID that was not completed");

    free(op);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_lookup(
    na_class_t NA_UNUSED *na_class, const char *name, na_addr_t **addr_p)
{
    struct na_lsquic_addr *addr = NULL;
    struct sockaddr *sa = NULL;
    socklen_t salen = 0;
    char *host_copy = NULL;
    na_return_t ret;

    addr = (struct na_lsquic_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    /* Parse host:port */
    host_copy = strdup(name);
    NA_CHECK_SUBSYS_ERROR(
        addr, host_copy == NULL, error, ret, NA_NOMEM, "strdup() failed");

    {
        char *port_str = strrchr(host_copy, ':');
        uint16_t port = 0;
        if (port_str != NULL) {
            *port_str = '\0';
            port_str++;
            port = (uint16_t) atoi(port_str);
        }

        ret = na_ip_check_interface(
            host_copy, port, AF_UNSPEC, NULL, &sa, &salen);
        NA_CHECK_SUBSYS_NA_ERROR(
            addr, error, ret, "Could not resolve address: %s", name);
    }

    memcpy(&addr->ss, sa, salen);
    hg_atomic_init32(&addr->refcount, 1);
    addr->is_self = false;
    addr->conn = NULL;

    free(sa);
    free(host_copy);
    *addr_p = (na_addr_t *) addr;

    return NA_SUCCESS;

error:
    free(sa);
    free(host_copy);
    free(addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_lsquic_addr *addr = (struct na_lsquic_addr *) na_addr;

    if (addr == NULL)
        return;

    if (hg_atomic_decr32(&addr->refcount) == 0)
        free(addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_self(na_class_t *na_class, na_addr_t **addr_p)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_addr *addr = NULL;
    na_return_t ret;

    addr = (struct na_lsquic_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    memcpy(&addr->ss, &priv->self_addr, priv->self_addr_len);
    hg_atomic_init32(&addr->refcount, 1);
    addr->is_self = true;
    addr->conn = NULL;

    *addr_p = (na_addr_t *) addr;
    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr,
    na_addr_t **new_addr_p)
{
    struct na_lsquic_addr *addr = (struct na_lsquic_addr *) na_addr;

    hg_atomic_incr32(&addr->refcount);
    *new_addr_p = na_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static bool
na_lsquic_addr_cmp(na_class_t NA_UNUSED *na_class, na_addr_t *addr1,
    na_addr_t *addr2)
{
    struct na_lsquic_addr *a1 = (struct na_lsquic_addr *) addr1;
    struct na_lsquic_addr *a2 = (struct na_lsquic_addr *) addr2;
    struct sockaddr_in *sin1, *sin2;
    struct sockaddr_in6 *sin6_1, *sin6_2;

    if (a1->ss.ss_family != a2->ss.ss_family)
        return false;

    if (a1->ss.ss_family == AF_INET) {
        sin1 = (struct sockaddr_in *) &a1->ss;
        sin2 = (struct sockaddr_in *) &a2->ss;
        return (sin1->sin_port == sin2->sin_port) &&
               (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr);
    } else if (a1->ss.ss_family == AF_INET6) {
        sin6_1 = (struct sockaddr_in6 *) &a1->ss;
        sin6_2 = (struct sockaddr_in6 *) &a2->ss;
        return (sin6_1->sin6_port == sin6_2->sin6_port) &&
               (memcmp(&sin6_1->sin6_addr, &sin6_2->sin6_addr,
                    sizeof(struct in6_addr)) == 0);
    }

    return false;
}

/*---------------------------------------------------------------------------*/
static bool
na_lsquic_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_lsquic_addr *addr = (struct na_lsquic_addr *) na_addr;

    return addr->is_self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    size_t *buf_size, na_addr_t *na_addr)
{
    struct na_lsquic_addr *addr = (struct na_lsquic_addr *) na_addr;
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
    socklen_t salen;
    int rc;
    size_t needed;

    salen = (addr->ss.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                              : sizeof(struct sockaddr_in);

    rc = getnameinfo((struct sockaddr *) &addr->ss, salen, host, sizeof(host),
        port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        /* Fallback */
        needed = (size_t) snprintf(buf, *buf_size, "<unknown>");
        *buf_size = needed + 1;
        return NA_SUCCESS;
    }

    needed = (size_t) snprintf(buf, *buf_size, "%s:%s", host, port);
    *buf_size = needed + 1;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
na_lsquic_addr_get_serialize_size(
    na_class_t NA_UNUSED *na_class, na_addr_t NA_UNUSED *addr)
{
    /* Serialize: family(2) + sockaddr_in or sockaddr_in6 */
    return sizeof(struct sockaddr_storage);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_addr_t *na_addr)
{
    struct na_lsquic_addr *addr = (struct na_lsquic_addr *) na_addr;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(struct sockaddr_storage),
        error, ret, NA_OVERFLOW, "Buffer too small for serialization");

    memcpy(buf, &addr->ss, sizeof(struct sockaddr_storage));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_addr_deserialize(na_class_t *na_class,
    na_addr_t **addr_p, const void *buf, size_t buf_size,
    uint64_t NA_UNUSED flags)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_addr *addr = NULL;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(struct sockaddr_storage),
        error, ret, NA_OVERFLOW, "Buffer too small for deserialization");

    addr = (struct na_lsquic_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    memcpy(&addr->ss, buf, sizeof(struct sockaddr_storage));
    hg_atomic_init32(&addr->refcount, 1);
    addr->conn = NULL;

    /* Check if deserialized address matches our own address */
    {
        struct na_lsquic_addr self_tmp;
        memcpy(&self_tmp.ss, &priv->self_addr, priv->self_addr_len);
        addr->is_self = na_lsquic_addr_cmp(NULL,
            (na_addr_t *) &self_tmp, (na_addr_t *) addr);
    }

    *addr_p = (na_addr_t *) addr;
    return NA_SUCCESS;

error:
    free(addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static size_t
na_lsquic_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_LSQUIC_CLASS(na_class)->max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static size_t
na_lsquic_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_LSQUIC_CLASS(na_class)->max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_lsquic_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_TAG_MAX;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_msg_send_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_lsquic_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_LSQUIC_MSG_UNEXPECTED, NA_CB_SEND_UNEXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_msg_recv_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data, na_op_id_t *op_id)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;
    struct na_lsquic_msg_recv_unexpected *queued;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_UNEXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_QUEUED);

    /* Lock to protect queue access - these queues are also accessed
     * from process_recv_unexpected (under queue_lock during process_conns) */
    hg_thread_mutex_lock(&priv->queue_lock);

    /* Check if there's already a queued unexpected message */
    queued = STAILQ_FIRST(&priv->unexpected_msg_queue);
    if (queued != NULL) {
        size_t copy_size;

        STAILQ_REMOVE_HEAD(&priv->unexpected_msg_queue, entry);

        hg_thread_mutex_unlock(&priv->queue_lock);

        /* Copy data */
        copy_size = (queued->buf_size < buf_size)
                        ? queued->buf_size : buf_size;
        if (copy_size > 0 && buf != NULL)
            memcpy(buf, queued->buf, copy_size);

        /* Fill callback info */
        op->completion_data.callback_info.info.recv_unexpected
            .actual_buf_size = queued->buf_size;
        op->completion_data.callback_info.info.recv_unexpected.tag =
            queued->tag;
        op->completion_data.callback_info.info.recv_unexpected.source =
            (na_addr_t *) queued->source; /* Transfer ownership */

        free(queued->buf);
        free(queued);

        na_lsquic_complete_op(op, NA_SUCCESS);
        return NA_SUCCESS;
    }

    /* No queued message - add op to unexpected recv queue */
    STAILQ_INSERT_TAIL(&priv->unexpected_recv_queue, op, entry);

    hg_thread_mutex_unlock(&priv->queue_lock);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_msg_send_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_lsquic_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_LSQUIC_MSG_EXPECTED, NA_CB_SEND_EXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_msg_recv_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *source_addr, uint8_t source_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_EXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    op->info.msg.addr = (struct na_lsquic_addr *) source_addr;
    op->info.msg.tag = tag;
    op->info.msg.dest_id = source_id;
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_QUEUED);

    NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG(" msg_recv_expected posted tag=%u source_id=%u\n", tag, source_id);

    /* Lock to protect queue access - these queues are also accessed
     * from process_recv_expected (under queue_lock during process_conns) */
    hg_thread_mutex_lock(&priv->queue_lock);

    /* Check if there's already a queued expected message that matches */
    {
        struct na_lsquic_msg_recv_expected *queued, *prev = NULL;
        STAILQ_FOREACH(queued, &priv->expected_msg_queue, entry) {
            if (queued->tag == tag && queued->dest_id == source_id) {
                /* Match found - remove from queue and complete immediately */
                if (prev == NULL)
                    STAILQ_REMOVE_HEAD(&priv->expected_msg_queue, entry);
                else
                    STAILQ_REMOVE(&priv->expected_msg_queue, queued,
                        na_lsquic_msg_recv_expected, entry);

                hg_thread_mutex_unlock(&priv->queue_lock);

                {
                    size_t copy_size =
                        (queued->buf_size < buf_size)
                            ? queued->buf_size : buf_size;
                    if (copy_size > 0 && buf != NULL)
                        memcpy(buf, queued->buf, copy_size);

                    op->completion_data.callback_info.info.recv_expected
                        .actual_buf_size = queued->buf_size;
                }

                free(queued->buf);
                if (queued->source != NULL)
                    hg_atomic_decr32(&queued->source->refcount);
                free(queued);

                na_lsquic_complete_op(op, NA_SUCCESS);
                return NA_SUCCESS;
            }
            prev = queued;
        }
    }

    /* No match yet - add to expected recv queue */
    STAILQ_INSERT_TAIL(&priv->expected_recv_queue, op, entry);

    hg_thread_mutex_unlock(&priv->queue_lock);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, unsigned long flags,
    na_mem_handle_t **mem_handle_p)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_mem_handle *mh = NULL;
    na_return_t ret;

    mh = (struct na_lsquic_mem_handle *) calloc(1, sizeof(*mh));
    NA_CHECK_SUBSYS_ERROR(
        mem, mh == NULL, error, ret, NA_NOMEM, "calloc() failed");

    mh->buf = buf;
    mh->buf_size = buf_size;
    mh->flags = flags;
    mh->handle_id = (uint64_t) hg_atomic_incr64(&priv->next_handle_id);

    NA_LSQUIC_DBG("DEBUG[%d]: ", getpid()); NA_LSQUIC_DBG("mem_handle_create id=%lu buf=%p size=%zu flags=%lx\n",
        (unsigned long)mh->handle_id, buf, buf_size, flags);

    /* Register in handle map so remote RMA can look it up */
    hg_hash_table_insert(priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) mh->handle_id,
        (hg_hash_table_value_t) mh);

    *mem_handle_p = (na_mem_handle_t *) mh;
    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_lsquic_mem_handle_free(
    na_class_t *na_class, na_mem_handle_t *mem_handle)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_mem_handle *mh =
        (struct na_lsquic_mem_handle *) mem_handle;

    /* Remove from handle map (only if locally created with a real buf) */
    if (mh->buf != NULL) {
        hg_hash_table_remove(priv->mem_handle_map,
            (hg_hash_table_key_t) (uintptr_t) mh->handle_id);
    }

    free(mh);
}

/*---------------------------------------------------------------------------*/
static size_t
na_lsquic_mem_handle_get_serialize_size(
    na_class_t NA_UNUSED *na_class, na_mem_handle_t NA_UNUSED *mem_handle)
{
    /* handle_id(8) + buf_size(8) + flags(8) */
    return sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_mem_handle_t *mem_handle)
{
    struct na_lsquic_mem_handle *mh =
        (struct na_lsquic_mem_handle *) mem_handle;
    char *buf_ptr = (char *) buf;
    size_t buf_size_left = buf_size;
    na_return_t ret = NA_SUCCESS;

    NA_ENCODE(error, ret, buf_ptr, buf_size_left, &mh->handle_id, uint64_t);
    NA_ENCODE(error, ret, buf_ptr, buf_size_left, &mh->buf_size, uint64_t);
    NA_ENCODE(error, ret, buf_ptr, buf_size_left, &mh->flags, uint64_t);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size)
{
    struct na_lsquic_mem_handle *mh = NULL;
    const char *buf_ptr = (const char *) buf;
    size_t buf_size_left = buf_size;
    na_return_t ret;

    mh = (struct na_lsquic_mem_handle *) calloc(1, sizeof(*mh));
    NA_CHECK_SUBSYS_ERROR(
        mem, mh == NULL, error, ret, NA_NOMEM, "calloc() failed");

    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->handle_id, uint64_t);
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->buf_size, uint64_t);
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->flags, uint64_t);

    /* Note: deserialized handle has no local buf pointer (remote ref only) */
    mh->buf = NULL;

    *mem_handle_p = (na_mem_handle_t *) mh;
    return NA_SUCCESS;

error:
    free(mh);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_put(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_mem_handle *local_mh =
        (struct na_lsquic_mem_handle *) local_mem_handle;
    struct na_lsquic_mem_handle *remote_mh =
        (struct na_lsquic_mem_handle *) remote_mem_handle;
    struct na_lsquic_addr *dest = (struct na_lsquic_addr *) remote_addr;
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;
    struct na_lsquic_stream_ctx *sctx = NULL;
    struct na_lsquic_conn_ctx *conn_ctx;
    lsquic_conn_t *conn;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(rma,
        local_offset + length > local_mh->buf_size, error, ret, NA_OVERFLOW,
        "Local offset+length exceeds buffer size");

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_PUT;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->completion_data.callback_info.type = NA_CB_PUT;
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_QUEUED);

    /* Allocate stream context for the send */
    sctx = (struct na_lsquic_stream_ctx *) calloc(1, sizeof(*sctx));
    NA_CHECK_SUBSYS_ERROR(
        rma, sctx == NULL, error, ret, NA_NOMEM, "calloc() failed");

    sctx->priv = priv;
    sctx->op = op;
    sctx->is_sender = true;

    /* Data to send is from the local memory handle at local_offset */
    sctx->send_buf = (const char *) local_mh->buf + local_offset;
    sctx->send_buf_size = length;
    sctx->hdr_sent = 0;
    sctx->rma_hdr_sent = 0;
    sctx->data_sent = 0;

    /* Fill wire header */
    sctx->send_hdr.type = NA_LSQUIC_MSG_RMA_PUT;
    sctx->send_hdr.tag = 0;
    sctx->send_hdr.dest_id = remote_id;
    sctx->send_hdr.payload_length = length;
    sctx->send_hdr.source_addr_hash = na_lsquic_hash_addr(&priv->self_addr);

    /* Fill RMA header */
    sctx->send_rma_hdr.remote_handle_id = remote_mh->handle_id;
    sctx->send_rma_hdr.remote_offset = remote_offset;
    sctx->send_rma_hdr.local_handle_id = 0; /* Not used for PUT */
    sctx->send_rma_hdr.length = length;

    /* Get or create connection to dest */
    hg_thread_mutex_lock(&priv->engine_lock);

    ret = na_lsquic_get_conn(priv, dest, &conn);
    if (ret != NA_SUCCESS) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        goto error;
    }

    conn_ctx = (struct na_lsquic_conn_ctx *) lsquic_conn_get_ctx(conn);
    if (conn_ctx == NULL) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        ret = NA_PROTOCOL_ERROR;
        goto error;
    }

    STAILQ_INSERT_TAIL(&conn_ctx->pending_sends, sctx, entry);
    lsquic_conn_make_stream(conn);

    /* Run full progress to flush data and read ACKs (prevents congestion
     * starvation when many concurrent PUTs hold engine_lock) */
    na_lsquic_progress(priv);

    hg_thread_mutex_unlock(&priv->engine_lock);

    return NA_SUCCESS;

error:
    free(sctx);
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_get(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_mem_handle *local_mh =
        (struct na_lsquic_mem_handle *) local_mem_handle;
    struct na_lsquic_mem_handle *remote_mh =
        (struct na_lsquic_mem_handle *) remote_mem_handle;
    struct na_lsquic_addr *dest = (struct na_lsquic_addr *) remote_addr;
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;
    struct na_lsquic_stream_ctx *sctx = NULL;
    struct na_lsquic_conn_ctx *conn_ctx;
    lsquic_conn_t *conn;
    na_return_t ret;

    NA_LSQUIC_TRACE("[%d] TRACE NA_GET remote_handle=%lu length=%zu remote_offset=%lu (entering)\n",
        getpid(), (unsigned long)remote_mh->handle_id, length, (unsigned long)remote_offset);

    NA_CHECK_SUBSYS_ERROR(rma,
        local_offset + length > local_mh->buf_size, error, ret, NA_OVERFLOW,
        "Local offset+length exceeds buffer size");

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_GET;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->completion_data.callback_info.type = NA_CB_GET;
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_QUEUED);

    /* Store local handle info in op so we can copy data when response arrives */
    op->info.rma.local_handle_id = local_mh->handle_id;
    op->info.rma.remote_handle_id = remote_mh->handle_id;
    op->info.rma.local_offset = local_offset;
    op->info.rma.remote_offset = remote_offset;
    op->info.rma.length = length;

    /* Add to pending RMA GET queue - will be matched when response arrives */
    hg_thread_mutex_lock(&priv->queue_lock);
    STAILQ_INSERT_TAIL(&priv->rma_get_queue, op, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    /* Allocate stream context to send the GET request */
    sctx = (struct na_lsquic_stream_ctx *) calloc(1, sizeof(*sctx));
    NA_CHECK_SUBSYS_ERROR(
        rma, sctx == NULL, error_dequeue, ret, NA_NOMEM, "calloc() failed");

    sctx->priv = priv;
    sctx->op = NULL; /* Op completes when response arrives, not when request is sent */
    sctx->is_sender = true;

    /* No payload for GET request */
    sctx->send_buf = NULL;
    sctx->send_buf_size = 0;
    sctx->hdr_sent = 0;
    sctx->rma_hdr_sent = 0;
    sctx->data_sent = 0;

    /* Fill wire header */
    sctx->send_hdr.type = NA_LSQUIC_MSG_RMA_GET;
    sctx->send_hdr.tag = 0;
    sctx->send_hdr.dest_id = remote_id;
    sctx->send_hdr.payload_length = 0;
    sctx->send_hdr.source_addr_hash = na_lsquic_hash_addr(&priv->self_addr);

    /* Fill RMA header */
    sctx->send_rma_hdr.remote_handle_id = remote_mh->handle_id;
    sctx->send_rma_hdr.remote_offset = remote_offset;
    sctx->send_rma_hdr.local_handle_id = local_mh->handle_id;
    sctx->send_rma_hdr.length = length;

    /* Get or create connection to dest */
    hg_thread_mutex_lock(&priv->engine_lock);

    ret = na_lsquic_get_conn(priv, dest, &conn);
    if (ret != NA_SUCCESS) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        goto error_dequeue;
    }

    conn_ctx = (struct na_lsquic_conn_ctx *) lsquic_conn_get_ctx(conn);
    if (conn_ctx == NULL) {
        hg_thread_mutex_unlock(&priv->engine_lock);
        ret = NA_PROTOCOL_ERROR;
        goto error_dequeue;
    }

    STAILQ_INSERT_TAIL(&conn_ctx->pending_sends, sctx, entry);
    lsquic_conn_make_stream(conn);

    /* Run full progress to flush data and read ACKs */
    na_lsquic_progress(priv);

    hg_thread_mutex_unlock(&priv->engine_lock);

    NA_LSQUIC_TRACE("[%d] TRACE NA_GET done, returning NA_SUCCESS\n", getpid());
    return NA_SUCCESS;

error_dequeue:
    hg_thread_mutex_lock(&priv->queue_lock);
    STAILQ_REMOVE(&priv->rma_get_queue, op, na_lsquic_op_id, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);
    free(sctx);
error:
    NA_LSQUIC_TRACE("[%d] TRACE NA_GET ERROR ret=%d\n", getpid(), ret);
    hg_atomic_set32(&op->status, NA_LSQUIC_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_poll_get_fd(na_class_t *na_class,
    na_context_t NA_UNUSED *context)
{
    return NA_LSQUIC_CLASS(na_class)->udp_fd;
}

/*---------------------------------------------------------------------------*/
static bool
na_lsquic_poll_try_wait(na_class_t *na_class,
    na_context_t NA_UNUSED *context)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    int diff;
    static unsigned ptw_count = 0;
    ptw_count++;
    if (ptw_count % 500 == 0)
        NA_LSQUIC_DBG("DEBUG[%d]:  poll_try_wait #%u\n", getpid(), ptw_count);

    /* Check if streams were queued but not yet flushed by process_conns */
    if (hg_atomic_get32(&priv->needs_progress))
        return false;

    /* Check if any queued unexpected messages are waiting */
    if (!STAILQ_EMPTY(&priv->unexpected_msg_queue))
        return false;

    /* Check if lsquic engine has pending work (timers, retransmits, etc.) */
    if (priv->server_engine != NULL &&
        lsquic_engine_earliest_adv_tick(priv->server_engine, &diff) &&
        diff <= 0)
        return false;

    if (lsquic_engine_earliest_adv_tick(priv->client_engine, &diff) &&
        diff <= 0)
        return false;

    return true;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_poll(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int *count_p)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    static unsigned poll_count = 0;
    poll_count++;
    if (poll_count <= 3 || poll_count % 5000 == 0)
        NA_LSQUIC_DBG("DEBUG[%d]:  poll #%u\n", getpid(), poll_count);

    /* Use trylock so only one thread drives the engine at a time;
     * other threads skip and return, allowing them to process completions */
    if (hg_thread_mutex_try_lock(&priv->engine_lock) == HG_UTIL_SUCCESS) {
        na_lsquic_progress(priv);
        hg_thread_mutex_unlock(&priv->engine_lock);
    }

    if (count_p != NULL)
        *count_p = NA_Context_get_completion_count(context);
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
na_lsquic_engine_timeout_us(struct na_lsquic_class *priv)
{
    int diff, min_diff = INT_MAX;

    /* Check both engines for earliest advisory tick */
    if (priv->server_engine != NULL &&
        lsquic_engine_earliest_adv_tick(priv->server_engine, &diff)) {
        if (diff < min_diff)
            min_diff = diff;
    }
    if (lsquic_engine_earliest_adv_tick(priv->client_engine, &diff)) {
        if (diff < min_diff)
            min_diff = diff;
    }

    return min_diff;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_poll_wait(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms, unsigned int *count_p)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct pollfd pfd;
    int rc, poll_timeout_ms;
    int engine_timeout_us;

    /* Determine poll timeout: use the smaller of user timeout and
     * lsquic engine's earliest advisory tick time */
    poll_timeout_ms = (int) timeout_ms;
    engine_timeout_us = na_lsquic_engine_timeout_us(priv);
    if (engine_timeout_us != INT_MAX) {
        int engine_ms = (engine_timeout_us <= 0)
                            ? 0
                            : (engine_timeout_us + 999) / 1000;
        if (engine_ms < poll_timeout_ms)
            poll_timeout_ms = engine_ms;
    }

    NA_LSQUIC_DBG("DEBUG[%d]:  poll_wait timeout_ms=%d engine_us=%d\n",
        getpid(), poll_timeout_ms, engine_timeout_us);

    /* Wait for data on the UDP socket */
    pfd.fd = priv->udp_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    rc = poll(&pfd, 1, poll_timeout_ms);
    if (rc < 0 && errno != EINTR)
        return NA_IO_ERROR;

    /* Process regardless of poll result (timers may need processing) */
    hg_thread_mutex_lock(&priv->engine_lock);
    na_lsquic_progress(priv);
    hg_thread_mutex_unlock(&priv->engine_lock);

    if (count_p != NULL)
        *count_p = NA_Context_get_completion_count(context);

    /* Only return TIMEOUT if the user's actual timeout has elapsed */
    if (rc == 0 && poll_timeout_ms >= (int) timeout_ms)
        return NA_TIMEOUT;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_lsquic_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
    na_op_id_t *op_id)
{
    struct na_lsquic_class *priv = NA_LSQUIC_CLASS(na_class);
    struct na_lsquic_op_id *op = (struct na_lsquic_op_id *) op_id;

    if (!(hg_atomic_get32(&op->status) & NA_LSQUIC_OP_QUEUED))
        return NA_SUCCESS;

    /* Try to remove from unexpected recv queue */
    if (op->type == NA_CB_RECV_UNEXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->unexpected_recv_queue, op,
            na_lsquic_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    /* Try to remove from expected recv queue */
    if (op->type == NA_CB_RECV_EXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->expected_recv_queue, op,
            na_lsquic_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    /* Try to remove from RMA GET queue */
    if (op->type == NA_CB_GET) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->rma_get_queue, op,
            na_lsquic_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    /* Complete with canceled status */
    na_lsquic_complete_op(op, NA_CANCELED);

    return NA_SUCCESS;
}
