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

#include <curl/curl.h>
#include <curl/multi.h>
#include <microhttpd.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/****************/
/* Local Macros */
/****************/

/* Name used in class_name field */
#define NA_HTTP_CLASS_NAME "http"

/* Protocol name used for URI matching */
#define NA_HTTP_PROTOCOL_NAME "http"

/* Default max message sizes */
#define NA_HTTP_MSG_UNEXPECTED_SIZE (4096)
#define NA_HTTP_MSG_EXPECTED_SIZE   (4 * 1024 * 1024)

/* Max held connections per client (for NAT traversal) */
#define NA_HTTP_MAX_HELD_PER_CLIENT 8

/* Op status bits */
#define NA_HTTP_OP_COMPLETED (1 << 0)
#define NA_HTTP_OP_CANCELED  (1 << 1)
#define NA_HTTP_OP_QUEUED    (1 << 2)

/* Accessor macro */
#define NA_HTTP_CLASS(na_class)                                                \
    ((struct na_http_class *) (na_class->plugin_class))

/* Wire format sizes */
#define NA_HTTP_MSG_HDR_SIZE  (sizeof(struct na_http_msg_hdr))
#define NA_HTTP_RMA_HDR_SIZE  (sizeof(struct na_http_rma_hdr))
#define NA_HTTP_SOURCE_SIZE   (sizeof(struct sockaddr_storage))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Wire protocol message types */
enum na_http_msg_type {
    NA_HTTP_MSG_UNEXPECTED = 1,
    NA_HTTP_MSG_EXPECTED   = 2,
    NA_HTTP_MSG_RMA_PUT    = 3,
    NA_HTTP_MSG_RMA_GET    = 4,
    NA_HTTP_MSG_RMA_RESP   = 5
};

/* Wire protocol header (17 bytes) */
struct na_http_msg_hdr {
    uint32_t type;
    uint32_t tag;
    uint8_t dest_id;
    uint64_t payload_length;
} NA_PACKED();

/* Wire protocol RMA header extension (32 bytes) */
struct na_http_rma_hdr {
    uint64_t remote_handle_id;
    uint64_t remote_offset;
    uint64_t local_handle_id;
    uint64_t length;
} NA_PACKED();

/* Address */
struct na_http_addr {
    struct sockaddr_storage ss;   /* Peer address (IP:port) */
    hg_atomic_int32_t refcount;   /* Reference count */
    bool is_self;                 /* True if this is our own address */
};

/* Msg info stored in op */
struct na_http_msg_info {
    void *buf;
    size_t buf_size;
    void *plugin_data;
    struct na_http_addr *addr;
    na_tag_t tag;
    uint8_t dest_id;
};

/* RMA info stored in op */
struct na_http_rma_info {
    struct na_http_addr *addr;
    uint64_t local_handle_id;
    uint64_t remote_handle_id;
    uint64_t local_offset;
    uint64_t remote_offset;
    uint64_t length;
    uint8_t remote_id;
};

/* Op ID */
struct na_http_op_id {
    struct na_cb_completion_data completion_data; /* Must be accessible */
    union {
        struct na_http_msg_info msg;
        struct na_http_rma_info rma;
    } info;
    STAILQ_ENTRY(na_http_op_id) entry;
    na_class_t *na_class;
    na_context_t *context;
    hg_atomic_int32_t status;
    na_cb_type_t type;
};

/* Memory handle */
struct na_http_mem_handle {
    void *buf;
    size_t buf_size;
    unsigned long flags;
    uint64_t handle_id;
};

/* Received unexpected message (queued when no matching recv is posted) */
struct na_http_msg_recv_unexpected {
    STAILQ_ENTRY(na_http_msg_recv_unexpected) entry;
    void *buf;
    size_t buf_size;
    struct na_http_addr *source;
    na_tag_t tag;
};

/* Queued expected message (arrived before recv_expected posted) */
struct na_http_msg_recv_expected {
    STAILQ_ENTRY(na_http_msg_recv_expected) entry;
    void *buf;
    size_t buf_size;
    struct na_http_addr *source;
    na_tag_t tag;
    uint8_t dest_id;
};

/* Held MHD connection waiting to carry a response (NAT traversal) */
struct na_http_held_conn {
    STAILQ_ENTRY(na_http_held_conn) entry;
    struct MHD_Connection *connection;
    struct na_http_request_state *rs;   /* Back-pointer to clear rs->held */
};

/* Per-client pool of held connections */
struct na_http_client_pool {
    STAILQ_ENTRY(na_http_client_pool) entry;
    struct sockaddr_storage client_ss;
    STAILQ_HEAD(, na_http_held_conn) held_conns;
    int count;
};

/* MHD per-request state (body accumulation) */
struct na_http_request_state {
    char *data;
    size_t data_size;
    size_t data_alloc;
    struct na_http_held_conn *held;    /* Non-NULL if connection is suspended */
    struct na_http_class *priv;        /* Back-pointer for cleanup */
};

/* Per-transfer state for curl cleanup */
struct na_http_curl_state {
    struct curl_slist *headers;
    struct na_http_class *priv;   /* Back-pointer for dispatching response */
    char *resp_data;              /* Accumulated response body */
    size_t resp_size;             /* Response body size */
    struct sockaddr_storage dest_ss; /* Address we sent to (for source override) */
};

/* Private class data */
struct na_http_class {
    struct MHD_Daemon *mhd_daemon;       /* libmicrohttpd daemon */
    int mhd_epoll_fd;                    /* MHD's epoll FD */
    CURLM *curl_multi;                   /* curl multi handle */
    int wakeup_pipe[2];                  /* Wakeup pipe for signaling */
    struct sockaddr_storage self_addr;    /* Our bound address */
    socklen_t self_addr_len;

    hg_thread_mutex_t socket_lock;       /* Protects transport ops */
    hg_thread_mutex_t queue_lock;        /* Protects recv/rma queues */

    /* Pending recv op queues (posted by app, waiting for data) */
    STAILQ_HEAD(, na_http_op_id) unexpected_recv_queue;
    STAILQ_HEAD(, na_http_op_id) expected_recv_queue;

    /* Pending RMA GET ops (waiting for RMA_RESP) */
    STAILQ_HEAD(, na_http_op_id) rma_get_queue;

    /* Unexpected messages received but not yet matched */
    STAILQ_HEAD(, na_http_msg_recv_unexpected) unexpected_msg_queue;

    /* Expected messages received but not yet matched */
    STAILQ_HEAD(, na_http_msg_recv_expected) expected_msg_queue;

    /* Memory handle map (for RMA) */
    hg_hash_table_t *mem_handle_map;
    hg_atomic_int64_t next_handle_id;

    /* Held connection pools for NAT traversal */
    STAILQ_HEAD(, na_http_client_pool) client_pools;

    /* Message size limits */
    size_t max_unexpected_size;
    size_t max_expected_size;
};

/********************/
/* Local Prototypes */
/********************/

/* get_protocol_info */
static na_return_t
na_http_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p);

/* check_protocol */
static bool
na_http_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_http_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen);

/* finalize */
static na_return_t
na_http_finalize(na_class_t *na_class);

/* context_create */
static na_return_t
na_http_context_create(na_class_t *na_class, na_context_t *context,
    void **context_p, uint8_t id);

/* context_destroy */
static na_return_t
na_http_context_destroy(na_class_t *na_class, void *context);

/* op_create */
static na_op_id_t *
na_http_op_create(na_class_t *na_class, unsigned long flags);

/* op_destroy */
static void
na_http_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_http_addr_lookup(
    na_class_t *na_class, const char *name, na_addr_t **addr_p);

/* addr_free */
static void
na_http_addr_free(na_class_t *na_class, na_addr_t *addr);

/* addr_self */
static na_return_t
na_http_addr_self(na_class_t *na_class, na_addr_t **addr_p);

/* addr_dup */
static na_return_t
na_http_addr_dup(
    na_class_t *na_class, na_addr_t *addr, na_addr_t **new_addr_p);

/* addr_cmp */
static bool
na_http_addr_cmp(na_class_t *na_class, na_addr_t *addr1, na_addr_t *addr2);

/* addr_is_self */
static bool
na_http_addr_is_self(na_class_t *na_class, na_addr_t *addr);

/* addr_to_string */
static na_return_t
na_http_addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size, na_addr_t *addr);

/* addr_get_serialize_size */
static size_t
na_http_addr_get_serialize_size(na_class_t *na_class, na_addr_t *addr);

/* addr_serialize */
static na_return_t
na_http_addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t *addr);

/* addr_deserialize */
static na_return_t
na_http_addr_deserialize(na_class_t *na_class, na_addr_t **addr_p,
    const void *buf, size_t buf_size, uint64_t flags);

/* msg_get_max_unexpected_size */
static size_t
na_http_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static size_t
na_http_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_max_tag */
static na_tag_t
na_http_msg_get_max_tag(const na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t
na_http_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_http_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size,
    void *plugin_data, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_http_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_http_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *source_addr, uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id);

/* mem_handle_create */
static na_return_t
na_http_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t **mem_handle_p);

/* mem_handle_free */
static void
na_http_mem_handle_free(na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_get_serialize_size */
static size_t
na_http_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_serialize */
static na_return_t
na_http_mem_handle_serialize(na_class_t *na_class, void *buf, size_t buf_size,
    na_mem_handle_t *mem_handle);

/* mem_handle_deserialize */
static na_return_t
na_http_mem_handle_deserialize(na_class_t *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size);

/* put */
static na_return_t
na_http_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_http_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static int
na_http_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static bool
na_http_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* poll */
static na_return_t
na_http_poll(
    na_class_t *na_class, na_context_t *context, unsigned int *count_p);

/* poll_wait */
static na_return_t
na_http_poll_wait(na_class_t *na_class, na_context_t *context,
    unsigned int timeout_ms, unsigned int *count_p);

/* cancel */
static na_return_t
na_http_cancel(
    na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/* Internal helpers */
static void
na_http_release(void *arg);

static unsigned int
na_http_handle_id_hash(hg_hash_table_key_t key);

static int
na_http_handle_id_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

static void
na_http_complete_op(struct na_http_op_id *op, na_return_t ret);

static na_return_t
na_http_progress(struct na_http_class *priv);

static na_return_t
na_http_send_msg(struct na_http_class *priv,
    const struct sockaddr_storage *dest_ss,
    const struct na_http_msg_hdr *hdr,
    const struct na_http_rma_hdr *rma_hdr,
    const void *payload, size_t payload_size);

static void
na_http_process_recv_unexpected(struct na_http_class *priv,
    struct na_http_addr *source, na_tag_t tag, void *data, size_t data_size);

static void
na_http_process_recv_expected(struct na_http_class *priv,
    struct na_http_addr *source, na_tag_t tag, uint8_t dest_id,
    void *data, size_t data_size);

static void
na_http_process_rma_put(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr, void *data, size_t data_size);

static void
na_http_process_rma_get(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr,
    const struct sockaddr_storage *requester_ss);

static void
na_http_process_rma_resp(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr, void *data, size_t data_size);

static enum MHD_Result
na_http_mhd_handler(void *cls, struct MHD_Connection *connection,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size, void **req_cls);

static void
na_http_mhd_completed(void *cls, struct MHD_Connection *connection,
    void **req_cls, enum MHD_RequestTerminationCode toe);

static size_t
na_http_curl_write_cb(void *contents, size_t size, size_t nmemb,
    void *userp);

static bool
na_http_ss_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b);

static struct na_http_client_pool *
na_http_find_client_pool(struct na_http_class *priv,
    const struct sockaddr_storage *client_ss);

/*******************/
/* Local Variables */
/*******************/

/* Ops table */
const struct na_class_ops NA_PLUGIN_OPS(http) = {
    NA_HTTP_CLASS_NAME,                      /* class_name */
    na_http_get_protocol_info,               /* get_protocol_info */
    na_http_check_protocol,                  /* check_protocol */
    na_http_initialize,                      /* initialize */
    na_http_finalize,                        /* finalize */
    NULL,                                    /* cleanup */
    NULL,                                    /* has_opt_feature */
    na_http_context_create,                  /* context_create */
    na_http_context_destroy,                 /* context_destroy */
    na_http_op_create,                       /* op_create */
    na_http_op_destroy,                      /* op_destroy */
    na_http_addr_lookup,                     /* addr_lookup */
    na_http_addr_free,                       /* addr_free */
    NULL,                                    /* addr_set_remove */
    na_http_addr_self,                       /* addr_self */
    na_http_addr_dup,                        /* addr_dup */
    na_http_addr_cmp,                        /* addr_cmp */
    na_http_addr_is_self,                    /* addr_is_self */
    na_http_addr_to_string,                  /* addr_to_string */
    na_http_addr_get_serialize_size,         /* addr_get_serialize_size */
    na_http_addr_serialize,                  /* addr_serialize */
    na_http_addr_deserialize,                /* addr_deserialize */
    na_http_msg_get_max_unexpected_size,     /* msg_get_max_unexpected_size */
    na_http_msg_get_max_expected_size,       /* msg_get_max_expected_size */
    NULL,                                    /* msg_get_unexpected_header_size */
    NULL,                                    /* msg_get_expected_header_size */
    na_http_msg_get_max_tag,                 /* msg_get_max_tag */
    NULL,                                    /* msg_buf_alloc */
    NULL,                                    /* msg_buf_free */
    NULL,                                    /* msg_init_unexpected */
    na_http_msg_send_unexpected,             /* msg_send_unexpected */
    na_http_msg_recv_unexpected,             /* msg_recv_unexpected */
    NULL,                                    /* msg_multi_recv_unexpected */
    NULL,                                    /* msg_init_expected */
    na_http_msg_send_expected,               /* msg_send_expected */
    na_http_msg_recv_expected,               /* msg_recv_expected */
    na_http_mem_handle_create,               /* mem_handle_create */
    NULL,                                    /* mem_handle_create_segments */
    na_http_mem_handle_free,                 /* mem_handle_free */
    NULL,                                    /* mem_handle_get_max_segments */
    NULL,                                    /* mem_register */
    NULL,                                    /* mem_deregister */
    na_http_mem_handle_get_serialize_size,   /* mem_handle_get_serialize_size */
    na_http_mem_handle_serialize,            /* mem_handle_serialize */
    na_http_mem_handle_deserialize,          /* mem_handle_deserialize */
    na_http_put,                             /* put */
    na_http_get,                             /* get */
    na_http_poll_get_fd,                     /* poll_get_fd */
    na_http_poll_try_wait,                   /* poll_try_wait */
    na_http_poll,                            /* poll */
    na_http_poll_wait,                       /* poll_wait */
    na_http_cancel                           /* cancel */
};

/********************/
/* Internal helpers */
/********************/

/*---------------------------------------------------------------------------*/
static void
na_http_release(void NA_UNUSED *arg)
{
    struct na_http_op_id *op = (struct na_http_op_id *) arg;

    hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
}

/*---------------------------------------------------------------------------*/
static unsigned int
na_http_handle_id_hash(hg_hash_table_key_t key)
{
    uint64_t id = (uint64_t) (uintptr_t) key;

    return (unsigned int) (id ^ (id >> 16));
}

/*---------------------------------------------------------------------------*/
static int
na_http_handle_id_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    return (uintptr_t) key1 == (uintptr_t) key2;
}

/*---------------------------------------------------------------------------*/
static void
na_http_complete_op(struct na_http_op_id *op, na_return_t ret)
{
    /* Mark as completed */
    hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);

    /* Fill callback info */
    op->completion_data.callback_info.type = op->type;
    op->completion_data.callback_info.ret = ret;

    /* Enqueue completion */
    na_cb_completion_add(op->context, &op->completion_data);
}

/*---------------------------------------------------------------------------*/
static size_t
na_http_curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct na_http_curl_state *cs = (struct na_http_curl_state *) userp;
    size_t realsize = size * nmemb;
    char *new_data;

    if (realsize == 0)
        return 0;

    new_data = (char *) realloc(cs->resp_data, cs->resp_size + realsize);
    if (new_data == NULL)
        return 0;
    cs->resp_data = new_data;
    memcpy(cs->resp_data + cs->resp_size, contents, realsize);
    cs->resp_size += realsize;

    return realsize;
}

/*---------------------------------------------------------------------------*/
static bool
na_http_ss_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return false;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *) a;
        const struct sockaddr_in *sb = (const struct sockaddr_in *) b;
        return sa->sin_port == sb->sin_port &&
               sa->sin_addr.s_addr == sb->sin_addr.s_addr;
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *) a;
        const struct sockaddr_in6 *sb = (const struct sockaddr_in6 *) b;
        return sa->sin6_port == sb->sin6_port &&
               memcmp(&sa->sin6_addr, &sb->sin6_addr, 16) == 0;
    }
    return false;
}

/*---------------------------------------------------------------------------*/
static struct na_http_client_pool *
na_http_find_client_pool(struct na_http_class *priv,
    const struct sockaddr_storage *client_ss)
{
    struct na_http_client_pool *pool;

    STAILQ_FOREACH(pool, &priv->client_pools, entry) {
        if (na_http_ss_equal(&pool->client_ss, client_ss))
            return pool;
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
static void
na_http_wakeup(struct na_http_class *priv)
{
    char c = 'W';
    ssize_t n;

    do {
        n = write(priv->wakeup_pipe[1], &c, 1);
    } while (n < 0 && errno == EINTR);
}

/*---------------------------------------------------------------------------*/
static void
na_http_drain_wakeup(struct na_http_class *priv)
{
    char buf[64];
    ssize_t n;

    do {
        n = read(priv->wakeup_pipe[0], buf, sizeof(buf));
    } while (n > 0 || (n < 0 && errno == EINTR));
}

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p)
{
    const char *protocol_name =
        (na_info != NULL) ? na_info->protocol_name : NULL;
    na_return_t ret;

    if (protocol_name != NULL &&
        strcmp(protocol_name, NA_HTTP_PROTOCOL_NAME)) {
        *na_protocol_info_p = NULL;
        return NA_SUCCESS;
    }

    *na_protocol_info_p = na_protocol_info_alloc(
        NA_HTTP_CLASS_NAME, NA_HTTP_PROTOCOL_NAME, "tcp");
    NA_CHECK_SUBSYS_ERROR(cls, *na_protocol_info_p == NULL, error, ret,
        NA_NOMEM, "Could not allocate protocol info entry");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static bool
na_http_check_protocol(const char *protocol_name)
{
    return !strcmp(NA_HTTP_PROTOCOL_NAME, protocol_name);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen)
{
    const struct na_init_info *na_init_info = &na_info->na_init_info;
    struct na_http_class *priv = NULL;
    int rc;
    na_return_t ret;

    (void) listen;

    NA_LOG_SUBSYS_DEBUG(cls, "Initializing HTTP plugin (listen=%d host=%s)",
        listen, na_info->host_name ? na_info->host_name : "(null)");

    /* Allocate private class */
    priv = (struct na_http_class *) calloc(1, sizeof(*priv));
    NA_CHECK_SUBSYS_ERROR(cls, priv == NULL, error, ret, NA_NOMEM,
        "Could not allocate HTTP private class");

    priv->wakeup_pipe[0] = -1;
    priv->wakeup_pipe[1] = -1;
    priv->mhd_epoll_fd = -1;

    priv->max_unexpected_size = na_init_info->max_unexpected_size
                                    ? na_init_info->max_unexpected_size
                                    : NA_HTTP_MSG_UNEXPECTED_SIZE;
    priv->max_expected_size = na_init_info->max_expected_size
                                  ? na_init_info->max_expected_size
                                  : NA_HTTP_MSG_EXPECTED_SIZE;

    /* Initialize queues */
    STAILQ_INIT(&priv->unexpected_recv_queue);
    STAILQ_INIT(&priv->expected_recv_queue);
    STAILQ_INIT(&priv->rma_get_queue);
    STAILQ_INIT(&priv->unexpected_msg_queue);
    STAILQ_INIT(&priv->expected_msg_queue);
    STAILQ_INIT(&priv->client_pools);

    /* Initialize locks */
    rc = hg_thread_mutex_init(&priv->socket_lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_mutex_init() failed");
    rc = hg_thread_mutex_init(&priv->queue_lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_mutex_init() failed");

    /* Initialize atomic handle ID counter */
    hg_atomic_init64(&priv->next_handle_id, 1);

    /* Initialize memory handle map (for RMA) */
    priv->mem_handle_map = hg_hash_table_new(
        na_http_handle_id_hash, na_http_handle_id_equal);
    NA_CHECK_SUBSYS_ERROR(cls, priv->mem_handle_map == NULL, error, ret,
        NA_NOMEM, "Could not create mem_handle_map");

    /* Resolve host:port to sockaddr */
    {
        struct sockaddr *sa = NULL;
        socklen_t salen = 0;
        uint16_t port = 0;

        if (na_info->host_name != NULL && *na_info->host_name != '\0') {
            char *host_copy = strdup(na_info->host_name);
            NA_CHECK_SUBSYS_ERROR(cls, host_copy == NULL, error, ret,
                NA_NOMEM, "strdup() failed");

            char *port_str = strrchr(host_copy, ':');
            if (port_str != NULL) {
                *port_str = '\0';
                port_str++;
                port = (uint16_t) atoi(port_str);
            }

            ret = na_ip_check_interface(
                host_copy, port, AF_UNSPEC, NULL, &sa, &salen);
            free(host_copy);
            NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
                "Could not resolve host: %s", na_info->host_name);
        } else {
            struct sockaddr_in *sin =
                (struct sockaddr_in *) calloc(1, sizeof(*sin));
            NA_CHECK_SUBSYS_ERROR(cls, sin == NULL, error, ret, NA_NOMEM,
                "calloc() failed");
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = INADDR_ANY;
            sin->sin_port = 0;
            sa = (struct sockaddr *) sin;
            salen = sizeof(*sin);
        }

        /* Store the resolved address */
        memcpy(&priv->self_addr, sa, salen);
        priv->self_addr_len = salen;
        port = ntohs(((struct sockaddr_in *) sa)->sin_port);

        /* Create wakeup pipe */
        rc = pipe(priv->wakeup_pipe);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error_sa, ret, NA_PROTOCOL_ERROR,
            "pipe() failed");
        fcntl(priv->wakeup_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(priv->wakeup_pipe[1], F_SETFL, O_NONBLOCK);

        /* Start MHD daemon with epoll */
        priv->mhd_daemon = MHD_start_daemon(
            MHD_USE_EPOLL | MHD_USE_NO_THREAD_SAFETY |
                MHD_ALLOW_SUSPEND_RESUME,
            port, NULL, NULL,
            na_http_mhd_handler, priv,
            MHD_OPTION_NOTIFY_COMPLETED, na_http_mhd_completed, priv,
            MHD_OPTION_SOCK_ADDR, sa,
            MHD_OPTION_END);
        free(sa);
        sa = NULL;

        NA_CHECK_SUBSYS_ERROR(cls, priv->mhd_daemon == NULL, error, ret,
            NA_PROTOCOL_ERROR, "MHD_start_daemon() failed");

        /* Query the actual bound port */
        {
            const union MHD_DaemonInfo *info;
            info = MHD_get_daemon_info(priv->mhd_daemon,
                MHD_DAEMON_INFO_BIND_PORT);
            NA_CHECK_SUBSYS_ERROR(cls, info == NULL, error, ret,
                NA_PROTOCOL_ERROR, "Could not query MHD bind port");
            port = info->port;
        }

        /* Update self_addr with actual port */
        if (priv->self_addr.ss_family == AF_INET) {
            struct sockaddr_in *sin =
                (struct sockaddr_in *) &priv->self_addr;
            sin->sin_port = htons(port);
            /* Replace INADDR_ANY with loopback */
            if (sin->sin_addr.s_addr == INADDR_ANY)
                sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
            struct sockaddr_in6 *sin6 =
                (struct sockaddr_in6 *) &priv->self_addr;
            sin6->sin6_port = htons(port);
        }

        /* Get MHD's epoll FD */
        {
            const union MHD_DaemonInfo *info;
            info = MHD_get_daemon_info(priv->mhd_daemon,
                MHD_DAEMON_INFO_EPOLL_FD);
            NA_CHECK_SUBSYS_ERROR(cls, info == NULL, error, ret,
                NA_PROTOCOL_ERROR, "Could not query MHD epoll FD");
            priv->mhd_epoll_fd = info->epoll_fd;
        }

        goto skip_sa_free;
error_sa:
        free(sa);
        goto error;
skip_sa_free:
        (void) 0;
    }

    /* Initialize curl */
    curl_global_init(CURL_GLOBAL_ALL);
    priv->curl_multi = curl_multi_init();
    NA_CHECK_SUBSYS_ERROR(cls, priv->curl_multi == NULL, error, ret,
        NA_PROTOCOL_ERROR, "curl_multi_init() failed");

    na_class->plugin_class = (void *) priv;

    NA_LOG_SUBSYS_DEBUG(cls, "Initialized HTTP plugin (listen=%d)", listen);

    return NA_SUCCESS;

error:
    if (priv != NULL) {
        if (priv->curl_multi != NULL)
            curl_multi_cleanup(priv->curl_multi);
        if (priv->mhd_daemon != NULL)
            MHD_stop_daemon(priv->mhd_daemon);
        if (priv->wakeup_pipe[0] >= 0)
            close(priv->wakeup_pipe[0]);
        if (priv->wakeup_pipe[1] >= 0)
            close(priv->wakeup_pipe[1]);
        if (priv->mem_handle_map != NULL)
            hg_hash_table_free(priv->mem_handle_map);
        hg_thread_mutex_destroy(&priv->socket_lock);
        hg_thread_mutex_destroy(&priv->queue_lock);
        free(priv);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_finalize(na_class_t *na_class)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);

    if (priv == NULL)
        return NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(cls, "Finalizing HTTP plugin");

    /* Clean up curl multi (remove any remaining handles) */
    if (priv->curl_multi != NULL) {
        CURLMsg *msg;
        int msgs_left;

        while ((msg = curl_multi_info_read(priv->curl_multi, &msgs_left))
               != NULL) {
            if (msg->msg == CURLMSG_DONE) {
                struct na_http_curl_state *cs = NULL;
                curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &cs);
                curl_multi_remove_handle(priv->curl_multi, msg->easy_handle);
                curl_easy_cleanup(msg->easy_handle);
                if (cs != NULL) {
                    free(cs->resp_data);
                    curl_slist_free_all(cs->headers);
                    free(cs);
                }
            }
        }
        curl_multi_cleanup(priv->curl_multi);
    }

    /* Resume all held connections before stopping MHD (API requirement) */
    {
        struct na_http_client_pool *pool;
        while (!STAILQ_EMPTY(&priv->client_pools)) {
            pool = STAILQ_FIRST(&priv->client_pools);
            STAILQ_REMOVE_HEAD(&priv->client_pools, entry);

            struct na_http_held_conn *hc;
            while (!STAILQ_EMPTY(&pool->held_conns)) {
                hc = STAILQ_FIRST(&pool->held_conns);
                STAILQ_REMOVE_HEAD(&pool->held_conns, entry);

                struct MHD_Response *response =
                    MHD_create_response_from_buffer(
                        0, NULL, MHD_RESPMEM_PERSISTENT);
                if (response != NULL) {
                    MHD_queue_response(
                        hc->connection, MHD_HTTP_OK, response);
                    MHD_destroy_response(response);
                }
                MHD_resume_connection(hc->connection);
                hc->rs->held = NULL;
                free(hc);
            }
            free(pool);
        }
        if (priv->mhd_daemon != NULL)
            MHD_run(priv->mhd_daemon);
    }

    /* Stop MHD daemon */
    if (priv->mhd_daemon != NULL)
        MHD_stop_daemon(priv->mhd_daemon);

    /* Close FDs */
    if (priv->wakeup_pipe[0] >= 0)
        close(priv->wakeup_pipe[0]);
    if (priv->wakeup_pipe[1] >= 0)
        close(priv->wakeup_pipe[1]);

    /* Destroy locks */
    hg_thread_mutex_destroy(&priv->socket_lock);
    hg_thread_mutex_destroy(&priv->queue_lock);

    /* Free mem_handle_map */
    if (priv->mem_handle_map != NULL)
        hg_hash_table_free(priv->mem_handle_map);

    /* Free unexpected_msg_queue entries */
    {
        struct na_http_msg_recv_unexpected *queued;
        while (!STAILQ_EMPTY(&priv->unexpected_msg_queue)) {
            queued = STAILQ_FIRST(&priv->unexpected_msg_queue);
            STAILQ_REMOVE_HEAD(&priv->unexpected_msg_queue, entry);
            if (queued->source != NULL &&
                hg_atomic_decr32(&queued->source->refcount) == 0)
                free(queued->source);
            free(queued->buf);
            free(queued);
        }
    }

    /* Free expected_msg_queue entries */
    {
        struct na_http_msg_recv_expected *queued;
        while (!STAILQ_EMPTY(&priv->expected_msg_queue)) {
            queued = STAILQ_FIRST(&priv->expected_msg_queue);
            STAILQ_REMOVE_HEAD(&priv->expected_msg_queue, entry);
            if (queued->source != NULL &&
                hg_atomic_decr32(&queued->source->refcount) == 0)
                free(queued->source);
            free(queued->buf);
            free(queued);
        }
    }

    free(priv);
    na_class->plugin_class = NULL;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_context_create(na_class_t NA_UNUSED *na_class,
    na_context_t NA_UNUSED *context, void **context_p,
    uint8_t NA_UNUSED id)
{
    /* No per-context state needed; store a non-NULL sentinel */
    *context_p = (void *) (uintptr_t) 1;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_context_destroy(na_class_t NA_UNUSED *na_class,
    void NA_UNUSED *context)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_http_op_create(na_class_t *na_class, unsigned long NA_UNUSED flags)
{
    struct na_http_op_id *op = NULL;

    op = (struct na_http_op_id *) calloc(1, sizeof(*op));
    NA_CHECK_SUBSYS_ERROR_NORET(
        op, op == NULL, done, "Could not allocate HTTP operation ID");

    op->na_class = na_class;

    /* Completed by default */
    hg_atomic_init32(&op->status, NA_HTTP_OP_COMPLETED);

    /* Set op release callbacks */
    op->completion_data.plugin_callback = na_http_release;
    op->completion_data.plugin_callback_args = op;

done:
    return (na_op_id_t *) op;
}

/*---------------------------------------------------------------------------*/
static void
na_http_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;

    NA_CHECK_SUBSYS_WARNING(op,
        !(hg_atomic_get32(&op->status) & NA_HTTP_OP_COMPLETED),
        "Attempting to destroy OP ID that was not completed");

    free(op);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_addr_lookup(na_class_t NA_UNUSED *na_class,
    const char *name, na_addr_t **addr_p)
{
    struct na_http_addr *addr = NULL;
    struct sockaddr *sa = NULL;
    socklen_t salen = 0;
    char *host_copy = NULL;
    na_return_t ret;

    /* Strip optional "http://" prefix */
    if (strncmp(name, "http://", 7) == 0)
        name += 7;

    addr = (struct na_http_addr *) calloc(1, sizeof(*addr));
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
na_http_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_http_addr *addr = (struct na_http_addr *) na_addr;

    if (addr == NULL)
        return;

    if (hg_atomic_decr32(&addr->refcount) == 0)
        free(addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_addr_self(na_class_t *na_class, na_addr_t **addr_p)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_addr *addr = NULL;
    na_return_t ret;

    addr = (struct na_http_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    memcpy(&addr->ss, &priv->self_addr, priv->self_addr_len);
    hg_atomic_init32(&addr->refcount, 1);
    addr->is_self = true;

    *addr_p = (na_addr_t *) addr;
    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr,
    na_addr_t **new_addr_p)
{
    struct na_http_addr *addr = (struct na_http_addr *) na_addr;

    hg_atomic_incr32(&addr->refcount);
    *new_addr_p = na_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static bool
na_http_addr_cmp(na_class_t NA_UNUSED *na_class,
    na_addr_t *addr1, na_addr_t *addr2)
{
    struct na_http_addr *a1 = (struct na_http_addr *) addr1;
    struct na_http_addr *a2 = (struct na_http_addr *) addr2;

    if (a1->ss.ss_family != a2->ss.ss_family)
        return false;

    if (a1->ss.ss_family == AF_INET) {
        struct sockaddr_in *sin1 = (struct sockaddr_in *) &a1->ss;
        struct sockaddr_in *sin2 = (struct sockaddr_in *) &a2->ss;
        return (sin1->sin_port == sin2->sin_port) &&
               (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr);
    } else if (a1->ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6_1 = (struct sockaddr_in6 *) &a1->ss;
        struct sockaddr_in6 *sin6_2 = (struct sockaddr_in6 *) &a2->ss;
        return (sin6_1->sin6_port == sin6_2->sin6_port) &&
               (memcmp(&sin6_1->sin6_addr, &sin6_2->sin6_addr,
                    sizeof(struct in6_addr)) == 0);
    }

    return false;
}

/*---------------------------------------------------------------------------*/
static bool
na_http_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_http_addr *addr = (struct na_http_addr *) na_addr;

    return addr->is_self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    size_t *buf_size, na_addr_t *na_addr)
{
    struct na_http_addr *addr = (struct na_http_addr *) na_addr;
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
        needed = (size_t) snprintf(buf, *buf_size, "<unknown>");
        *buf_size = needed + 1;
        return NA_SUCCESS;
    }

    needed = (size_t) snprintf(buf, *buf_size, "http://%s:%s", host, port);
    *buf_size = needed + 1;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
na_http_addr_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_addr_t NA_UNUSED *addr)
{
    return sizeof(struct sockaddr_storage);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_addr_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_addr_t *na_addr)
{
    struct na_http_addr *addr = (struct na_http_addr *) na_addr;
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
na_http_addr_deserialize(na_class_t *na_class, na_addr_t **addr_p,
    const void *buf, size_t buf_size, uint64_t NA_UNUSED flags)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_addr *addr = NULL;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(struct sockaddr_storage),
        error, ret, NA_OVERFLOW, "Buffer too small for deserialization");

    addr = (struct na_http_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    memcpy(&addr->ss, buf, sizeof(struct sockaddr_storage));
    hg_atomic_init32(&addr->refcount, 1);

    /* Check if deserialized address matches our own address */
    {
        struct na_http_addr self_tmp;
        memcpy(&self_tmp.ss, &priv->self_addr, priv->self_addr_len);
        addr->is_self = na_http_addr_cmp(NULL,
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
na_http_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_HTTP_CLASS(na_class)->max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static size_t
na_http_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_HTTP_CLASS(na_class)->max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_http_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_TAG_MAX;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_send_msg(struct na_http_class *priv,
    const struct sockaddr_storage *dest_ss,
    const struct na_http_msg_hdr *hdr,
    const struct na_http_rma_hdr *rma_hdr,
    const void *payload, size_t payload_size)
{
    struct na_http_rma_hdr zero_rma;
    char *wire_buf = NULL;
    size_t wire_size;
    size_t offset;

    /* Build wire body: hdr + rma_hdr + payload + source_ss */
    wire_size = NA_HTTP_MSG_HDR_SIZE + NA_HTTP_RMA_HDR_SIZE +
                payload_size + NA_HTTP_SOURCE_SIZE;
    wire_buf = (char *) malloc(wire_size);
    if (wire_buf == NULL)
        return NA_NOMEM;

    offset = 0;
    memcpy(wire_buf + offset, hdr, NA_HTTP_MSG_HDR_SIZE);
    offset += NA_HTTP_MSG_HDR_SIZE;

    if (rma_hdr != NULL) {
        memcpy(wire_buf + offset, rma_hdr, NA_HTTP_RMA_HDR_SIZE);
    } else {
        memset(&zero_rma, 0, sizeof(zero_rma));
        memcpy(wire_buf + offset, &zero_rma, NA_HTTP_RMA_HDR_SIZE);
    }
    offset += NA_HTTP_RMA_HDR_SIZE;

    if (payload != NULL && payload_size > 0) {
        memcpy(wire_buf + offset, payload, payload_size);
    }
    offset += payload_size;

    memcpy(wire_buf + offset, &priv->self_addr, NA_HTTP_SOURCE_SIZE);

    /* Try to send via a held connection (NAT traversal) */
    {
        struct na_http_client_pool *pool;
        struct na_http_held_conn *hc = NULL;

        hg_thread_mutex_lock(&priv->queue_lock);
        pool = na_http_find_client_pool(priv, dest_ss);
        if (pool != NULL) {
            hc = STAILQ_FIRST(&pool->held_conns);
            if (hc != NULL) {
                STAILQ_REMOVE_HEAD(&pool->held_conns, entry);
                pool->count--;
            }
        }
        hg_thread_mutex_unlock(&priv->queue_lock);

        if (hc != NULL) {
            struct MHD_Response *response =
                MHD_create_response_from_buffer(
                    wire_size, wire_buf, MHD_RESPMEM_MUST_FREE);
            if (response != NULL) {
                MHD_add_response_header(response,
                    "Content-Type", "application/octet-stream");
                MHD_queue_response(
                    hc->connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);
                MHD_resume_connection(hc->connection);
                hc->rs->held = NULL;
                free(hc);
                na_http_wakeup(priv);
                return NA_SUCCESS; /* wire_buf owned by MHD */
            }
            /* MHD response creation failed, fall through to curl */
            free(hc);
        }
    }

    /* Fallback: send via curl POST */
    {
        CURL *easy = NULL;
        struct na_http_curl_state *cs = NULL;
        char url[256];
        CURLMcode mc;

        if (dest_ss->ss_family == AF_INET) {
            const struct sockaddr_in *sin =
                (const struct sockaddr_in *) dest_ss;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            snprintf(url, sizeof(url), "http://%s:%u/",
                ip_str, ntohs(sin->sin_port));
        } else {
            const struct sockaddr_in6 *sin6 =
                (const struct sockaddr_in6 *) dest_ss;
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
            snprintf(url, sizeof(url), "http://[%s]:%u/",
                ip_str, ntohs(sin6->sin6_port));
        }

        easy = curl_easy_init();
        if (easy == NULL) {
            free(wire_buf);
            return NA_NOMEM;
        }

        cs = (struct na_http_curl_state *) calloc(1, sizeof(*cs));
        if (cs == NULL) {
            curl_easy_cleanup(easy);
            free(wire_buf);
            return NA_NOMEM;
        }
        cs->priv = priv;
        memcpy(&cs->dest_ss, dest_ss, sizeof(cs->dest_ss));

        curl_easy_setopt(easy, CURLOPT_URL, url);
        curl_easy_setopt(easy, CURLOPT_POST, 1L);
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long) wire_size);
        curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, wire_buf);
        curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, na_http_curl_write_cb);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, cs);

        cs->headers = curl_slist_append(NULL,
            "Content-Type: application/octet-stream");
        curl_easy_setopt(easy, CURLOPT_HTTPHEADER, cs->headers);
        curl_easy_setopt(easy, CURLOPT_PRIVATE, cs);

        mc = curl_multi_add_handle(priv->curl_multi, easy);
        free(wire_buf);

        if (mc != CURLM_OK) {
            curl_slist_free_all(cs->headers);
            free(cs);
            curl_easy_cleanup(easy);
            return NA_PROTOCOL_ERROR;
        }

        na_http_wakeup(priv);
        return NA_SUCCESS;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_msg_send(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg,
    const void *buf, size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id, enum na_http_msg_type msg_type,
    na_cb_type_t cb_type)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_addr *dest = (struct na_http_addr *) dest_addr;
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;
    struct na_http_msg_hdr hdr;
    na_return_t ret;

    /* Set up the operation */
    op->context = context;
    op->type = cb_type;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&op->status, NA_HTTP_OP_QUEUED);

    /* Fill wire header */
    hdr.type = (uint32_t) msg_type;
    hdr.tag = tag;
    hdr.dest_id = dest_id;
    hdr.payload_length = buf_size;

    /* Send under socket_lock */
    hg_thread_mutex_lock(&priv->socket_lock);

    ret = na_http_send_msg(priv, &dest->ss, &hdr, NULL, buf, buf_size);

    /* Inline progress to handle self-send and prevent starvation */
    na_http_progress(priv);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
        return ret;
    }

    /* Send completes synchronously (CURLOPT_COPYPOSTFIELDS copies data) */
    na_http_complete_op(op, NA_SUCCESS);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_msg_send_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_http_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_HTTP_MSG_UNEXPECTED, NA_CB_SEND_UNEXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_msg_recv_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data, na_op_id_t *op_id)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;
    struct na_http_msg_recv_unexpected *queued;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_UNEXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    hg_atomic_set32(&op->status, NA_HTTP_OP_QUEUED);

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

        na_http_complete_op(op, NA_SUCCESS);
        return NA_SUCCESS;
    }

    /* No queued message - add op to unexpected recv queue */
    STAILQ_INSERT_TAIL(&priv->unexpected_recv_queue, op, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_msg_send_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_http_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_HTTP_MSG_EXPECTED, NA_CB_SEND_EXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_msg_recv_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *source_addr, uint8_t source_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_EXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    op->info.msg.addr = (struct na_http_addr *) source_addr;
    op->info.msg.tag = tag;
    op->info.msg.dest_id = source_id;
    hg_atomic_set32(&op->status, NA_HTTP_OP_QUEUED);

    hg_thread_mutex_lock(&priv->queue_lock);

    /* Check if there's already a queued expected message that matches */
    {
        struct na_http_msg_recv_expected *queued, *prev = NULL;
        STAILQ_FOREACH(queued, &priv->expected_msg_queue, entry) {
            if (queued->tag == tag && queued->dest_id == source_id) {
                if (prev == NULL)
                    STAILQ_REMOVE_HEAD(&priv->expected_msg_queue, entry);
                else
                    STAILQ_REMOVE(&priv->expected_msg_queue, queued,
                        na_http_msg_recv_expected, entry);

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
                if (queued->source != NULL &&
                    hg_atomic_decr32(&queued->source->refcount) == 0)
                    free(queued->source);
                free(queued);

                na_http_complete_op(op, NA_SUCCESS);
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
na_http_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t **mem_handle_p)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_mem_handle *mh = NULL;
    na_return_t ret;

    mh = (struct na_http_mem_handle *) calloc(1, sizeof(*mh));
    NA_CHECK_SUBSYS_ERROR(
        mem, mh == NULL, error, ret, NA_NOMEM, "calloc() failed");

    mh->buf = buf;
    mh->buf_size = buf_size;
    mh->flags = flags;
    mh->handle_id = (uint64_t) hg_atomic_incr64(&priv->next_handle_id);

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
na_http_mem_handle_free(na_class_t *na_class, na_mem_handle_t *mem_handle)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_mem_handle *mh =
        (struct na_http_mem_handle *) mem_handle;

    if (mh->buf != NULL) {
        hg_hash_table_remove(priv->mem_handle_map,
            (hg_hash_table_key_t) (uintptr_t) mh->handle_id);
    }

    free(mh);
}

/*---------------------------------------------------------------------------*/
static size_t
na_http_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t NA_UNUSED *mem_handle)
{
    return sizeof(uint64_t) * 3;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_mem_handle_t *mem_handle)
{
    struct na_http_mem_handle *mh =
        (struct na_http_mem_handle *) mem_handle;
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
na_http_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size)
{
    struct na_http_mem_handle *mh = NULL;
    const char *buf_ptr = (const char *) buf;
    size_t buf_size_left = buf_size;
    na_return_t ret;

    mh = (struct na_http_mem_handle *) calloc(1, sizeof(*mh));
    NA_CHECK_SUBSYS_ERROR(
        mem, mh == NULL, error, ret, NA_NOMEM, "calloc() failed");

    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->handle_id, uint64_t);
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->buf_size, uint64_t);
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &mh->flags, uint64_t);

    mh->buf = NULL;

    *mem_handle_p = (na_mem_handle_t *) mh;
    return NA_SUCCESS;

error:
    free(mh);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_put(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_mem_handle *local_mh =
        (struct na_http_mem_handle *) local_mem_handle;
    struct na_http_mem_handle *remote_mh =
        (struct na_http_mem_handle *) remote_mem_handle;
    struct na_http_addr *dest = (struct na_http_addr *) remote_addr;
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;
    struct na_http_msg_hdr hdr;
    struct na_http_rma_hdr rma_hdr;
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
    hg_atomic_set32(&op->status, NA_HTTP_OP_QUEUED);

    /* Fill wire header */
    hdr.type = NA_HTTP_MSG_RMA_PUT;
    hdr.tag = 0;
    hdr.dest_id = remote_id;
    hdr.payload_length = length;

    /* Fill RMA header */
    rma_hdr.remote_handle_id = remote_mh->handle_id;
    rma_hdr.remote_offset = remote_offset;
    rma_hdr.local_handle_id = 0;
    rma_hdr.length = length;

    /* Send under socket_lock */
    hg_thread_mutex_lock(&priv->socket_lock);

    ret = na_http_send_msg(priv, &dest->ss, &hdr, &rma_hdr,
        (const char *) local_mh->buf + local_offset, length);

    /* Inline progress */
    na_http_progress(priv);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
        return ret;
    }

    na_http_complete_op(op, NA_SUCCESS);
    return NA_SUCCESS;

error:
    hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_get(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_mem_handle *local_mh =
        (struct na_http_mem_handle *) local_mem_handle;
    struct na_http_mem_handle *remote_mh =
        (struct na_http_mem_handle *) remote_mem_handle;
    struct na_http_addr *dest = (struct na_http_addr *) remote_addr;
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;
    struct na_http_msg_hdr hdr;
    struct na_http_rma_hdr rma_hdr;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(rma,
        local_offset + length > local_mh->buf_size, error, ret, NA_OVERFLOW,
        "Local offset+length exceeds buffer size");

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_GET;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->completion_data.callback_info.type = NA_CB_GET;
    hg_atomic_set32(&op->status, NA_HTTP_OP_QUEUED);

    /* Store local handle info for when response arrives */
    op->info.rma.local_handle_id = local_mh->handle_id;
    op->info.rma.remote_handle_id = remote_mh->handle_id;
    op->info.rma.local_offset = local_offset;
    op->info.rma.remote_offset = remote_offset;
    op->info.rma.length = length;

    /* Add to pending RMA GET queue */
    hg_thread_mutex_lock(&priv->queue_lock);
    STAILQ_INSERT_TAIL(&priv->rma_get_queue, op, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    /* Fill wire header */
    hdr.type = NA_HTTP_MSG_RMA_GET;
    hdr.tag = 0;
    hdr.dest_id = remote_id;
    hdr.payload_length = 0;

    /* Fill RMA header */
    rma_hdr.remote_handle_id = remote_mh->handle_id;
    rma_hdr.remote_offset = remote_offset;
    rma_hdr.local_handle_id = local_mh->handle_id;
    rma_hdr.length = length;

    /* Send under socket_lock */
    hg_thread_mutex_lock(&priv->socket_lock);

    ret = na_http_send_msg(priv, &dest->ss, &hdr, &rma_hdr, NULL, 0);

    /* Inline progress */
    na_http_progress(priv);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        /* Remove from rma_get_queue on send failure */
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->rma_get_queue, op, na_http_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
        hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
        return ret;
    }

    return NA_SUCCESS;

error:
    hg_atomic_set32(&op->status, NA_HTTP_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_http_process_recv_unexpected(struct na_http_class *priv,
    struct na_http_addr *source, na_tag_t tag, void *data, size_t data_size)
{
    struct na_http_op_id *op;

    hg_thread_mutex_lock(&priv->queue_lock);

    op = STAILQ_FIRST(&priv->unexpected_recv_queue);
    if (op != NULL) {
        size_t copy_size;

        STAILQ_REMOVE_HEAD(&priv->unexpected_recv_queue, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);

        copy_size = (data_size < op->info.msg.buf_size)
                        ? data_size : op->info.msg.buf_size;
        if (copy_size > 0 && op->info.msg.buf != NULL)
            memcpy(op->info.msg.buf, data, copy_size);

        op->completion_data.callback_info.info.recv_unexpected
            .actual_buf_size = data_size;
        op->completion_data.callback_info.info.recv_unexpected.tag = tag;

        if (source != NULL) {
            hg_atomic_incr32(&source->refcount);
            op->completion_data.callback_info.info.recv_unexpected.source =
                (na_addr_t *) source;
        } else {
            op->completion_data.callback_info.info.recv_unexpected.source =
                NULL;
        }

        free(data);
        na_http_complete_op(op, NA_SUCCESS);
    } else {
        struct na_http_msg_recv_unexpected *queued =
            (struct na_http_msg_recv_unexpected *) calloc(1, sizeof(*queued));
        if (queued != NULL) {
            queued->buf = data;
            queued->buf_size = data_size;
            queued->tag = tag;
            if (source != NULL) {
                hg_atomic_incr32(&source->refcount);
                queued->source = source;
            }
            STAILQ_INSERT_TAIL(&priv->unexpected_msg_queue, queued, entry);
        } else {
            free(data);
        }
        hg_thread_mutex_unlock(&priv->queue_lock);
    }
}

/*---------------------------------------------------------------------------*/
static void
na_http_process_recv_expected(struct na_http_class *priv,
    struct na_http_addr *source, na_tag_t tag, uint8_t dest_id,
    void *data, size_t data_size)
{
    struct na_http_op_id *op;
    struct na_http_op_id *match = NULL;

    hg_thread_mutex_lock(&priv->queue_lock);

    STAILQ_FOREACH(op, &priv->expected_recv_queue, entry) {
        if (op->info.msg.tag == tag && op->info.msg.dest_id == dest_id) {
            if (op->info.msg.addr == NULL || source == NULL) {
                match = op;
                break;
            }
            if (na_http_addr_cmp(NULL, (na_addr_t *) op->info.msg.addr,
                    (na_addr_t *) source)) {
                match = op;
                break;
            }
        }
    }

    if (match != NULL) {
        size_t copy_size;

        STAILQ_REMOVE(&priv->expected_recv_queue, match,
            na_http_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);

        copy_size = (data_size < match->info.msg.buf_size)
                        ? data_size : match->info.msg.buf_size;
        if (copy_size > 0 && match->info.msg.buf != NULL)
            memcpy(match->info.msg.buf, data, copy_size);

        match->completion_data.callback_info.info.recv_expected
            .actual_buf_size = data_size;

        free(data);
        na_http_complete_op(match, NA_SUCCESS);
    } else {
        struct na_http_msg_recv_expected *queued =
            (struct na_http_msg_recv_expected *) calloc(1, sizeof(*queued));
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
            free(data);
        }
        hg_thread_mutex_unlock(&priv->queue_lock);
    }
}

/*---------------------------------------------------------------------------*/
static void
na_http_process_rma_put(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_http_mem_handle *mh;

    mh = (struct na_http_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) rma_hdr->remote_handle_id);

    if (mh == NULL) {
        NA_LOG_SUBSYS_WARNING(rma, "RMA PUT: unknown handle_id %" PRIu64,
            rma_hdr->remote_handle_id);
        free(data);
        return;
    }

    if (rma_hdr->remote_offset + data_size > mh->buf_size) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA PUT: offset+length exceeds buffer");
        free(data);
        return;
    }

    memcpy((char *) mh->buf + rma_hdr->remote_offset, data, data_size);
    free(data);
}

/*---------------------------------------------------------------------------*/
static void
na_http_process_rma_get(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr,
    const struct sockaddr_storage *requester_ss)
{
    struct na_http_mem_handle *mh;
    struct na_http_msg_hdr resp_hdr;
    struct na_http_rma_hdr resp_rma_hdr;

    mh = (struct na_http_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) rma_hdr->remote_handle_id);

    if (mh == NULL) {
        NA_LOG_SUBSYS_WARNING(rma, "RMA GET: unknown handle_id %" PRIu64,
            rma_hdr->remote_handle_id);
        return;
    }

    if (rma_hdr->remote_offset + rma_hdr->length > mh->buf_size) {
        NA_LOG_SUBSYS_WARNING(rma,
            "RMA GET: offset+length exceeds buffer");
        return;
    }

    /* Build response */
    resp_hdr.type = NA_HTTP_MSG_RMA_RESP;
    resp_hdr.tag = 0;
    resp_hdr.dest_id = 0;
    resp_hdr.payload_length = rma_hdr->length;

    resp_rma_hdr.remote_handle_id = rma_hdr->remote_handle_id;
    resp_rma_hdr.remote_offset = rma_hdr->remote_offset;
    resp_rma_hdr.local_handle_id = rma_hdr->local_handle_id;
    resp_rma_hdr.length = rma_hdr->length;

    /* Send response back (socket_lock already held by progress) */
    na_http_send_msg(priv, requester_ss, &resp_hdr, &resp_rma_hdr,
        (const char *) mh->buf + rma_hdr->remote_offset,
        rma_hdr->length);
}

/*---------------------------------------------------------------------------*/
static void
na_http_process_rma_resp(struct na_http_class *priv,
    const struct na_http_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_http_op_id *op;
    struct na_http_op_id *match = NULL;
    struct na_http_mem_handle *local_mh;

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

    STAILQ_REMOVE(&priv->rma_get_queue, match, na_http_op_id, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    local_mh = (struct na_http_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) match->info.rma.local_handle_id);

    if (local_mh == NULL) {
        free(data);
        na_http_complete_op(match, NA_FAULT);
        return;
    }

    if (match->info.rma.local_offset + data_size > local_mh->buf_size) {
        free(data);
        na_http_complete_op(match, NA_OVERFLOW);
        return;
    }

    memcpy((char *) local_mh->buf + match->info.rma.local_offset,
        data, data_size);
    free(data);

    na_http_complete_op(match, NA_SUCCESS);
}

/*---------------------------------------------------------------------------*/
static void
na_http_dispatch_message(struct na_http_class *priv,
    const char *body, size_t body_size,
    const struct sockaddr_storage *source_override)
{
    struct na_http_msg_hdr hdr;
    struct na_http_rma_hdr rma_hdr;
    struct sockaddr_storage source_ss;
    struct na_http_addr *source_addr = NULL;
    const char *ptr;
    size_t remaining;
    size_t payload_size;
    void *payload_data = NULL;
    size_t min_size;

    min_size = NA_HTTP_MSG_HDR_SIZE + NA_HTTP_RMA_HDR_SIZE +
               NA_HTTP_SOURCE_SIZE;
    if (body_size < min_size)
        return;

    ptr = body;
    remaining = body_size;

    /* Parse msg_hdr */
    memcpy(&hdr, ptr, NA_HTTP_MSG_HDR_SIZE);
    ptr += NA_HTTP_MSG_HDR_SIZE;
    remaining -= NA_HTTP_MSG_HDR_SIZE;

    /* Parse rma_hdr */
    memcpy(&rma_hdr, ptr, NA_HTTP_RMA_HDR_SIZE);
    ptr += NA_HTTP_RMA_HDR_SIZE;
    remaining -= NA_HTTP_RMA_HDR_SIZE;

    /* Parse payload (remaining - source_ss) */
    if (remaining < NA_HTTP_SOURCE_SIZE)
        return;

    payload_size = remaining - NA_HTTP_SOURCE_SIZE;
    if (payload_size > 0) {
        payload_data = malloc(payload_size);
        if (payload_data == NULL)
            return;
        memcpy(payload_data, ptr, payload_size);
    }
    ptr += payload_size;

    /* Parse source sockaddr_storage */
    memset(&source_ss, 0, sizeof(source_ss));
    memcpy(&source_ss, ptr, NA_HTTP_SOURCE_SIZE);

    /* Use source override if provided (NAT traversal: the wire's source_ss
     * is the remote's self_addr which may be a private address unreachable
     * from us; the override is the address we actually connected to) */
    if (source_override != NULL && source_override->ss_family != 0)
        memcpy(&source_ss, source_override, sizeof(source_ss));

    /* Create source addr for msg dispatch */
    if (source_ss.ss_family != 0) {
        source_addr = (struct na_http_addr *) calloc(1,
            sizeof(*source_addr));
        if (source_addr != NULL) {
            memcpy(&source_addr->ss, &source_ss, sizeof(source_ss));
            hg_atomic_init32(&source_addr->refcount, 1);
            source_addr->is_self = false;
        }
    }

    /* Dispatch based on message type */
    switch (hdr.type) {
    case NA_HTTP_MSG_UNEXPECTED:
        na_http_process_recv_unexpected(priv, source_addr,
            hdr.tag, payload_data, payload_size);
        payload_data = NULL; /* ownership transferred */
        break;

    case NA_HTTP_MSG_EXPECTED:
        na_http_process_recv_expected(priv, source_addr,
            hdr.tag, hdr.dest_id, payload_data, payload_size);
        payload_data = NULL;
        break;

    case NA_HTTP_MSG_RMA_PUT:
        na_http_process_rma_put(priv, &rma_hdr,
            payload_data, payload_size);
        payload_data = NULL;
        break;

    case NA_HTTP_MSG_RMA_GET:
        na_http_process_rma_get(priv, &rma_hdr, &source_ss);
        break;

    case NA_HTTP_MSG_RMA_RESP:
        na_http_process_rma_resp(priv, &rma_hdr,
            payload_data, payload_size);
        payload_data = NULL;
        break;

    default:
        break;
    }

    free(payload_data);
    if (source_addr != NULL &&
        hg_atomic_decr32(&source_addr->refcount) == 0)
        free(source_addr);
}

/*---------------------------------------------------------------------------*/
static enum MHD_Result
na_http_mhd_handler(void *cls, struct MHD_Connection *connection,
    const char NA_UNUSED *url, const char NA_UNUSED *method,
    const char NA_UNUSED *version,
    const char *upload_data, size_t *upload_data_size, void **req_cls)
{
    struct na_http_class *priv = (struct na_http_class *) cls;

    /* First call - allocate request state */
    if (*req_cls == NULL) {
        struct na_http_request_state *rs =
            (struct na_http_request_state *) calloc(1, sizeof(*rs));
        if (rs == NULL)
            return MHD_NO;
        rs->priv = priv;
        *req_cls = rs;
        return MHD_YES;
    }

    /* Body data available - accumulate */
    if (*upload_data_size > 0) {
        struct na_http_request_state *rs =
            (struct na_http_request_state *) *req_cls;
        size_t new_size = rs->data_size + *upload_data_size;

        if (new_size > rs->data_alloc) {
            size_t new_alloc = (new_size < 4096) ? 4096 : new_size * 2;
            char *new_data = (char *) realloc(rs->data, new_alloc);
            if (new_data == NULL)
                return MHD_NO;
            rs->data = new_data;
            rs->data_alloc = new_alloc;
        }

        memcpy(rs->data + rs->data_size, upload_data, *upload_data_size);
        rs->data_size = new_size;
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* Final call - upload complete, dispatch message */
    {
        struct na_http_request_state *rs =
            (struct na_http_request_state *) *req_cls;
        struct sockaddr_storage source_ss;
        bool has_source = false;

        /* Dispatch the inbound message */
        if (rs->data != NULL && rs->data_size > 0) {
            na_http_dispatch_message(priv, rs->data, rs->data_size, NULL);

            /* Extract source_ss from wire body for pool keying */
            size_t min_size = NA_HTTP_MSG_HDR_SIZE + NA_HTTP_RMA_HDR_SIZE +
                              NA_HTTP_SOURCE_SIZE;
            if (rs->data_size >= min_size) {
                size_t payload_size = rs->data_size - min_size;
                memcpy(&source_ss,
                    rs->data + NA_HTTP_MSG_HDR_SIZE + NA_HTTP_RMA_HDR_SIZE +
                        payload_size,
                    NA_HTTP_SOURCE_SIZE);
                has_source = (source_ss.ss_family != 0);
            }
        }

        /* Free accumulated body (already dispatched) */
        free(rs->data);
        rs->data = NULL;
        rs->data_size = 0;
        rs->data_alloc = 0;

        /* Try to suspend connection and add to held pool */
        if (has_source) {
            struct na_http_held_conn *hc = (struct na_http_held_conn *)
                calloc(1, sizeof(*hc));
            if (hc != NULL) {
                struct na_http_client_pool *pool;

                hc->connection = connection;
                hc->rs = rs;

                hg_thread_mutex_lock(&priv->queue_lock);
                pool = na_http_find_client_pool(priv, &source_ss);
                if (pool == NULL) {
                    pool = (struct na_http_client_pool *)
                        calloc(1, sizeof(*pool));
                    if (pool != NULL) {
                        memcpy(&pool->client_ss, &source_ss,
                            sizeof(source_ss));
                        STAILQ_INIT(&pool->held_conns);
                        pool->count = 0;
                        STAILQ_INSERT_TAIL(
                            &priv->client_pools, pool, entry);
                    }
                }
                if (pool != NULL &&
                    pool->count < NA_HTTP_MAX_HELD_PER_CLIENT) {
                    STAILQ_INSERT_TAIL(&pool->held_conns, hc, entry);
                    pool->count++;
                    rs->held = hc;
                    hg_thread_mutex_unlock(&priv->queue_lock);

                    MHD_suspend_connection(connection);
                    return MHD_YES;
                }
                hg_thread_mutex_unlock(&priv->queue_lock);
                free(hc);
            }
        }

        /* Fallback: immediate 200 OK */
        {
            struct MHD_Response *response =
                MHD_create_response_from_buffer(
                    0, NULL, MHD_RESPMEM_PERSISTENT);
            enum MHD_Result mhd_ret =
                MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            return mhd_ret;
        }
    }
}

/*---------------------------------------------------------------------------*/
static void
na_http_mhd_completed(void *cls,
    struct MHD_Connection NA_UNUSED *connection,
    void **req_cls, enum MHD_RequestTerminationCode NA_UNUSED toe)
{
    struct na_http_class *priv = (struct na_http_class *) cls;
    struct na_http_request_state *rs =
        (struct na_http_request_state *) *req_cls;

    if (rs != NULL) {
        /* If this connection was held, remove from pool */
        if (rs->held != NULL) {
            hg_thread_mutex_lock(&priv->queue_lock);
            {
                struct na_http_client_pool *pool;
                STAILQ_FOREACH(pool, &priv->client_pools, entry) {
                    struct na_http_held_conn *hc;
                    STAILQ_FOREACH(hc, &pool->held_conns, entry) {
                        if (hc == rs->held) {
                            STAILQ_REMOVE(&pool->held_conns, hc,
                                na_http_held_conn, entry);
                            pool->count--;
                            break;
                        }
                    }
                }
            }
            hg_thread_mutex_unlock(&priv->queue_lock);
            free(rs->held);
        }

        free(rs->data);
        free(rs);
        *req_cls = NULL;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_progress(struct na_http_class *priv)
{
    int running = 0;
    CURLMsg *msg;
    int msgs_left;

    /* Process incoming HTTP requests (triggers handler callback) */
    MHD_run(priv->mhd_daemon);

    /* Drive outgoing transfers */
    curl_multi_perform(priv->curl_multi, &running);

    /* Clean up completed transfers */
    while ((msg = curl_multi_info_read(priv->curl_multi, &msgs_left))
           != NULL) {
        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            struct na_http_curl_state *cs = NULL;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &cs);
            curl_multi_remove_handle(priv->curl_multi, easy);
            curl_easy_cleanup(easy);
            if (cs != NULL) {
                /* Dispatch response body as incoming message.
                 * Use dest_ss as source override — the wire body's
                 * source_ss is the remote's self_addr (private addr
                 * behind NAT), but Mercury expects the address we
                 * connected to (public addr). */
                if (cs->resp_data != NULL && cs->resp_size > 0) {
                    na_http_dispatch_message(
                        priv, cs->resp_data, cs->resp_size, &cs->dest_ss);
                }
                free(cs->resp_data);
                curl_slist_free_all(cs->headers);
                free(cs);
            }
        }
    }

    /* Run MHD again in case handler dispatched new sends that need
     * their HTTP 200 responses flushed */
    MHD_run(priv->mhd_daemon);

    /* Drain wakeup pipe */
    na_http_drain_wakeup(priv);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
na_http_poll_get_fd(na_class_t NA_UNUSED *na_class,
    na_context_t NA_UNUSED *context)
{
    /* Return -1 so Mercury uses the legacy path (NA_Poll_wait).
     * HTTP needs to monitor both MHD's epoll FD (incoming requests) and
     * curl's running transfers (outgoing). Exposing a single FD doesn't
     * capture both event sources — curl multi performs needs to be driven
     * even when MHD has no events. Our poll_wait() properly blocks on both
     * MHD epoll FD + wakeup pipe using poll(). */
    return -1;
}

/*---------------------------------------------------------------------------*/
static bool
na_http_poll_try_wait(na_class_t *na_class,
    na_context_t NA_UNUSED *context)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);

    /* Check if there are queued messages waiting */
    if (!STAILQ_EMPTY(&priv->unexpected_msg_queue))
        return false;
    if (!STAILQ_EMPTY(&priv->expected_msg_queue))
        return false;

    return true;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_poll(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int *count_p)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);

    if (hg_thread_mutex_try_lock(&priv->socket_lock) == HG_UTIL_SUCCESS) {
        na_http_progress(priv);
        hg_thread_mutex_unlock(&priv->socket_lock);
    }

    if (count_p != NULL)
        *count_p = 0;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_poll_wait(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms, unsigned int *count_p)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct pollfd pfds[66]; /* 2 fixed (mhd + wakeup) + up to 64 curl FDs */
    nfds_t npfds;
    int nfds;
    int wait_ms;
    MHD_UNSIGNED_LONG_LONG mhd_timeout;
    fd_set curl_rd, curl_wr, curl_ex;
    int curl_max_fd = -1;
    long curl_timeout_ms;

    /* Always do one progress first to handle any pending work */
    hg_thread_mutex_lock(&priv->socket_lock);
    na_http_progress(priv);
    hg_thread_mutex_unlock(&priv->socket_lock);

    /* Get MHD timeout - must not block longer than this */
    wait_ms = (int) timeout_ms;
    if (MHD_get_timeout(priv->mhd_daemon, &mhd_timeout) == MHD_YES) {
        if ((int) mhd_timeout < wait_ms)
            wait_ms = (int) mhd_timeout;
    }

    /* Get curl's FDs and timeout */
    FD_ZERO(&curl_rd);
    FD_ZERO(&curl_wr);
    FD_ZERO(&curl_ex);
    curl_multi_fdset(priv->curl_multi, &curl_rd, &curl_wr, &curl_ex,
        &curl_max_fd);
    if (curl_multi_timeout(priv->curl_multi, &curl_timeout_ms) == CURLM_OK &&
        curl_timeout_ms >= 0) {
        if ((int) curl_timeout_ms < wait_ms)
            wait_ms = (int) curl_timeout_ms;
    }

    /* Build pollfd array: MHD epoll FD + wakeup pipe + curl FDs */
    npfds = 0;
    pfds[npfds].fd = priv->mhd_epoll_fd;
    pfds[npfds].events = POLLIN;
    pfds[npfds].revents = 0;
    npfds++;

    pfds[npfds].fd = priv->wakeup_pipe[0];
    pfds[npfds].events = POLLIN;
    pfds[npfds].revents = 0;
    npfds++;

    /* Add curl FDs to the poll set */
    {
        int fd;
        for (fd = 0; fd <= curl_max_fd && npfds < 66; fd++) {
            short events = 0;
            if (FD_ISSET(fd, &curl_rd))
                events |= POLLIN;
            if (FD_ISSET(fd, &curl_wr))
                events |= POLLOUT;
            if (FD_ISSET(fd, &curl_ex))
                events |= POLLPRI;
            if (events != 0) {
                pfds[npfds].fd = fd;
                pfds[npfds].events = events;
                pfds[npfds].revents = 0;
                npfds++;
            }
        }
    }

    nfds = poll(pfds, npfds, wait_ms);
    if (nfds < 0 && errno != EINTR)
        return NA_IO_ERROR;

    /* Process after poll returns */
    hg_thread_mutex_lock(&priv->socket_lock);
    na_http_progress(priv);
    hg_thread_mutex_unlock(&priv->socket_lock);

    if (count_p != NULL)
        *count_p = 0;

    if (nfds == 0)
        return NA_TIMEOUT;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_http_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
    na_op_id_t *op_id)
{
    struct na_http_class *priv = NA_HTTP_CLASS(na_class);
    struct na_http_op_id *op = (struct na_http_op_id *) op_id;

    if (!(hg_atomic_get32(&op->status) & NA_HTTP_OP_QUEUED))
        return NA_SUCCESS;

    if (op->type == NA_CB_RECV_UNEXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->unexpected_recv_queue, op,
            na_http_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    if (op->type == NA_CB_RECV_EXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->expected_recv_queue, op,
            na_http_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    if (op->type == NA_CB_GET) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->rma_get_queue, op,
            na_http_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    na_http_complete_op(op, NA_CANCELED);

    return NA_SUCCESS;
}
