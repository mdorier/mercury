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

#include <zmq.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/****************/
/* Local Macros */
/****************/

/* Name used in class_name field */
#define NA_ZMQ_CLASS_NAME "zmq"

/* Protocol name used for URI matching */
#define NA_ZMQ_PROTOCOL_NAME "zmq"

/* Default max message sizes */
#define NA_ZMQ_MSG_UNEXPECTED_SIZE (4096)
#define NA_ZMQ_MSG_EXPECTED_SIZE   (4 * 1024 * 1024)

/* Op status bits */
#define NA_ZMQ_OP_COMPLETED (1 << 0)
#define NA_ZMQ_OP_CANCELED  (1 << 1)
#define NA_ZMQ_OP_QUEUED    (1 << 2)

/* Accessor macro */
#define NA_ZMQ_CLASS(na_class)                                                 \
    ((struct na_zmq_class *) (na_class->plugin_class))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Wire protocol message types */
enum na_zmq_msg_type {
    NA_ZMQ_MSG_UNEXPECTED = 1,
    NA_ZMQ_MSG_EXPECTED   = 2,
    NA_ZMQ_MSG_RMA_PUT    = 3,
    NA_ZMQ_MSG_RMA_GET    = 4,
    NA_ZMQ_MSG_RMA_RESP   = 5
};

/* Wire protocol header (17 bytes) */
struct na_zmq_msg_hdr {
    uint32_t type;
    uint32_t tag;
    uint8_t dest_id;
    uint64_t payload_length;
} NA_PACKED();

/* Wire protocol RMA header extension (32 bytes) */
struct na_zmq_rma_hdr {
    uint64_t remote_handle_id;
    uint64_t remote_offset;
    uint64_t local_handle_id;
    uint64_t length;
} NA_PACKED();

/* Address */
struct na_zmq_addr {
    struct sockaddr_storage ss;   /* Peer address (IP:port) */
    hg_atomic_int32_t refcount;   /* Reference count */
    bool is_self;                 /* True if this is our own address */
};

/* Msg info stored in op */
struct na_zmq_msg_info {
    void *buf;
    size_t buf_size;
    void *plugin_data;
    struct na_zmq_addr *addr;
    na_tag_t tag;
    uint8_t dest_id;
};

/* RMA info stored in op */
struct na_zmq_rma_info {
    struct na_zmq_addr *addr;
    uint64_t local_handle_id;
    uint64_t remote_handle_id;
    uint64_t local_offset;
    uint64_t remote_offset;
    uint64_t length;
    uint8_t remote_id;
};

/* Op ID */
struct na_zmq_op_id {
    struct na_cb_completion_data completion_data; /* Must be accessible */
    union {
        struct na_zmq_msg_info msg;
        struct na_zmq_rma_info rma;
    } info;
    STAILQ_ENTRY(na_zmq_op_id) entry;
    na_class_t *na_class;
    na_context_t *context;
    hg_atomic_int32_t status;
    na_cb_type_t type;
};

/* Memory handle */
struct na_zmq_mem_handle {
    void *buf;
    size_t buf_size;
    unsigned long flags;
    uint64_t handle_id;
};

/* Received unexpected message (queued when no matching recv is posted) */
struct na_zmq_msg_recv_unexpected {
    STAILQ_ENTRY(na_zmq_msg_recv_unexpected) entry;
    void *buf;
    size_t buf_size;
    struct na_zmq_addr *source;
    na_tag_t tag;
};

/* Queued expected message (arrived before recv_expected posted) */
struct na_zmq_msg_recv_expected {
    STAILQ_ENTRY(na_zmq_msg_recv_expected) entry;
    void *buf;
    size_t buf_size;
    struct na_zmq_addr *source;
    na_tag_t tag;
    uint8_t dest_id;
};

/* Peer tracking (tracks connections and identity mapping) */
struct na_zmq_peer {
    struct sockaddr_storage ss;
    uint64_t addr_hash;             /* Hash of sockaddr for fast lookup */
    uint8_t *identity;              /* ZMQ identity bytes for ROUTER routing */
    size_t identity_size;
    void *dealer_socket;            /* ZMQ_DEALER for outbound, or NULL */
    bool is_inbound;                /* True if this peer connected to us */
    STAILQ_ENTRY(na_zmq_peer) entry;
};

/* Private class data */
struct na_zmq_class {
    void *zmq_context;                  /* zmq_ctx_new() */
    void *router_socket;                /* ZMQ_ROUTER socket */
    struct sockaddr_storage self_addr;   /* Our bound address */
    socklen_t self_addr_len;

    hg_thread_mutex_t socket_lock;      /* Protects ZMQ socket ops */
    hg_thread_mutex_t queue_lock;       /* Protects recv/rma queues */

    /* Pending recv op queues (posted by app, waiting for data) */
    STAILQ_HEAD(, na_zmq_op_id) unexpected_recv_queue;
    STAILQ_HEAD(, na_zmq_op_id) expected_recv_queue;

    /* Pending RMA GET ops (waiting for RMA_RESP) */
    STAILQ_HEAD(, na_zmq_op_id) rma_get_queue;

    /* Unexpected messages received but not yet matched */
    STAILQ_HEAD(, na_zmq_msg_recv_unexpected) unexpected_msg_queue;

    /* Expected messages received but not yet matched */
    STAILQ_HEAD(, na_zmq_msg_recv_expected) expected_msg_queue;

    /* Memory handle map (for RMA) */
    hg_hash_table_t *mem_handle_map;
    hg_atomic_int64_t next_handle_id;

    /* Connected peer tracking */
    STAILQ_HEAD(, na_zmq_peer) peer_list;

    /* Message size limits */
    size_t max_unexpected_size;
    size_t max_expected_size;
};

/********************/
/* Local Prototypes */
/********************/

/* get_protocol_info */
static na_return_t
na_zmq_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p);

/* check_protocol */
static bool
na_zmq_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_zmq_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen);

/* finalize */
static na_return_t
na_zmq_finalize(na_class_t *na_class);

/* context_create */
static na_return_t
na_zmq_context_create(na_class_t *na_class, na_context_t *context,
    void **context_p, uint8_t id);

/* context_destroy */
static na_return_t
na_zmq_context_destroy(na_class_t *na_class, void *context);

/* op_create */
static na_op_id_t *
na_zmq_op_create(na_class_t *na_class, unsigned long flags);

/* op_destroy */
static void
na_zmq_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_zmq_addr_lookup(
    na_class_t *na_class, const char *name, na_addr_t **addr_p);

/* addr_free */
static void
na_zmq_addr_free(na_class_t *na_class, na_addr_t *addr);

/* addr_self */
static na_return_t
na_zmq_addr_self(na_class_t *na_class, na_addr_t **addr_p);

/* addr_dup */
static na_return_t
na_zmq_addr_dup(
    na_class_t *na_class, na_addr_t *addr, na_addr_t **new_addr_p);

/* addr_cmp */
static bool
na_zmq_addr_cmp(na_class_t *na_class, na_addr_t *addr1, na_addr_t *addr2);

/* addr_is_self */
static bool
na_zmq_addr_is_self(na_class_t *na_class, na_addr_t *addr);

/* addr_to_string */
static na_return_t
na_zmq_addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size, na_addr_t *addr);

/* addr_get_serialize_size */
static size_t
na_zmq_addr_get_serialize_size(na_class_t *na_class, na_addr_t *addr);

/* addr_serialize */
static na_return_t
na_zmq_addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t *addr);

/* addr_deserialize */
static na_return_t
na_zmq_addr_deserialize(na_class_t *na_class, na_addr_t **addr_p,
    const void *buf, size_t buf_size, uint64_t flags);

/* msg_get_max_unexpected_size */
static size_t
na_zmq_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static size_t
na_zmq_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_max_tag */
static na_tag_t
na_zmq_msg_get_max_tag(const na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t
na_zmq_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_zmq_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size,
    void *plugin_data, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_zmq_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_zmq_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size,
    void *plugin_data, na_addr_t *source_addr, uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id);

/* mem_handle_create */
static na_return_t
na_zmq_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t **mem_handle_p);

/* mem_handle_free */
static void
na_zmq_mem_handle_free(na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_get_serialize_size */
static size_t
na_zmq_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t *mem_handle);

/* mem_handle_serialize */
static na_return_t
na_zmq_mem_handle_serialize(na_class_t *na_class, void *buf, size_t buf_size,
    na_mem_handle_t *mem_handle);

/* mem_handle_deserialize */
static na_return_t
na_zmq_mem_handle_deserialize(na_class_t *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size);

/* put */
static na_return_t
na_zmq_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_zmq_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static int
na_zmq_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static bool
na_zmq_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* poll */
static na_return_t
na_zmq_poll(
    na_class_t *na_class, na_context_t *context, unsigned int *count_p);

/* poll_wait */
static na_return_t
na_zmq_poll_wait(na_class_t *na_class, na_context_t *context,
    unsigned int timeout_ms, unsigned int *count_p);

/* cancel */
static na_return_t
na_zmq_cancel(
    na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/* Internal helpers */
static void
na_zmq_release(void *arg);

static unsigned int
na_zmq_handle_id_hash(hg_hash_table_key_t key);

static int
na_zmq_handle_id_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

static uint64_t
na_zmq_hash_addr(const struct sockaddr_storage *ss);

static void
na_zmq_complete_op(struct na_zmq_op_id *op, na_return_t ret);

static struct na_zmq_peer *
na_zmq_find_peer_by_hash(struct na_zmq_class *priv, uint64_t addr_hash);

static struct na_zmq_peer *
na_zmq_find_peer_by_ss(struct na_zmq_class *priv,
    const struct sockaddr_storage *ss);

static void
na_zmq_update_peer_identity(struct na_zmq_class *priv,
    uint64_t addr_hash, const struct sockaddr_storage *ss,
    const void *identity, size_t identity_size);

/*******************/
/* Local Variables */
/*******************/

/* Ops table */
const struct na_class_ops NA_PLUGIN_OPS(zmq) = {
    NA_ZMQ_CLASS_NAME,                       /* class_name */
    na_zmq_get_protocol_info,                /* get_protocol_info */
    na_zmq_check_protocol,                   /* check_protocol */
    na_zmq_initialize,                       /* initialize */
    na_zmq_finalize,                         /* finalize */
    NULL,                                    /* cleanup */
    NULL,                                    /* has_opt_feature */
    na_zmq_context_create,                   /* context_create */
    na_zmq_context_destroy,                  /* context_destroy */
    na_zmq_op_create,                        /* op_create */
    na_zmq_op_destroy,                       /* op_destroy */
    na_zmq_addr_lookup,                      /* addr_lookup */
    na_zmq_addr_free,                        /* addr_free */
    NULL,                                    /* addr_set_remove */
    na_zmq_addr_self,                        /* addr_self */
    na_zmq_addr_dup,                         /* addr_dup */
    na_zmq_addr_cmp,                         /* addr_cmp */
    na_zmq_addr_is_self,                     /* addr_is_self */
    na_zmq_addr_to_string,                   /* addr_to_string */
    na_zmq_addr_get_serialize_size,          /* addr_get_serialize_size */
    na_zmq_addr_serialize,                   /* addr_serialize */
    na_zmq_addr_deserialize,                 /* addr_deserialize */
    na_zmq_msg_get_max_unexpected_size,      /* msg_get_max_unexpected_size */
    na_zmq_msg_get_max_expected_size,        /* msg_get_max_expected_size */
    NULL,                                    /* msg_get_unexpected_header_size */
    NULL,                                    /* msg_get_expected_header_size */
    na_zmq_msg_get_max_tag,                  /* msg_get_max_tag */
    NULL,                                    /* msg_buf_alloc */
    NULL,                                    /* msg_buf_free */
    NULL,                                    /* msg_init_unexpected */
    na_zmq_msg_send_unexpected,              /* msg_send_unexpected */
    na_zmq_msg_recv_unexpected,              /* msg_recv_unexpected */
    NULL,                                    /* msg_multi_recv_unexpected */
    NULL,                                    /* msg_init_expected */
    na_zmq_msg_send_expected,                /* msg_send_expected */
    na_zmq_msg_recv_expected,                /* msg_recv_expected */
    na_zmq_mem_handle_create,                /* mem_handle_create */
    NULL,                                    /* mem_handle_create_segments */
    na_zmq_mem_handle_free,                  /* mem_handle_free */
    NULL,                                    /* mem_handle_get_max_segments */
    NULL,                                    /* mem_register */
    NULL,                                    /* mem_deregister */
    na_zmq_mem_handle_get_serialize_size,    /* mem_handle_get_serialize_size */
    na_zmq_mem_handle_serialize,             /* mem_handle_serialize */
    na_zmq_mem_handle_deserialize,           /* mem_handle_deserialize */
    na_zmq_put,                              /* put */
    na_zmq_get,                              /* get */
    na_zmq_poll_get_fd,                      /* poll_get_fd */
    na_zmq_poll_try_wait,                    /* poll_try_wait */
    na_zmq_poll,                             /* poll */
    na_zmq_poll_wait,                        /* poll_wait */
    na_zmq_cancel                            /* cancel */
};

/********************/
/* Internal helpers */
/********************/

/*---------------------------------------------------------------------------*/
static void
na_zmq_release(void NA_UNUSED *arg)
{
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) arg;

    hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
}

/*---------------------------------------------------------------------------*/
static unsigned int
na_zmq_handle_id_hash(hg_hash_table_key_t key)
{
    uint64_t id = (uint64_t) (uintptr_t) key;

    return (unsigned int) (id ^ (id >> 16));
}

/*---------------------------------------------------------------------------*/
static int
na_zmq_handle_id_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    return (uintptr_t) key1 == (uintptr_t) key2;
}

/*---------------------------------------------------------------------------*/
static uint64_t
na_zmq_hash_addr(const struct sockaddr_storage *ss)
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
na_zmq_complete_op(struct na_zmq_op_id *op, na_return_t ret)
{
    /* Mark as completed */
    hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);

    /* Fill callback info */
    op->completion_data.callback_info.type = op->type;
    op->completion_data.callback_info.ret = ret;

    /* Enqueue completion */
    na_cb_completion_add(op->context, &op->completion_data);
}

/*---------------------------------------------------------------------------*/
static struct na_zmq_peer *
na_zmq_find_peer_by_hash(struct na_zmq_class *priv, uint64_t addr_hash)
{
    struct na_zmq_peer *peer;

    STAILQ_FOREACH(peer, &priv->peer_list, entry) {
        if (peer->addr_hash == addr_hash)
            return peer;
    }
    return NULL;
}

/*---------------------------------------------------------------------------*/
static struct na_zmq_peer *
na_zmq_find_peer_by_ss(struct na_zmq_class *priv,
    const struct sockaddr_storage *ss)
{
    uint64_t hash = na_zmq_hash_addr(ss);
    return na_zmq_find_peer_by_hash(priv, hash);
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_update_peer_identity(struct na_zmq_class *priv,
    uint64_t addr_hash, const struct sockaddr_storage *ss,
    const void *identity, size_t identity_size)
{
    struct na_zmq_peer *peer;

    peer = na_zmq_find_peer_by_hash(priv, addr_hash);
    if (peer != NULL) {
        /* Update identity if changed */
        if (peer->identity_size != identity_size ||
            memcmp(peer->identity, identity, identity_size) != 0) {
            free(peer->identity);
            peer->identity = (uint8_t *) malloc(identity_size);
            if (peer->identity != NULL) {
                memcpy(peer->identity, identity, identity_size);
                peer->identity_size = identity_size;
            }
        }
        return;
    }

    /* Create new peer entry (inbound — they connected to us) */
    peer = (struct na_zmq_peer *) calloc(1, sizeof(*peer));
    if (peer == NULL)
        return;

    if (ss != NULL)
        memcpy(&peer->ss, ss, sizeof(*ss));
    peer->addr_hash = addr_hash;
    peer->identity = (uint8_t *) malloc(identity_size);
    if (peer->identity != NULL) {
        memcpy(peer->identity, identity, identity_size);
        peer->identity_size = identity_size;
    }
    peer->is_inbound = true;
    STAILQ_INSERT_TAIL(&priv->peer_list, peer, entry);
}

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_get_protocol_info(
    const struct na_info *na_info, struct na_protocol_info **na_protocol_info_p)
{
    const char *protocol_name =
        (na_info != NULL) ? na_info->protocol_name : NULL;
    na_return_t ret;

    if (protocol_name != NULL &&
        strcmp(protocol_name, NA_ZMQ_PROTOCOL_NAME)) {
        *na_protocol_info_p = NULL;
        return NA_SUCCESS;
    }

    *na_protocol_info_p = na_protocol_info_alloc(
        NA_ZMQ_CLASS_NAME, NA_ZMQ_PROTOCOL_NAME, "tcp");
    NA_CHECK_SUBSYS_ERROR(cls, *na_protocol_info_p == NULL, error, ret,
        NA_NOMEM, "Could not allocate protocol info entry");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static bool
na_zmq_check_protocol(const char *protocol_name)
{
    return !strcmp(NA_ZMQ_PROTOCOL_NAME, protocol_name);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen)
{
    const struct na_init_info *na_init_info = &na_info->na_init_info;
    struct na_zmq_class *priv = NULL;
    int rc;
    na_return_t ret;

    NA_LOG_SUBSYS_DEBUG(cls, "Initializing ZMQ plugin (listen=%d host=%s)",
        listen, na_info->host_name ? na_info->host_name : "(null)");

    /* Allocate private class */
    priv = (struct na_zmq_class *) calloc(1, sizeof(*priv));
    NA_CHECK_SUBSYS_ERROR(cls, priv == NULL, error, ret, NA_NOMEM,
        "Could not allocate ZMQ private class");

    priv->max_unexpected_size = na_init_info->max_unexpected_size
                                    ? na_init_info->max_unexpected_size
                                    : NA_ZMQ_MSG_UNEXPECTED_SIZE;
    priv->max_expected_size = na_init_info->max_expected_size
                                  ? na_init_info->max_expected_size
                                  : NA_ZMQ_MSG_EXPECTED_SIZE;

    /* Initialize queues */
    STAILQ_INIT(&priv->unexpected_recv_queue);
    STAILQ_INIT(&priv->expected_recv_queue);
    STAILQ_INIT(&priv->rma_get_queue);
    STAILQ_INIT(&priv->unexpected_msg_queue);
    STAILQ_INIT(&priv->expected_msg_queue);
    STAILQ_INIT(&priv->peer_list);

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
        na_zmq_handle_id_hash, na_zmq_handle_id_equal);
    NA_CHECK_SUBSYS_ERROR(cls, priv->mem_handle_map == NULL, error, ret,
        NA_NOMEM, "Could not create mem_handle_map");

    /* Create ZMQ context */
    priv->zmq_context = zmq_ctx_new();
    NA_CHECK_SUBSYS_ERROR(cls, priv->zmq_context == NULL, error, ret,
        NA_PROTOCOL_ERROR, "zmq_ctx_new() failed");

    /* Create ROUTER socket */
    priv->router_socket = zmq_socket(priv->zmq_context, ZMQ_ROUTER);
    NA_CHECK_SUBSYS_ERROR(cls, priv->router_socket == NULL, error, ret,
        NA_PROTOCOL_ERROR, "zmq_socket(ZMQ_ROUTER) failed");

    /* Set socket options */
    {
        int opt_val;

        /* Allow pending messages to flush on close */
        opt_val = 1000;
        zmq_setsockopt(priv->router_socket, ZMQ_LINGER, &opt_val,
            sizeof(opt_val));

        /* Unlimited high-water marks */
        opt_val = 0;
        zmq_setsockopt(priv->router_socket, ZMQ_SNDHWM, &opt_val,
            sizeof(opt_val));
        zmq_setsockopt(priv->router_socket, ZMQ_RCVHWM, &opt_val,
            sizeof(opt_val));

        /* Error on unroutable messages */
        opt_val = 1;
        zmq_setsockopt(priv->router_socket, ZMQ_ROUTER_MANDATORY, &opt_val,
            sizeof(opt_val));
    }

    /* Resolve host:port to sockaddr */
    {
        struct sockaddr *sa = NULL;
        socklen_t salen = 0;
        char bind_endpoint[256];
        char last_endpoint[256];
        size_t last_endpoint_len;

        if (na_info->host_name != NULL && *na_info->host_name != '\0') {
            char *host_copy = strdup(na_info->host_name);
            NA_CHECK_SUBSYS_ERROR(cls, host_copy == NULL, error, ret,
                NA_NOMEM, "strdup() failed");

            char *port_str = strrchr(host_copy, ':');
            uint16_t port = 0;
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

        /* Note: We do NOT set ZMQ_ROUTING_ID. For ephemeral ports, the
         * actual port isn't known until after bind, and ZMQ_ROUTING_ID
         * cannot be changed after bind. Instead, we include our full
         * sockaddr as a separate wire frame in every message. */

        /* Build bind endpoint string */
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *) sa;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            snprintf(bind_endpoint, sizeof(bind_endpoint), "tcp://%s:%u",
                ip_str, ntohs(sin->sin_port));
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
            snprintf(bind_endpoint, sizeof(bind_endpoint), "tcp://[%s]:%u",
                ip_str, ntohs(sin6->sin6_port));
        }

        /* Bind */
        rc = zmq_bind(priv->router_socket, bind_endpoint);
        if (rc != 0) {
            free(sa);
            NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_ADDRINUSE,
                "zmq_bind(%s) failed: %s", bind_endpoint,
                zmq_strerror(zmq_errno()));
        }

        /* If port was 0 (ephemeral), query the actual bound port */
        last_endpoint_len = sizeof(last_endpoint);
        zmq_getsockopt(priv->router_socket, ZMQ_LAST_ENDPOINT,
            last_endpoint, &last_endpoint_len);

        /* Store self address */
        memcpy(&priv->self_addr, sa, salen);
        priv->self_addr_len = salen;

        /* Update port if ephemeral */
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *) &priv->self_addr;
            if (sin->sin_port == 0) {
                /* Parse port from last_endpoint "tcp://x.x.x.x:PORT" */
                char *colon = strrchr(last_endpoint, ':');
                if (colon != NULL)
                    sin->sin_port = htons((uint16_t) atoi(colon + 1));
            }
            /* Replace INADDR_ANY with loopback */
            if (sin->sin_addr.s_addr == INADDR_ANY)
                sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
            struct sockaddr_in6 *sin6 =
                (struct sockaddr_in6 *) &priv->self_addr;
            if (sin6->sin6_port == 0) {
                char *colon = strrchr(last_endpoint, ':');
                if (colon != NULL)
                    sin6->sin6_port = htons((uint16_t) atoi(colon + 1));
            }
        }

        free(sa);
    }

    na_class->plugin_class = (void *) priv;

    NA_LOG_SUBSYS_DEBUG(cls, "Initialized ZMQ plugin (listen=%d)", listen);

    return NA_SUCCESS;

error:
    if (priv != NULL) {
        if (priv->router_socket != NULL)
            zmq_close(priv->router_socket);
        if (priv->zmq_context != NULL)
            zmq_ctx_destroy(priv->zmq_context);
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
na_zmq_finalize(na_class_t *na_class)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);

    if (priv == NULL)
        return NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(cls, "Finalizing ZMQ plugin");

    /* Close all DEALER sockets first (must be before zmq_ctx_destroy) */
    {
        struct na_zmq_peer *peer;
        STAILQ_FOREACH(peer, &priv->peer_list, entry) {
            if (peer->dealer_socket != NULL) {
                zmq_close(peer->dealer_socket);
                peer->dealer_socket = NULL;
            }
        }
    }

    /* Close ROUTER socket and context */
    if (priv->router_socket != NULL)
        zmq_close(priv->router_socket);
    if (priv->zmq_context != NULL)
        zmq_ctx_destroy(priv->zmq_context);

    /* Destroy locks */
    hg_thread_mutex_destroy(&priv->socket_lock);
    hg_thread_mutex_destroy(&priv->queue_lock);

    /* Free mem_handle_map */
    if (priv->mem_handle_map != NULL)
        hg_hash_table_free(priv->mem_handle_map);

    /* Free unexpected_msg_queue entries */
    {
        struct na_zmq_msg_recv_unexpected *queued;
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
        struct na_zmq_msg_recv_expected *queued;
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

    /* Free peer list */
    {
        struct na_zmq_peer *peer;
        while (!STAILQ_EMPTY(&priv->peer_list)) {
            peer = STAILQ_FIRST(&priv->peer_list);
            STAILQ_REMOVE_HEAD(&priv->peer_list, entry);
            free(peer->identity);
            free(peer);
        }
    }

    free(priv);
    na_class->plugin_class = NULL;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_context_create(na_class_t NA_UNUSED *na_class,
    na_context_t NA_UNUSED *context, void **context_p,
    uint8_t NA_UNUSED id)
{
    /* No per-context state needed; store a non-NULL sentinel */
    *context_p = (void *) (uintptr_t) 1;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_context_destroy(na_class_t NA_UNUSED *na_class,
    void NA_UNUSED *context)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_zmq_op_create(na_class_t *na_class, unsigned long NA_UNUSED flags)
{
    struct na_zmq_op_id *op = NULL;

    op = (struct na_zmq_op_id *) calloc(1, sizeof(*op));
    NA_CHECK_SUBSYS_ERROR_NORET(
        op, op == NULL, done, "Could not allocate ZMQ operation ID");

    op->na_class = na_class;

    /* Completed by default */
    hg_atomic_init32(&op->status, NA_ZMQ_OP_COMPLETED);

    /* Set op release callbacks */
    op->completion_data.plugin_callback = na_zmq_release;
    op->completion_data.plugin_callback_args = op;

done:
    return (na_op_id_t *) op;
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;

    NA_CHECK_SUBSYS_WARNING(op,
        !(hg_atomic_get32(&op->status) & NA_ZMQ_OP_COMPLETED),
        "Attempting to destroy OP ID that was not completed");

    free(op);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_addr_lookup(na_class_t NA_UNUSED *na_class,
    const char *name, na_addr_t **addr_p)
{
    struct na_zmq_addr *addr = NULL;
    struct sockaddr *sa = NULL;
    socklen_t salen = 0;
    char *host_copy = NULL;
    na_return_t ret;

    addr = (struct na_zmq_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    /* Strip optional "tcp://" prefix */
    if (strncmp(name, "tcp://", 6) == 0)
        name += 6;

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
na_zmq_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_zmq_addr *addr = (struct na_zmq_addr *) na_addr;

    if (addr == NULL)
        return;

    if (hg_atomic_decr32(&addr->refcount) == 0)
        free(addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_addr_self(na_class_t *na_class, na_addr_t **addr_p)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_addr *addr = NULL;
    na_return_t ret;

    addr = (struct na_zmq_addr *) calloc(1, sizeof(*addr));
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
na_zmq_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr,
    na_addr_t **new_addr_p)
{
    struct na_zmq_addr *addr = (struct na_zmq_addr *) na_addr;

    hg_atomic_incr32(&addr->refcount);
    *new_addr_p = na_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static bool
na_zmq_addr_cmp(na_class_t NA_UNUSED *na_class,
    na_addr_t *addr1, na_addr_t *addr2)
{
    struct na_zmq_addr *a1 = (struct na_zmq_addr *) addr1;
    struct na_zmq_addr *a2 = (struct na_zmq_addr *) addr2;

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
na_zmq_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t *na_addr)
{
    struct na_zmq_addr *addr = (struct na_zmq_addr *) na_addr;

    return addr->is_self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    size_t *buf_size, na_addr_t *na_addr)
{
    struct na_zmq_addr *addr = (struct na_zmq_addr *) na_addr;
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

    needed = (size_t) snprintf(buf, *buf_size, "tcp://%s:%s", host, port);
    *buf_size = needed + 1;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
na_zmq_addr_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_addr_t NA_UNUSED *addr)
{
    return sizeof(struct sockaddr_storage);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_addr_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_addr_t *na_addr)
{
    struct na_zmq_addr *addr = (struct na_zmq_addr *) na_addr;
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
na_zmq_addr_deserialize(na_class_t *na_class, na_addr_t **addr_p,
    const void *buf, size_t buf_size, uint64_t NA_UNUSED flags)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_addr *addr = NULL;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(struct sockaddr_storage),
        error, ret, NA_OVERFLOW, "Buffer too small for deserialization");

    addr = (struct na_zmq_addr *) calloc(1, sizeof(*addr));
    NA_CHECK_SUBSYS_ERROR(
        addr, addr == NULL, error, ret, NA_NOMEM, "calloc() failed");

    memcpy(&addr->ss, buf, sizeof(struct sockaddr_storage));
    hg_atomic_init32(&addr->refcount, 1);

    /* Check if deserialized address matches our own address */
    {
        struct na_zmq_addr self_tmp;
        memcpy(&self_tmp.ss, &priv->self_addr, priv->self_addr_len);
        addr->is_self = na_zmq_addr_cmp(NULL,
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
na_zmq_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_ZMQ_CLASS(na_class)->max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static size_t
na_zmq_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_ZMQ_CLASS(na_class)->max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_zmq_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_TAG_MAX;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_ensure_connect(struct na_zmq_class *priv,
    const struct sockaddr_storage *dest_ss)
{
    struct na_zmq_peer *peer;
    char endpoint[256];
    uint64_t addr_hash = na_zmq_hash_addr(dest_ss);
    void *dealer;
    int opt_val;

    /* Check if we already know this peer (either they connected to us
     * via ROUTER and we have their identity, or we have a DEALER) */
    peer = na_zmq_find_peer_by_hash(priv, addr_hash);
    if (peer != NULL && (peer->dealer_socket != NULL ||
                         peer->identity != NULL))
        return NA_SUCCESS;

    /* Build endpoint string */
    if (dest_ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) dest_ss;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        snprintf(endpoint, sizeof(endpoint), "tcp://%s:%u",
            ip_str, ntohs(sin->sin_port));
    } else {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *) dest_ss;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
        snprintf(endpoint, sizeof(endpoint), "tcp://[%s]:%u",
            ip_str, ntohs(sin6->sin6_port));
    }

    /* Create a dedicated DEALER socket for this outbound connection */
    dealer = zmq_socket(priv->zmq_context, ZMQ_DEALER);
    if (dealer == NULL)
        return NA_PROTOCOL_ERROR;

    /* Set socket options */
    opt_val = 1000;
    zmq_setsockopt(dealer, ZMQ_LINGER, &opt_val, sizeof(opt_val));
    opt_val = 0;
    zmq_setsockopt(dealer, ZMQ_SNDHWM, &opt_val, sizeof(opt_val));
    zmq_setsockopt(dealer, ZMQ_RCVHWM, &opt_val, sizeof(opt_val));

    if (zmq_connect(dealer, endpoint) != 0) {
        zmq_close(dealer);
        return NA_PROTOCOL_ERROR;
    }

    if (peer != NULL) {
        /* Update existing peer entry (was created from an inbound msg) */
        peer->dealer_socket = dealer;
    } else {
        /* Create new peer entry */
        peer = (struct na_zmq_peer *) calloc(1, sizeof(*peer));
        if (peer == NULL) {
            zmq_close(dealer);
            return NA_NOMEM;
        }

        memcpy(&peer->ss, dest_ss, sizeof(*dest_ss));
        peer->addr_hash = addr_hash;
        peer->dealer_socket = dealer;
        peer->is_inbound = false;
        STAILQ_INSERT_TAIL(&priv->peer_list, peer, entry);
    }

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_send_msg(struct na_zmq_class *priv,
    const struct sockaddr_storage *dest_ss,
    const struct na_zmq_msg_hdr *hdr,
    const struct na_zmq_rma_hdr *rma_hdr,
    const void *payload, size_t payload_size)
{
    zmq_msg_t msg_identity, msg_hdr, msg_rma, msg_payload, msg_source;
    struct na_zmq_peer *peer;
    socklen_t self_salen;
    void *send_socket;
    bool use_dealer;
    int rc;
    na_return_t ret;

    /* Ensure connected (this is a no-op if peer already known) */
    ret = na_zmq_ensure_connect(priv, dest_ss);
    NA_CHECK_SUBSYS_NA_ERROR(msg, error, ret, "Could not connect to peer");

    /* Look up peer to determine send path */
    peer = na_zmq_find_peer_by_ss(priv, dest_ss);
    NA_CHECK_SUBSYS_ERROR(msg, peer == NULL, error, ret,
        NA_PROTOCOL_ERROR, "No peer found for destination");

    /* Choose socket: DEALER for outbound peers, ROUTER for inbound peers */
    if (peer->dealer_socket != NULL) {
        send_socket = peer->dealer_socket;
        use_dealer = true;
    } else if (peer->identity != NULL) {
        send_socket = priv->router_socket;
        use_dealer = false;
    } else {
        NA_GOTO_SUBSYS_ERROR(msg, error, ret, NA_PROTOCOL_ERROR,
            "Peer has neither DEALER socket nor ROUTER identity");
    }

    self_salen = (priv->self_addr.ss_family == AF_INET6)
                     ? (socklen_t) sizeof(struct sockaddr_in6)
                     : (socklen_t) sizeof(struct sockaddr_in);

    /* Frame 1: msg_hdr */
    zmq_msg_init_size(&msg_hdr, sizeof(*hdr));
    memcpy(zmq_msg_data(&msg_hdr), hdr, sizeof(*hdr));

    /* Frame 2: rma_hdr (may be empty) */
    if (rma_hdr != NULL) {
        zmq_msg_init_size(&msg_rma, sizeof(*rma_hdr));
        memcpy(zmq_msg_data(&msg_rma), rma_hdr, sizeof(*rma_hdr));
    } else {
        zmq_msg_init(&msg_rma);
    }

    /* Frame 3: payload */
    if (payload != NULL && payload_size > 0) {
        zmq_msg_init_size(&msg_payload, payload_size);
        memcpy(zmq_msg_data(&msg_payload), payload, payload_size);
    } else {
        zmq_msg_init(&msg_payload);
    }

    /* Frame 4: source sockaddr (our own address) */
    zmq_msg_init_size(&msg_source, self_salen);
    memcpy(zmq_msg_data(&msg_source), &priv->self_addr, self_salen);

    if (!use_dealer) {
        /* Send via ROUTER: prepend identity frame */
        zmq_msg_init_size(&msg_identity, peer->identity_size);
        memcpy(zmq_msg_data(&msg_identity), peer->identity,
            peer->identity_size);

        rc = zmq_msg_send(&msg_identity, send_socket, ZMQ_SNDMORE);
        if (rc < 0) goto send_error_router;
    }

    /* Send data frames (same for both DEALER and ROUTER after identity) */
    rc = zmq_msg_send(&msg_hdr, send_socket, ZMQ_SNDMORE);
    if (rc < 0) goto send_error;

    rc = zmq_msg_send(&msg_rma, send_socket, ZMQ_SNDMORE);
    if (rc < 0) goto send_error;

    rc = zmq_msg_send(&msg_payload, send_socket, ZMQ_SNDMORE);
    if (rc < 0) goto send_error;

    rc = zmq_msg_send(&msg_source, send_socket, 0);
    if (rc < 0) goto send_error;

    return NA_SUCCESS;

send_error_router:
    zmq_msg_close(&msg_identity);
send_error:
    zmq_msg_close(&msg_hdr);
    zmq_msg_close(&msg_rma);
    zmq_msg_close(&msg_payload);
    zmq_msg_close(&msg_source);
    return NA_PROTOCOL_ERROR;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_msg_send(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg,
    const void *buf, size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id, enum na_zmq_msg_type msg_type,
    na_cb_type_t cb_type)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_addr *dest = (struct na_zmq_addr *) dest_addr;
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;
    struct na_zmq_msg_hdr hdr;
    na_return_t ret;

    /* Set up the operation */
    op->context = context;
    op->type = cb_type;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&op->status, NA_ZMQ_OP_QUEUED);

    /* Fill wire header */
    hdr.type = (uint32_t) msg_type;
    hdr.tag = tag;
    hdr.dest_id = dest_id;
    hdr.payload_length = buf_size;

    /* Send under socket_lock */
    hg_thread_mutex_lock(&priv->socket_lock);

    ret = na_zmq_send_msg(priv, &dest->ss, &hdr, NULL, buf, buf_size);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
        return ret;
    }

    /* Send completes synchronously in ZMQ */
    na_zmq_complete_op(op, NA_SUCCESS);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_msg_send_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_zmq_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_ZMQ_MSG_UNEXPECTED, NA_CB_SEND_UNEXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_msg_recv_unexpected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data, na_op_id_t *op_id)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;
    struct na_zmq_msg_recv_unexpected *queued;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_UNEXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    hg_atomic_set32(&op->status, NA_ZMQ_OP_QUEUED);

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

        na_zmq_complete_op(op, NA_SUCCESS);
        return NA_SUCCESS;
    }

    /* No queued message - add op to unexpected recv queue */
    STAILQ_INSERT_TAIL(&priv->unexpected_recv_queue, op, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_msg_send_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t *dest_addr,
    uint8_t dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_zmq_msg_send(na_class, context, callback, arg, buf, buf_size,
        plugin_data, dest_addr, dest_id, tag, op_id,
        NA_ZMQ_MSG_EXPECTED, NA_CB_SEND_EXPECTED);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_msg_recv_expected(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void NA_UNUSED *plugin_data,
    na_addr_t *source_addr, uint8_t source_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;

    /* Set up the operation */
    op->context = context;
    op->type = NA_CB_RECV_EXPECTED;
    op->completion_data.callback = callback;
    op->completion_data.callback_info.arg = arg;
    op->info.msg.buf = buf;
    op->info.msg.buf_size = buf_size;
    op->info.msg.addr = (struct na_zmq_addr *) source_addr;
    op->info.msg.tag = tag;
    op->info.msg.dest_id = source_id;
    hg_atomic_set32(&op->status, NA_ZMQ_OP_QUEUED);

    hg_thread_mutex_lock(&priv->queue_lock);

    /* Check if there's already a queued expected message that matches */
    {
        struct na_zmq_msg_recv_expected *queued, *prev = NULL;
        STAILQ_FOREACH(queued, &priv->expected_msg_queue, entry) {
            if (queued->tag == tag && queued->dest_id == source_id) {
                if (prev == NULL)
                    STAILQ_REMOVE_HEAD(&priv->expected_msg_queue, entry);
                else
                    STAILQ_REMOVE(&priv->expected_msg_queue, queued,
                        na_zmq_msg_recv_expected, entry);

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

                na_zmq_complete_op(op, NA_SUCCESS);
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
na_zmq_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t **mem_handle_p)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_mem_handle *mh = NULL;
    na_return_t ret;

    mh = (struct na_zmq_mem_handle *) calloc(1, sizeof(*mh));
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
na_zmq_mem_handle_free(na_class_t *na_class, na_mem_handle_t *mem_handle)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_mem_handle *mh =
        (struct na_zmq_mem_handle *) mem_handle;

    if (mh->buf != NULL) {
        hg_hash_table_remove(priv->mem_handle_map,
            (hg_hash_table_key_t) (uintptr_t) mh->handle_id);
    }

    free(mh);
}

/*---------------------------------------------------------------------------*/
static size_t
na_zmq_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t NA_UNUSED *mem_handle)
{
    return sizeof(uint64_t) * 3;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_mem_handle_t *mem_handle)
{
    struct na_zmq_mem_handle *mh =
        (struct na_zmq_mem_handle *) mem_handle;
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
na_zmq_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t **mem_handle_p, const void *buf, size_t buf_size)
{
    struct na_zmq_mem_handle *mh = NULL;
    const char *buf_ptr = (const char *) buf;
    size_t buf_size_left = buf_size;
    na_return_t ret;

    mh = (struct na_zmq_mem_handle *) calloc(1, sizeof(*mh));
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
na_zmq_put(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_mem_handle *local_mh =
        (struct na_zmq_mem_handle *) local_mem_handle;
    struct na_zmq_mem_handle *remote_mh =
        (struct na_zmq_mem_handle *) remote_mem_handle;
    struct na_zmq_addr *dest = (struct na_zmq_addr *) remote_addr;
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;
    struct na_zmq_msg_hdr hdr;
    struct na_zmq_rma_hdr rma_hdr;
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
    hg_atomic_set32(&op->status, NA_ZMQ_OP_QUEUED);

    /* Fill wire header */
    hdr.type = NA_ZMQ_MSG_RMA_PUT;
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

    ret = na_zmq_send_msg(priv, &dest->ss, &hdr, &rma_hdr,
        (const char *) local_mh->buf + local_offset, length);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
        return ret;
    }

    na_zmq_complete_op(op, NA_SUCCESS);
    return NA_SUCCESS;

error:
    hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_get(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg,
    na_mem_handle_t *local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t *remote_mem_handle, na_offset_t remote_offset,
    size_t length, na_addr_t *remote_addr, uint8_t remote_id,
    na_op_id_t *op_id)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_mem_handle *local_mh =
        (struct na_zmq_mem_handle *) local_mem_handle;
    struct na_zmq_mem_handle *remote_mh =
        (struct na_zmq_mem_handle *) remote_mem_handle;
    struct na_zmq_addr *dest = (struct na_zmq_addr *) remote_addr;
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;
    struct na_zmq_msg_hdr hdr;
    struct na_zmq_rma_hdr rma_hdr;
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
    hg_atomic_set32(&op->status, NA_ZMQ_OP_QUEUED);

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
    hdr.type = NA_ZMQ_MSG_RMA_GET;
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

    ret = na_zmq_send_msg(priv, &dest->ss, &hdr, &rma_hdr, NULL, 0);

    hg_thread_mutex_unlock(&priv->socket_lock);

    if (ret != NA_SUCCESS) {
        /* Remove from rma_get_queue on failure */
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->rma_get_queue, op, na_zmq_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
        hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
        return ret;
    }

    return NA_SUCCESS;

error:
    hg_atomic_set32(&op->status, NA_ZMQ_OP_COMPLETED);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_process_recv_unexpected(struct na_zmq_class *priv,
    struct na_zmq_addr *source, na_tag_t tag, void *data, size_t data_size)
{
    struct na_zmq_op_id *op;

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
        na_zmq_complete_op(op, NA_SUCCESS);
    } else {
        struct na_zmq_msg_recv_unexpected *queued =
            (struct na_zmq_msg_recv_unexpected *) calloc(1, sizeof(*queued));
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
na_zmq_process_recv_expected(struct na_zmq_class *priv,
    struct na_zmq_addr *source, na_tag_t tag, uint8_t dest_id,
    void *data, size_t data_size)
{
    struct na_zmq_op_id *op;
    struct na_zmq_op_id *match = NULL;

    hg_thread_mutex_lock(&priv->queue_lock);

    STAILQ_FOREACH(op, &priv->expected_recv_queue, entry) {
        if (op->info.msg.tag == tag && op->info.msg.dest_id == dest_id) {
            if (op->info.msg.addr == NULL || source == NULL) {
                match = op;
                break;
            }
            if (na_zmq_addr_cmp(NULL, (na_addr_t *) op->info.msg.addr,
                    (na_addr_t *) source)) {
                match = op;
                break;
            }
        }
    }

    if (match != NULL) {
        size_t copy_size;

        STAILQ_REMOVE(&priv->expected_recv_queue, match,
            na_zmq_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);

        copy_size = (data_size < match->info.msg.buf_size)
                        ? data_size : match->info.msg.buf_size;
        if (copy_size > 0 && match->info.msg.buf != NULL)
            memcpy(match->info.msg.buf, data, copy_size);

        match->completion_data.callback_info.info.recv_expected
            .actual_buf_size = data_size;

        free(data);
        na_zmq_complete_op(match, NA_SUCCESS);
    } else {
        struct na_zmq_msg_recv_expected *queued =
            (struct na_zmq_msg_recv_expected *) calloc(1, sizeof(*queued));
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
na_zmq_process_rma_put(struct na_zmq_class *priv,
    const struct na_zmq_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_zmq_mem_handle *mh;

    mh = (struct na_zmq_mem_handle *) hg_hash_table_lookup(
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
na_zmq_process_rma_get(struct na_zmq_class *priv,
    const struct na_zmq_rma_hdr *rma_hdr,
    const struct sockaddr_storage *requester_ss)
{
    struct na_zmq_mem_handle *mh;
    struct na_zmq_msg_hdr resp_hdr;
    struct na_zmq_rma_hdr resp_rma_hdr;

    mh = (struct na_zmq_mem_handle *) hg_hash_table_lookup(
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
    resp_hdr.type = NA_ZMQ_MSG_RMA_RESP;
    resp_hdr.tag = 0;
    resp_hdr.dest_id = 0;
    resp_hdr.payload_length = rma_hdr->length;

    resp_rma_hdr.remote_handle_id = rma_hdr->remote_handle_id;
    resp_rma_hdr.remote_offset = rma_hdr->remote_offset;
    resp_rma_hdr.local_handle_id = rma_hdr->local_handle_id;
    resp_rma_hdr.length = rma_hdr->length;

    /* Send response back (socket_lock already held by progress) */
    na_zmq_send_msg(priv, requester_ss, &resp_hdr, &resp_rma_hdr,
        (const char *) mh->buf + rma_hdr->remote_offset,
        rma_hdr->length);
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_process_rma_resp(struct na_zmq_class *priv,
    const struct na_zmq_rma_hdr *rma_hdr, void *data, size_t data_size)
{
    struct na_zmq_op_id *op;
    struct na_zmq_op_id *match = NULL;
    struct na_zmq_mem_handle *local_mh;

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

    STAILQ_REMOVE(&priv->rma_get_queue, match, na_zmq_op_id, entry);
    hg_thread_mutex_unlock(&priv->queue_lock);

    local_mh = (struct na_zmq_mem_handle *) hg_hash_table_lookup(
        priv->mem_handle_map,
        (hg_hash_table_key_t) (uintptr_t) match->info.rma.local_handle_id);

    if (local_mh == NULL) {
        free(data);
        na_zmq_complete_op(match, NA_FAULT);
        return;
    }

    if (match->info.rma.local_offset + data_size > local_mh->buf_size) {
        free(data);
        na_zmq_complete_op(match, NA_OVERFLOW);
        return;
    }

    memcpy((char *) local_mh->buf + match->info.rma.local_offset,
        data, data_size);
    free(data);

    na_zmq_complete_op(match, NA_SUCCESS);
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_dispatch_message(struct na_zmq_class *priv,
    struct na_zmq_msg_hdr *hdr, struct na_zmq_rma_hdr *rma_hdr,
    struct sockaddr_storage *source_ss, void *payload_data,
    size_t payload_size)
{
    struct na_zmq_addr *source_addr = NULL;

    /* Create source addr for msg dispatch */
    if (source_ss->ss_family != 0) {
        source_addr = (struct na_zmq_addr *) calloc(1,
            sizeof(*source_addr));
        if (source_addr != NULL) {
            memcpy(&source_addr->ss, source_ss, sizeof(*source_ss));
            hg_atomic_init32(&source_addr->refcount, 1);
            source_addr->is_self = false;
        }
    }

    /* Dispatch based on message type */
    switch (hdr->type) {
    case NA_ZMQ_MSG_UNEXPECTED:
        na_zmq_process_recv_unexpected(priv, source_addr,
            hdr->tag, payload_data, payload_size);
        payload_data = NULL; /* ownership transferred */
        break;

    case NA_ZMQ_MSG_EXPECTED:
        na_zmq_process_recv_expected(priv, source_addr,
            hdr->tag, hdr->dest_id, payload_data, payload_size);
        payload_data = NULL;
        break;

    case NA_ZMQ_MSG_RMA_PUT:
        na_zmq_process_rma_put(priv, rma_hdr,
            payload_data, payload_size);
        payload_data = NULL;
        break;

    case NA_ZMQ_MSG_RMA_GET:
        na_zmq_process_rma_get(priv, rma_hdr, source_ss);
        break;

    case NA_ZMQ_MSG_RMA_RESP:
        na_zmq_process_rma_resp(priv, rma_hdr,
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
static void
na_zmq_progress_router(struct na_zmq_class *priv)
{
    zmq_msg_t msg_identity, msg_hdr, msg_rma, msg_payload;
    int rc;

    /* Drain all available messages from the ROUTER socket */
    for (;;) {
        struct na_zmq_msg_hdr hdr;
        struct na_zmq_rma_hdr rma_hdr;
        struct sockaddr_storage source_ss;
        void *payload_data = NULL;
        size_t payload_size;
        zmq_msg_t msg_source;

        /* Read identity frame (opaque routing token from ROUTER socket) */
        zmq_msg_init(&msg_identity);
        rc = zmq_msg_recv(&msg_identity, priv->router_socket, ZMQ_DONTWAIT);
        if (rc < 0) {
            zmq_msg_close(&msg_identity);
            break; /* No more messages */
        }

        /* Save the raw identity frame for later routing responses back */
        uint8_t *saved_identity = NULL;
        size_t saved_identity_size = 0;
        {
            void *recv_id_data = zmq_msg_data(&msg_identity);
            size_t recv_id_size = zmq_msg_size(&msg_identity);
            if (recv_id_size > 0) {
                saved_identity = (uint8_t *) malloc(recv_id_size);
                if (saved_identity != NULL) {
                    memcpy(saved_identity, recv_id_data, recv_id_size);
                    saved_identity_size = recv_id_size;
                }
            }
        }
        zmq_msg_close(&msg_identity);

        /* Read header frame */
        zmq_msg_init(&msg_hdr);
        rc = zmq_msg_recv(&msg_hdr, priv->router_socket, 0);
        if (rc < 0 || (size_t) rc < sizeof(hdr)) {
            zmq_msg_close(&msg_hdr);
            free(saved_identity);
            continue;
        }
        memcpy(&hdr, zmq_msg_data(&msg_hdr), sizeof(hdr));
        zmq_msg_close(&msg_hdr);

        /* Read RMA header frame */
        zmq_msg_init(&msg_rma);
        rc = zmq_msg_recv(&msg_rma, priv->router_socket, 0);
        if (rc < 0) {
            zmq_msg_close(&msg_rma);
            free(saved_identity);
            continue;
        }
        if (zmq_msg_size(&msg_rma) >= sizeof(rma_hdr))
            memcpy(&rma_hdr, zmq_msg_data(&msg_rma), sizeof(rma_hdr));
        zmq_msg_close(&msg_rma);

        /* Read payload frame */
        zmq_msg_init(&msg_payload);
        rc = zmq_msg_recv(&msg_payload, priv->router_socket, 0);
        if (rc < 0) {
            zmq_msg_close(&msg_payload);
            free(saved_identity);
            continue;
        }
        payload_size = zmq_msg_size(&msg_payload);
        if (payload_size > 0) {
            payload_data = malloc(payload_size);
            if (payload_data != NULL)
                memcpy(payload_data, zmq_msg_data(&msg_payload), payload_size);
        }
        zmq_msg_close(&msg_payload);

        /* Read source sockaddr frame (frame 4) */
        memset(&source_ss, 0, sizeof(source_ss));
        zmq_msg_init(&msg_source);
        rc = zmq_msg_recv(&msg_source, priv->router_socket, 0);
        if (rc >= 0) {
            size_t src_size = zmq_msg_size(&msg_source);
            if (src_size == sizeof(struct sockaddr_in) ||
                src_size == sizeof(struct sockaddr_in6)) {
                memcpy(&source_ss, zmq_msg_data(&msg_source), src_size);
            }
        }
        zmq_msg_close(&msg_source);

        /* Store identity->addr mapping for routing responses back.
         * The source_ss (from frame 4) tells us the sender's actual address.
         * The saved_identity tells us the ZMQ routing token for that peer. */
        if (source_ss.ss_family != 0 && saved_identity != NULL) {
            uint64_t src_hash = na_zmq_hash_addr(&source_ss);
            na_zmq_update_peer_identity(priv, src_hash,
                &source_ss, saved_identity, saved_identity_size);
        }
        free(saved_identity);

        na_zmq_dispatch_message(priv, &hdr, &rma_hdr, &source_ss,
            payload_data, payload_size);
    }
}

/*---------------------------------------------------------------------------*/
static void
na_zmq_progress_dealer(struct na_zmq_class *priv,
    struct na_zmq_peer *peer)
{
    zmq_msg_t msg_hdr, msg_rma, msg_payload;
    int rc;

    /* Drain all available messages from this DEALER socket.
     * DEALER receives 4 frames (no identity prefix). */
    for (;;) {
        struct na_zmq_msg_hdr hdr;
        struct na_zmq_rma_hdr rma_hdr;
        struct sockaddr_storage source_ss;
        void *payload_data = NULL;
        size_t payload_size;
        zmq_msg_t msg_source;

        /* Read header frame */
        zmq_msg_init(&msg_hdr);
        rc = zmq_msg_recv(&msg_hdr, peer->dealer_socket, ZMQ_DONTWAIT);
        if (rc < 0) {
            zmq_msg_close(&msg_hdr);
            break; /* No more messages */
        }
        if ((size_t) rc < sizeof(hdr)) {
            zmq_msg_close(&msg_hdr);
            continue;
        }
        memcpy(&hdr, zmq_msg_data(&msg_hdr), sizeof(hdr));
        zmq_msg_close(&msg_hdr);

        /* Read RMA header frame */
        zmq_msg_init(&msg_rma);
        rc = zmq_msg_recv(&msg_rma, peer->dealer_socket, 0);
        if (rc < 0) {
            zmq_msg_close(&msg_rma);
            continue;
        }
        if (zmq_msg_size(&msg_rma) >= sizeof(rma_hdr))
            memcpy(&rma_hdr, zmq_msg_data(&msg_rma), sizeof(rma_hdr));
        zmq_msg_close(&msg_rma);

        /* Read payload frame */
        zmq_msg_init(&msg_payload);
        rc = zmq_msg_recv(&msg_payload, peer->dealer_socket, 0);
        if (rc < 0) {
            zmq_msg_close(&msg_payload);
            continue;
        }
        payload_size = zmq_msg_size(&msg_payload);
        if (payload_size > 0) {
            payload_data = malloc(payload_size);
            if (payload_data != NULL)
                memcpy(payload_data, zmq_msg_data(&msg_payload), payload_size);
        }
        zmq_msg_close(&msg_payload);

        /* Read source sockaddr frame (consume but ignore — we know
         * the peer from the DEALER socket we're reading from) */
        zmq_msg_init(&msg_source);
        zmq_msg_recv(&msg_source, peer->dealer_socket, 0);
        zmq_msg_close(&msg_source);

        /* Use the peer's stored address as source. This is the address
         * we used to connect, which matches what Mercury expects —
         * the wire frame's source_ss would be the remote's self_addr
         * which may differ behind NAT. */
        na_zmq_dispatch_message(priv, &hdr, &rma_hdr, &peer->ss,
            payload_data, payload_size);
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_progress(struct na_zmq_class *priv)
{
    struct na_zmq_peer *peer;

    /* Progress the ROUTER socket (receives from DEALER peers) */
    na_zmq_progress_router(priv);

    /* Progress each DEALER socket (receives from ROUTER peers) */
    STAILQ_FOREACH(peer, &priv->peer_list, entry) {
        if (peer->dealer_socket != NULL)
            na_zmq_progress_dealer(priv, peer);
    }

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
na_zmq_poll_get_fd(na_class_t NA_UNUSED *na_class,
    na_context_t NA_UNUSED *context)
{
    /* Cannot expose a single FD for ROUTER + multiple DEALERs.
     * Returning -1 forces Mercury to use poll_wait() instead. */
    return -1;
}

/*---------------------------------------------------------------------------*/
static bool
na_zmq_poll_try_wait(na_class_t *na_class,
    na_context_t NA_UNUSED *context)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_peer *peer;
    int events = 0;
    size_t events_size = sizeof(events);

    /* Check if there are queued messages waiting */
    if (!STAILQ_EMPTY(&priv->unexpected_msg_queue))
        return false;

    /* Check ROUTER socket events */
    zmq_getsockopt(priv->router_socket, ZMQ_EVENTS, &events, &events_size);
    if (events & ZMQ_POLLIN)
        return false;

    /* Check all DEALER sockets */
    STAILQ_FOREACH(peer, &priv->peer_list, entry) {
        if (peer->dealer_socket != NULL) {
            events = 0;
            events_size = sizeof(events);
            zmq_getsockopt(peer->dealer_socket, ZMQ_EVENTS,
                &events, &events_size);
            if (events & ZMQ_POLLIN)
                return false;
        }
    }

    return true;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_poll(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int *count_p)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);

    if (hg_thread_mutex_try_lock(&priv->socket_lock) == HG_UTIL_SUCCESS) {
        na_zmq_progress(priv);
        hg_thread_mutex_unlock(&priv->socket_lock);
    }

    if (count_p != NULL)
        *count_p = 0;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_poll_wait(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms, unsigned int *count_p)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_peer *peer;
    struct pollfd pfds[64];
    nfds_t nfds = 0;
    int events, rc;
    size_t events_size;
    bool has_data = false;

    /* Build pollfd array from ROUTER + all DEALER sockets.
     * Also check ZMQ_EVENTS to re-arm edge-triggered FDs. */
    {
        int fd = -1;
        size_t fd_size = sizeof(fd);

        /* ROUTER socket */
        zmq_getsockopt(priv->router_socket, ZMQ_FD, &fd, &fd_size);
        events = 0;
        events_size = sizeof(events);
        zmq_getsockopt(priv->router_socket, ZMQ_EVENTS,
            &events, &events_size);
        if (events & ZMQ_POLLIN)
            has_data = true;
        if (fd >= 0 && nfds < 64) {
            pfds[nfds].fd = fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        /* DEALER sockets */
        STAILQ_FOREACH(peer, &priv->peer_list, entry) {
            if (peer->dealer_socket != NULL && nfds < 64) {
                fd = -1;
                fd_size = sizeof(fd);
                zmq_getsockopt(peer->dealer_socket, ZMQ_FD, &fd, &fd_size);
                events = 0;
                events_size = sizeof(events);
                zmq_getsockopt(peer->dealer_socket, ZMQ_EVENTS,
                    &events, &events_size);
                if (events & ZMQ_POLLIN)
                    has_data = true;
                if (fd >= 0) {
                    pfds[nfds].fd = fd;
                    pfds[nfds].events = POLLIN;
                    pfds[nfds].revents = 0;
                    nfds++;
                }
            }
        }
    }

    if (has_data) {
        /* Data available - process immediately */
        hg_thread_mutex_lock(&priv->socket_lock);
        na_zmq_progress(priv);
        hg_thread_mutex_unlock(&priv->socket_lock);

        if (count_p != NULL)
            *count_p = 0;
        return NA_SUCCESS;
    }

    /* Wait for activity on any socket FD */
    rc = poll(pfds, nfds, (int) timeout_ms);
    if (rc < 0 && errno != EINTR)
        return NA_IO_ERROR;

    /* Process regardless (ZMQ edge-triggered FD semantics) */
    hg_thread_mutex_lock(&priv->socket_lock);
    na_zmq_progress(priv);
    hg_thread_mutex_unlock(&priv->socket_lock);

    if (count_p != NULL)
        *count_p = 0;

    if (rc == 0)
        return NA_TIMEOUT;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_zmq_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
    na_op_id_t *op_id)
{
    struct na_zmq_class *priv = NA_ZMQ_CLASS(na_class);
    struct na_zmq_op_id *op = (struct na_zmq_op_id *) op_id;

    if (!(hg_atomic_get32(&op->status) & NA_ZMQ_OP_QUEUED))
        return NA_SUCCESS;

    if (op->type == NA_CB_RECV_UNEXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->unexpected_recv_queue, op,
            na_zmq_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    if (op->type == NA_CB_RECV_EXPECTED) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->expected_recv_queue, op,
            na_zmq_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    if (op->type == NA_CB_GET) {
        hg_thread_mutex_lock(&priv->queue_lock);
        STAILQ_REMOVE(&priv->rma_get_queue, op,
            na_zmq_op_id, entry);
        hg_thread_mutex_unlock(&priv->queue_lock);
    }

    na_zmq_complete_op(op, NA_CANCELED);

    return NA_SUCCESS;
}
