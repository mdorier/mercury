/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_fs.h"
#include "shipper_test.h"
#include "function_shipper_handler.h"

#include <stdio.h>
#include <stdlib.h>

/* Actual definition of the function that needs to be executed */
int bla_open(const char *path, bla_handle_t handle, int *event_id)
{
    printf("Called bla_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return S_SUCCESS;
}

/******************************************************************************/
int fs_bla_open(fs_handle_t handle)
{
    int ret = S_SUCCESS;

    void          *bla_open_in_buf;
    size_t         bla_open_in_buf_size;
    bla_open_in_t  bla_open_in_struct;

    void          *bla_open_out_buf;
    size_t         bla_open_out_buf_size;
    void          *bla_open_out_extra_buf = NULL;
    size_t         bla_open_out_extra_buf_size = 0;
    bla_open_out_t bla_open_out_struct;

    fs_proc_t proc;

    const char *bla_open_path;
    bla_handle_t bla_open_handle;
    int bla_open_event_id;
    int bla_open_ret;

    /* Get input buffer */
    ret = fs_handler_get_input(handle, &bla_open_in_buf, &bla_open_in_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    fs_proc_create(bla_open_in_buf, bla_open_in_buf_size, FS_DECODE, &proc);
    fs_proc_bla_open_in_t(proc, &bla_open_in_struct);
    fs_proc_free(proc);

    /* Get parameters */
    bla_open_path = bla_open_in_struct.path;
    bla_open_handle = bla_open_in_struct.handle;

    /* Call bla_open */
    bla_open_ret = bla_open(bla_open_path, bla_open_handle, &bla_open_event_id);

    /* Fill output structure */
    bla_open_out_struct.event_id = bla_open_event_id;
    bla_open_out_struct.ret = bla_open_ret;

    /* Create a new encoding proc */
    ret = fs_handler_get_output(handle, &bla_open_out_buf, &bla_open_out_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get output buffer\n");
        return ret;
    }

    fs_proc_create(bla_open_out_buf, bla_open_out_buf_size, FS_ENCODE, &proc);
    fs_proc_bla_open_out_t(proc, &bla_open_out_struct);
    if (fs_proc_get_extra_buf(proc)) {
        bla_open_out_extra_buf = fs_proc_get_extra_buf(proc);
        bla_open_out_extra_buf_size = fs_proc_get_extra_size(proc);
        fs_proc_set_extra_buf_is_mine(proc, 1);
    }
    fs_proc_free(proc);

    /* Free handle and send response back */
    ret = fs_handler_respond(handle, bla_open_out_extra_buf, bla_open_out_extra_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Also free memory allocated during decoding */
    fs_proc_create(NULL, 0, FS_FREE, &proc);
    fs_proc_bla_open_in_t(proc, &bla_open_in_struct);
    fs_proc_free(proc);

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;
    unsigned int number_of_peers;
    unsigned int i;
    int fs_ret;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_ret = fs_handler_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper handler\n");
        return EXIT_FAILURE;
    }

    /* Register routine */
    IOFSL_SHIPPER_HANDLER_REGISTER("bla_open", fs_bla_open);

    for (i = 0; i < number_of_peers; i++) {
        /* Receive new function calls */
        fs_ret = fs_handler_process(FS_HANDLER_MAX_IDLE_TIME);
        if (fs_ret != S_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
        }
    }

    printf("Finalizing...\n");

    fs_ret = fs_handler_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper handler\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
