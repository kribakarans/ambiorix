/****************************************************************************
**
** - DISCLAIMER OF WARRANTY -
**
** THIS FILE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
** EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
** PURPOSE.
**
** THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOURCE
** CODE IS WITH YOU. SHOULD THE SOURCE CODE PROVE DEFECTIVE, YOU
** ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
**
** - LIMITATION OF LIABILITY -
**
** IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN
** WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES
** AND/OR DISTRIBUTES THE SOURCE CODE, BE LIABLE TO YOU FOR DAMAGES,
** INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES
** ARISING OUT OF THE USE OR INABILITY TO USE THE SOURCE CODE
** (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED
** INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE
** OF THE SOURCE CODE TO OPERATE WITH ANY OTHER PROGRAM), EVEN IF SUCH
** HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
** DAMAGES.
**
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <amxrt/amxrt.h>
#include "main.h"

typedef struct _sub_data {
    const char* object;
    const char* expression;
} sub_data_t;

static int exit_code = 0;

static int check_args(int argc, int index) {
    int retval = -1;

    if(argc - index < 1) {
        printf("\n\nInvalid number of arguments\n");
        amxrt_print_usage();
        goto leave;
    }

    retval = 0;

leave:
    return retval;
}

static void notify_handler(const char* const sig_name,
                           const amxc_var_t* const data,
                           UNUSED void* const priv) {
    printf("Notification received from [%s]:\n", sig_name);
    amxc_var_dump(data, STDOUT_FILENO);
}

static void wait_done(UNUSED const char* const sig_name,
                      UNUSED const amxc_var_t* const d,
                      void* const priv) {
    int retval = 0;
    sub_data_t* data = (sub_data_t*) priv;
    amxb_bus_ctx_t* bus_ctx = amxb_be_who_has(data->object);
    if(bus_ctx == NULL) {
        printf("Unexpected error: no bus context found that can provide object [%s]\n", data->object);
        amxrt_el_stop();
        exit_code = 1;
        goto exit;
    }
    printf("Wait done - object [%s] is available\n", data->object);

    retval = amxb_subscribe(bus_ctx,
                            data->object,
                            data->expression,
                            notify_handler,
                            NULL);
    if(retval != 0) {
        printf("Failed to create subscription for [%s] - [retval = %d]\n", data->object, retval);
        exit_code = 2;
        amxrt_el_stop();
    }

exit:
    return;
}

static int subscribe(sub_data_t* data) {
    int retval = 0;

    printf("Wait until object [%s] is available\n", data->object);
    retval = amxp_slot_connect(NULL, "wait:done", NULL, wait_done, data);
    when_failed(retval, exit);
    retval = amxb_wait_for_object(data->object);

exit:
    return retval;
}

int SUBSCRIBE_MAIN(int argc, char* argv[]) {
    int index = 0;
    amxc_var_t* config = NULL;

    sub_data_t data = {
        .object = NULL,
        .expression = NULL,
    };

    amxrt_new();

    config = amxrt_get_config();

    // set the usage doc
    amxrt_cmd_line_set_usage_doc("[OPTIONS] <OBJECT PATH> [<FILTER EXPRESSION>]");
    // remove all default options and re-add some of them
    amxrt_cmd_line_options_reset();
    amxrt_cmd_line_add_option(0, 'h', "help", no_argument, "Print usage help and exit", NULL);
    amxrt_cmd_line_add_option(0, 'B', "backend", required_argument, "Loads the shared object as bus backend", "so file");
    amxrt_cmd_line_add_option(0, 'u', "uri", required_argument, "Adds an uri to the list of uris", "uri");
    amxrt_cmd_line_add_option(0, 'A', "no-auto-detect", no_argument, "Do not auto detect unix domain sockets and back-ends", NULL);

    exit_code = amxrt_config_init(argc, argv, &index, NULL);
    when_failed(exit_code, leave);

    // turn off creation of the pid file
    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_PID_FILE), false);

    exit_code = check_args(argc, index);
    when_failed(exit_code, leave);

    data.object = argv[index];
    index++;
    if(index < argc) {
        data.expression = argv[index];
    }

    exit_code = amxrt_connect();
    when_failed(exit_code, leave);

    exit_code = amxrt_el_create();
    when_failed(exit_code, leave);

    exit_code = subscribe(&data);
    when_failed(exit_code, leave);

    amxrt_el_start(); // will block until amxrt_el_stop is called

leave:
    amxp_slot_disconnect_all(wait_done);
    amxrt_stop();
    amxrt_delete();
    return exit_code;
}
