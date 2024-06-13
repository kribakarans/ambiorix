/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
**
** Redistribution and use in source and binary forms, with or without modification,
** are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright notice,
** this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above copyright notice,
** this list of conditions and the following disclaimer in the documentation
** and/or other materials provided with the distribution.
**
** Subject to the terms and conditions of this license, each copyright holder
** and contributor hereby grants to those receiving rights under this license
** a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
** (except for failure to satisfy the conditions of this license) patent license
** to make, have made, use, offer to sell, sell, import, and otherwise transfer
** this software, where such license applies only to those patent claims, already
** acquired or hereafter acquired, licensable by such copyright holder or contributor
** that are necessarily infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright holders and
** non-copyrightable additions of contributors, in source or binary form) alone;
** or
**
** (b) combination of their Contribution(s) with the work of authorship to which
** such Contribution(s) was added by such copyright holder or contributor, if,
** at the time the Contribution is added, such addition causes such combination
** to be necessarily infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any copyright
** holder or contributor is granted under this license, whether expressly, by
** implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
** USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include <amxc/amxc.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb_register.h>
#include <amxb/amxb.h>

#include "check.h"
#include "utils.h"

#define EXIT(rv, code, label) rv = code; goto label;

static struct sigaction sig_handler;

static void clean_exit_on_sig(int sig_num) {
    print_error("No\n");
    print_reason("Causes signal ");
    printf("[%d]\n", sig_num);
    exit(99);
}

static void signal_init(void) {
    sig_handler.sa_handler = clean_exit_on_sig;
    sigemptyset(&sig_handler.sa_mask);
    sig_handler.sa_flags = 0;
    sigaction(SIGINT, &sig_handler, NULL);
    sigaction(SIGSEGV, &sig_handler, NULL);
}

static void print_usage(const char* name) {
    printf("Usage: %s <options> <backend>\n", name);
    printf("\n");
    printf("Options:\n");
    printf("\t -n: no colors");
    printf("\n\n\n");
}

static int verify_is_amxb_backend(const char* so, void** handle,
                                  amxb_be_info_t** be_info) {
    int retval = 0;
    amxb_be_info_fn_t get_info_fn = NULL;

    print_message("\n\n");
    print_message("1. Verify is valid amxb backend shared object\n");

    *handle = check_can_load(so);
    if(*handle == NULL) {
        EXIT(retval, 1, leave);
    }
    get_info_fn = check_is_amxb_backend(*handle);
    if(get_info_fn == NULL) {
        EXIT(retval, 2, leave);
    }
    *be_info = check_can_fetch_info(*get_info_fn);
    if(*be_info == NULL) {
        EXIT(retval, 3, leave);
    }

leave:
    return retval;
}

static int verify_backend_information(amxb_be_info_t* be_info) {
    int retval = 0;

    print_message("\n\n");
    print_message("2. Verify provides valid information\n");
    if(check_info_has_name(be_info) != 0) {
        EXIT(retval, 4, leave);
    }
    if(check_info_version(STR_INFO_HAS_BE_VERSION,
                          "be_version",
                          be_info->be_version) != 0) {
        EXIT(retval, 5, leave);
    }
    if(check_info_version(STR_INFO_HAS_MIN_SUP_VERSION,
                          "min_supported",
                          be_info->min_supported) != 0) {
        EXIT(retval, 6, leave);
    }
    if(check_info_version(STR_INFO_HAS_MAX_SUP_VERSION,
                          "max_supported",
                          be_info->max_supported) != 0) {
        EXIT(retval, 7, leave);
    }
    if(check_versions_are_valid(be_info) != 0) {
        EXIT(retval, 8, leave);
    }
    if(check_be_is_supported(be_info) != 0) {
        EXIT(retval, 9, leave);
    }

leave:
    return retval;
}

static int verify_amxb_integration(const char* so, const char* name) {
    int retval = 0;
    amxb_be_funcs_t* funcs = NULL;

    print_message("\n\n");
    print_message("3. Verify libamxb integration\n");

    if(check_amxb_can_load(so) != 0) {
        EXIT(retval, 10, leave);
    }
    funcs = check_be_registers_function_table(name);
    if(funcs == NULL) {
        EXIT(retval, 11, leave);
    }

    if(check_be_supports_fn("connect", (void*) funcs->connect, true) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("disconnect", (void*) funcs->disconnect, true) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("get_fd", (void*) funcs->get_fd, true) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("read", (void*) funcs->read, true) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("free", (void*) funcs->free, true) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("listen", (void*) funcs->listen, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("accept", (void*) funcs->accept, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("read_raw", (void*) funcs->read_raw, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("register", (void*) funcs->register_dm, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("new_invoke", (void*) funcs->new_invoke, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("free_invoke", (void*) funcs->free_invoke, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("invoke", (void*) funcs->invoke, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("async_invoke", (void*) funcs->async_invoke, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("get", (void*) funcs->get, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("set", (void*) funcs->set, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("add", (void*) funcs->add, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("del", (void*) funcs->del, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("get_supported", (void*) funcs->get_supported, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("set_config", (void*) funcs->set_config, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("describe", (void*) funcs->describe, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("list", (void*) funcs->list, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("close_request", (void*) funcs->close_request, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("wait_request", (void*) funcs->wait_request, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("subscribe", (void*) funcs->subscribe, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("unsubscribe",
                            (void*) funcs->unsubscribe,
                            ( funcs->subscribe != NULL)) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("wait_for", (void*) funcs->wait_for, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("has", (void*) funcs->has, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("capabilities", (void*) funcs->capabilities, false) != 0) {
        EXIT(retval, 12, leave);
    }
    if(check_be_supports_fn("get_instances", (void*) funcs->get_instances, false) != 0) {
        EXIT(retval, 12, leave);
    }

leave:
    amxb_be_remove_all();
    return retval;
}

static int verify(const char* so, char** name) {
    int retval = -1;
    void* handle = NULL;
    amxb_be_info_t* be_info = NULL;
    size_t name_length = 0;

    print_message("\nInspecting ");
    print_success(so);
    print_message(":");

    retval = verify_is_amxb_backend(so, &handle, &be_info);
    if(retval != 0) {
        goto leave;
    }

    retval = verify_backend_information(be_info);
    if(retval != 0) {
        goto leave;
    }

    name_length = strlen(be_info->name) + 1;
    *name = (char*) calloc(1, name_length);
    strcpy(*name, be_info->name);

    dlclose(handle);

    handle = NULL;

    retval = verify_amxb_integration(so, *name);

leave:
    if(handle != NULL) {
        dlclose(handle);
    }
    return retval;
}

static void easter_egg(const char* procname) {
    while(procname[0] && ispunct(procname[0])) {
        procname++;
    }

    if(strcmp(procname, "hocus") == 0) {
        printf("pocus\n");
        exit(0);
    }

    if(strcmp(procname, "simsala") == 0) {
        printf("bim\n");
        exit(0);
    }

    if(strcmp(procname, "acra") == 0) {
        printf("cadabra\n");
        exit(0);
    }

    if(strcmp(procname, "geminio") == 0) {
        printf("This is a worthless duplicate of the amxb-inspect\n");
        exit(0);
    }

    if(strcmp(procname, "incendio") == 0) {
        printf("The roof, the roof, the roof is on fire\n");
        exit(0);
    }

}

int main(int argc, char* argv[]) {
    int retval = 0;
    char* name = NULL;
    int ch = 0;
    const char* procname = argv[0];
    struct stat buffer;

    signal_init();

    while((ch = getopt(argc, argv, "n")) != -1) {
        switch(ch) {
        case 'n':
            enable_colors(false);
            break;
        }
    }

    easter_egg(procname);

    argc -= optind;
    argv += optind;

    if(argc < 1) {
        print_usage(procname);
        EXIT(retval, -1, leave);
    }

    if(stat(argv[0], &buffer) != 0) {
        printf("File not found %s\n\n", argv[0]);
        print_usage(procname);
        EXIT(retval, -1, leave);
    }

    retval = verify(argv[0], &name);

leave:
    if(retval != -1) {
        print_message("\nIs ");
        print_message(argv[0]);
        print_message(" a valid amxb backend? ");
        if(retval == 0) {
            print_success("YES\n\n");
        } else {
            print_error("NO\n\n");
        }
    }
    amxb_be_remove_all();
    free(name);
    return retval;
}
