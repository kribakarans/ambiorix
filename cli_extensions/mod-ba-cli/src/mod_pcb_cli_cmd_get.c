/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
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

#include <string.h>
#include <stdio.h>

#include "ba_cli_priv.h"

#include "mod_pcb_cli.h"
#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"
#include "amxa/amxa_get.h"

typedef struct _sub_info {
    amxc_llist_it_t it;
    char* opath;
    char* filter;
    amxb_subscription_t* sub;
} subscription_info_t;

static amxc_llist_t subscriptions;

static void mod_pcb_cli_new_sub_info(amxb_subscription_t* sub,
                                     const char* orig_path,
                                     const char* filter) {
    subscription_info_t* info = (subscription_info_t*) calloc(1, sizeof(subscription_info_t));
    info->opath = strdup(orig_path);
    info->filter = filter == NULL ? NULL : strdup(filter);
    info->sub = sub;
    amxc_llist_append(&subscriptions, &info->it);
}

static void mod_pcb_cli_free_sub_info(amxc_llist_it_t* it) {
    subscription_info_t* info = amxc_container_of(it, subscription_info_t, it);
    free(info->opath);
    free(info->filter);
    amxc_llist_it_take(&info->it);
    amxb_subscription_delete(&info->sub);
    free(info);
}

static subscription_info_t* mod_pcb_cli_find_sub(const char* object) {
    subscription_info_t* info = NULL;

    if(object != NULL) {

        amxc_llist_iterate(it, (&subscriptions)) {
            info = amxc_container_of(it, subscription_info_t, it);
            if(strcmp(info->sub->object, object) == 0) {
                break;
            }
            info = NULL;
        }
    }

    return info;
}

static int mod_pcb_cli_add_sub(amxt_tty_t* tty,
                               amxb_bus_ctx_t* bus_ctx,
                               amxd_path_t* path,
                               const char* filter) {
    int rv = 0;
    amxb_subscription_t* sub = NULL;
    const char* prefix = " ";
    amxc_string_t expr;
    const char* sub_path = NULL;

    amxc_string_init(&expr, 0);
    sub_path = amxd_path_get(path, AMXD_OBJECT_TERMINATE);
    if(amxd_path_get_param(path) != NULL) {
        amxc_string_appendf(&expr, "contains('parameters.%s')",
                            amxd_path_get_param(path));
        prefix = " && ";
    }
    if((filter != NULL) && (*filter != 0)) {
        amxc_string_appendf(&expr, "%s%s", prefix, filter);
    }
    filter = amxc_string_is_empty(&expr) ? NULL : amxc_string_get(&expr, 0);

    rv = amxb_subscription_new(&sub, bus_ctx, sub_path, filter, mod_pcb_cli_event_cb, NULL);
    if(rv == AMXB_STATUS_OK) {
        amxt_tty_messagef(tty, "Added subscription for ${color.blue}%s${color.green}\n",
                          sub_path);
        if(filter != NULL) {
            amxt_tty_messagef(tty, "Using filter ${color.blue}%s${color.green}\n", filter);
        }
        mod_pcb_cli_new_sub_info(sub, amxd_path_get(path, AMXD_OBJECT_TERMINATE), filter);
    } else {
        amxt_tty_errorf(tty, "Failed to create subscription for ${color.blue}%s${color.green}\n",
                        amxd_path_get(path, AMXD_OBJECT_TERMINATE));
    }

    amxc_string_clean(&expr);
    return rv;
}

static int mod_pcb_cli_remove_subs(amxt_tty_t* tty,
                                   amxd_path_t* path) {
    int rv = 0;
    subscription_info_t* info = NULL;
    const char* p = amxd_path_get(path, 0);

    if(amxd_path_is_search_path(path)) {
        amxt_tty_errorf(tty, "Search paths not allowed [%s]\n", p);
        rv = -1;
        goto exit;
    }
    info = mod_pcb_cli_find_sub(p);
    if(info == NULL) {
        amxt_tty_errorf(tty, "No subscription found for [%s]\n", p);
        rv = -1;
        goto exit;
    }

    while(info != NULL) {
        amxt_tty_messagef(tty, "Remove subscription for [%s]\n", info->sub->object);
        mod_pcb_cli_free_sub_info(&info->it);
        info = mod_pcb_cli_find_sub(p);
    }

exit:
    return rv;
}

int mod_pcb_cli_get(amxt_tty_t* tty,
                    amxb_bus_ctx_t* bus_ctx,
                    UNUSED amxc_var_t* options,
                    const char* path,
                    amxc_var_t* cmd) {
    amxc_var_t data;
    int rv = 0;
    char* part = NULL;
    char* acl_file = NULL;
    int32_t depth = INT32_MAX;
    char* filter = NULL;
    amxd_path_t p;
    amxd_path_init(&p, path);
    amxc_var_init(&data);

    // [DEPTH <FILTER>|& [<FILTER>]|$]
    part = amxt_cmd_pop_part(cmd);
    while(part != NULL && *part == 0) {
        free(part);
        part = amxt_cmd_pop_part(cmd);
    }
    if(part != NULL) {
        if(part[0] == '&') {
            filter = amxt_cmd_take_all(cmd);
            rv = mod_pcb_cli_add_sub(tty, bus_ctx, &p, filter);
            goto exit;
        } else if(part[0] == '$') {
            rv = mod_pcb_cli_remove_subs(tty, &p);
            goto exit;
        } else {
            char* endptr = NULL;
            depth = strtol(part, &endptr, 10);
            if((endptr != NULL) && (*endptr != 0)) {
                depth = INT32_MAX;
                amxt_cmd_prepend_part(cmd, part);
                part = NULL;
            }
        }
    }

    filter = amxt_cmd_take_all(cmd);
    if(mod_pcb_cli_acl_enabled()) {
        acl_file = mod_pcb_cli_get_acl_file();
        rv = amxa_get_filtered(bus_ctx, path, filter, acl_file, depth, &data, 5);
    } else {
        rv = amxb_get_filtered(bus_ctx, path, filter, depth, &data, 5);
    }
    if(rv != 0) {
        amxt_tty_errorf(tty, "get %s failed (%d - %s)\n", path, rv, amxd_status_string((amxd_status_t) rv));
        goto exit;
    }

    if((filter != NULL) && (*filter != 0)) {
        // When a filter is provided, remove all empty objects
        amxc_var_t* d = GETI_ARG(&data, 0);
        amxc_var_for_each(reply_object_path, d) {
            const amxc_htable_t* params = amxc_var_constcast(amxc_htable_t, reply_object_path);
            if(amxc_htable_is_empty(params)) {
                amxc_var_delete(&reply_object_path);
            }
        }
    }

    mod_pcb_cli_output_flat(tty, &data, amxd_path_get_param(&p) != NULL);

exit:
    free(filter);
    free(acl_file);
    free(part);
    amxd_path_clean(&p);
    amxc_var_clean(&data);
    return rv;
}

int mod_pcb_cli_cmd_subscriptions(UNUSED const char* function_name,
                                  amxc_var_t* args,
                                  UNUSED amxc_var_t* ret) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxd_path_t path;
    amxc_var_t objects;
    int rv = 0;
    amxt_tty_t* tty = GET_TTY(args);

    amxd_path_init(&path, NULL);
    amxc_var_init(&objects);

    if(amxc_llist_is_empty(&subscriptions)) {
        amxt_tty_writef(tty, "${color.green}No subscriptions taken${color.reset}\n");
    }

    amxc_llist_iterate(it, &subscriptions) {
        subscription_info_t* info = amxc_container_of(it, subscription_info_t, it);
        amxb_subscription_t* sub = info->sub;
        amxt_tty_writef(tty, "${color.green}Subscription path    : ${color.blue}%s${color.reset}\n", sub->object);
        if(info->filter != NULL) {
            amxt_tty_writef(tty, "    ${color.green}Applied filter   : ${color.blue}%s${color.reset}\n", info->filter);
        }
        amxt_tty_writef(tty, "    ${color.green}Requested path   : ${color.blue}%s${color.reset}\n", info->opath);

        amxd_path_setf(&path, false, "%s", info->opath);
        if(amxd_path_is_search_path(&path)) {
            amxc_var_clean(&objects);
            bus_ctx = mod_pcb_cli_get_bus_ctx(sub->object);
            if((amxb_resolve(bus_ctx, &path, &objects) == 0) &&
               ( amxc_var_type_of(&objects) == AMXC_VAR_ID_LIST)) {
                amxt_tty_writef(tty, "    ${color.green}Matching objects : ");
                amxc_var_for_each(object, (&objects)) {
                    const char* mop = GET_CHAR(object, NULL);
                    amxt_tty_writef(tty, "${color.blue}%s${color.reset}\n                       ", mop);
                }
            }
        }

        amxt_tty_writef(tty, "\n");
    }

    amxd_path_clean(&path);
    amxc_var_clean(&objects);
    return rv;
}

void mod_pcb_cli_subscriptions_init(void) {
    amxc_llist_init(&subscriptions);
}

void mod_pcb_cli_subscriptions_clean(void) {
    amxc_llist_clean(&subscriptions, mod_pcb_cli_free_sub_info);
}