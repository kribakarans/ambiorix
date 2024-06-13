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

#include <sys/resource.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <dirent.h>
#include <ctype.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>

static amxp_expr_status_t amxp_proci_expr_get_field(UNUSED amxp_expr_t* expr,
                                                    amxc_var_t* value,
                                                    const char* path,
                                                    void* priv) {
    amxp_expr_status_t status = amxp_expr_status_ok;
    amxp_proc_info_t* pi = (amxp_proc_info_t*) priv;

    if(strcmp(path, "name") == 0) {
        amxc_var_set(cstring_t, value, pi->name);
    } else if(strcmp(path, "parent_pid") == 0) {
        amxc_var_set(int32_t, value, pi->parent_pid);
    } else if(strcmp(path, "ppid") == 0) {
        amxc_var_set(int32_t, value, pi->parent_pid);
    } else if(strcmp(path, "state") == 0) {
        amxc_var_set(int8_t, value, pi->state);
    } else {
        status = amxp_expr_status_field_not_found;
    }

    return status;
}

static void amxp_proci_fill(amxp_proc_info_t* proc_info, amxc_var_t* data) {
    int index = 0;
    amxc_var_for_each(item, data) {
        switch(index) {
        case 0:
            proc_info->pid = amxc_var_dyncast(int32_t, item);
            break;
        case 1: {
            amxc_string_t name;
            char* n = amxc_var_take(cstring_t, item);
            amxc_string_init(&name, 0);
            amxc_string_push_buffer(&name, n, n == NULL ? 0 : strlen(n) + 1);
            amxc_string_trim(&name, ispunct);
            proc_info->name = amxc_string_take_buffer(&name);
        }
        break;
        case 2:
            proc_info->state = amxc_var_dyncast(int8_t, item);
            break;
        case 3:
            proc_info->parent_pid = amxc_var_dyncast(int32_t, item);
            break;
        case 4:
            proc_info->process_gid = amxc_var_dyncast(int32_t, item);
            break;
        case 5:
            proc_info->session_id = amxc_var_dyncast(int32_t, item);
            break;
        }
        index++;
    }
}

static amxp_proc_info_t* amxp_proci_read_stat(amxc_string_t* file) {
    FILE* fp = NULL;
    amxp_proc_info_t* proc_info = NULL;
    amxc_var_t stat;
    ssize_t read = 0;
    char* line = NULL;
    size_t len = 0;

    amxc_var_init(&stat);

    fp = fopen(amxc_string_get(file, 0), "r");
    if(fp == NULL) {
        goto exit;
    }

    read = getline(&line, &len, fp);
    if(read == -1) {
        fclose(fp);
        free(line);
        goto exit;
    }
    fclose(fp);

    amxc_var_push(ssv_string_t, &stat, line);
    amxc_var_cast(&stat, AMXC_VAR_ID_LIST);

    proc_info = (amxp_proc_info_t*) calloc(1, sizeof(amxp_proc_info_t));
    when_null(proc_info, exit);

    amxp_proci_fill(proc_info, &stat);

exit:
    amxc_var_clean(&stat);
    return proc_info;
}

static int amxp_proci_scan_proc(amxc_llist_t* procs, amxp_expr_t* expr) {
    int retval = -1;
    DIR* dp;
    struct dirent* ep;
    amxc_string_t filename;
    amxp_proc_info_t* pi = NULL;
    amxp_expr_status_t status = amxp_expr_status_ok;

    amxc_string_init(&filename, 128);

    dp = opendir("/proc/");
    when_null(dp, exit);

    for(ep = readdir(dp); ep; ep = readdir(dp)) {
        if(ep->d_type != DT_DIR) {
            continue;
        }

        if(ep->d_name[0] == '.') {
            continue;
        }

        amxc_string_reset(&filename);
        amxc_string_setf(&filename, "/proc/%s/stat", ep->d_name);
        pi = amxp_proci_read_stat(&filename);
        if(pi != NULL) {
            if(expr != NULL) {
                if(amxp_expr_evaluate(expr, amxp_proci_expr_get_field, pi, &status)) {
                    amxc_llist_append(procs, &pi->it);
                } else {
                    amxp_proci_free_it(&pi->it);
                }
            } else {
                amxc_llist_append(procs, &pi->it);
            }
        }

    }
    closedir(dp);

    retval = 0;

exit:
    amxc_string_clean(&filename);
    return retval;
}

void amxp_proci_free_it(amxc_llist_it_t* it) {
    amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
    free(pi->name);
    free(pi);
}

int amxp_proci_findf(amxc_llist_t* result, const char* filter, ...) {
    int retval = -1;
    amxc_string_t expression;
    va_list args;
    amxp_expr_t expr;

    amxc_string_init(&expression, 0);
    when_null(result, exit);

    if(filter != NULL) {
        va_start(args, filter);
        amxc_string_vsetf(&expression, filter, args);
        va_end(args);
        when_failed(amxp_expr_init(&expr, amxc_string_get(&expression, 0)), exit);
    }


    retval = amxp_proci_scan_proc(result, filter == NULL ? NULL : &expr);

exit:
    if(filter != NULL) {
        amxp_expr_clean(&expr);
    }
    amxc_string_clean(&expression);
    return retval;
}