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

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>

#include "amxp/amxp_expression.h"
#include "amxp/amxp_dir.h"

static amxp_expr_status_t amxp_expr_dir_get_field(UNUSED amxp_expr_t* expr,
                                                  amxc_var_t* value,
                                                  const char* path,
                                                  void* priv) {
    struct dirent* ep = (struct dirent*) priv;
    amxp_expr_status_t status = amxp_expr_status_ok;

    if(strcmp(path, "d_ino") == 0) {
        amxc_var_set(uint32_t, value, ep->d_ino);
    } else if(strcmp(path, "d_type") == 0) {
        amxc_var_set(uint32_t, value, ep->d_type);
    } else if(strcmp(path, "d_name") == 0) {
        amxc_var_set(cstring_t, value, ep->d_name);
    } else if(strcmp(path, "DT_BLK") == 0) {
        amxc_var_set(uint32_t, value, DT_BLK);
    } else if(strcmp(path, "DT_CHR") == 0) {
        amxc_var_set(uint32_t, value, DT_CHR);
    } else if(strcmp(path, "DT_DIR") == 0) {
        amxc_var_set(uint32_t, value, DT_DIR);
    } else if(strcmp(path, "DT_FIFO") == 0) {
        amxc_var_set(uint32_t, value, DT_FIFO);
    } else if(strcmp(path, "DT_LNK") == 0) {
        amxc_var_set(uint32_t, value, DT_LNK);
    } else if(strcmp(path, "DT_REG") == 0) {
        amxc_var_set(uint32_t, value, DT_REG);
    } else if(strcmp(path, "DT_SOCK") == 0) {
        amxc_var_set(uint32_t, value, DT_SOCK);
    } else if(strcmp(path, "DT_UNKNOWN") == 0) {
        amxc_var_set(uint32_t, value, DT_UNKNOWN);
    } else {
        status = amxp_expr_status_field_not_found;
    }

    return status;
}

static int amxp_dir_check_is_empty(UNUSED const char* name, UNUSED void* priv) {
    return -1;
}

static int amxp_dir_scan_impl(const char* path,
                              amxp_expr_t* expr,
                              bool recursive,
                              amxp_dir_match_fn_t fn,
                              void* priv) {
    int retval = -1;
    DIR* dp = NULL;
    struct dirent* ep = NULL;
    amxc_string_t filename;
    size_t path_len = strlen(path);
    amxc_string_init(&filename, 128);
    dp = opendir(path);
    when_null(dp, exit);

    retval = 0;

    for(ep = readdir(dp); ep; ep = readdir(dp)) {
        if(ep->d_name[0] == '.') {
            continue;
        }
        if(path[path_len - 1] == '/') {
            amxc_string_setf(&filename, "%s%s", path, ep->d_name);
        } else {
            amxc_string_setf(&filename, "%s/%s", path, ep->d_name);
        }
        if((expr == NULL) || amxp_expr_evaluate(expr, amxp_expr_dir_get_field, ep, NULL)) {
            if(fn != NULL) {
                retval = fn(amxc_string_get(&filename, 0), priv);
                when_failed(retval, exit);
            }
        }
        if(recursive && (ep->d_type == DT_DIR)) {
            retval = amxp_dir_scan_impl(amxc_string_get(&filename, 0), expr, recursive, fn, priv);
            when_failed(retval, exit);
        }
    }

exit:
    amxc_string_clean(&filename);
    if(dp != NULL) {
        closedir(dp);
    }
    return retval;
}

int amxp_dir_owned_make(const char* path, const mode_t mode, uid_t uid, gid_t gid) {
    int retval = -1;
    char* dir = NULL;
    char* current = NULL;
    struct stat sb;

    when_str_empty(path, exit);

    if(stat(path, &sb) == 0) {
        retval = 0;
        goto exit;
    }

    dir = strdup(path);
    when_null(dir, exit);
    /* 'dir' does not exist. Create it, from left to right. */
    current = strchr(dir, '/');

    while(current != NULL && *current != 0) {
        *current = '\0';

        if(dir[0] == 0) {
            *current = '/';
            current = strchr(current + 1, '/');
            continue;
        }

        if(stat(dir, &sb) == 0) {
            *current = '/';
            current = strchr(current + 1, '/');
            continue;
        }

        retval = mkdir(dir, mode);
        when_failed(retval, exit);
        if((uid != 0) || (gid != 0)) {
            retval = chown(dir, uid, gid);
            when_failed(retval, exit);
        }
        *current = '/';
        current = strchr(current + 1, '/');
    }

    if(stat(dir, &sb) != 0) {
        retval = mkdir(dir, mode);
        when_failed(retval, exit);
        if((uid != 0) || (gid != 0)) {
            retval = chown(dir, uid, gid);
        }
    }

exit:
    free(dir);
    return retval;
}

int amxp_dir_make(const char* path, const mode_t mode) {
    return amxp_dir_owned_make(path, mode, 0, 0);
}

int amxp_dir_scan(const char* path,
                  const char* filter,
                  bool recursive,
                  amxp_dir_match_fn_t fn,
                  void* priv) {
    int retval = -1;
    amxp_expr_t* expr = NULL;
    char* real_path = NULL;

    when_str_empty(path, exit);

    real_path = realpath(path, NULL);
    when_null(real_path, exit);

    if((filter != NULL) && (*filter != 0)) {
        when_failed(amxp_expr_new(&expr, filter), exit);
    }

    retval = amxp_dir_scan_impl(real_path, expr, recursive, fn, priv);

exit:
    free(real_path);
    amxp_expr_delete(&expr);
    return retval;

}

bool amxp_dir_is_empty(const char* path) {
    bool retval = true;
    when_str_empty(path, exit);

    when_false(amxp_dir_is_directory(path), exit);

    if(amxp_dir_scan(path, NULL, false, amxp_dir_check_is_empty, NULL)) {
        retval = false;
    }

exit:
    return retval;
}

bool amxp_dir_is_directory(const char* path) {
    bool retval = false;
    struct stat sb;
    when_str_empty(path, exit);

    when_false(stat(path, &sb) == 0, exit);
    when_false((sb.st_mode & S_IFMT) == S_IFDIR, exit);

    retval = true;

exit:
    return retval;
}
