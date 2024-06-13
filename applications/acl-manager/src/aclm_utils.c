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

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include <amxa/amxa_utils.h>

#include <debug/sahtrace.h>

#include "aclm.h"
#include "aclm_utils.h"

static int aclm_strip_until_slash(int c) {
    if(c == '/') {
        return 0;
    } else {
        return 1;
    }
}

static amxc_string_t* aclm_strip_last_dir(const char* dst) {
    amxc_string_t* dst_stripped = NULL;
    int len = 0;

    amxc_string_new(&dst_stripped, 0);
    amxc_string_setf(dst_stripped, "%s", dst);

    len = amxc_string_text_length(dst_stripped);
    if(dst[len - 1] == '/') {
        amxc_string_remove_at(dst_stripped, len - 1, 1);
    }
    amxc_string_trimr(dst_stripped, aclm_strip_until_slash);

    return dst_stripped;
}

static void aclm_array_it_free(amxc_array_it_t* it) {
    free(it->data);
}

static int aclm_build_and_exec_cp(const char* src, const char* dst) {
    int retval = -1;
    amxp_subproc_t* subproc = NULL;
    amxc_array_t c;
    amxc_string_t* dst_stripped = NULL;

    amxc_array_init(&c, 4);
    amxp_subproc_new(&subproc);

    // Need to strip last dir because wildcards don't work in subprocess command
    dst_stripped = aclm_strip_last_dir(dst);

    amxc_array_append_data(&c, strdup("cp"));
    amxc_array_append_data(&c, strdup("-r"));
    amxc_array_append_data(&c, strdup(src));
    amxc_array_append_data(&c, strdup(amxc_string_get(dst_stripped, 0)));

    retval = amxp_subproc_astart(subproc, &c);
    while(amxp_subproc_is_running(subproc)) {
        int sig = amxp_syssig_read();
        if(sig != -1) {
            break;
        }
    }

    amxc_string_delete(&dst_stripped);
    amxc_array_clean(&c, aclm_array_it_free);
    amxp_subproc_delete(&subproc);
    return retval;
}

static int aclm_file_remove(const char* name, UNUSED void* priv) {
    return remove(name);
}

static int aclm_chown(const char* name, UNUSED void* priv) {
    return chown(name, amxa_utils_get_owner_uid(), amxa_utils_get_group_gid());
}

int aclm_create_role_dir(const char* role_name) {
    amxo_parser_t* parser = aclm_get_parser();
    const char* acl_dir = GET_CHAR(&parser->config, "acl_dir");
    const char* dir = NULL;
    struct stat sb;
    amxc_string_t role_dir;
    int retval = -1;

    amxc_string_init(&role_dir, 0);

    when_str_empty(role_name, exit);

    amxc_string_setf(&role_dir, "%s", role_name);
    retval = amxc_string_search(&role_dir, "/", 0);
    when_true_status(retval >= 0, exit, retval = -1);

    amxc_string_prependf(&role_dir, "%s/", acl_dir);

    dir = amxc_string_get(&role_dir, 0);
    retval = 0;
    if((stat(dir, &sb) != 0) || (!S_ISDIR(sb.st_mode))) {
        SAH_TRACEZ_INFO(ME, "ACL dir does not exist, creating %s", dir);
        retval = amxp_dir_owned_make(dir,
                                     AMXA_DIR_PERMISSIONS,
                                     amxa_utils_get_owner_uid(),
                                     amxa_utils_get_group_gid());
        if(retval != 0) {
            SAH_TRACEZ_INFO(ME, "Failed to create %s", dir);
            goto exit;
        }
    }

exit:
    amxc_string_clean(&role_dir);

    return retval;
}

int aclm_remove_role_dir(const char* role_name) {
    amxo_parser_t* parser = aclm_get_parser();
    const char* acl_dir = GET_CHAR(&parser->config, "acl_dir");
    amxc_string_t role_dir;
    int retval = -1;

    amxc_string_init(&role_dir, 0);

    when_str_empty(role_name, exit);

    amxc_string_setf(&role_dir, "%s/%s", acl_dir, role_name);

    retval = amxp_dir_scan(amxc_string_get(&role_dir, 0), "d_type == DT_REG",
                           false, aclm_file_remove, NULL);
    when_failed(retval, exit);

    retval = rmdir(amxc_string_get(&role_dir, 0));

exit:
    amxc_string_clean(&role_dir);

    return retval;
}

void aclm_write_json_var(amxc_var_t* json_var, const char* dest_file) {
    variant_json_t* writer = NULL;
    int fd = -1;

    amxj_writer_new(&writer, json_var);

    fd = open(dest_file, O_WRONLY | O_CREAT | O_TRUNC, AMXA_FILE_PERMISSIONS);
    when_true(fd < 0, exit);

    amxj_write(writer, fd);
    when_failed(chown(dest_file, amxa_utils_get_owner_uid(), amxa_utils_get_group_gid()), exit);

exit:
    amxj_writer_delete(&writer);
    if(fd != -1) {
        close(fd);
    }
}

amxc_string_t* aclm_dir_from_role(const char* role) {
    amxc_string_t* role_dir = NULL;
    amxo_parser_t* parser = aclm_get_parser();
    const char* acl_dir = GET_CHAR(&parser->config, "acl_dir");

    when_str_empty(role, exit);

    amxc_string_new(&role_dir, 0);
    amxc_string_setf(role_dir, "%s/%s", acl_dir, role);

exit:
    return role_dir;
}

int aclm_copy_recursively(const char* src, const char* dst) {
    int retval = -1;
    struct stat sb;

    when_str_empty(src, exit);
    when_str_empty(dst, exit);

    if(!((stat(dst, &sb) == 0) && S_ISDIR(sb.st_mode))) {
        retval = amxp_dir_owned_make(dst,
                                     AMXA_DIR_PERMISSIONS,
                                     amxa_utils_get_owner_uid(),
                                     amxa_utils_get_group_gid());
        if(retval != 0) {
            SAH_TRACEZ_WARNING(ME, "Failed create %s", dst);
            goto exit;
        }
    }

    retval = 0;
    if(!((stat(src, &sb) == 0) && S_ISDIR(sb.st_mode))) {
        SAH_TRACEZ_INFO(ME, "Source directory [%s] does not exists, not copying", src);
        goto exit;
    }
    when_true(amxp_dir_is_empty(src), exit);

    retval = aclm_build_and_exec_cp(src, dst);
    if(retval != 0) {
        SAH_TRACEZ_WARNING(ME, "Failed to copy %s to %s", src, dst);
        goto exit;
    }

    retval = amxp_dir_scan(dst, NULL, true, aclm_chown, NULL);
    if(retval != 0) {
        SAH_TRACEZ_WARNING(ME, "Failed to chown %s", dst);
        // Don't exit with nonzero if chown failed
    }

    retval = 0;
exit:
    return retval;
}
