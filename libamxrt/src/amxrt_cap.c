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

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <cap-ng.h>

#include <amxrt/amxrt.h>

#include "amxrt_priv.h"

static int32_t amxrt_get_user_id(amxc_var_t* user) {
    int32_t uid = 0;

    if(amxc_var_type_of(user) == AMXC_VAR_ID_NULL) {
        uid = -1;
    } else if(amxc_var_type_of(user) == AMXC_VAR_ID_CSTRING) {
        struct passwd* user_info = NULL;
        user_info = getpwnam(GET_CHAR(user, NULL));
        when_null_status(user_info, exit, uid = -1);
        uid = user_info->pw_uid;
    } else {
        uid = GET_INT32(user, NULL);
    }

exit:
    return uid;
}

static int32_t amxrt_get_group_id(amxc_var_t* group) {
    int32_t gid = 0;

    if(amxc_var_type_of(group) == AMXC_VAR_ID_NULL) {
        gid = -1;
    } else if(amxc_var_type_of(group) == AMXC_VAR_ID_CSTRING) {
        struct group* group_info = NULL;
        group_info = getgrnam(GET_CHAR(group, NULL));
        when_null_status(group_info, exit, gid = -1);
        gid = group_info->gr_gid;
    } else {
        gid = GET_INT32(group, NULL);
    }

exit:
    return gid;
}

int amxrt_caps_apply(void) {
    int rv = -1;
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = GET_ARG(config, "privileges");
    amxc_var_t* caps = GET_ARG(privileges, "capabilities");
    amxc_var_t* user = GET_ARG(privileges, "user");
    amxc_var_t* group = GET_ARG(privileges, "group");

    when_null_status(privileges, exit, rv = 0);
    capng_get_caps_process();

    if(!GET_BOOL(privileges, "keep-all")) {
        capng_clear(CAPNG_SELECT_BOTH);

        amxc_var_for_each(cap, caps) {
            int id = -1;

            if(amxc_var_type_of(cap) == AMXC_VAR_ID_CSTRING) {
                const char* cap_name = GET_CHAR(cap, NULL);
                amxc_string_t str_cap_name;
                int offset = 0;

                /* work-around for musl-c issue.
                   when using strncasecmp which is defined in <strings.h>
                   and using musl-c the following compilation error/warning
                   is given
                   In file included from amxrt_cap.c:62:
                   /home/sahbot/workspace/build/buildsystem/staging_dir/toolchain-x86_64_gcc-8.4.0_musl/include/fortify/strings.h:19:2: error: #include_next is a GCC extension [-Werror]
                 #include_next <strings.h>
                   ^~~~~~~~~~~~

                   muslc strings.h uses include_next. The use of include_next should be
                   avoided as it can lead to confusion.

                   see https://gcc.gnu.org/onlinedocs/cpp/Wrapper-Headers.html
                 */
                amxc_string_init(&str_cap_name, 0);
                amxc_string_set(&str_cap_name, cap_name);
                amxc_string_to_upper(&str_cap_name);
                offset = strncmp(amxc_string_get(&str_cap_name, 0), "CAP_", 4) == 0 ? 4 : 0;
                amxc_string_clean(&str_cap_name);

                id = capng_name_to_capability(cap_name + offset);
                if(id == -1) {
                    amxrt_print_error("Unknown capability - [%s]", cap_name);
                    continue;
                }
            } else {
                id = GET_INT32(cap, NULL);
                if((id < 0) || (id > CAP_LAST_CAP)) {
                    amxrt_print_error("Invalid capability id - [%d]", GET_INT32(cap, NULL));
                    continue;
                }
            }
            rv = capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET | CAPNG_INHERITABLE), id);
            if(rv != 0) {
                amxrt_print_error("Apply capability [%d] failed with %d\n", id, rv);
            }
        }
    }

    if((user == NULL) && (group == NULL)) {
        amxrt_dm_create_dir(amxrt_get_parser(), 0, 0);
        rv = capng_apply(CAPNG_SELECT_BOTH);
    } else {
        int32_t uid = amxrt_get_user_id(user);
        int32_t gid = amxrt_get_group_id(group);
        amxrt_print_message("Switching to user id %d and group id %d", uid, gid);
        amxrt_dm_create_dir(amxrt_get_parser(), uid, gid);
        rv = capng_change_id(uid, gid, (capng_flags_t) (CAPNG_DROP_SUPP_GRP));
    }
    if(rv != 0) {
        amxrt_print_error("Apply capabilities failed with %d\n", rv);
    }

exit:
    return rv;
}

void amxrt_caps_dump(void) {
    capng_print_caps_numeric(CAPNG_PRINT_STDOUT, CAPNG_SELECT_BOTH);

    printf("\nCAPNG_EFFECTIVE:\n");
    capng_print_caps_text(CAPNG_PRINT_STDOUT, CAPNG_EFFECTIVE);
    printf("\nCAPNG_PERMITTED:\n");
    capng_print_caps_text(CAPNG_PRINT_STDOUT, CAPNG_PERMITTED);
    printf("\nCAPNG_INHERITABLE:\n");
    capng_print_caps_text(CAPNG_PRINT_STDOUT, CAPNG_INHERITABLE);
    printf("\nCAPNG_BOUNDING_SET:\n");
    capng_print_caps_text(CAPNG_PRINT_STDOUT, CAPNG_BOUNDING_SET);
    printf("\n");
}
