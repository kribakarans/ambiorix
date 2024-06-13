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
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <grp.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include <amxo/amxo.h>

#include "aclm.h"

#include "test_aclm_start_stop.h"

static amxo_parser_t parser;
static amxd_dm_t dm;
static const char* odl_config = "./aclm-test.odl";

static int extend_groups(void) {
    const char* filename = "/etc/group";
    const char* gr_name = "acl";
    struct group* acl_group = NULL;
    struct group* existing_group = getgrnam(gr_name);
    FILE* fp = fopen(filename, "a+");
    int retval = -1;

    if(fp == NULL) {
        printf("Failed to open %s\n", filename);
        goto exit;
    }

    if(existing_group) {
        printf("Group %s already exists\n", gr_name);
        retval = 0;
        goto exit;
    }

    acl_group = calloc(1, sizeof(struct group));
    acl_group->gr_gid = 5000;
    acl_group->gr_name = strdup(gr_name);
    retval = putgrent(acl_group, fp);

    free(acl_group->gr_name);
    free(acl_group);

exit:
    if(fp != NULL) {
        fclose(fp);
    }
    return retval;
}

int test_aclm_setup(UNUSED void** state) {
    int retval = 0;
    amxd_object_t* root_obj = NULL;

    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    retval = amxo_parser_parse_file(&parser, odl_config, root_obj);
    assert_int_equal(retval, 0);

    extend_groups();

    return 0;
}

int test_aclm_teardown(UNUSED void** state) {
    system("rm -r ./none");
    amxo_parser_clean(&parser);

    return 0;
}

void test_can_start_plugin(UNUSED void** state) {
    assert_int_equal(_aclm_main(0, &dm, &parser), 0);

    amxc_var_dump(&parser.config, STDOUT_FILENO);
    assert_string_equal(GETP_CHAR(&parser.config, "acl_dir"), "./none/existing/runtime/dir");
    assert_string_equal(GETP_CHAR(&parser.config, "acl_install_dir"), "./acldir");
}

void test_can_stop_plugin(UNUSED void** state) {
    assert_int_equal(_aclm_main(1, &dm, &parser), 0);
}

void test_entry_point_succeeds_when_unhandled_reason_is_provided(UNUSED void** state) {
    assert_int_equal(_aclm_main(99, &dm, &parser), 0);
}
