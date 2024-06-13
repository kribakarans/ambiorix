/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxo/amxo.h>
#include <amxo/amxo_hooks.h>

#include "testutil.h"

#include <amxc/amxc_macros.h>

void amxo_testutil_load_odl_file(amxo_parser_t* parser, amxd_dm_t* dm, const char* filename) {
    amxd_object_t* root_obj = amxd_dm_get_root(dm);

    if(0 != amxo_parser_parse_file(parser, filename, root_obj)) {
        fail_msg("Parse error on %s: Parser message: %s", filename, amxc_string_get(&parser->msg, 0));
    }
}

void amxo_testutil_assert_odl_error_string(const char* odl_text) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxd_object_t* root_obj = NULL;
    int status = -1;
    amxd_dm_init(&dm);
    amxo_parser_init(&parser);
    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    status = amxo_parser_parse_string(&parser, odl_text, root_obj);

    if(status == 0) {
        fail_msg("Expected parse error on: %s", odl_text);
    }

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void amxo_testutil_load_odl_string(amxo_parser_t* parser, amxd_dm_t* dm, const char* odl_text) {
    amxd_object_t* root_obj = amxd_dm_get_root(dm);

    if(0 != amxo_parser_parse_string(parser, odl_text, root_obj)) {
        fail_msg("Parse error when parsing the following odl text\n"
                 "--------------begin odl text--------------\n"
                 "%s\n"
                 "--------------end odl text--------------\n"
                 "Parser message: %s. ", odl_text, amxc_string_get(&parser->msg, 0));
    }
}

void amxo_testutil_assert_var_equal(const amxc_var_t* var1, const amxc_var_t* var2) {
    int comparison_result = -2;
    int comparison_status = -2;
    comparison_status = amxc_var_compare(var2, var1, &comparison_result);
    if((0 != comparison_result) || (0 != comparison_status)) {
        print_message("Not equal:\n");
        amxc_var_dump(var1, 1);
        print_message("^----- not equal to ------v\n");
        amxc_var_dump(var2, 1);
        fail_msg("Two variants expected to be equal but are not");
    }
}

void amxo_testutil_assert_odl_config_string_sets(const char* odl_text, const char* config_var_name, const amxc_var_t* expected_value) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxc_var_t* actual_value = NULL;
    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_testutil_load_odl_string(&parser, &dm, odl_text);

    actual_value = amxo_parser_get_config(&parser, config_var_name);

    amxo_testutil_assert_var_equal(actual_value, expected_value);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}