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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <getopt.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>

#include "test_amxo_parse.h"
#include "amxo_xml_to.h"

static bool test_verify_data(const amxc_var_t* data, const char* field, const char* value) {
    bool rv = false;
    char* field_value = NULL;
    amxc_var_t* field_data = GETP_ARG(data, field);

    printf("Verify event data: check field [%s] contains [%s]\n", field, value);
    fflush(stdout);
    when_null(field_data, exit);

    field_value = amxc_var_dyncast(cstring_t, field_data);
    when_null(field_value, exit);

    rv = (strcmp(field_value, value) == 0);

exit:
    free(field_value);
    return rv;
}

void test_can_print_help(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-h" };
    int argc = sizeof(argv) / sizeof(argv[0]);

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, argc, argv), -1);
    amxo_xml_print_usage(argc, argv);

    amxc_var_clean(&config);
}

void test_can_pass_xsl_type(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "foo" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), 3);

    amxc_var_clean(&config);
}

void test_can_override_xsl_type(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "foo" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);
    amxc_var_add_key(cstring_t, &config, "xsl", "bar");

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), 3);
    assert_true(test_verify_data(&config, "xsl", "foo"));

    amxc_var_clean(&config);
}

void test_can_pass_output_dir(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "foo", "-o", "output-dir=./output" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), 5);

    amxc_var_clean(&config);
}

void test_can_add_config_option(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "html", "-o", "foo=bar" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), 5);

    amxc_var_clean(&config);
}

void test_cannot_add_option_with_invalid_format(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "html", "-o", "foo:bar" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), 5);
    assert_false(test_verify_data(&config, "foo", "bar"));

    amxc_var_clean(&config);
}

void test_print_error_on_invalid_option(UNUSED void** state) {
    amxc_var_t config;
    char* argv[] = { "amxo-cg", "-x", "html", "-Z", "foo=bar" };

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_config(&config);

    optind = 1;
    assert_int_equal(amxo_xml_args_parse_cmd(&config, sizeof(argv) / sizeof(argv[0]), argv), -1);

    amxc_var_clean(&config);
}
