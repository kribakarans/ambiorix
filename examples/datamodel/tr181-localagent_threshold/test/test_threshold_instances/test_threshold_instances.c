/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include <amxo/amxo.h>

#include "threshold.h"
#include "dm_threshold.h"
#include "test_threshold_instances.h"

#define UNUSED __attribute__((unused))
#define GET_KEY(v, k) amxc_var_get_key(v, k, AMXC_VAR_FLAG_DEFAULT)
#define CHAR(v) amxc_var_constcast(cstring_t, v)
#define UINT32(v) amxc_var_constcast(uint32_t, v)

static amxd_dm_t dm;
static amxo_parser_t parser;
static const char* odl_defs = "../../odl/la_threshold_definition.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

int test_threshold_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_instance_is_valid", AMXO_FUNC(_threshold_instance_is_valid)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_instance_cleanup", AMXO_FUNC(_threshold_instance_cleanup)), 0);

    retval = amxo_parser_parse_file(&parser, odl_defs, root_obj);
    printf("PARSER MESSAGE = %s\n", amxc_string_get(&parser.msg, 0));
    assert_int_equal(retval, 0);

    _threshold_main(0, &dm, &parser);

    handle_events();

    return 0;
}

int test_threshold_teardown(UNUSED void** state) {
    _threshold_main(1, &dm, &parser);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_create_instance(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_false(amxc_var_is_null(&ret));

    assert_string_equal(CHAR(GET_KEY(&ret, "name")), "cpe-Threshold-1");
    assert_int_equal(UINT32(GET_KEY(&ret, "index")), 1);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_delete_instance(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);

    assert_int_equal(amxd_object_invoke_function(threshold, "del", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_true(amxc_var_is_null(&ret));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_instance_creation_fails_when_enable_without_ref_path(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t* params = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);

    assert_int_not_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_true(amxc_var_is_null(&ret));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_instance_creation_fails_when_enable_without_ref_param(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t* params = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "ReferencePath", "Dummy.Path.Reference.");

    assert_int_not_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_true(amxc_var_is_null(&ret));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_create_instance_whith_enable_and_references(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t* params = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "ReferencePath", "Dummy.Path.Reference.");
    amxc_var_add_key(cstring_t, params, "ThresholdParam", "SomeParam");

    assert_int_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_false(amxc_var_is_null(&ret));

    assert_string_equal(CHAR(GET_KEY(&ret, "name")), "cpe-Threshold-4");
    assert_int_equal(UINT32(GET_KEY(&ret, "index")), 4);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_threshold_operator(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.4.");
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "Rise");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Fall");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);
    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "Fall");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Eq");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);
    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "Eq");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "NotEq");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);
    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "NotEq");

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_not_change_threshold_operator_to_unsupported(UNUSED void** state) {
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.4.");
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "NotEq");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Cross");
    assert_int_not_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);
    amxd_object_get_params(threshold, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "ThresholdOperator")), "NotEq");

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}