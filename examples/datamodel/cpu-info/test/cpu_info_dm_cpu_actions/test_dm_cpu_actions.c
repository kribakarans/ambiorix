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

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>

#include "cpu_info.h"
#include "dm_cpu_info.h"
#include "test_dm_cpu_actions.h"

static amxo_parser_t parser;
static amxd_dm_t dm;

static const char* odl_defs = "../../odl/cpu_info_definition.odl";

int test_dm_cpu_actions_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    amxc_var_t* fields = NULL;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "cpu_read", AMXO_FUNC(_cpu_read)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "cpu_list", AMXO_FUNC(_cpu_list)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "cpu_describe", AMXO_FUNC(_cpu_describe)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "cpu_cleanup", AMXO_FUNC(_cpu_cleanup)), 0);

    fields = amxc_var_add_key(amxc_htable_t, &parser.config, "cpu_field_names", NULL);
    amxc_var_add_key(cstring_t, fields, "vendor_id", "VendorId");
    amxc_var_add_key(cstring_t, fields, "cpu_family", "Family");
    amxc_var_add_key(cstring_t, fields, "cpu_MHz", "MHz");
    amxc_var_add_key(cstring_t, fields, "model_name", "ModelName");
    amxc_var_add_key(cstring_t, fields, "model", "Model");
    amxc_var_add_key(cstring_t, fields, "processor", "ID");

    assert_int_equal(amxo_parser_parse_file(&parser, odl_defs, root_obj), 0);
    assert_int_equal(_cpu_main(AMXO_START, &dm, &parser), 0);

    return 0;
}

int test_dm_cpu_actions_teardown(UNUSED void** state) {

    assert_int_equal(_cpu_main(AMXO_STOP, &dm, &parser), 0);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_dm_cpu_instances_are_created(UNUSED void** state) {
    amxd_object_t* cpu_template = amxd_dm_findf(&dm, "CPUMonitor.CPU.");

    assert_non_null(cpu_template);
    assert_int_not_equal(amxd_object_get_instance_count(cpu_template), 0);
}

void test_can_read_cpu_instance(UNUSED void** state) {
    amxc_var_t data;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");

    amxc_var_init(&data);

    assert_int_equal(amxd_object_get_params(cpu_instance, &data, amxd_dm_access_protected), 0);
    amxc_var_dump(&data, STDOUT_FILENO);
    amxc_var_clean(&data);
}

void test_can_read_single_cpu_instance_parameter(UNUSED void** state) {
    amxc_var_t data;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");

    amxc_var_init(&data);
    assert_int_equal(amxd_object_get_param(cpu_instance, "ModelName", &data), 0);
    amxc_var_dump(&data, STDOUT_FILENO);
    amxc_var_clean(&data);
}

void test_can_list_cpu_instance_parameters(UNUSED void** state) {
    amxc_var_t params;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");

    amxc_var_init(&params);
    assert_int_equal(amxd_object_list_params(cpu_instance, &params, amxd_dm_access_protected), 0);
    amxc_var_dump(&params, STDOUT_FILENO);
    amxc_var_clean(&params);
}

void test_can_list_cpu_template_parameters(UNUSED void** state) {
    amxc_var_t params;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.");

    amxc_var_init(&params);
    assert_int_equal(amxd_object_list_params(cpu_instance, &params, amxd_dm_access_protected), 0);
    amxc_var_dump(&params, STDOUT_FILENO);
    amxc_var_clean(&params);
}

void test_can_describe_cpu_instance_parameters(UNUSED void** state) {
    amxc_var_t params;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");

    amxc_var_init(&params);
    assert_int_equal(amxd_object_describe_params(cpu_instance, &params, amxd_dm_access_protected), 0);
    amxc_var_dump(&params, STDOUT_FILENO);

    assert_non_null(GETP_ARG(&params, "ModelName.type_id"));
    assert_int_equal(GETP_UINT32(&params, "ModelName.type_id"), AMXC_VAR_ID_CSTRING);
    amxc_var_clean(&params);
}

void test_can_list_cpu_instance_parameters_without_mapping(UNUSED void** state) {
    amxc_var_t params;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");
    amxc_var_t* fields = amxo_parser_get_config(&parser, "cpu_field_names");
    amxc_var_delete(&fields);

    amxc_var_init(&params);
    assert_int_equal(amxd_object_list_params(cpu_instance, &params, amxd_dm_access_protected), 0);
    amxc_var_dump(&params, STDOUT_FILENO);
    amxc_var_clean(&params);
}

void test_can_list_cpu_instance_functions(UNUSED void** state) {
    amxc_var_t params;
    amxd_object_t* cpu_instance = amxd_dm_findf(&dm, "CPUMonitor.CPU.1.");

    amxc_var_init(&params);
    assert_int_equal(amxd_object_list_functions(cpu_instance, &params, amxd_dm_access_protected), 0);
    amxc_var_dump(&params, STDOUT_FILENO);
    amxc_var_clean(&params);
}
