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
#include "test_read_info.h"

static amxo_parser_t parser;
static amxd_dm_t dm;

int test_read_info_setup(UNUSED void** state) {
    amxc_var_t* fields = NULL;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    fields = amxc_var_add_key(amxc_htable_t, &parser.config, "cpu_field_names", NULL);
    amxc_var_add_key(cstring_t, fields, "vendor_id", "VendorId");
    amxc_var_add_key(cstring_t, fields, "cpu_family", "Family");
    amxc_var_add_key(cstring_t, fields, "cpu_MHz", "MHz");
    amxc_var_add_key(cstring_t, fields, "model_name", "ModelName");
    amxc_var_add_key(cstring_t, fields, "model", "Model");
    amxc_var_add_key(cstring_t, fields, "processor", "ID");

    assert_int_equal(_cpu_main(0, &dm, &parser), 0);

    return 0;
}

int test_read_info_teardown(UNUSED void** state) {

    assert_int_equal(_cpu_main(AMXO_STOP, &dm, &parser), 0);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_read_all_cpu_info(UNUSED void** state) {
    amxc_var_t data;

    amxc_var_init(&data);
    assert_int_equal(cpu_info_read(&data, 0), 0);
    amxc_var_dump(&data, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_LIST);
    amxc_var_for_each(cpu, &data) {
        assert_int_equal(amxc_var_type_of(cpu), AMXC_VAR_ID_HTABLE);
        assert_non_null(GETP_ARG(cpu, "VendorId"));
        assert_non_null(GETP_ARG(cpu, "Family"));
        assert_non_null(GETP_ARG(cpu, "MHz"));
        assert_non_null(GETP_ARG(cpu, "ModelName"));
        assert_non_null(GETP_ARG(cpu, "Model"));
        assert_non_null(GETP_ARG(cpu, "ID"));
    }

    amxc_var_clean(&data);
}

void test_can_read_single_cpu_info(UNUSED void** state) {
    amxc_var_t data;

    amxc_var_init(&data);
    assert_int_equal(cpu_info_read(&data, 1), 0);
    amxc_var_dump(&data, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_HTABLE);
    assert_non_null(GETP_ARG(&data, "VendorId"));
    assert_non_null(GETP_ARG(&data, "Family"));
    assert_non_null(GETP_ARG(&data, "MHz"));
    assert_non_null(GETP_ARG(&data, "ModelName"));
    assert_non_null(GETP_ARG(&data, "Model"));
    assert_non_null(GETP_ARG(&data, "ID"));

    amxc_var_clean(&data);
}

void test_can_read_cpu_info_without_field_mapping(UNUSED void** state) {
    amxc_var_t* fields = amxo_parser_get_config(&parser, "cpu_field_names");
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_delete(&fields);

    assert_int_equal(cpu_info_read(&data, 1), 0);
    amxc_var_dump(&data, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_HTABLE);
    assert_non_null(GETP_ARG(&data, "vendor_id"));
    assert_non_null(GETP_ARG(&data, "cpu_family"));

    amxc_var_clean(&data);
}

void test_can_read_cpu_info_invalid_names_are_skipped(UNUSED void** state) {
    amxc_var_t* fields = NULL;
    amxc_var_t data;

    amxc_var_init(&data);
    fields = amxc_var_add_key(amxc_htable_t, &parser.config, "cpu_field_names", NULL);
    amxc_var_add_key(cstring_t, fields, "vendor_id", "1_VendorId");
    amxc_var_add_key(cstring_t, fields, "cpu_family", "Family");
    amxc_var_add_key(cstring_t, fields, "cpu_MHz", "%MHz");

    assert_int_equal(cpu_info_read(&data, 1), 0);
    amxc_var_dump(&data, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_HTABLE);
    assert_non_null(GETP_ARG(&data, "Family"));
    assert_null(GETP_ARG(&data, "%MHz"));
    assert_null(GETP_ARG(&data, "1_VendorId"));

    amxc_var_clean(&data);
}