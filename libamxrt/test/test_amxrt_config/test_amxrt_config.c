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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "test_amxrt_config.h"

int test_config_setup(UNUSED void** state) {
    amxrt_new();
    return 0;
}

int test_config_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_config_init(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    const char* inc_dirs[] = { ".", "${prefix}${cfg-dir}/${name}", "${prefix}${cfg-dir}/modules" };
    const char* lib_dirs[] = { ".",
        "${prefix}${plugin-dir}/${name}",
        "${prefix}${plugin-dir}/modules",
        "${prefix}/usr/local/lib/amx/${name}",
        "${prefix}/usr/local/lib/amx/modules" };
    const char* mib_dirs[] = { "${prefix}${cfg-dir}/${name}/mibs" };
    char* argv[] = { "amxrt" };
    int index = 0;

    assert_int_equal(amxrt_config_init(sizeof(argv) / sizeof(argv[0]), argv, &index, NULL), 0);
    assert_int_equal(index, 1);

    amxc_var_dump(config, STDOUT_FILENO);

    assert_true(GET_BOOL(config, AMXRT_COPT_AUTO_DETECT));
    assert_true(GET_BOOL(config, AMXRT_COPT_AUTO_CONNECT));
    assert_false(GET_BOOL(config, AMXRT_COPT_DAEMON));
    assert_int_equal(GET_INT32(config, AMXRT_COPT_PRIORITY), 0);
    assert_true(GET_BOOL(config, AMXRT_COPT_PID_FILE));
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_PREFIX_PATH), "");
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_PLUGIN_DIR), AMXRT_CVAL_PLUGIN_DIR);
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_CFG_DIR), AMXRT_CVAL_CFG_DIR);
    assert_false(GET_BOOL(config, AMXRT_COPT_EVENT));
    assert_false(GET_BOOL(config, AMXRT_COPT_DUMP_CONFIG));
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_BACKENDS_DIR), AMXRT_CVAL_BACKEND_DIR);
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_STORAGE_TYPE), AMXRT_CVAL_STORAGE_TYPE);
    assert_false(GET_BOOL(config, AMXRT_COPT_LOG));
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_RW_DATA_PATH), "${prefix}" RWDATAPATH);
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_STORAGE_DIR), "${rw_data_path}/${name}/");

    index = 0;
    amxc_var_for_each(var, GET_ARG(config, AMXRT_COPT_INCDIRS)) {
        assert_string_equal(GET_CHAR(var, NULL), inc_dirs[index]);
        index++;
    }

    index = 0;
    amxc_var_for_each(var, GET_ARG(config, AMXRT_COPT_LIBDIRS)) {
        assert_string_equal(GET_CHAR(var, NULL), lib_dirs[index]);
        index++;
    }

    index = 0;
    amxc_var_for_each(var, GET_ARG(config, AMXRT_COPT_MIBDIRS)) {
        assert_string_equal(GET_CHAR(var, NULL), mib_dirs[index]);
        index++;
    }
}

void test_config_can_use_env_vars(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();

    setenv("AMXRT_PREFIX_PATH", "/tmp/test/", 1);
    setenv("AMXB_BACKENDS", "/tmp/test1.so;/tmp/test2.so", 1);
    setenv("TEST_VAR", "some value", 1);

    char* argv[] = { "amxrt.bin" };
    int index = 0;

    assert_int_equal(amxrt_config_init(sizeof(argv) / sizeof(argv[0]), argv, &index, NULL), 0);
    assert_int_equal(index, 1);
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_PREFIX_PATH), "/tmp/test/");

    amxrt_config_read_env_var("TEST_VAR", "test", AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(config, "test"), "some value");

}

void test_invalid_options(UNUSED void** state) {
    char* argv[] = { "amxrt.bin", "-B" };
    int index = 0;

    assert_int_not_equal(amxrt_config_init(sizeof(argv) / sizeof(argv[0]), argv, &index, NULL), 0);
    assert_int_equal(index, sizeof(argv) / sizeof(argv[0]));
}