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

#include "test_amxrt_args.h"

int test_args_setup(UNUSED void** state) {
    amxrt_new();
    return 0;
}

int test_args_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_can_print_help(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    char* argv[] = { "amxrt", "-h" };

    amxc_var_add_key(cstring_t, config, "name", "amxrt");
    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), -1);
}

void test_can_print_extended_help(UNUSED void** state) {
    char* argv[] = { "amxrt", "-H" };

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), -1);
}

void test_can_add_include_dir(UNUSED void** state) {
    char* argv[] = { "amxrt", "-I", "/tmp/include/", "-I", "/etc/odl/" };
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* option = GET_ARG(config, AMXRT_COPT_INCDIRS);
    const char* include_dirs[] = {
        ".", "/tmp/include/", "/etc/odl/"
    };
    int index = 0;

    assert_non_null(option);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    amxc_var_for_each(var, option) {
        assert_string_equal(GET_CHAR(var, NULL), include_dirs[index]);
        index++;
    }
}

void test_can_add_import_dir(UNUSED void** state) {
    char* argv[] = { "amxrt", "-L", "/tmp/include/", "-L", "/etc/odl/" };
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* option = GET_ARG(config, AMXRT_COPT_LIBDIRS);
    const char* include_dirs[] = {
        ".", "/tmp/include/", "/etc/odl/"
    };
    int index = 0;

    assert_non_null(option);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    amxc_var_for_each(var, option) {
        assert_string_equal(GET_CHAR(var, NULL), include_dirs[index]);
        index++;
    }
}

void test_can_add_backend(UNUSED void** state) {
    char* argv[] = { "amxrt", "-B", "/usr/bin/mods/amx/mod_amxb_test.so", "-B", "/usr/bin/mods/amx/mod_amxb_dummy.so" };
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* option = GET_ARG(config, AMXRT_COPT_BACKENDS);
    const char* include_dirs[] = {
        "/usr/bin/mods/amx/mod_amxb_test.so", "/usr/bin/mods/amx/mod_amxb_dummy.so"
    };
    int index = 0;

    assert_non_null(option);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    amxc_var_for_each(var, option) {
        assert_string_equal(GET_CHAR(var, NULL), include_dirs[index]);
        index++;
    }
}

void test_can_add_uri(UNUSED void** state) {
    char* argv[] = { "amxrt", "-u", "dummy:/var/run/dummy.sock", "-u", "dummy:/var/run/ubus.sock" };
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* option = GET_ARG(config, AMXRT_COPT_URIS);
    const char* include_dirs[] = {
        "dummy:/var/run/dummy.sock", "dummy:/var/run/ubus.sock"
    };
    int index = 0;

    assert_non_null(option);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    amxc_var_for_each(var, option) {
        assert_string_equal(GET_CHAR(var, NULL), include_dirs[index]);
        index++;
    }
}

void test_can_accept_option(UNUSED void** state) {
    char* argv[] = {"amxrt", "-o option=new_option", "-o", "text=hallo"};
    amxc_var_t* config = amxrt_get_config();

    assert_null(GET_ARG(config, "option"));
    assert_null(GET_ARG(config, "text"));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    assert_non_null(GET_ARG(config, "option"));
    assert_non_null(GET_ARG(config, "text"));

    assert_string_equal(GET_CHAR(config, "option"), "new_option");
    assert_string_equal(GET_CHAR(config, "text"), "hallo");
}

void test_can_overwrite_option(UNUSED void** state) {
    char* argv[] = {"amxrt", "-o cfg-dir=my_cfg_dir", "-o", "daemon=no"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_CFG_DIR));
    assert_non_null(GET_ARG(config, AMXRT_COPT_DAEMON));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_CFG_DIR), "my_cfg_dir");
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_DAEMON), "no");
}

void test_ignores_invalid_options(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-o"};
    char* argv2[] = {"amxrt", "-o option2"};
    amxc_var_t* config = amxrt_get_config();

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), -1);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv2) / sizeof(argv2[0]), argv2, NULL), sizeof(argv2) / sizeof(argv2[0]));
    assert_null(GET_CHAR(config, "option2"));
}

void test_can_disable_auto_detect(UNUSED void** state) {
    char* argv[] = {"amxrt", "-A"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_AUTO_DETECT));
    assert_true(GET_BOOL(config, AMXRT_COPT_AUTO_DETECT));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_false(GET_BOOL(config, AMXRT_COPT_AUTO_DETECT));
}

void test_can_disable_auto_connect(UNUSED void** state) {
    char* argv[] = {"amxrt", "-C"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_AUTO_CONNECT));
    assert_true(GET_BOOL(config, AMXRT_COPT_AUTO_CONNECT));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_false(GET_BOOL(config, AMXRT_COPT_AUTO_CONNECT));
}

void test_can_enable_daemonize(UNUSED void** state) {
    char* argv[] = {"amxrt", "-D"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_DAEMON));
    assert_false(GET_BOOL(config, AMXRT_COPT_DAEMON));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_true(GET_BOOL(config, AMXRT_COPT_DAEMON));
}

void test_can_enable_eventing(UNUSED void** state) {
    char* argv[] = {"amxrt", "-E"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_EVENT));
    assert_false(GET_BOOL(config, AMXRT_COPT_EVENT));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_true(GET_BOOL(config, AMXRT_COPT_EVENT));
}

void test_can_enable_dump_config(UNUSED void** state) {
    char* argv[] = {"amxrt", "-d"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_DUMP_CONFIG));
    assert_false(GET_BOOL(config, AMXRT_COPT_DUMP_CONFIG));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_true(GET_BOOL(config, AMXRT_COPT_DUMP_CONFIG));
}

void test_can_set_nice_level(UNUSED void** state) {
    char* argv[] = {"amxrt", "-p", "-5"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_PRIORITY));
    assert_int_equal(GET_INT32(config, AMXRT_COPT_PRIORITY), 0);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_int_equal(GET_INT32(config, AMXRT_COPT_PRIORITY), -5);
}

void test_can_disable_pid_file_creation(UNUSED void** state) {
    char* argv[] = {"amxrt", "-N"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_PID_FILE));
    assert_true(GET_BOOL(config, AMXRT_COPT_PID_FILE));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_false(GET_BOOL(config, AMXRT_COPT_PID_FILE));
}

void test_can_pass_odl_string(UNUSED void** state) {
    char* argv[] = {"amxrt", "-O", "%%config { test = 123; }"};
    amxc_var_t* config = amxrt_get_config();

    assert_null(GET_ARG(config, AMXRT_COPT_ODL));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_non_null(GET_ARG(config, AMXRT_COPT_ODL));
    assert_string_equal(GET_CHAR(config, AMXRT_COPT_ODL), "%%config { test = 123; }");
}

void test_can_enable_syslog(UNUSED void** state) {
    char* argv[] = {"amxrt", "-l"};
    amxc_var_t* config = amxrt_get_config();

    assert_non_null(GET_ARG(config, AMXRT_COPT_LOG));
    assert_false(GET_BOOL(config, AMXRT_COPT_LOG));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));
    assert_true(GET_BOOL(config, AMXRT_COPT_LOG));
}

void test_can_add_required_objects(UNUSED void** state) {
    char* argv[] = { "amxrt", "-R", "NetModel.", "-R", "NetDev." };
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* option = GET_ARG(config, AMXRT_COPT_REQUIRES);
    const char* include_dirs[] = {
        "NetModel.", "NetDev."
    };
    int index = 0;

    assert_non_null(option);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv) / sizeof(argv[0]), argv, NULL), sizeof(argv) / sizeof(argv[0]));

    amxc_var_for_each(var, option) {
        assert_string_equal(GET_CHAR(var, NULL), include_dirs[index]);
        index++;
    }

}

void test_can_add_forced_option(UNUSED void** state) {

}

static int test_args(UNUSED amxc_var_t* config,
                     int arg_id,
                     UNUSED const char* value) {
    int rv = 0;
    if(arg_id != 'z') {
        rv = -2;
    }
    return rv;
}

void test_can_add_custom_options(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-z"};

    amxrt_cmd_line_add_option(0, 'z', "zulu", no_argument, "testing", NULL);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv1) / sizeof(argv1[0]), argv1, test_args), sizeof(argv1) / sizeof(argv1[0]));
}


void test_cmd_line_parse_fails_after_reset(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-z"};
    char* argv2[] = {"amxrt", "-z", "-t"};

    amxrt_cmd_line_options_reset();
    amxrt_cmd_line_add_option(0, 'z', "zulu", no_argument, "testing", NULL);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), -1);

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv1) / sizeof(argv1[0]), argv1, test_args), sizeof(argv1) / sizeof(argv1[0]));

    optind = 1;
    assert_int_equal(amxrt_cmd_line_parse(sizeof(argv2) / sizeof(argv2[0]), argv2, test_args), -1);
}

void test_can_set_usage_doc(UNUSED void** state) {
    amxrt_cmd_line_set_usage_doc("Test usage");
    amxrt_print_usage();
    amxrt_cmd_line_set_usage_doc(NULL);
    amxrt_print_usage();
}