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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_amxrt_runtime.h"

typedef struct dummy_bus {
    int data_pipe[2];
    amxb_bus_ctx_t ctx;
} dummy_bus_t;

static dummy_bus_t dummy_ctx;

int __wrap_amxb_be_load_multiple(amxc_var_t* const bes);
int __wrap_amxb_connect(amxb_bus_ctx_t** ctx, const char* uri);
int __wrap_amxb_listen(amxb_bus_ctx_t** ctx, const char* uri);
int __wrap_amxb_get_fd(amxb_bus_ctx_t* ctx);
void __wrap_amxb_free(amxb_bus_ctx_t** ctx);
int __wrap_amxb_register(amxb_bus_ctx_t* ctx, amxd_dm_t* dm);
int __wrap_amxb_read(amxb_bus_ctx_t* ctx);
int __wrap_amxb_wait_for_object(const char* object);
int __wrap_daemon(int nochdir, int noclose);
int __wrap_setpriority(int which, id_t who, int value);

int __wrap_amxb_be_load_multiple(UNUSED amxc_var_t* const bes) {
    return (int) mock();
}

int __wrap_amxb_connect(amxb_bus_ctx_t** ctx, UNUSED const char* uri) {
    *ctx = &dummy_ctx.ctx;
    return (int) mock();
}

int __wrap_amxb_listen(amxb_bus_ctx_t** ctx, UNUSED const char* uri) {
    *ctx = &dummy_ctx.ctx;
    return (int) mock();
}

int __wrap_amxb_get_fd(UNUSED amxb_bus_ctx_t* ctx) {
    return dummy_ctx.data_pipe[0];
}

void __wrap_amxb_free(amxb_bus_ctx_t** ctx) {
    *ctx = NULL;
}

int __wrap_amxb_register(UNUSED amxb_bus_ctx_t* ctx, UNUSED amxd_dm_t* dm) {
    return (int) mock();
}

int __wrap_amxb_read(UNUSED amxb_bus_ctx_t* ctx) {
    char buf[10];
    read(dummy_ctx.data_pipe[0], buf, 1);
    amxrt_el_stop();
    return 0;
}

int __wrap_amxb_wait_for_object(UNUSED const char* object) {
    return (int) mock();
}

int __wrap_daemon(UNUSED int nochdir, UNUSED int noclose) {
    return (int) mock();
}

int __wrap_setpriority(UNUSED int which, UNUSED id_t who, UNUSED int value) {
    return (int) mock();
}

int test_runtime_setup(UNUSED void** state) {
    amxd_dm_t* dm = NULL;
    amxrt_new();
    dm = amxrt_get_dm();
    memset(&dummy_ctx.ctx, 0, sizeof(amxb_bus_ctx_t));
    amxp_sigmngr_init(&dummy_ctx.ctx.sigmngr);
    amxc_htable_init(&dummy_ctx.ctx.subscriptions, 5);
    amxd_dm_clean(dm);
    assert_int_equal(pipe(dummy_ctx.data_pipe), 0);
    return 0;
}

int test_runtime_teardown(UNUSED void** state) {
    close(dummy_ctx.data_pipe[0]);
    close(dummy_ctx.data_pipe[1]);
    amxp_sigmngr_clean(&dummy_ctx.ctx.sigmngr);
    amxc_htable_clean(&dummy_ctx.ctx.subscriptions, NULL);
    amxrt_delete();
    return 0;
}

void test_runtime_start_prints_help_and_exits(UNUSED void** state) {
    char* argv[] = {"amxrt", "-h"};

    optind = 1;
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
}

void test_runtime_parses_default_odl(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-B dymmy", "-u", "dummy://127.0.0.1:1970"};
    char* argv2[] = {"test-plugin", "-B fake", "-u", "dummy://127.0.0.1:1970"};

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* prefix = GET_ARG(config, "prefix");

    char* current_wd = getcwd(NULL, 0);

    will_return_always(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return_always(__wrap_amxb_register, 0);

    amxc_var_set(cstring_t, prefix, current_wd);

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    assert_int_equal(amxrt(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), 0);
    amxd_dm_clean(dm);

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    amxc_var_set(cstring_t, prefix, current_wd);
    assert_int_equal(amxrt(sizeof(argv2) / sizeof(argv2[0]), argv2, NULL), 0);
    amxd_dm_clean(dm);

    amxc_var_set(cstring_t, prefix, "");

    free(current_wd);
}

void test_runtime_parses_odls(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970",
        "test.odl", "etc/amx/amxrt/amxrt.odl", "etc/amx/test-plugin/test-plugin.odl"};

    amxd_dm_t* dm = amxrt_get_dm();

    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return_always(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_parses_odls_and_handle_events(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970",
        "test.odl", "-E", "etc/amx/amxrt/amxrt.odl", "etc/amx/test-plugin/test-plugin.odl"};

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();

    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return_always(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    amxc_var_add_key(bool, config, AMXRT_COPT_HANDLE_EVENTS, true);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_HANDLE_EVENTS), false);

    amxd_dm_clean(dm);
}

void test_runtime_succeeds_when_no_odl(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-B a", "-u", "dummy://127.0.0.1:1970"};

    amxd_dm_t* dm = amxrt_get_dm();

    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return_always(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    assert_int_equal(amxrt(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_fails_when_invalid_odl(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-B a", "-u", "dummy://127.0.0.1:1970", "invalid.odl"};

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    assert_int_not_equal(amxrt(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_connects_to_uri(UNUSED void** state) {
    char* argv1[] = {"amxrt", "-B a", "-u", "dummy://127.0.0.1:1970", "test.odl"};

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);

    assert_int_equal(amxrt(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_cannot_load_backends(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl"};

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, -1);
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_cannot_connect_bus_uri(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl", "-u", "dummy://127.0.0.1:1970"};

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, -1);
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_creates_pid_file(UNUSED void** state) {
    char* argv1[] = {"dummy_name", "-B a", "test.odl",
        "-u", "dummy://127.0.0.1:1970"};
    struct stat sb;
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read = 0;

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* name = GET_ARG(config, "name");
    amxc_var_delete(&name);

    optind = 1;
    system("sudo rm -rf /var/run/dummy_name");
    system("sudo mkdir -p /var/run/dummy_name");
    system("sudo chown $USER /var/run/dummy_name");
    system("sudo chmod 777 /var/run/dummy_name");
    system("ls -la /var/run/dummy_name");
    system("echo $USER");

    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_connect, 0);

    amxd_dm_init(dm);
    assert_int_equal(amxrt_init(sizeof(argv1) / sizeof(argv1[0]), argv1, NULL), 0);
    assert_true(stat("/var/run/dummy_name.pid", &sb) == 0 ||
                stat("/var/run/dummy_name/dummy_name.pid", &sb) == 0);

    if(stat("/var/run/dummy_name.pid", &sb) == 0) {
        fp = fopen("/var/run/dummy_name.pid", "r");
    } else {
        fp = fopen("/var/run/dummy_name/dummy_name.pid", "r");
    }
    read = getline(&line, &len, fp);
    assert_true(read > 0);
    assert_int_equal(atol(line), getpid());
    fclose(fp);
    free(line);

    system("sudo rm -rf /var/run/dummy_name");
    amxrt_stop();

    amxd_dm_clean(dm);
}

void test_runtime_daemon_failed(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl", "-D", "-u", "dummy://127.0.0.1:1970"};

    amxc_var_t* config = amxrt_get_config();
    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return(__wrap_daemon, -1);
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DAEMON), false);
    amxd_dm_clean(dm);
}

void test_runtime_set_priority_failed(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-D", "-u", "dummy://127.0.0.1:1970", "test.odl"};

    amxc_var_t* config = amxrt_get_config();
    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return(__wrap_daemon, 0);
    will_return(__wrap_setpriority, -1);
    will_return_always(__wrap_amxb_connect, 0);
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DAEMON), false);
    amxd_dm_clean(dm);
}

void test_runtime_parse_args_odl(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl", "-O", "%define {object TestObject2 {string Text = \"Hallo World\";}}",
        "-u", "dummy://127.0.0.1:1970"};

    amxc_var_t* config = amxrt_get_config();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);
    amxd_dm_clean(dm);
}

void test_runtime_parse_args_wrong_odl(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl", "-O", "%define {object TestObject2 {string Text = \"Hallo World\";}"}; //invalid odl string
    amxc_var_t* config = amxrt_get_config();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);
    amxd_dm_clean(dm);
}

void test_runtime_no_pidfile(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "test.odl", "-N", "-u", "dummy://127.0.0.1:1970"};

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_parses_post_includes(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "post_include.odl" };

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_opens_syslog(UNUSED void** state) {
    char* argv[] = {"amxrt", "-l", "test.odl", "-B b", "-u", "dummy://127.0.0.1:1970" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    assert_true(GET_BOOL(config, AMXRT_COPT_LOG));
    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_LOG), false);

    amxd_dm_clean(dm);
}

void test_runtime_dumps_config(UNUSED void** state) {
    char* argv[] = {"amxrt", "-d", "test.odl", "-B b", "-u", "dummy://127.0.0.1:1970" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    assert_true(GET_BOOL(config, AMXRT_COPT_DUMP_CONFIG));
    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CONFIG), false);

    amxd_dm_clean(dm);
}

void test_runtime_enables_system_signals_list(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-O", "%config { system-signals = [ 17 ]; }", "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    assert_true(amxp_syssig_is_enabled(17));
    amxp_syssig_enable(17, false);

    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);
    amxd_dm_clean(dm);
}

void test_runtime_enables_system_signal(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-O", "%config { system-signals = 17; }", "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    assert_true(amxp_syssig_is_enabled(17));
    amxp_syssig_enable(17, false);

    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);
    amxd_dm_clean(dm);
}

void test_runtime_forced_options_are_kept(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u",
        "dummy://127.0.0.1:1970",
        "-F", "my-option=123",
        "-O", "%config { my-option = 666; }", "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);

    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    assert_int_equal(GET_INT32(config, "my-option"), 123);
    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);

    amxd_dm_clean(dm);
}

void test_runtime_options_can_be_overwritten(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u",
        "dummy://127.0.0.1:1970",
        "-o", "my-option=123",
        "-O", "%config { my-option = 666; }", "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    assert_int_equal(GET_INT32(config, "my-option"), 999);
    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);

    amxd_dm_clean(dm);
}

void test_runtime_can_pass_option_path(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u",
        "dummy://127.0.0.1:1970",
        "-o", "my-table.my-key.0=123",
        "-o", "my-table.my-key.1=true",
        "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* cfg = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    cfg = GETP_ARG(config, "my-table.my-key.0");
    assert_int_equal(amxc_var_dyncast(int32_t, cfg), 123);
    cfg = GETP_ARG(config, "my-table.my-key.1");
    assert_true(GET_BOOL(cfg, NULL));

    amxd_dm_clean(dm);
}

void test_runtime_forced_options_with_path_are_kept(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u",
        "dummy://127.0.0.1:1970",
        "-F", "my-table.odl-key=xyz",
        "-O", "%config{ my-table = { odl-key=\"abc\" }; }",
        "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* cfg = NULL;
    amxc_var_t* odl_string = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    cfg = GETP_ARG(config, "my-table.odl-key");
    assert_string_equal(GET_CHAR(cfg, NULL), "xyz");
    odl_string = GET_ARG(config, AMXRT_COPT_ODL);
    amxc_var_delete(&odl_string);

    amxd_dm_clean(dm);
}

void test_runtime_can_pass_json_value_option(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u",
        "dummy://127.0.0.1:1970",
        "-o", "my-table.my-key.2={\"key1\":true, \"key2\":[1,2,3], \"key3\":\"abc\"}",
        "./test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* cfg = NULL;

    amxd_dm_init(dm);
    optind = 1;
    write(dummy_ctx.data_pipe[1], "s", 1);
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    cfg = GETP_ARG(config, "my-table.my-key.2.key1");
    assert_true(amxc_var_constcast(bool, cfg));
    cfg = GETP_ARG(config, "my-table.my-key.2.key2.0");
    assert_int_equal(amxc_var_dyncast(uint32_t, cfg), 1);
    cfg = GETP_ARG(config, "my-table.my-key.2.key2.1");
    assert_int_equal(amxc_var_dyncast(uint32_t, cfg), 2);
    cfg = GETP_ARG(config, "my-table.my-key.2.key2.2");
    assert_int_equal(amxc_var_dyncast(uint32_t, cfg), 3);
    cfg = GETP_ARG(config, "my-table.my-key.2.key3");
    assert_string_equal(amxc_var_constcast(cstring_t, cfg), "abc");

    amxd_dm_clean(dm);
}

void test_runtime_fails_when_registering_dm_fails(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    write(dummy_ctx.data_pipe[1], "s", 1);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, -1);
    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    amxd_dm_clean(dm);
}

void test_runtime_can_wait_for_objects(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-R", "NetDev.", "test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return(__wrap_amxb_wait_for_object, 0);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    will_return_always(__wrap_amxb_register, 0);
    amxp_sigmngr_trigger_signal(NULL, "wait:done", NULL);

    amxd_dm_clean(dm);
}

void test_runtime_wait_for_objects_can_fail(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-R", "NetDev.", "test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return(__wrap_amxb_wait_for_object, -1);

    assert_int_not_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    will_return_always(__wrap_amxb_register, 0);
    amxp_sigmngr_trigger_signal(NULL, "wait:done", NULL);

    amxd_dm_clean(dm);
}

void test_runtime_can_suspend_events_while_waiting(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-R", "NetDev.", "test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* config = amxrt_get_config();

    amxd_dm_init(dm);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_wait_for_object, 0);
    amxc_var_add_key(bool, config, AMXRT_COPT_SUSPEND, true);
    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);

    will_return_always(__wrap_amxb_register, 0);
    amxp_sigmngr_trigger_signal(NULL, "wait:done", NULL);

    amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_SUSPEND), false);

    amxd_dm_clean(dm);
}

void test_runtime_stops_el_when_registering_after_wait_fails(UNUSED void** state) {
    char* argv[] = {"amxrt", "-B b", "-u", "dummy://127.0.0.1:1970", "-R", "NetDev.", "test.odl" };

    amxd_dm_t* dm = amxrt_get_dm();

    amxd_dm_init(dm);
    optind = 1;
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, -1);
    will_return(__wrap_amxb_wait_for_object, 0);

    assert_int_equal(amxrt(sizeof(argv) / sizeof(argv[0]), argv, NULL), 0);
    amxp_sigmngr_trigger_signal(NULL, "wait:done", NULL);

    amxd_dm_clean(dm);
}

void test_runtime_can_create_listen_sockets(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* listen = GET_ARG(config, AMXRT_COPT_LISTEN);

    amxc_var_add(cstring_t, listen, "usp:/var/run/usp-ep.sock");
    will_return(__wrap_amxb_be_load_multiple, 0);
    will_return_always(__wrap_amxb_connect, 0);
    will_return_always(__wrap_amxb_listen, 0);
    will_return(__wrap_setpriority, 0);
    will_return_always(__wrap_amxb_register, 0);
    assert_int_equal(amxrt_connect(), 0);
    assert_int_equal(amxrt_register_or_wait(), 0);
}

void test_runtime_connect_fails_if_no_backends(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* backends = GET_ARG(config, AMXRT_COPT_BACKENDS);

    amxc_var_set_type(backends, AMXC_VAR_ID_CSTRING);
    assert_int_not_equal(amxrt_connect(), 0);
    amxc_var_set_type(backends, AMXC_VAR_ID_LIST);
    assert_int_not_equal(amxrt_connect(), 0);
}
