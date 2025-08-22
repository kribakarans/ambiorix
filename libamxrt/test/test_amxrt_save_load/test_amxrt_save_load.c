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
#include <sys/stat.h>

#include <amxrt/amxrt.h>

#include "test_amxrt_save_load.h"

#include <amxd/amxd_transaction.h>

static int event_count;

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
        event_count++;
    }
    printf("\n");
}

static void read_sigalrm(void) {
    sigset_t mask;
    int sfd;
    struct signalfd_siginfo fdsi;
    ssize_t s;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    sfd = signalfd(-1, &mask, 0);
    s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
    assert_int_equal(s, sizeof(struct signalfd_siginfo));
    if(fdsi.ssi_signo == SIGALRM) {
        printf("Got SIGALRM\n");
        amxp_timers_calculate();
        amxp_timers_check();
    } else {
        printf("Read unexpected signal\n");
    }
}

int test_save_load_setup(UNUSED void** state) {
    amxc_var_t* odl = NULL;
    amxc_var_t* config = NULL;
    amxd_dm_t* dm = NULL;

    amxrt_new();
    config = amxrt_get_config();
    dm = amxrt_get_dm();
    odl = amxc_var_add_key(amxc_htable_t, config, "odl", NULL);

    amxc_var_add_key(bool, odl, "dm-load", true);
    amxc_var_add_key(bool, odl, "dm-save", true);
    amxc_var_add_key(uint32_t, odl, "dm-save-init-delay", 1000);

    amxp_sigmngr_enable(&dm->sigmngr, true);

    return 0;
}

int test_save_load_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_can_start_with_no_storage_type(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* storage = GET_ARG(config, "storage-type");
    amxc_var_take_it(storage);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    amxc_var_set_key(config, "storage-type", storage, AMXC_VAR_FLAG_DEFAULT);
}

void test_can_start_with_no_odl_storage_type(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* storage = GET_ARG(config, "storage-type");
    amxc_var_set(cstring_t, storage, "uci");

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
}

void test_can_start_with_odl_storage_type(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* storage = GET_ARG(config, "storage-type");
    amxc_var_set(cstring_t, storage, "odl");

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
}

void test_can_start_with_no_storage_path(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_var_t* storage = GET_ARG(config, "storage-path");
    amxc_var_take_it(storage);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    amxc_var_set_key(config, "storage-path", storage, AMXC_VAR_FLAG_DEFAULT);
}

void test_can_start_with_directory_configured(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_add_key(cstring_t, odl, "directory", "./odl");

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);
    handle_events();
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    amxd_dm_clean(dm);
}

void test_can_load_files_with_eventing_on_or_off(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_t* events = NULL;

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    event_count = 0;
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);
    handle_events();
    assert_int_equal(event_count, 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    amxd_dm_clean(dm);
    amxd_dm_init(dm);

    events = amxc_var_add_key(bool, odl, "load-dm-events", true);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    event_count = 0;
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);
    handle_events();
    assert_int_not_equal(event_count, 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    amxc_var_delete(&events);
    amxd_dm_clean(dm);
}

void test_start_fails_with_invalid_directory_configured(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    amxc_var_t* dir = GETP_ARG(config, "odl.directory");
    amxc_var_set(cstring_t, dir, "./rubish");

    amxd_dm_init(dm);

    assert_int_not_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    amxd_dm_clean(dm);
}

void test_loads_default_when_valid_dir_is_used(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_add_key(cstring_t, odl, "dm-defaults", "./defaults");

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    amxd_dm_clean(dm);
}

void test_load_fails_with_invalid_dir_and_invalid_defaults(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    amxc_var_t* dir = GETP_ARG(config, "odl.dm-defaults");
    amxc_var_set(cstring_t, dir, "./rubish");

    amxd_dm_init(dm);

    assert_int_not_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_null(amxd_dm_findf(dm, "Test.Table"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
}

void test_can_save_all_objects(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    struct stat statbuf;

    amxc_var_t* dir = GETP_ARG(config, "odl.dm-defaults");
    amxc_var_t* save = GETP_ARG(config, "odl.dm-save");

    amxc_var_delete(&dir);

    dir = GETP_ARG(config, "odl.directory");
    amxc_var_set(cstring_t, dir, "./odl");
    amxc_var_add_key(cstring_t, config, "name", "save_test");

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxc_var_set(bool, save, true);
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);
    unlink("./odl/save_test.odl");
    amxd_dm_clean(dm);
}

void test_save_fails_when_invalid_dir(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    struct stat statbuf;
    amxc_var_t* dir = GETP_ARG(config, "odl.directory");
    amxc_var_set(cstring_t, dir, "./odl");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxc_var_set(cstring_t, dir, "./rubish");
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_equal(stat("./odl/save_test.odl", &statbuf), -1);
    amxc_var_set(cstring_t, dir, "./odl");
    amxd_dm_clean(dm);
}

void test_can_save_separate_objects_csv(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_add_key(csv_string_t, odl, "dm-objects", "Test,Test2.");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);


    assert_int_not_equal(stat("./odl/00_Test.odl", &statbuf), -1);
    unlink("./odl/00_Test.odl");
    assert_int_not_equal(stat("./odl/01_Test2.odl", &statbuf), -1);
    unlink("./odl/01_Test2.odl");
    amxd_dm_clean(dm);
}

void test_save_separate_objects_fail_when_invalid_dir(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxc_var_t* dir = GETP_ARG(config, "odl.directory");
    amxc_var_set(cstring_t, dir, "./odl");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxc_var_set(cstring_t, dir, "./rubish");
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_equal(stat("./odl/00_Test.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/01_Test2.odl", &statbuf), -1);
    amxc_var_set(cstring_t, dir, "./odl");
    amxd_dm_clean(dm);
}

void test_can_save_separate_objects_string(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxc_var_t* objects = GETP_ARG(config, "odl.dm-objects");
    amxc_var_set(cstring_t, objects, "Test,Test2");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_not_equal(stat("./odl/00_Test.odl", &statbuf), -1);
    unlink("./odl/00_Test.odl");
    assert_int_not_equal(stat("./odl/01_Test2.odl", &statbuf), -1);
    unlink("./odl/01_Test2.odl");
    amxd_dm_clean(dm);
}

void test_does_not_save_when_invalid_objects(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxc_var_t* objects = GETP_ARG(config, "odl.dm-objects");
    amxc_var_set(uint32_t, objects, 100);

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_equal(stat("./odl/00_Test.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/01_Test2.odl", &statbuf), -1);
    amxd_dm_clean(dm);
}

void test_save_skips_unknown_objects(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxc_var_t* objects = GETP_ARG(config, "odl.dm-objects");
    amxc_var_set(csv_string_t, objects, "Test3, Test, Test4, Test2");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    assert_int_not_equal(stat("./odl/00_Test.odl", &statbuf), -1);
    unlink("./odl/00_Test.odl");
    assert_int_not_equal(stat("./odl/01_Test2.odl", &statbuf), -1);
    unlink("./odl/01_Test2.odl");
    assert_int_equal(stat("./odl/00_Test3.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/02_Test4.odl", &statbuf), -1);
    amxd_dm_clean(dm);
}

void test_can_save_on_changes(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxd_trans_t transaction;
    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_t* objects = GETP_ARG(config, "odl.dm-objects");
    amxc_var_delete(&objects);
    amxc_var_add_key(bool, odl, "dm-save-on-changed", true);

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    amxd_trans_apply(&transaction, dm);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    unlink("./odl/save_test.odl");
    amxd_dm_clean(dm);
}

void test_saves_when_persistent_parameter_changes(UNUSED void** state) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxd_trans_t transaction;

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);
    unlink("./odl/save_test.odl");

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table.1");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "World");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    unlink("./odl/save_test.odl");
    amxd_dm_clean(dm);
}

void test_does_not_save_when_not_persistent_parameter_changes(UNUSED void** state) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxd_trans_t transaction;

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);
    unlink("./odl/save_test.odl");

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table.1");
    amxd_trans_set_value(uint32_t, &transaction, "Number", 999);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    sleep(1);
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();
    assert_int_equal(stat("./odl/save_test.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    unlink("./odl/save_test.odl");
    amxd_dm_clean(dm);
}

void test_saves_when_instance_deleted(UNUSED void** state) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();
    struct stat statbuf;
    amxd_trans_t transaction;

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test.Table");
    amxd_trans_del_inst(&transaction, 1, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/save_test.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);
    unlink("./odl/save_test.odl");
    amxd_dm_clean(dm);
}

void test_can_save_on_changes_with_object_list(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxd_trans_t transaction;
    amxc_var_t* odl = GET_ARG(config, "odl");
    amxc_var_add_key(csv_string_t, odl, "dm-objects", "Test2");

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test2");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    amxd_trans_select_pathf(&transaction, "Test.Table.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test2");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "World");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    read_sigalrm();
    handle_events();
    assert_int_not_equal(stat("./odl/00_Test2.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/02_Test.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    unlink("./odl/00_Test2.odl");
    amxd_dm_clean(dm);
}

void test_does_not_save_on_changed_when_invalid_objects(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxo_parser_t* parser = amxrt_get_parser();
    amxd_dm_t* dm = amxrt_get_dm();

    struct stat statbuf;
    amxd_trans_t transaction;
    amxc_var_t* objects = GETP_ARG(config, "odl.dm-objects");
    amxc_var_set(uint32_t, objects, 100);

    amxd_dm_init(dm);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_START, dm, parser), 0);
    assert_non_null(amxd_dm_findf(dm, "Test.Table"));
    assert_non_null(amxd_dm_findf(dm, "Test2"));
    amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "Test2");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    amxd_trans_select_pathf(&transaction, "Test.Table.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hallo");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    sleep(1);
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    assert_int_equal(stat("./odl/save_test.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/Test2.odl", &statbuf), -1);
    assert_int_equal(stat("./odl/Test2.odl", &statbuf), -1);

    assert_int_equal(amxrt_dm_save_load_main(AMXO_STOP, dm, parser), 0);

    amxd_dm_clean(dm);
}
