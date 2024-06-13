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
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include "ssh_server.h"
#include "dm_ssh_server.h"
#include "test_start_stop.h"

static amxd_dm_t dm;
static amxo_parser_t parser;
static const char* odl_defs = "ssh_server_test.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
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
    } else {
        printf("Read unexpected signal\n");
    }
}

static void test_timer_callback(UNUSED amxp_timer_t* const timer,
                                void* data) {
    amxp_proc_ctrl_t* proc = (amxp_proc_ctrl_t*) data;
    amxc_var_t pid;
    amxc_var_init(&pid);
    amxc_var_set(uint32_t, &pid, proc->proc->pid);
    amxp_proc_ctrl_stop(proc);
    amxp_sigmngr_emit_signal(NULL, "proc:disable", &pid);

    amxc_var_clean(&pid);
}

static void test_stopped(UNUSED const char* const event_name,
                         UNUSED const amxc_var_t* const event_data,
                         void* const priv) {
    amxp_proc_ctrl_t* proc = (amxp_proc_ctrl_t*) priv;
    amxc_var_t pid;
    amxc_var_init(&pid);

    when_null(proc, leave);

    amxc_var_set(uint32_t, &pid, proc->proc->pid);
    amxp_timer_stop(proc->timer);
    amxp_proc_ctrl_stop_childs(proc);

    amxp_sigmngr_emit_signal(NULL, "proc:stopped", &pid);

leave:
    amxc_var_clean(&pid);
}

static void test_free_char(amxc_array_it_t* it) {
    char* txt = (char*) amxc_array_it_get_data(it);
    free(txt);
}

int __wrap_amxp_proc_ctrl_new(amxp_proc_ctrl_t** proc, amxp_proc_ctrl_cmd_t cmd_build_fn);
void __wrap_amxp_proc_ctrl_delete(amxp_proc_ctrl_t** proc);
int __wrap_amxp_proc_ctrl_stop(amxp_proc_ctrl_t* proc);
int __wrap_amxp_proc_ctrl_start(amxp_proc_ctrl_t* proc, uint32_t minutes, amxc_var_t* settings);

int __wrap_amxp_proc_ctrl_new(amxp_proc_ctrl_t** proc, amxp_proc_ctrl_cmd_t cmd_build_fn) {
    int retval = -1;
    when_null(proc, leave);
    when_null(cmd_build_fn, leave);

    *proc = (amxp_proc_ctrl_t*) calloc(1, sizeof(amxp_proc_ctrl_t));
    when_null(*proc, leave);

    when_failed(amxp_subproc_new(&(*proc)->proc), leave);
    when_failed(amxp_timer_new(&(*proc)->timer, test_timer_callback, *proc), leave);
    when_failed(amxc_array_init(&(*proc)->cmd, 10), leave);
    when_failed(amxc_var_init(&(*proc)->child_proc_pids), leave);

    (*proc)->build = cmd_build_fn;
    amxp_slot_connect((*proc)->proc->sigmngr, "stop", NULL, test_stopped, *proc);

    retval = 0;

leave:
    if((retval != 0) &&
       ((proc != NULL) && (*proc != NULL))) {
        amxp_subproc_delete(&(*proc)->proc);
        amxp_timer_delete(&(*proc)->timer);
        amxc_array_clean(&(*proc)->cmd, NULL);
        amxc_var_clean(&(*proc)->child_proc_pids);
        free(*proc);
        *proc = NULL;
    }
    return retval;
}

void __wrap_amxp_proc_ctrl_delete(amxp_proc_ctrl_t** proc) {
    when_null(proc, leave);
    when_null(*proc, leave);

    amxp_slot_disconnect((*proc)->proc->sigmngr, "stop", test_stopped);

    amxp_subproc_delete(&(*proc)->proc);
    amxp_timer_delete(&(*proc)->timer);
    amxc_array_clean(&(*proc)->cmd, test_free_char);
    amxc_var_clean(&(*proc)->child_proc_pids);

    free(*proc);
    *proc = NULL;

leave:
    return;
}

int __wrap_amxp_proc_ctrl_start(amxp_proc_ctrl_t* proc, uint32_t minutes, amxc_var_t* settings) {
    static uint32_t current_pid = 1000;
    int retval = -1;
    when_null(proc, leave);

    amxc_array_clean(&proc->cmd, test_free_char);
    retval = proc->build(&proc->cmd, settings);
    when_failed(retval, leave);

    if(minutes != 0) {
        amxp_timer_start(proc->timer, minutes * 60 * 1000);
    }

    proc->proc->pid = current_pid++;
    proc->proc->is_running = true;
    retval = mock();

leave:
    return retval;
}

int __wrap_amxp_proc_ctrl_stop(amxp_proc_ctrl_t* proc) {
    int rv = mock();
    amxp_timer_stop(proc->timer);
    proc->proc->pid = 0;
    proc->proc->is_running = false;
    return rv;
}

int test_ssh_server_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    amxp_signal_t* signal = NULL;
    amxc_var_t* ssh_server_config = NULL;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(amxp_signal_new(NULL, &signal, strsignal(SIGCHLD)), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "print_event", AMXO_FUNC(_print_event)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "cleanup_server", AMXO_FUNC(_cleanup_server)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "app_start", AMXO_FUNC(_app_start)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "ssh_server_enable_changed", AMXO_FUNC(_ssh_server_enable_changed)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "ssh_toggle", AMXO_FUNC(_ssh_toggle)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "ssh_server_added", AMXO_FUNC(_ssh_server_added)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "ssh_server_duration_changed", AMXO_FUNC(_ssh_server_duration_changed)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "ssh_server_settings_changed", AMXO_FUNC(_ssh_server_settings_changed)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "close_sessions", AMXO_FUNC(_close_sessions)), 0);

    will_return_always(__wrap_amxp_proc_ctrl_start, 0);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_defs, root_obj), 0);
    ssh_server_config = amxc_var_add_key(amxc_htable_t, &parser.config, "ssh-server", NULL);
    amxc_var_add_key(bool, ssh_server_config, "auto-restart", false);

    amxc_var_add_key(amxc_htable_t, &parser.config, "ssh-server", NULL);

    _ssh_server_main(0, &dm, &parser);

    handle_events();

    return 0;
}

int test_ssh_server_teardown(UNUSED void** state) {
    _ssh_server_main(1, &dm, &parser);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_ssh_server_instances_have_dropbear_ctrl(UNUSED void** state) {
    amxd_object_t* servers = amxd_dm_findf(&dm, "SSH.Server");
    amxd_object_t* server = NULL;
    char* status = NULL;

    assert_non_null(servers);
    amxp_sigmngr_trigger_signal(&dm.sigmngr, "app:start", NULL);

    amxd_object_for_each(instance, it, servers) {
        amxd_object_t* server = amxc_container_of(it, amxd_object_t, it);
        assert_non_null(server->priv);
    }

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);
}

void test_ssh_server_can_be_started(UNUSED void** state) {
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.2.");
    char* status = NULL;
    amxd_trans_t transaction;

    assert_non_null(server);
    will_return_always(__wrap_amxp_proc_ctrl_start, 0);

    assert_int_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, server);
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    amxd_trans_apply(&transaction, &dm);

    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_int_not_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);

    amxd_trans_clean(&transaction);
}

void test_ssh_server_can_be_stopped(UNUSED void** state) {
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.2.");
    char* status = NULL;
    amxd_trans_t transaction;

    assert_non_null(server);
    will_return_always(__wrap_amxp_proc_ctrl_stop, 0);

    assert_int_not_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, server);
    amxd_trans_set_value(bool, &transaction, "Enable", false);
    amxd_trans_apply(&transaction, &dm);

    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);
    assert_int_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);

    amxd_trans_clean(&transaction);
}

void test_ssh_server_status_is_error_when_failed_to_start(UNUSED void** state) {
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.2.");
    char* status = NULL;
    amxd_trans_t transaction;

    assert_non_null(server);
    will_return(__wrap_amxp_proc_ctrl_start, -1);

    assert_int_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, server);
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    amxd_trans_apply(&transaction, &dm);

    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Error");
    free(status);
    assert_int_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    amxd_trans_clean(&transaction);
}

void test_no_ssh_server_is_stopped_when_sigchld_with_unkown_pid_is_received(UNUSED void** state) {
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.1.");
    struct signalfd_siginfo si;
    amxc_var_t sig_var;
    char* status = NULL;
    amxp_signal_t* signal = NULL;

    memset(&si, 0, sizeof(struct signalfd_siginfo));
    amxc_var_init(&sig_var);

    assert_non_null(server);

    si.ssi_pid = 1234;
    amxc_var_set(amxp_siginfo_t, &sig_var, &si);

    signal = amxp_sigmngr_find_signal(NULL, strsignal(SIGCHLD));
    assert_non_null(signal);
    amxp_signal_trigger(signal, &sig_var);

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_int_not_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    amxc_var_clean(&sig_var);
}

void test_ssh_server_status_is_updated_when_process_is_killed(UNUSED void** state) {
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.1.");
    amxc_var_t pid;
    char* status = NULL;
    amxp_signal_t* signal = NULL;

    amxc_var_init(&pid);
    assert_non_null(server);

    amxc_var_set(uint32_t, &pid, amxd_object_get_value(uint32_t, server, "PID", NULL));

    signal = amxp_sigmngr_find_signal(NULL, "proc:stopped");
    assert_non_null(signal);
    amxp_signal_trigger(signal, &pid);

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Stopped");
    free(status);
    assert_int_equal(amxd_object_get_value(uint32_t, server, "PID", NULL), 0);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    amxc_var_clean(&pid);
}

void test_ssh_servers_are_stopped_when_service_is_disabled(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;

    will_return_always(__wrap_amxp_proc_ctrl_start, 0);
    will_return_always(__wrap_amxp_proc_ctrl_stop, 0);

    server = amxd_dm_findf(&dm, "SSH.");
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(bool, &transaction, "Enable", false);
    amxd_trans_select_pathf(&transaction, "SSH.Server.2.");
    amxd_trans_set_value(bool, &transaction, "Enable", false);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));
    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    amxd_trans_select_pathf(&transaction, "SSH.Server.2.");
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));
    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    amxd_trans_select_pathf(&transaction, "SSH.");
    amxd_trans_set_value(bool, &transaction, "Enable", false);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);
    server = amxd_dm_findf(&dm, "SSH.");
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));
    handle_events();

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Stopped");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Stopped");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();
}

void test_ssh_servers_can_be_added_while_service_is_disabled(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(bool, &transaction, "Enable", false);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    server = amxd_dm_findf(&dm, "SSH.");
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));

    server = amxd_dm_findf(&dm, "SSH.Server.3.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);

    server = amxd_dm_findf(&dm, "SSH.Server.4.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);

    amxd_trans_clean(&transaction);
}

void test_ssh_servers_are_started_when_service_is_enabled(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;

    will_return_always(__wrap_amxp_proc_ctrl_start, 0);

    server = amxd_dm_findf(&dm, "SSH.");
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.");
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);
    server = amxd_dm_findf(&dm, "SSH.");
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    server = amxd_dm_findf(&dm, "SSH.Server.2.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    server = amxd_dm_findf(&dm, "SSH.Server.3.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));

    server = amxd_dm_findf(&dm, "SSH.Server.4.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));

    handle_events();
}

void test_ssh_server_active_duration_can_be_set_after_start(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;
    amxp_proc_ctrl_t* dropbear_ctrl = NULL;

    will_return_always(__wrap_amxp_proc_ctrl_stop, 0);

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);
    assert_true(amxd_object_get_value(bool, server, "Enable", NULL));
    assert_int_equal(amxd_object_get_value(uint32_t, server, "ActivationDuration", NULL), 0);
    dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;
    assert_int_not_equal(amxp_timer_get_state(dropbear_ctrl->timer), amxp_timer_running);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(uint32_t, &transaction, "ActivationDuration", 1);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();
    amxp_timers_calculate();
    amxp_timers_check();

    assert_int_equal(amxp_timer_get_state(dropbear_ctrl->timer), amxp_timer_running);

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Disabled");
    free(status);
    assert_false(amxd_object_get_value(bool, server, "Enable", NULL));
    assert_int_not_equal(amxp_timer_get_state(dropbear_ctrl->timer), amxp_timer_running);
}

void test_ssh_server_is_not_restarted_if_auto_restart_is_off(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;
    amxp_proc_ctrl_t* dropbear_ctrl = NULL;
    uint32_t pid = 0;

    will_return_always(__wrap_amxp_proc_ctrl_start, 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(uint32_t, &transaction, "ActivationDuration", 0);
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    assert_true(amxp_subproc_is_running(dropbear_ctrl->proc));
    pid = dropbear_ctrl->proc->pid;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(uint32_t, &transaction, "Port", 2020);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    assert_true(amxp_subproc_is_running(dropbear_ctrl->proc));
    assert_int_equal(pid, dropbear_ctrl->proc->pid);
}

void test_ssh_server_is_restarted_if_settings_changed(UNUSED void** state) {
    char* status = NULL;
    amxd_object_t* server = NULL;
    amxd_trans_t transaction;
    amxp_proc_ctrl_t* dropbear_ctrl = NULL;
    uint32_t pid = 0;

    amxc_var_t* auto_restart = GETP_ARG(&parser.config, "ssh-server.auto-restart");
    amxc_var_set(bool, auto_restart, true);

    will_return_always(__wrap_amxp_proc_ctrl_start, 0);
    will_return_always(__wrap_amxp_proc_ctrl_stop, 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(uint32_t, &transaction, "ActivationDuration", 0);
    amxd_trans_set_value(bool, &transaction, "Enable", true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    server = amxd_dm_findf(&dm, "SSH.Server.1.");
    assert_non_null(server);
    dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    assert_true(amxp_subproc_is_running(dropbear_ctrl->proc));
    pid = dropbear_ctrl->proc->pid;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "SSH.Server.1.");
    amxd_trans_set_value(uint32_t, &transaction, "Port", 22);
    amxd_trans_set_value(bool, &transaction, "AllowRootPasswordLogin", true);
    amxd_trans_set_value(bool, &transaction, "AllowRootLogin", false);
    amxd_trans_set_value(bool, &transaction, "AllowPasswordLogin", false);
    amxd_trans_set_value(cstring_t, &transaction, "SourcePrefix", "0.0.0.0");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    handle_events();

    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    assert_string_equal(status, "Running");
    free(status);

    assert_true(amxp_subproc_is_running(dropbear_ctrl->proc));
    assert_int_not_equal(pid, dropbear_ctrl->proc->pid);
}

void test_ssh_server_can_stop_sessions(UNUSED void** state) {
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.1.");

    assert_int_equal(amxd_object_invoke_function(server, "close_sessions", &args, &ret), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_ssh_server_destroy_action_can_not_be_used_for_other_action(UNUSED void** state) {
    amxc_var_t retval;
    amxd_object_t* server = amxd_dm_findf(&dm, "SSH.Server.1.");
    amxc_var_init(&retval);

    assert_int_equal(_cleanup_server(server, NULL, action_object_validate, NULL, &retval, NULL),
                     amxd_status_function_not_implemented);
    assert_int_equal(_cleanup_server(server, NULL, action_param_destroy, NULL, &retval, NULL),
                     amxd_status_function_not_implemented);

    amxc_var_clean(&retval);
}

