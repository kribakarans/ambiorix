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

#ifndef __TEST_AMXRT_RUNTIME_H__
#define __TEST_AMXRT_RUNTIME_H__

#include <amxrt/amxrt.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxo/amxo.h>

int test_runtime_setup(UNUSED void** state);
int test_runtime_teardown(UNUSED void** state);

void test_runtime_start_prints_help_and_exits(UNUSED void** state);
void test_runtime_parses_default_odl(UNUSED void** state);
void test_runtime_parses_odls(UNUSED void** state);
void test_runtime_parses_odls_and_handle_events(UNUSED void** state);
void test_runtime_succeeds_when_no_odl(UNUSED void** state);
void test_runtime_fails_when_invalid_odl(UNUSED void** state);
void test_runtime_connects_to_uri(UNUSED void** state);
void test_runtime_cannot_load_backends(UNUSED void** state);
void test_runtime_cannot_connect_bus_uri(UNUSED void** state);
void test_runtime_creates_pid_file(UNUSED void** state);
void test_runtime_daemon_failed(UNUSED void** state);
void test_runtime_set_priority_failed(UNUSED void** state);
void test_runtime_parse_args_odl(UNUSED void** state);
void test_runtime_parse_args_wrong_odl(UNUSED void** state);
void test_runtime_no_pidfile(UNUSED void** state);
void test_runtime_parses_post_includes(UNUSED void** state);
void test_runtime_opens_syslog(UNUSED void** state);
void test_runtime_dumps_config(UNUSED void** state);
void test_runtime_enables_system_signals_list(UNUSED void** state);
void test_runtime_enables_system_signal(UNUSED void** state);
void test_runtime_forced_options_are_kept(UNUSED void** state);
void test_runtime_options_can_be_overwritten(UNUSED void** state);
void test_runtime_can_pass_option_path(UNUSED void** state);
void test_runtime_forced_options_with_path_are_kept(UNUSED void** state);
void test_runtime_can_pass_json_value_option(UNUSED void** state);
void test_runtime_fails_when_registering_dm_fails(UNUSED void** state);
void test_runtime_can_wait_for_objects(UNUSED void** state);
void test_runtime_wait_for_objects_can_fail(UNUSED void** state);
void test_runtime_can_suspend_events_while_waiting(UNUSED void** state);
void test_runtime_stops_el_when_registering_after_wait_fails(UNUSED void** state);
void test_runtime_can_create_listen_sockets(UNUSED void** state);
void test_runtime_connect_fails_if_no_backends(UNUSED void** state);

#endif // __TEST_AMXRT_RUNTIME_H__