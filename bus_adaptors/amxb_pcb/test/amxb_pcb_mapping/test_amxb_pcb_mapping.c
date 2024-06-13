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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#include "test_amxb_pcb_mapping.h"

static amxb_bus_ctx_t* bus_ctx = NULL;

int test_amxb_pcb_get_pcb_setup(UNUSED void** state) {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxc_string_setf(&txt, "pcb_sysbus -n test_bus -I /tmp/test.sock");
    system(amxc_string_get(&txt, 0));
    sleep(1);

    amxc_string_setf(&txt, "amxrt -A -D ./amx.odl");
    system(amxc_string_get(&txt, 0));

    amxc_string_setf(&txt, "pcb_app -u pcb://ipc:[/tmp/test.sock] -n mapper -N Device -c ./mapper.odl");
    system(amxc_string_get(&txt, 0));

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] ?");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

    assert_int_equal(amxb_be_load("../mod-amxb-test-pcb.so"), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    return 0;
}

int test_amxb_pcb_get_pcb_teardown(UNUSED void** state) {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    amxc_string_setf(&txt, "killall amxrt");
    system(amxc_string_get(&txt, 0));
    amxc_string_setf(&txt, "killall mapper");
    system(amxc_string_get(&txt, 0));
    amxc_string_setf(&txt, "killall test_bus");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

    amxb_be_remove_all();

    return 0;
}

void test_can_get_controller_object(UNUSED void** state) {
    amxc_var_t values;
    const char* path = "LocalAgent.Controller.";
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, path, 0, &values, 5), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);

    amxc_var_clean(&values);
}

void test_can_get_localagent_object_through_mapper(UNUSED void** state) {
    amxc_var_t values;
    const char* path = "Device.LocalAgent.";
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, path, INT32_MAX, &values, 5), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);

    amxc_var_clean(&values);
}

void test_can_get_controller_object_through_mapper(UNUSED void** state) {
    amxc_var_t values;
    const char* path = "Device.LocalAgent.Controller.";
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, path, INT32_MAX, &values, 5), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);

    amxc_var_clean(&values);
}
