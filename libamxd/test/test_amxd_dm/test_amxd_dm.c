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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include "test_amxd_dm.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static const char* expected_signal = NULL;

static void test_amxd_root_signals(const char* const sig_name,
                                   const amxc_var_t* const data,
                                   UNUSED void* const priv) {
    amxc_var_t* object_path = NULL;
    assert_string_equal(sig_name, expected_signal);
    object_path = amxc_var_get_key(data, "object", AMXC_VAR_FLAG_DEFAULT);
    assert_string_equal(amxc_var_constcast(cstring_t, object_path), "test_object");

}

void test_amxd_dm_init_clean(UNUSED void** state) {
    assert_int_equal(amxd_dm_init(&dm), 0);
    amxd_dm_clean(&dm);

    assert_int_not_equal(amxd_dm_init(NULL), 0);
    amxd_dm_clean(NULL);
}

void test_amxd_dm_new_delete(UNUSED void** state) {
    amxd_dm_t* dm = NULL;

    assert_int_equal(amxd_dm_new(&dm), 0);
    assert_int_not_equal(amxd_dm_new(&dm), 0);
    amxd_dm_delete(&dm);
    assert_ptr_equal(dm, NULL);
    amxd_dm_delete(&dm);

    assert_int_not_equal(amxd_dm_new(NULL), 0);
    amxd_dm_delete(NULL);
}

void test_amxd_dm_get_root(UNUSED void** state) {
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_ptr_equal(amxd_dm_get_root(&dm), &dm.object);
    assert_ptr_equal(amxd_dm_get_root(NULL), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_dm_add_root_object(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);
    assert_ptr_not_equal(object, NULL);

    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxc_llist_size(&dm.object.objects), 1);
    assert_ptr_equal(object->it.llist, &dm.object.objects);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);
    assert_int_not_equal(amxd_dm_add_root_object(&dm, object), 0);
    amxd_object_delete(&object);

    assert_int_not_equal(amxd_dm_add_root_object(&dm, NULL), 0);
    assert_int_not_equal(amxd_dm_add_root_object(NULL, NULL), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_dm_remove_root_object(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);
    assert_ptr_not_equal(object, NULL);

    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxc_llist_size(&dm.object.objects), 1);
    assert_ptr_equal(object->it.llist, &dm.object.objects);

    object = NULL;
    assert_int_equal(amxd_dm_remove_root_object(&dm, "test_object"), 0);
    assert_int_equal(amxc_llist_size(&dm.object.objects), 0);
    assert_int_not_equal(amxd_dm_remove_root_object(&dm, ""), 0);
    assert_int_not_equal(amxd_dm_remove_root_object(&dm, NULL), 0);
    assert_int_not_equal(amxd_dm_remove_root_object(NULL, NULL), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_dm_root_object_signals(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    amxp_slot_connect(&dm.sigmngr, "dm:root-added", NULL, test_amxd_root_signals, NULL);
    amxp_slot_connect(&dm.sigmngr, "dm:root-removed", NULL, test_amxd_root_signals, NULL);

    expected_signal = "dm:root-added";
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxp_signal_read(), 0);

    expected_signal = "dm:root-removed";
    assert_int_equal(amxd_dm_remove_root_object(&dm, "test_object"), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_dm_error_string(UNUSED void** state) {
    assert_string_equal(amxd_status_string(amxd_status_ok), "ok");
    assert_string_equal(amxd_status_string(amxd_status_invalid_action), "invalid action");
    assert_string_equal(amxd_status_string(amxd_status_last + 1), "unknown error");
    assert_string_equal(amxd_status_string(amxd_status_last), "last");
}