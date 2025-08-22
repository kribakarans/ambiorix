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
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <cap-ng.h>
#include <pwd.h>
#include <grp.h>

#include "test_amxrt_caps.h"

int __wrap_capng_get_caps_process(void);
int __real_capng_get_caps_process(void);
void __wrap_capng_clear(capng_select_t set);
int __wrap_capng_update(capng_act_t action, capng_type_t type, unsigned int capability);
int __wrap_capng_apply(capng_select_t set);
int __wrap_capng_change_id(int uid, int gid, capng_flags_t flag);
struct passwd* __wrap_getpwnam(const char* __name);
struct group* __wrap_getgrnam(const char* __name);

int __wrap_capng_get_caps_process() {
    return 0;
}

void __wrap_capng_clear(UNUSED capng_select_t set) {

}

int __wrap_capng_update(UNUSED capng_act_t action, UNUSED capng_type_t type, UNUSED unsigned int capability) {
    return mock();
}

int __wrap_capng_apply(UNUSED capng_select_t set) {
    return mock();
}

int __wrap_capng_change_id(UNUSED int uid, UNUSED int gid, UNUSED capng_flags_t flag) {
    return 0;
}

struct passwd* __wrap_getpwnam(const char* name) {
    static struct passwd pwd;
    pwd.pw_uid = 1000;

    check_expected(name);

    if(strcmp(name, "webadmin") == 0) {
        return &pwd;
    } else {
        return NULL;
    }
}

struct group* __wrap_getgrnam(const char* name) {
    static struct group grp;
    grp.gr_gid = 100;

    check_expected(name);

    if(strcmp(name, "webui") == 0) {
        return &grp;
    } else {
        return NULL;
    }
}

int test_caps_setup(UNUSED void** state) {
    amxrt_new();
    return 0;
}

int test_caps_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_caps_switch_user_group(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);

    amxc_var_add_key(cstring_t, privileges, "user", "webadmin");
    amxc_var_add_key(cstring_t, privileges, "group", "webui");

    expect_string(__wrap_getpwnam, name, "webadmin");
    expect_string(__wrap_getgrnam, name, "webui");

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_use_null_user_group(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* group = amxc_var_add_new_key(privileges, "group");

    amxc_var_add_new_key(privileges, "user");

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_set(cstring_t, group, "webui");
    expect_string(__wrap_getgrnam, name, "webui");

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_use_non_existing_user_group(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);

    amxc_var_add_key(cstring_t, privileges, "user", "non-existing");
    amxc_var_add_key(cstring_t, privileges, "group", "fake-group");

    expect_string(__wrap_getpwnam, name, "non-existing");
    expect_string(__wrap_getgrnam, name, "fake-group");

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_use_user_and_group_id(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);

    amxc_var_add_key(uint32_t, privileges, "user", 100);
    amxc_var_add_key(uint32_t, privileges, "group", 100);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_can_keep_capabilities(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(cstring_t, capabilities, "CAP_CHOWN");
    amxc_var_add(cstring_t, capabilities, "CAP_KILL");

    will_return_always(__wrap_capng_update, 0);
    will_return_always(__wrap_capng_apply, 0);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_set_type(capabilities, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, capabilities, "chown");
    amxc_var_add(cstring_t, capabilities, "KILL");

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_unknown_capabilities_are_ignored(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(cstring_t, capabilities, "CAP_DUMMY");

    amxc_var_set_type(capabilities, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, capabilities, "dummy");

    will_return_always(__wrap_capng_apply, 0);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_can_use_capability_ids(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(uint32_t, capabilities, 0);
    amxc_var_add(uint32_t, capabilities, 10);

    will_return_always(__wrap_capng_apply, 0);

    will_return_always(__wrap_capng_update, 0);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_invalid_capability_ids_are_ignored(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(int32_t, capabilities, -1);
    amxc_var_add(int32_t, capabilities, 25000);

    will_return_always(__wrap_capng_apply, 0);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_update_capability_can_fail(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(cstring_t, capabilities, "CAP_KILL");

    will_return_always(__wrap_capng_update, -1);

    will_return_always(__wrap_capng_apply, 0);

    assert_int_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_apply_can_fail(UNUSED void** state) {
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* privileges = amxc_var_add_key(amxc_htable_t, config, "privileges", NULL);
    amxc_var_t* capabilities = amxc_var_add_key(amxc_llist_t, privileges, "capabilities", NULL);

    amxc_var_add(cstring_t, capabilities, "CAP_CHOWN");
    amxc_var_add(cstring_t, capabilities, "CAP_KILL");

    will_return_always(__wrap_capng_update, 0);
    will_return_always(__wrap_capng_apply, -1);

    assert_int_not_equal(amxrt_caps_apply(), 0);

    amxc_var_delete(&privileges);
}

void test_caps_can_dump_capabilities(UNUSED void** state) {
    assert_int_equal(__real_capng_get_caps_process(), 0);

    amxrt_caps_dump();
}