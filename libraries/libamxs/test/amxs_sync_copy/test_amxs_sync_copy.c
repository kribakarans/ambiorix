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
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_htable.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include <amxs/amxs.h>

#include <amxc/amxc_macros.h>

#include "test_amxs_sync_copy.h"
#include "dummy_be.h"

static amxb_bus_ctx_t* bus_ctx = NULL;

static void handle_events(void) {
    while(amxp_signal_read() == 0) {
    }
}

int test_amxs_sync_setup(UNUSED void** state) {
    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    assert_int_equal(test_load_dummy_remote("a.odl"), 0);
    assert_int_equal(test_load_dummy_remote("b.odl"), 0);

    return 0;
}

int test_amxs_sync_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);
    assert_int_equal(test_unregister_dummy_be(), 0);

    return 0;
}

void test_amxs_sync_copy_param(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.param_A", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);


    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_same_param(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.", 3, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.", 3, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    ptr_a = GETP_ARG(&data_a, "0.'A.object_A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "object_A.", "object_B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 6);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.param_B", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data_a, "param_A", "Updated string");
    assert_int_equal(amxb_set(bus_ctx, "A.object_A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.object_A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.object_A.param_A", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.object_A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "object_A.", "object_B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.param_B", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data_a, "param_A", "Updated string");
    assert_int_equal(amxb_set(bus_ctx, "A.object_A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.object_A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.object_B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

/*
 * Simple callback function that adds an extra character to the flag value of the parameter that is synced.
 */
static amxs_status_t param_action_cb(const amxs_sync_entry_t* sync_entry, amxs_sync_direction_t direction, amxc_var_t* data, void* priv) {
    amxc_var_t current_object_data;
    amxc_var_t new_settings;
    amxc_string_t new_flags_str;

    const char* previous_flags = NULL;

    amxc_var_init(&current_object_data);
    amxc_var_init(&new_settings);
    amxc_string_init(&new_flags_str, 0);
    amxc_var_set_type(&new_settings, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxb_get(bus_ctx, GET_CHAR(data, "path"), 0, &current_object_data, 5), 0);
    previous_flags = GETP_CHAR(&current_object_data, "0.0.flag");

    amxc_string_setf(&new_flags_str, "%s C", (previous_flags == NULL ? "" : previous_flags));

    amxc_var_add_key(cstring_t, &new_settings, "flag", amxc_string_get(&new_flags_str, 0));

    assert_int_equal(amxb_set(bus_ctx, GET_CHAR(data, "path"), &new_settings, &new_settings, 5), 0);
    handle_events();

    amxc_string_clean(&new_flags_str);
    amxc_var_clean(&new_settings);
    amxc_var_clean(&current_object_data);

    return amxs_sync_param_copy_action_cb(sync_entry, direction, data, priv);
}

static void get_latest_template_data(amxc_var_t* data, amxc_var_t** ptr, uint32_t template_nr, char name) {
    amxc_string_t new_flags_str;

    amxc_string_init(&new_flags_str, 0);

    amxc_var_clean(data);

    amxc_string_setf(&new_flags_str, "%c.%c_template.%d.", name, name, template_nr);
    assert_int_equal(amxb_get(bus_ctx, amxc_string_get(&new_flags_str, 0), 0, data, 5), 0);
    amxc_string_prependf(&new_flags_str, "0.'");
    amxc_string_appendf(&new_flags_str, "'.param_%c", name);
    *ptr = GETP_ARG(data, amxc_string_get(&new_flags_str, 0));

    amxc_string_clean(&new_flags_str);
}

static void check_parameter(amxc_var_t* data_a, amxc_var_t** ptr_a, char name_a, amxc_var_t* data_b, amxc_var_t** ptr_b, char name_b, uint32_t template_nr, bool ptrs_equal) {
    int ret = 0;

    get_latest_template_data(data_a, ptr_a, template_nr, name_a);
    get_latest_template_data(data_b, ptr_b, template_nr, name_b);
    assert_int_equal(amxc_var_compare(*ptr_a, *ptr_b, &ret), 0);
    if(ptrs_equal) {
        assert_int_equal(ret, 0);
    } else {
        assert_int_not_equal(ret, 0);
    }
}

void test_amxs_sync_copy_template_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    /* Nothing synced yet, param_A and param_B each have their own value */
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, false);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.1.'.flag"), "AA"), 0); // No sync yet so no flags set in param_action_cb
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.1.'.flag"), "BB"), 0); // No sync yet so no flags set in param_action_cb

    /* Start syncing param_A and param_B */
    handle_events();
    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "A_template.", "B_template.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT, amxs_sync_param_copy_trans_cb, param_action_cb, ctx), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);

    /* Check param_A and param_B are in sync for template 1 */
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, true);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.1.'.flag"), "AA C"), 0); // Parameters are synced both ways so we entered param_action_cb once
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.1.'.flag"), "BB C"), 0); // Parameters are synced both ways so we entered param_action_cb once

    /* Check param_A and param_B are in sync for template 2 */
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 2, true);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.2.'.flag"), "AA C"), 0);
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.2.'.flag"), "BB C"), 0);

    /* Change param_A for template 1, it should sync to param_B */
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.A_template.1.", &data_a, &data_a, 5), 0);
    handle_events();
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, true);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.1.'.flag"), "AA C C"), 0); // 1st: creation ; 2nd: change of parameter
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.1.'.flag"), "BB C C"), 0); // 1st: creation ; 2nd: sync of parameter

    /* Add template 3 for A, it should sync to B */
    amxc_var_clean(&data_a);
    assert_int_equal(amxb_add(bus_ctx, "A.A_template.", 3, NULL, NULL, &data_a, 5), 0);
    handle_events();
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 3, true);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.3.'.flag"), "AA C"), 0);
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.3.'.flag"), "BB C"), 0);

    /* Change param_A for template 3, it should sync to param_B */
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 12345);
    assert_int_equal(amxb_set(bus_ctx, "A.A_template.3.", &data_a, &data_a, 5), 0);
    handle_events();
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 3, true);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.3.'.flag"), "AA C C"), 0); // 1st: creation ; 2nd: change of parameter
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.3.'.flag"), "BB C C"), 0); // 1st creation  ; 2nd: sync of parameter

    /* Remove template 3 */
    amxc_var_clean(&data_a);
    assert_int_equal(amxb_del(bus_ctx, "A.A_template.", 3, NULL, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template.3.", 0, &data_b, 5), 0);
    assert_null(GETP_ARG(&data_b, "0.0"));

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_root_copy_template_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    /* Nothing synced yet, param_A and param_B each have their own value */
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, false);
    assert_int_equal(strcmp(GETP_CHAR(&data_a, "0.'A.A_template.1.'.flag"), "AA"), 0); // No sync yet so no flags set in param_action_cb
    assert_int_equal(strcmp(GETP_CHAR(&data_b, "0.'B.B_template.1.'.flag"), "BB"), 0); // No sync yet so no flags set in param_action_cb

    /* Start syncing param_A and param_B */
    handle_events();
    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.A_template.", "B.B_template.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, amxs_sync_param_copy_trans_cb, param_action_cb, ctx), 0);
    assert_int_not_equal(amxs_sync_ctx_start_sync(ctx), 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_instance_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.A_template.1.param_A", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template.1.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template.1.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template.1.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    handle_events();
    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "A_template.1.", "B_template.1.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template.1.param_B", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template.1.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.A_template.1.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template.1.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template.1.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template.1.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

static bool compare_object_params(amxc_var_t* data_a, amxc_var_t* data_b) {
    bool ret = false;
    int result = -1;
    amxc_var_t* ptr_a = GETP_ARG(data_a, "0.'A.object_A.'.param_A");
    amxc_var_t* ptr_b = GETP_ARG(data_b, "0.'B.object_B.'.param_B");

    when_failed(amxc_var_compare(ptr_a, ptr_b, &result), exit);
    when_failed(result, exit);

    ptr_a = GETP_ARG(data_a, "0.'A.object_A.'.number_A");
    ptr_b = GETP_ARG(data_b, "0.'B.object_B.'.number_B");

    when_failed(amxc_var_compare(ptr_a, ptr_b, &result), exit);
    when_failed(result, exit);

    ret = true;

exit:
    return ret;
}

void test_amxs_sync_copy_object_batch(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_false(compare_object_params(&data_a, &data_b));

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "object_A.", "object_B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "number_A", "number_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_true(compare_object_params(&data_a, &data_b));

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data_a, "param_A", "Updated string");
    assert_int_equal(amxb_set(bus_ctx, "A.object_A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_true(compare_object_params(&data_a, &data_b));

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_object_batch_check_direction(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_false(compare_object_params(&data_a, &data_b));

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "object_A.", "object_B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_ONLY_A_TO_B), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "number_A", "number_B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_true(compare_object_params(&data_a, &data_b));

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data_a, "param_A", "Updated string");
    assert_int_equal(amxb_set(bus_ctx, "A.object_A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_true(compare_object_params(&data_a, &data_b));

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "number_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.object_A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_false(compare_object_params(&data_a, &data_b));

    amxc_var_clean(&data_b);
    amxc_var_set_type(&data_b, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_b, "number_B", 4321);
    assert_int_equal(amxb_set(bus_ctx, "B.object_B.", &data_b, &data_b, 5), 0);
    handle_events();
    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.object_A.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.object_B.", 0, &data_b, 5), 0);
    assert_true(compare_object_params(&data_a, &data_b));

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_param_loop_prevention(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.param_A", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    // Toggle one side twice, then handle events
    // Value should be the latest one
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.", &data_a, &data_a, 5), 0);
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 5678);
    assert_int_equal(amxb_set(bus_ctx, "A.", &data_a, &data_a, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    // Toggle both sides at the same time, then handle events
    // Values should be swapped
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.", &data_a, &data_a, 5), 0);
    amxc_var_clean(&data_b);
    amxc_var_set_type(&data_b, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_b, "param_B", 4321);
    assert_int_equal(amxb_set(bus_ctx, "B.", &data_b, &data_b, 5), 0);
    handle_events();
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B", 0, &data_b, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "A.param_A", 0, &data_a, 5), 0);
    assert_int_equal(GETP_INT32(&data_a, "0.'A.'.param_A"), 4321);
    assert_int_equal(GETP_INT32(&data_b, "0.'B.'.param_B"), 1234);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_param_loop_prevention_multi_instance(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* obj = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);
    handle_events();

    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, false);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new_copy(&obj, "A_template.", "B_template.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(obj, "param_A", "param_B", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, obj), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);

    // Verify that both sides are equal
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 1, true);
    check_parameter(&data_a, &ptr_a, 'A', &data_b, &ptr_b, 'B', 2, true);

    // Change A.1., B.2., A.2., then handle events
    // A.1 should be equal to B.1
    // A.2 and B.2 should be swapped
    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 1234);
    assert_int_equal(amxb_set(bus_ctx, "A.A_template.1.", &data_a, &data_a, 5), 0);

    amxc_var_clean(&data_b);
    amxc_var_set_type(&data_b, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_b, "param_B", 1234);
    assert_int_equal(amxb_set(bus_ctx, "B.B_template.2.", &data_b, &data_b, 5), 0);

    amxc_var_clean(&data_a);
    amxc_var_set_type(&data_a, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &data_a, "param_A", 4321);
    assert_int_equal(amxb_set(bus_ctx, "A.A_template.2.", &data_a, &data_a, 5), 0);

    handle_events();

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "A.A_template.", 1, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template.", 1, &data_b, 5), 0);

    assert_int_equal(GETP_UINT32(&data_a, "0.'A.A_template.1.'.param_A"), 1234);
    assert_int_equal(GETP_UINT32(&data_b, "0.'B.B_template.1.'.param_B"), 1234);

    assert_int_equal(GETP_UINT32(&data_a, "0.'A.A_template.2.'.param_A"), 1234);
    assert_int_equal(GETP_UINT32(&data_b, "0.'B.B_template.2.'.param_B"), 4321);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
}

void test_amxs_sync_copy_param_read_only(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    assert_int_equal(amxb_get(bus_ctx, "A.param_A_ro", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B_ro", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A_ro");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B_ro");

    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_param(ctx, "param_A_ro", "param_B_ro", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B_ro", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B_ro");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_not_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, test_get_dm()), 0);
    assert_ptr_equal(amxs_sync_ctx_get_dm(ctx, amxs_sync_a_to_b), NULL);
    assert_ptr_equal(amxs_sync_ctx_get_dm(ctx, amxs_sync_b_to_a), test_get_dm());
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    handle_events();

    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B_ro", 0, &data_b, 5), 0);
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B_ro");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.");
    amxd_trans_set_value(cstring_t, &trans, "param_A_ro", "I am written");
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);

    handle_events();
    amxc_var_clean(&data_a);
    assert_int_equal(amxb_get(bus_ctx, "A.param_A_ro", 0, &data_a, 5), 0);
    amxc_var_clean(&data_b);
    assert_int_equal(amxb_get(bus_ctx, "B.param_B_ro", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.'.param_A_ro");
    ptr_b = GETP_ARG(&data_b, "0.'B.'.param_B_ro");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}

void test_amxs_sync_copy_instances(UNUSED void** state) {
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.", 2, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.", 0, &data_b, 5), 0);

    assert_int_equal(test_load_dummy_remote("sync.odl"), 0);
    assert_int_equal(amxo_parser_start_synchronize(test_get_parser()), 0);

    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.", 2, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A template sub");

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_add_inst(&trans, 2, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.2.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.2.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.2.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.2.'.param_B");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A template sub");

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "B.B_template_sub.");
    amxd_trans_add_inst(&trans, 3, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.3.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.3.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.3.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.3.'.param_B");
    assert_string_equal(GET_CHAR(ptr_a, NULL), "I am B template sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}

void test_amxs_sync_copy_template_sub_object(UNUSED void** state) {
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    assert_int_equal(test_load_dummy_remote("sync.odl"), 0);
    assert_int_equal(amxo_parser_start_synchronize(test_get_parser()), 0);

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_add_inst(&trans, 2, NULL);
    amxd_trans_set_value(cstring_t, &trans, "A_sub.text_A", "Changed text");
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.2.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.2.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.2.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.2.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_add_inst(&trans, 3, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.3.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.3.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.3.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.3.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "B.B_template_sub.");
    amxd_trans_add_inst(&trans, 4, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.4.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.4.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.4.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.4.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am B sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}

void test_amxs_sync_copy_template_sub_object_with_batch(UNUSED void** state) {
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    assert_int_equal(test_load_dummy_remote("sync_batch.odl"), 0);
    assert_int_equal(amxo_parser_start_synchronize(test_get_parser()), 0);

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_add_inst(&trans, 2, NULL);
    amxd_trans_set_value(cstring_t, &trans, "A_sub.text_A", "Changed text");
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.2.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.2.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.2.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.2.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_add_inst(&trans, 3, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.3.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.3.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.3.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.3.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am A sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "B.B_template_sub.");
    amxd_trans_add_inst(&trans, 4, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.4.A_sub.", 0, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.4.B_sub.", 0, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.4.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.4.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_b, NULL), "I am B sub");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}

void test_amxs_sync_copy_template_sub_object_reverse(UNUSED void** state) {
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    assert_int_equal(test_load_dummy_remote("sync_reverse.odl"), 0);
    assert_int_equal(amxo_parser_start_synchronize(test_get_parser()), 0);

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    amxd_trans_select_pathf(&trans, "B.B_template_sub.");
    amxd_trans_add_inst(&trans, 1, NULL);
    amxd_trans_set_value(cstring_t, &trans, "B_sub.text_B", "Changed text");
    amxd_trans_set_value(cstring_t, &trans, "param_B", "Changed text");
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.", 2, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.", 2, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_a, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.'.param_B");
    assert_string_equal(GET_CHAR(ptr_a, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_del_inst(&trans, 1, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_not_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}

void test_amxs_sync_copy_template_sub_object_batch_reverse(UNUSED void** state) {
    amxc_var_t data_a;
    amxc_var_t data_b;
    amxc_var_t* ptr_a = NULL;
    amxc_var_t* ptr_b = NULL;
    int ret = 0;
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    assert_int_equal(test_load_dummy_remote("sync_batch_reverse.odl"), 0);
    assert_int_equal(amxo_parser_start_synchronize(test_get_parser()), 0);

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    handle_events();

    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    amxd_trans_select_pathf(&trans, "B.B_template_sub.");
    amxd_trans_add_inst(&trans, 1, NULL);
    amxd_trans_set_value(cstring_t, &trans, "B_sub.text_B", "Changed text");
    amxd_trans_set_value(cstring_t, &trans, "param_B", "Changed text");
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_equal(amxb_get(bus_ctx, "A.A_template_sub.1.", 2, &data_a, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "B.B_template_sub.1.", 2, &data_b, 5), 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.A_sub.'.text_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.B_sub.'.text_B");
    assert_string_equal(GET_CHAR(ptr_a, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);
    ptr_a = GETP_ARG(&data_a, "0.'A.A_template_sub.1.'.param_A");
    ptr_b = GETP_ARG(&data_b, "0.'B.B_template_sub.1.'.param_B");
    assert_string_equal(GET_CHAR(ptr_a, NULL), "Changed text");
    assert_int_equal(amxc_var_compare(ptr_a, ptr_b, &ret), 0);
    assert_int_equal(ret, 0);

    amxd_trans_select_pathf(&trans, "A.A_template_sub.");
    amxd_trans_del_inst(&trans, 1, NULL);
    assert_int_equal(amxd_trans_apply(&trans, test_get_dm()), 0);
    amxd_trans_clean(&trans);

    handle_events();
    assert_int_not_equal(amxb_get(bus_ctx, "A.A_template_sub.1.A_sub.", 0, &data_a, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "B.B_template_sub.1.B_sub.", 0, &data_b, 5), 0);

    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    amxd_trans_clean(&trans);
}
