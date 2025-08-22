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

#include <amxo/amxo.h>

#include <amxs/amxs.h>

#include <amxc/amxc_macros.h>

#include "test_amxs_sync_start.h"
#include "dummy_be.h"

static amxb_bus_ctx_t* bus_ctx = NULL;

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

void test_amxs_sync_start_args(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_start_sync(NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_start_sync(ctx), 0);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_stop_args(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_ctx_stop_sync(NULL);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_start_param(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT | AMXS_SYNC_INIT_B), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", NULL, AMXS_SYNC_ONLY_A_TO_B), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 1);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 1);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, NULL, NULL, AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 3);
    assert_null(ctx);
}

void test_amxs_sync_start_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_ONLY_A_TO_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 3);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 3);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_ONLY_A_TO_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_start_template_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A_template.", "B_template.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 4);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A_template.", "B_template.", AMXS_SYNC_ONLY_A_TO_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A_template.", "B_template.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_start_multiple_objects(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A_template.", "B_template.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 10);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_start_instance_object_search_path(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx,
                                       "A.A_template.[param_A == 1337].",
                                       "B.B_template.[param_B == 42].",
                                       AMXS_SYNC_DEFAULT),
                     0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), 0);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 2);
    assert_string_equal(ctx->a, "A.A_template.1.");
    assert_string_equal(ctx->b, "B.B_template.1.");
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx,
                                       "A.A_template.[nonexistent == 1337].",
                                       "B.B_template.[param_B == 42].",
                                       AMXS_SYNC_DEFAULT),
                     0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_start_sync(ctx), amxs_status_object_not_found);
    assert_int_equal(amxc_llist_size(&ctx->subscriptions), 0);
    amxs_sync_ctx_stop_sync(ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_start_copied(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_ctx_t* copy_ctx = NULL;
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A_template.", "B_template.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_int_equal(amxs_sync_object_new(&object, "object_A.", "object_B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);

    assert_int_equal(amxs_sync_ctx_copy(&copy_ctx, ctx, NULL), 0);

    assert_int_equal(amxs_sync_ctx_start_sync(copy_ctx), 0);
    assert_true(amxs_sync_ctx_is_started(copy_ctx));
    amxs_sync_ctx_stop_sync(copy_ctx);
    assert_false(amxs_sync_ctx_is_started(copy_ctx));

    amxs_sync_ctx_delete(&ctx);
    amxs_sync_ctx_delete(&copy_ctx);
}

void test_amxs_sync_start_copied_change_paths(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_ctx_t* copy_ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx,
                                       "A.A_template.{i}.",
                                       "B.B_template.{i}.",
                                       AMXS_SYNC_DEFAULT),
                     0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "param_A", "param_B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);

    assert_int_equal(amxs_sync_ctx_copy(&copy_ctx, ctx, NULL), 0);
    assert_int_equal(amxs_sync_ctx_set_paths(copy_ctx,
                                             "A.A_template.[param_A == 1337].",
                                             "B.B_template.[param_B == 42]."), 0);

    assert_int_equal(amxs_sync_ctx_start_sync(copy_ctx), 0);
    assert_true(amxs_sync_ctx_is_started(copy_ctx));
    amxs_sync_ctx_stop_sync(copy_ctx);
    assert_false(amxs_sync_ctx_is_started(copy_ctx));

    amxs_sync_ctx_delete(&ctx);
    amxs_sync_ctx_delete(&copy_ctx);
}
