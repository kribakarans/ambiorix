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

#include "test_amxs_sync_hierarchy.h"
#include "dummy_be.h"

#include <amxc/amxc_macros.h>

static amxs_status_t test_trans_cb(UNUSED const amxs_sync_entry_t* entry,
                                   UNUSED amxs_sync_direction_t direction,
                                   UNUSED const amxc_var_t* input,
                                   UNUSED amxc_var_t* output,
                                   UNUSED void* priv) {
    return amxs_status_ok;
}

static amxs_status_t test_action_cb(UNUSED const amxs_sync_entry_t* entry,
                                    UNUSED amxs_sync_direction_t direction,
                                    UNUSED amxc_var_t* data,
                                    UNUSED void* priv) {
    return amxs_status_ok;
}

void test_amxs_sync_ctx_new_args(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_not_equal(amxs_sync_ctx_new(&ctx, NULL, NULL, AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxs_sync_ctx_new(NULL, NULL, NULL, AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxs_sync_ctx_new(&ctx, "A.", NULL, AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxs_sync_ctx_new(&ctx, NULL, "B.", AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxs_sync_ctx_new(&ctx, "A", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxs_sync_ctx_new(&ctx, "A.", "B", AMXS_SYNC_DEFAULT), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_ctx_delete(&ctx);
    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", NULL, AMXS_SYNC_ONLY_A_TO_B), 0);
    amxs_sync_ctx_delete(&ctx);
    assert_int_not_equal(amxs_sync_ctx_new(&ctx, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A), 0);
    assert_ptr_equal(ctx, NULL);
    assert_int_equal(amxs_sync_ctx_new(&ctx, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_ctx_new(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_ptr_not_equal(ctx, NULL);
    assert_string_equal(ctx->a, "A.");
    assert_string_equal(ctx->b, "B.");
    assert_int_equal(ctx->attributes, AMXS_SYNC_DEFAULT);
    assert_int_equal(ctx->type, amxs_sync_type_ctx);
    assert_ptr_equal(ctx->action_cb, NULL);
    assert_ptr_equal(ctx->translation_cb, NULL);
    assert_ptr_equal(ctx->priv, NULL);
    assert_ptr_equal(ctx->bus_ctx_a, NULL);
    assert_ptr_equal(ctx->bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&ctx->entries));
    assert_true(amxc_llist_is_empty(&ctx->subscriptions));
    assert_ptr_equal(ctx->it.llist, NULL);

    amxs_sync_ctx_delete(&ctx);
    assert_ptr_equal(ctx, NULL);
}

void test_amxs_sync_ctx_init_args(UNUSED void** state) {
    amxs_sync_ctx_t ctx;

    assert_int_not_equal(amxs_sync_ctx_init(&ctx, NULL, NULL, AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(NULL, NULL, NULL, AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A.", NULL, AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, NULL, "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A.", "B", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B | AMXS_SYNC_ONLY_B_TO_A), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B | AMXS_SYNC_INIT_B), 0);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A), 0);
    assert_int_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_ctx_clean(&ctx);
    assert_int_equal(amxs_sync_ctx_init(&ctx, "A.", NULL, AMXS_SYNC_ONLY_A_TO_B), 0);
    amxs_sync_ctx_clean(&ctx);
    assert_int_not_equal(amxs_sync_ctx_init(&ctx, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A), 0);
    assert_int_equal(amxs_sync_ctx_init(&ctx, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    amxs_sync_ctx_clean(&ctx);
}

void test_amxs_sync_ctx_init(UNUSED void** state) {
    amxs_sync_ctx_t ctx;

    assert_int_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_string_equal(ctx.a, "A.");
    assert_string_equal(ctx.b, "B.");
    assert_int_equal(ctx.attributes, AMXS_SYNC_DEFAULT);
    assert_int_equal(ctx.type, amxs_sync_type_ctx);
    assert_ptr_equal(ctx.action_cb, NULL);
    assert_ptr_equal(ctx.translation_cb, NULL);
    assert_ptr_equal(ctx.priv, NULL);
    assert_ptr_equal(ctx.bus_ctx_a, NULL);
    assert_ptr_equal(ctx.bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&ctx.entries));
    assert_true(amxc_llist_is_empty(&ctx.subscriptions));
    assert_ptr_equal(ctx.it.llist, NULL);

    amxs_sync_ctx_clean(&ctx);
    assert_ptr_equal(ctx.a, NULL);
    assert_ptr_equal(ctx.b, NULL);
    assert_int_equal(ctx.attributes, 0);
    assert_int_equal(ctx.type, amxs_sync_type_invalid);
    assert_ptr_equal(ctx.action_cb, NULL);
    assert_ptr_equal(ctx.translation_cb, NULL);
    assert_ptr_equal(ctx.priv, NULL);
    assert_ptr_equal(ctx.bus_ctx_a, NULL);
    assert_ptr_equal(ctx.bus_ctx_b, NULL);
}

void test_amxs_sync_ctx_clean(UNUSED void** state) {
    amxs_sync_ctx_t ctx;

    assert_int_equal(amxs_sync_ctx_init(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);

    amxs_sync_ctx_clean(NULL);
    amxs_sync_ctx_clean(&ctx);
    amxs_sync_ctx_clean(&ctx);
}

void test_amxs_sync_ctx_delete(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);

    amxs_sync_ctx_delete(NULL);
    amxs_sync_ctx_delete(&ctx);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_object_new_args(UNUSED void** state) {
    amxs_sync_object_t* object = NULL;

    assert_int_not_equal(amxs_sync_object_new(NULL, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, "A", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, "A.", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, "A.", NULL, AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, NULL, "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, "A.", NULL, AMXS_SYNC_ONLY_B_TO_A, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, NULL, "B.", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxs_sync_object_new(&object, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(object, NULL);

    assert_int_equal(amxs_sync_object_new(&object, NULL, "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, NULL, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, NULL, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);
}

void test_amxs_sync_object_new(UNUSED void** state) {
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->a, "A.");
    assert_string_equal(object->b, "B.");
    assert_int_equal(object->attributes, AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B);
    assert_int_equal(object->type, amxs_sync_type_object);
    assert_ptr_equal(object->action_cb, test_action_cb);
    assert_ptr_equal(object->translation_cb, test_trans_cb);
    assert_ptr_equal(object->priv, NULL);
    assert_ptr_equal(object->bus_ctx_a, NULL);
    assert_ptr_equal(object->bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&object->entries));
    assert_true(amxc_llist_is_empty(&object->subscriptions));
    assert_ptr_equal(object->it.llist, NULL);

    amxs_sync_object_delete(&object);
    assert_ptr_equal(object, NULL);

    assert_int_equal(amxs_sync_object_new_copy(&object, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->a, "A.");
    assert_string_equal(object->b, "B.");
    assert_int_equal(object->attributes, AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B);
    assert_int_equal(object->type, amxs_sync_type_object);
    assert_ptr_equal(object->action_cb, amxs_sync_object_copy_action_cb);
    assert_ptr_equal(object->translation_cb, amxs_sync_object_copy_trans_cb);
    assert_ptr_equal(object->priv, NULL);
    assert_ptr_equal(object->bus_ctx_a, NULL);
    assert_ptr_equal(object->bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&object->entries));
    assert_true(amxc_llist_is_empty(&object->subscriptions));
    assert_ptr_equal(object->it.llist, NULL);

    amxs_sync_object_delete(&object);
    assert_ptr_equal(object, NULL);
}

void test_amxs_sync_object_delete(UNUSED void** state) {
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);

    amxs_sync_object_delete(NULL);
    amxs_sync_object_delete(&object);
    amxs_sync_object_delete(&object);
}

void test_amxs_sync_param_new_args(UNUSED void** state) {
    amxs_sync_param_t* param = NULL;

    assert_int_not_equal(amxs_sync_param_new(NULL, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxs_sync_param_new(&param, "A", NULL, AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxs_sync_param_new(&param, NULL, "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxs_sync_param_new(&param, "A", NULL, AMXS_SYNC_ONLY_B_TO_A, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxs_sync_param_new(&param, NULL, "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxs_sync_param_new(&param, NULL, "B", AMXS_SYNC_ONLY_B_TO_A, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_equal(param, NULL);

    assert_int_equal(amxs_sync_param_new(&param, NULL, "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, NULL, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, NULL, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, NULL, NULL, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_param_delete(&param);
}

void test_amxs_sync_param_new(UNUSED void** state) {
    amxs_sync_param_t* param = NULL;

    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_ptr_not_equal(param, NULL);
    assert_string_equal(param->a, "A");
    assert_string_equal(param->b, "B");
    assert_int_equal(param->attributes, AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B);
    assert_int_equal(param->type, amxs_sync_type_param);
    assert_ptr_equal(param->action_cb, test_action_cb);
    assert_ptr_equal(param->translation_cb, test_trans_cb);
    assert_ptr_equal(param->priv, NULL);
    assert_ptr_equal(param->bus_ctx_a, NULL);
    assert_ptr_equal(param->bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&param->entries));
    assert_true(amxc_llist_is_empty(&param->subscriptions));
    assert_ptr_equal(param->it.llist, NULL);

    amxs_sync_param_delete(&param);
    assert_ptr_equal(param, NULL);

    assert_int_equal(amxs_sync_param_new_copy(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_ptr_not_equal(param, NULL);
    assert_string_equal(param->a, "A");
    assert_string_equal(param->b, "B");
    assert_int_equal(param->attributes, AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B);
    assert_int_equal(param->type, amxs_sync_type_param);
    assert_ptr_equal(param->action_cb, amxs_sync_param_copy_action_cb);
    assert_ptr_equal(param->translation_cb, amxs_sync_param_copy_trans_cb);
    assert_ptr_equal(param->priv, NULL);
    assert_ptr_equal(param->bus_ctx_a, NULL);
    assert_ptr_equal(param->bus_ctx_b, NULL);
    assert_true(amxc_llist_is_empty(&param->entries));
    assert_true(amxc_llist_is_empty(&param->subscriptions));
    assert_ptr_equal(param->it.llist, NULL);

    amxs_sync_param_delete(&param);
    assert_ptr_equal(param, NULL);
}

void test_amxs_sync_param_delete(UNUSED void** state) {
    amxs_sync_param_t* param = NULL;

    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);

    amxs_sync_param_delete(NULL);
    amxs_sync_param_delete(&param);
    amxs_sync_param_delete(&param);
}

void test_amxs_sync_ctx_add_param(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_param_t* param = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_not_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    amxs_sync_param_delete(&param);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    amxs_sync_param_delete(&param);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    amxs_sync_param_delete(&param);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "C", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "D", "E", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_param(ctx, param), 0);
    amxs_sync_param_delete(&param);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_new_param(ctx, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_int_not_equal(amxs_sync_ctx_add_new_param(ctx, "A", "B", AMXS_SYNC_ONLY_A_TO_B, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_param(ctx, "A", "B", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_add_new_copy_param(ctx, "A", "B", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_ctx_add_object(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* object = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_object(ctx, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_ctx_add_new_object(ctx, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_object(ctx, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_new_object(ctx, "A.", "C.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_ctx_add_new_param(ctx, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_add_new_copy_object(ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_ctx_add_new_copy_object(ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_object_add_param(UNUSED void** state) {
    amxs_sync_object_t* object = NULL;
    amxs_sync_param_t* param = NULL;

    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_param(object, param), 0);
    amxs_sync_object_delete(&object);

    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_param(object, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_object_add_new_param(object, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&object);

    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_param(object, "A", "B", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_object_add_new_copy_param(object, "A", "B", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_object_delete(&object);
}

void test_amxs_sync_object_add_object(UNUSED void** state) {
    amxs_sync_object_t* parent = NULL;
    amxs_sync_object_t* child = NULL;

    assert_int_equal(amxs_sync_object_new(&parent, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_new(&child, "C.", "D.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_object(parent, child), 0);
    amxs_sync_object_delete(&parent);

    assert_int_equal(amxs_sync_object_new(&parent, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_object(parent, "C.", "D.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_not_equal(amxs_sync_object_add_new_object(parent, "C.", "D.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    amxs_sync_object_delete(&parent);

    assert_int_equal(amxs_sync_object_new(&parent, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_object_add_new_copy_object(parent, "C.", "D.", AMXS_SYNC_DEFAULT), 0);
    assert_int_not_equal(amxs_sync_object_add_new_copy_object(parent, "C.", "D.", AMXS_SYNC_DEFAULT), 0);
    amxs_sync_object_delete(&parent);
}

void test_amxs_sync_ctx_set_dm(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxd_dm_t* dm = test_get_dm();

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_DEFAULT), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, dm, dm), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, dm), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, dm, NULL), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B), 0);
    assert_int_not_equal(amxs_sync_ctx_set_local_dm(ctx, dm, dm), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, dm), 0);
    assert_int_not_equal(amxs_sync_ctx_set_local_dm(ctx, dm, NULL), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, NULL), 0);
    amxs_sync_ctx_delete(&ctx);

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_INIT_B), 0);
    assert_int_not_equal(amxs_sync_ctx_set_local_dm(ctx, dm, dm), 0);
    assert_int_not_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, dm), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, dm, NULL), 0);
    assert_int_equal(amxs_sync_ctx_set_local_dm(ctx, NULL, NULL), 0);
    amxs_sync_ctx_delete(&ctx);
}

void test_amxs_sync_attr_update(UNUSED void** state) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_object_t* object = NULL;
    amxs_sync_param_t* param = NULL;

    assert_int_equal(amxs_sync_ctx_new(&ctx, "A.", "B.", AMXS_SYNC_ONLY_A_TO_B), 0);
    assert_int_equal(amxs_sync_object_new(&object, "A.", "B.", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);
    assert_int_equal(amxs_sync_param_new(&param, "A", "B", AMXS_SYNC_DEFAULT, test_trans_cb, test_action_cb, NULL), 0);

    assert_true(amxs_sync_entry_direction_allowed(ctx, amxs_sync_a_to_b));
    assert_false(amxs_sync_entry_direction_allowed(ctx, amxs_sync_b_to_a));
    assert_true(amxs_sync_entry_direction_allowed(object, amxs_sync_a_to_b));
    assert_true(amxs_sync_entry_direction_allowed(object, amxs_sync_b_to_a));
    assert_true(amxs_sync_entry_direction_allowed(param, amxs_sync_a_to_b));
    assert_true(amxs_sync_entry_direction_allowed(param, amxs_sync_b_to_a));

    assert_int_equal(amxs_sync_object_add_param(object, param), 0);
    assert_true(amxs_sync_entry_direction_allowed(object, amxs_sync_a_to_b));
    assert_true(amxs_sync_entry_direction_allowed(object, amxs_sync_b_to_a));
    assert_true(amxs_sync_entry_direction_allowed(param, amxs_sync_a_to_b));
    assert_true(amxs_sync_entry_direction_allowed(param, amxs_sync_b_to_a));

    assert_int_equal(amxs_sync_ctx_add_object(ctx, object), 0);
    assert_true(amxs_sync_entry_direction_allowed(object, amxs_sync_a_to_b));
    assert_false(amxs_sync_entry_direction_allowed(object, amxs_sync_b_to_a));
    assert_true(amxs_sync_entry_direction_allowed(param, amxs_sync_a_to_b));
    assert_false(amxs_sync_entry_direction_allowed(param, amxs_sync_b_to_a));

    amxs_sync_ctx_delete(&ctx);
}
