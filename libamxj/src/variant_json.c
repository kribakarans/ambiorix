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
#include <string.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include <amxc/amxc_variant_type.h>
#include <amxc/amxc_string.h>

#include <amxj/amxj_variant.h>
#include "variant_json_priv.h"

static void variant_json_yajl_print(void* ctx, const char* str, size_t len) {
    variant_json_t* var_json = (variant_json_t*) ctx;

    amxc_string_append(&var_json->buffer, str, len);
}

static int variant_json_init(amxc_var_t* const var) {
    int retval = -1;
    variant_json_t* var_json = (variant_json_t*) calloc(1, sizeof(variant_json_t));
    when_null(var_json, exit);

    var_json->gen = yajl_gen_alloc(NULL);
    when_null(var_json->gen, exit);

    amxc_string_init(&var_json->buffer, 1024);
    amxc_lstack_init(&var_json->var_stack);
    amxc_lqueue_init(&var_json->result_queue);

    yajl_gen_config(var_json->gen, yajl_gen_beautify, 0);
    yajl_gen_config(var_json->gen, yajl_gen_validate_utf8, 1);
    yajl_gen_config(var_json->gen,
                    yajl_gen_print_callback,
                    variant_json_yajl_print,
                    var_json);

    var->data.data = var_json;
    retval = 0;

exit:
    if(retval != 0) {
        free(var_json);
    }
    return retval;
}

static void variant_json_delete(amxc_var_t* var) {
    variant_json_t* var_json = (variant_json_t*) var->data.data;
    var->data.data = NULL;
    if(var_json != NULL) {
        amxc_string_clean(&var_json->buffer);
        yajl_gen_free(var_json->gen);

        if(!amxc_lstack_is_empty(&var_json->var_stack)) {
            amxc_lstack_clean(&var_json->var_stack, variant_list_it_free);
        }

        if(!amxc_lqueue_is_empty(&var_json->result_queue)) {
            amxc_lqueue_clean(&var_json->result_queue, variant_list_it_free);
        }
    }
    free(var_json);
}

static int variant_json_copy(amxc_var_t* const dest,
                             const amxc_var_t* const src) {
    int retval = -1;
    const variant_json_t* src_var_json = (variant_json_t*) src->data.data;
    variant_json_t* dest_var_json = (variant_json_t*) dest->data.data;

    int length = amxc_string_text_length(&src_var_json->buffer);
    const char* text = amxc_string_get(&src_var_json->buffer, 0);

    when_failed(amxc_string_append(&dest_var_json->buffer, text, length), exit);

    retval = 0;

exit:
    if(retval == -1) {
        amxc_string_clean(&dest_var_json->buffer);
    }
    return retval;
}

static int variant_json_move(amxc_var_t* const dest,
                             amxc_var_t* const src) {
    variant_json_delete(dest);
    dest->data.data = src->data.data;
    src->data.data = NULL;
    return 0;
}

static amxc_var_type_t variant_json = {
    .init = variant_json_init,
    .del = variant_json_delete,
    .copy = variant_json_copy,
    .move = variant_json_move,
    .convert_from = variant_json_convert_from,
    .convert_to = variant_json_convert_to,
    .compare = NULL,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = NULL,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_JSON
};

CONSTRUCTOR static void variant_json_register(void) {
    amxc_var_register_type(&variant_json);
}

DESTRUCTOR static void variant_json_unregister(void) {
    amxc_var_unregister_type(&variant_json);
}

const char* amxc_var_get_const_jstring_t(const amxc_var_t* const var) {
    const char* retval = NULL;
    variant_json_t* json_string = NULL;

    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_JSON, exit);
    json_string = (variant_json_t*) var->data.data;

    retval = amxc_string_get(&json_string->buffer, 0);

exit:
    return retval;
}

int amxc_var_set_jstring_t(amxc_var_t* const var, const char* const val) {
    int retval = -1;
    int length = 0;
    variant_json_t* json_string = NULL;
    yajl_handle json_parse = NULL;
    yajl_status status = yajl_status_ok;

    when_null(var, exit);
    when_str_empty(val, exit);
    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_JSON), exit);

    length = strlen(val);
    json_parse = yajl_alloc(NULL, NULL, NULL);
    when_null(json_parse, exit);
    status = yajl_parse(json_parse, (const unsigned char*) val, length);
    when_true(status != yajl_status_ok, exit);

    json_string = (variant_json_t*) var->data.data;
    amxc_string_set_at(&json_string->buffer,
                       0,
                       val,
                       length,
                       amxc_string_overwrite);
    retval = 0;

exit:
    if(json_parse != NULL) {
        yajl_free(json_parse);
    }
    if(retval != 0) {
        amxc_var_set_type(var, AMXC_VAR_ID_NULL);
    }
    return retval;
}
