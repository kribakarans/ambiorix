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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include <amxc/amxc_variant_type.h>
#include <amxc/amxc_string.h>

#include <amxj/amxj_variant.h>
#include "variant_json_priv.h"

#define AMXJ_READ_BUFFER_SIZE 8192

// TODO: Refactor function - too long
static amxc_var_t* variant_json_parse(void* ctx, uint32_t type) {
    amxc_var_t* retval = NULL;
    variant_json_t* var_json = (variant_json_t*) ctx;
    amxc_llist_it_t* stack_it = amxc_lstack_pop(&var_json->var_stack);
    amxc_var_t* var = amxc_var_from_llist_it(stack_it);

    if((var_json->parse_state == amxj_reader_start) ||
       (var_json->parse_state == amxj_reader_start_verify)) {
        if(var_json->parse_state == amxj_reader_start_verify) {
            when_true(amxc_var_type_of(var) != type, exit);
        } else {
            amxc_var_set_type(var, type);
        }
        if((type == AMXC_VAR_ID_HTABLE) ||
           (type == AMXC_VAR_ID_LIST)) {
            when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
        }
        retval = var;
    } else {
        if(amxc_var_type_of(var) == AMXC_VAR_ID_LIST) {
            amxc_var_t* new_var = NULL;
            amxc_var_new(&new_var);
            when_null(new_var, exit);
            amxc_var_set_type(new_var, type);
            // put the list back
            when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
            // do not add htable or list to the list, this is done in
            // variant_json_parse_end_map and variant_json_parse_end_array
            // otherwise we can not add it to the stack
            if((type != AMXC_VAR_ID_HTABLE) &&
               (type != AMXC_VAR_ID_LIST)) {
                when_failed(amxc_llist_append(&var->data.vl, &new_var->lit), exit);
            } else {
                when_failed(amxc_lstack_push(&var_json->var_stack, &new_var->lit), exit);
            }
            retval = new_var;
        } else {
            amxc_var_t* var_top = NULL;
            when_failed(amxc_var_set_type(var, type), exit);
            // top of stack should be a variant containing a htable
            stack_it = amxc_lstack_peek(&var_json->var_stack);
            var_top = amxc_var_from_llist_it(stack_it);
            when_true(amxc_var_type_of(var_top) != AMXC_VAR_ID_HTABLE, exit);
            if((type == AMXC_VAR_ID_HTABLE) ||
               (type == AMXC_VAR_ID_LIST)) {
                when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
            }
            retval = var;
        }
    }

    var_json->parse_state = amxj_reader_parsing;
    if(amxc_lstack_is_empty(&var_json->var_stack)) {
        amxc_lqueue_add(&var_json->result_queue, &var->lit);
        when_failed(amxc_var_new(&var), exit);
        when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
        var_json->parse_state = amxj_reader_start;
    }

exit:
    return retval;
}

static int variant_json_parse_null(void* ctx) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_NULL);
    when_null(var, exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_boolean(void* ctx, int boolean) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_BOOL);
    when_null(var, exit);

    when_failed(amxc_var_set(bool, var, boolean == 0 ? false : true), exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_integer(void* ctx, long long integer) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_INT64);
    when_null(var, exit);

    when_failed(amxc_var_set(int64_t, var, integer), exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_double(void* ctx, double d) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_DOUBLE);
    when_null(var, exit);

    when_failed(amxc_var_set(double, var, d), exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_string(void* ctx,
                                     const unsigned char* stringVal,
                                     size_t stringLen) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_CSTRING);
    when_null(var, exit);

    when_failed(amxc_var_set(cstring_t, var, (const char*) stringVal), exit);
    var->data.s[stringLen] = 0;

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_key(void* ctx,
                                  const unsigned char* stringVal,
                                  size_t stringLen) {
    int retval = 0;
    variant_json_t* var_json = (variant_json_t*) ctx;
    amxc_llist_it_t* stack_it = amxc_lstack_pop(&var_json->var_stack);
    amxc_var_t* var = amxc_var_from_llist_it(stack_it);
    amxc_var_t* var_val = NULL;
    char* key = (char*) calloc(1, stringLen + 1);

    memcpy(key, stringVal, stringLen);
    key[stringLen] = 0;

    when_true(amxc_var_type_of(var) != AMXC_VAR_ID_HTABLE, exit);

    amxc_var_new(&var_val);
    when_null(var_val, exit);

    amxc_htable_insert(&var->data.vm, key, &var_val->hit);
    when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
    when_failed(amxc_lstack_push(&var_json->var_stack, &var_val->lit), exit);

    retval = 1;

exit:
    free(key);
    return retval;
}

static int amxj_reader_start_map(void* ctx) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_HTABLE);
    when_null(var, exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_end_map(void* ctx) {
    int retval = 0;
    variant_json_t* var_json = (variant_json_t*) ctx;
    amxc_llist_it_t* stack_it = amxc_lstack_pop(&var_json->var_stack);
    amxc_var_t* var = amxc_var_from_llist_it(stack_it);
    amxc_var_t* var_top = NULL;

    when_true(amxc_var_type_of(var) != AMXC_VAR_ID_HTABLE, exit);
    stack_it = amxc_lstack_peek(&var_json->var_stack);
    var_top = amxc_var_from_llist_it(stack_it);

    if(amxc_var_type_of(var_top) == AMXC_VAR_ID_LIST) {
        when_failed(amxc_llist_append(&var_top->data.vl, &var->lit), exit);
    }

    if(amxc_lstack_is_empty(&var_json->var_stack)) {
        amxc_lqueue_add(&var_json->result_queue, &var->lit);
        when_failed(amxc_var_new(&var), exit);
        when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
        var_json->parse_state = amxj_reader_start;
    }

    retval = 1;

exit:
    return retval;
}

static int amxj_reader_start_array(void* ctx) {
    int retval = 0;

    amxc_var_t* var = variant_json_parse(ctx, AMXC_VAR_ID_LIST);
    when_null(var, exit);

    retval = 1;

exit:
    return retval;
}

static int variant_json_parse_end_array(void* ctx) {
    int retval = 0;
    variant_json_t* var_json = (variant_json_t*) ctx;
    amxc_llist_it_t* stack_it = amxc_lstack_pop(&var_json->var_stack);
    amxc_var_t* var = amxc_var_from_llist_it(stack_it);
    amxc_var_t* var_top = NULL;

    when_true(amxc_var_type_of(var) != AMXC_VAR_ID_LIST, exit);
    stack_it = amxc_lstack_peek(&var_json->var_stack);
    var_top = amxc_var_from_llist_it(stack_it);
    if(amxc_var_type_of(var_top) == AMXC_VAR_ID_LIST) {
        when_failed(amxc_llist_append(&var_top->data.vl, &var->lit), exit);

    }

    if(amxc_lstack_is_empty(&var_json->var_stack)) {
        amxc_lqueue_add(&var_json->result_queue, &var->lit);
        when_failed(amxc_var_new(&var), exit);
        when_failed(amxc_lstack_push(&var_json->var_stack, &var->lit), exit);
        var_json->parse_state = amxj_reader_start;
    }

    retval = 1;

exit:
    return retval;
}

static yajl_callbacks jayl_parse_cb = {
    variant_json_parse_null,     // null
    variant_json_parse_boolean,  // boolean
    variant_json_parse_integer,  // integer (signed 64 bit)
    variant_json_parse_double,   // double
    NULL,                        // number (in string format)
    variant_json_parse_string,   // string
    amxj_reader_start_map,       // start of a map {
    variant_json_parse_key,      // key
    variant_json_parse_end_map,  // end of a map }
    amxj_reader_start_array,     // start of an array [
    variant_json_parse_end_array // end of an array ]
};

static int variant_json_convert_to_any(amxc_var_t* const dest,
                                       const amxc_var_t* const src) {
    // src variant is a jstring_t
    // dest variant is something else
    int retval = -1;
    const char* json_str = NULL;
    yajl_status status = yajl_status_ok;
    variant_json_t* var_json = (variant_json_t*) src->data.data;

    var_json->parse = yajl_alloc(&jayl_parse_cb, NULL, var_json);
    when_null(var_json->parse, exit);

    json_str = amxc_string_get(&var_json->buffer, 0);
    when_str_empty(json_str, exit);

    amxc_lstack_clean(&var_json->var_stack, variant_list_it_free);
    amxc_lqueue_clean(&var_json->result_queue, variant_list_it_free);
    when_failed(amxc_lstack_push(&var_json->var_stack, &dest->lit), exit);

    if(amxc_var_type_of(dest) == AMXC_VAR_ID_ANY) {
        var_json->parse_state = amxj_reader_start;
    } else {
        var_json->parse_state = amxj_reader_start_verify;
    }

    status = yajl_parse(var_json->parse,
                        (const unsigned char*) json_str,
                        amxc_string_text_length(&var_json->buffer));
    when_true(status != yajl_status_ok, exit);

    status = yajl_complete_parse(var_json->parse);
    var_json->parse_state = amxj_reader_done;
    when_true(status != yajl_status_ok, exit);

    retval = 0;

exit:
    amxc_lqueue_remove(&var_json->result_queue);

    amxc_lstack_clean(&var_json->var_stack, variant_list_it_free);
    amxc_lqueue_clean(&var_json->result_queue, variant_list_it_free);

    yajl_free(var_json->parse);
    var_json->parse = NULL;
    return retval;
}

int variant_json_convert_to(amxc_var_t* const dest,
                            const amxc_var_t* const src) {
    int retval = -1;
    if(amxc_var_type_of(dest) == AMXC_VAR_ID_JSON) {
        variant_json_t* src_var_json = (variant_json_t*) src->data.data;
        variant_json_t* dest_var_json = (variant_json_t*) dest->data.data;
        retval = amxc_string_set_at(&dest_var_json->buffer,
                                    0,
                                    amxc_string_get(&src_var_json->buffer, 0),
                                    amxc_string_text_length(&src_var_json->buffer),
                                    amxc_string_overwrite);
    } else if(amxc_var_type_of(dest) == AMXC_VAR_ID_CSTRING) {
        variant_json_t* src_var_json = (variant_json_t*) src->data.data;
        free(dest->data.s);
        amxc_string_trim(&src_var_json->buffer, NULL);
        if((src_var_json->buffer.buffer != NULL) && (src_var_json->buffer.buffer[0] == '"')) {
            retval = variant_json_convert_to_any(dest, src);
        } else {
            dest->data.s = strdup(amxc_string_get(&src_var_json->buffer, 0));
            retval = 0;
        }
    } else {
        retval = variant_json_convert_to_any(dest, src);
    }

//exit:
    return retval;
}

int amxj_reader_new(variant_json_t** reader) {
    int retval = -1;
    amxc_var_t* var = NULL;
    when_null(reader, exit);

    *reader = (variant_json_t*) calloc(1, sizeof(variant_json_t));
    when_null(*reader, exit);
    (*reader)->parse = yajl_alloc(&jayl_parse_cb, NULL, *reader);
    when_null((*reader)->parse, exit);
    when_failed(amxc_var_new(&var), exit);
    when_failed(amxc_lstack_push(&(*reader)->var_stack, &var->lit), exit);
    when_true(yajl_config((*reader)->parse, yajl_allow_multiple_values, 1) == 0, exit);
    (*reader)->parse_state = amxj_reader_start;

    retval = 0;

exit:
    if(retval != 0) {
        if(var != NULL) {
            amxc_var_delete(&var);
        }
        if((*reader != NULL) && ((*reader)->parse != NULL)) {
            yajl_free((*reader)->parse);
        }
        free(*reader);
        *reader = NULL;
    }
    return retval;
}

ssize_t amxj_read(variant_json_t* const reader, int fd) {
    static unsigned char buffer[AMXJ_READ_BUFFER_SIZE];
    ssize_t length = -1;
    yajl_status status = yajl_status_ok;
    when_null(reader, exit);

    when_true((reader->parse_state == amxj_reader_done) ||
              (reader->parse_state == amxj_reader_fail), exit);

    errno = 0;
    length = read(fd, buffer, AMXJ_READ_BUFFER_SIZE - 1);
    when_true(length < 0 && errno != EWOULDBLOCK, exit);

    if(errno == EWOULDBLOCK) {
        length = 0;
    } else if(length == 0) {
        reader->parse_state = amxj_reader_done;
    } else {
        buffer[length] = 0x00;
        status = yajl_parse(reader->parse, buffer, length);
    }

    if(status != yajl_status_ok) {
        memset(buffer, 0, AMXJ_READ_BUFFER_SIZE);
        length = -1;
        yajl_free(reader->parse);
        reader->parse = yajl_alloc(&jayl_parse_cb, NULL, reader);
        yajl_config(reader->parse, yajl_allow_multiple_values, 1);
        goto exit;
    }

exit:
    return length;
}

amxc_var_t* amxj_reader_result(variant_json_t* const reader) {
    amxc_var_t* var = NULL;

    amxc_llist_it_t* it = amxc_lqueue_remove(&reader->result_queue);
    if(it != NULL) {
        var = amxc_var_from_llist_it(it);
    }

    return var;
}

amxj_reader_state_t amxj_reader_get_state(const variant_json_t* const reader) {
    return reader == NULL ? amxj_reader_done : reader->parse_state;
}

void amxj_reader_delete(variant_json_t** reader) {
    when_null(reader, exit);
    when_null(*reader, exit);

    if(!amxc_lstack_is_empty(&(*reader)->var_stack)) {
        amxc_lstack_clean(&(*reader)->var_stack, variant_list_it_free);
    }

    if(!amxc_lqueue_is_empty(&(*reader)->result_queue)) {
        amxc_lqueue_clean(&(*reader)->result_queue, variant_list_it_free);
    }

    yajl_free((*reader)->parse);
    free(*reader);
    *reader = NULL;
exit:
    return;
}
