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
#include <fcntl.h>

#include <yajl/yajl_gen.h>

#include <amxc/amxc_variant_type.h>
#include <amxc/amxc_string.h>

#include <amxj/amxj_variant.h>
#include "variant_json_priv.h"

static size_t buffer_size = 16384;

typedef int (* amxj_convert_fn_t) (variant_json_t* const dest_var_json,
                                   const amxc_var_t* const src);

static int variant_json_convert_from_impl(variant_json_t* const dest_var_json,
                                          const amxc_var_t* const src);


static int variant_json_flush_buffer(variant_json_t* var_json) {
    int retval = 0;
    const char* buf = amxc_string_get(&var_json->buffer, 0);
    size_t length = amxc_string_text_length(&var_json->buffer);

    retval = write(var_json->fd, buf, length);

    amxc_string_reset(&var_json->buffer);
    return retval;
}

static void variant_json_print(void* ctx, const char* str, size_t len) {
    variant_json_t* var_json = (variant_json_t*) ctx;

    var_json->length += len;
    amxc_string_append(&var_json->buffer, str, len);
    if(amxc_string_text_length(&var_json->buffer) > buffer_size) {
        variant_json_flush_buffer(var_json);
    }
}

static int variant_json_from_null(variant_json_t* const dest_var_json,
                                  UNUSED const amxc_var_t* const src) {
    int retval = -1;
    when_true(yajl_gen_null(dest_var_json->gen) != yajl_gen_status_ok, exit);
    retval = 0;

exit:
    return retval;
}

static int variant_json_from_string(variant_json_t* const dest_var_json,
                                    const amxc_var_t* const src) {
    int retval = -1;
    if(src->data.s != NULL) {
        int length = strlen(src->data.s);
        when_true(yajl_gen_string(dest_var_json->gen,
                                  (unsigned char*) src->data.s, length) != yajl_gen_status_ok,
                  exit);
    } else {
        when_true(yajl_gen_string(dest_var_json->gen,
                                  (unsigned const char*) "", 0) != yajl_gen_status_ok,
                  exit);
    }
    retval = 0;

exit:
    return retval;
}

static int variant_json_from_number(variant_json_t* const dest_var_json,
                                    const amxc_var_t* const src) {
    int retval = -1;
    char* text = amxc_var_dyncast(cstring_t, src);
    int length = 0;

    when_null(text, exit);
    length = strlen(text);

    when_true(yajl_gen_number(dest_var_json->gen,
                              text,
                              length) != yajl_gen_status_ok,
              exit);
    retval = 0;

exit:
    free(text);
    return retval;
}

static int variant_json_from_bool(variant_json_t* const dest_var_json,
                                  const amxc_var_t* const src) {
    int retval = -1;
    when_true(yajl_gen_bool(dest_var_json->gen,
                            src->data.b) != yajl_gen_status_ok,
              exit);
    retval = 0;

exit:
    return retval;
}

static int variant_json_from_llist(variant_json_t* const dest_var_json,
                                   const amxc_var_t* const src) {
    int retval = -1;
    const amxc_llist_t* list = &src->data.vl;

    when_true(yajl_gen_array_open(dest_var_json->gen) != yajl_gen_status_ok,
              exit);
    amxc_llist_for_each(it, list) {
        amxc_var_t* item = amxc_var_from_llist_it(it);

        when_failed(variant_json_convert_from_impl(dest_var_json, item), exit);
    }
    when_true(yajl_gen_array_close(dest_var_json->gen) != yajl_gen_status_ok,
              exit);

    retval = 0;

exit:
    return retval;
}

static int variant_json_from_htable(variant_json_t* const dest_var_json,
                                    const amxc_var_t* const src) {
    int retval = -1;
    const amxc_htable_t* htable = &src->data.vm;

    when_true(yajl_gen_map_open(dest_var_json->gen) != yajl_gen_status_ok,
              exit);
    amxc_htable_for_each(it, htable) {
        const char* key = (const char*) amxc_htable_it_get_key(it);
        amxc_var_t* item = amxc_var_from_htable_it(it);
        int length = strlen(key);
        when_true(yajl_gen_string(dest_var_json->gen,
                                  (const unsigned char*) key, length) != yajl_gen_status_ok,
                  exit);

        when_failed(variant_json_convert_from_impl(dest_var_json, item), exit);
    }
    when_true(yajl_gen_map_close(dest_var_json->gen) != yajl_gen_status_ok,
              exit);

    retval = 0;

exit:
    return retval;
}

static int variant_json_from_ts(variant_json_t* const dest_var_json,
                                const amxc_var_t* const src) {
    int retval = -1;
    char ts_str[40];
    int length = 0;
    amxc_ts_format(&src->data.ts, ts_str, 40);
    length = strlen(ts_str);
    when_true(yajl_gen_string(dest_var_json->gen,
                              (unsigned char*) ts_str, length) != yajl_gen_status_ok,
              exit);
    retval = 0;

exit:
    return retval;
}

static int variant_json_convert_from_any(variant_json_t* const dest_var_json,
                                         const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_convert(&var, src, AMXC_VAR_ID_ANY);
    retval = variant_json_convert_from_impl(dest_var_json, &var);
    amxc_var_clean(&var);
    return retval;
}

static int variant_json_convert_from_custom(variant_json_t* const dest_var_json,
                                            const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t var;
    amxc_var_type_t* src_type = amxc_var_get_type(src->type_id);
    when_null(src_type, exit);
    when_null(src_type->convert_to, exit);

    amxc_var_init(&var);
    var.type_id = AMXC_VAR_ID_JSON;
    var.data.data = dest_var_json;
    retval = src_type->convert_to(&var, src);
    var.data.data = NULL;
    amxc_var_clean(&var);

exit:
    return retval;
}

static int variant_json_convert_from_impl(variant_json_t* const dest_var_json,
                                          const amxc_var_t* const src) {
    int retval = -1;
    uint32_t src_type = amxc_var_type_of(src);

    amxj_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        variant_json_from_null,   // null type
        variant_json_from_string, // cstring type
        variant_json_from_number, // int8 type
        variant_json_from_number, // int16 type
        variant_json_from_number, // int32 type
        variant_json_from_number, // int64 type
        variant_json_from_number, // uint8 type
        variant_json_from_number, // uint16 type
        variant_json_from_number, // uint32 type
        variant_json_from_number, // uint64 type
        variant_json_from_number, // float type
        variant_json_from_number, // double type
        variant_json_from_bool,   // bool type
        variant_json_from_llist,  // linked list type (array)
        variant_json_from_htable, // htable type (object)
        NULL,                     // File descriptor type
        variant_json_from_ts,     // Timestamp
        variant_json_from_string, // csv_string type
        variant_json_from_string, // ssv_string type
        NULL,                     // any
    };

    if(src_type == AMXC_VAR_ID_JSON) {
        retval = variant_json_convert_from_any(dest_var_json, src);
    } else if(src_type >= AMXC_VAR_ID_CUSTOM_BASE) {
        retval = variant_json_convert_from_custom(dest_var_json, src);
    } else {
        if(convfn[src_type] != NULL) {
            retval = convfn[src_type](dest_var_json, src);
        }
    }

    return retval;
}

int variant_json_convert_from(amxc_var_t* const dest,
                              const amxc_var_t* const src) {
    // destination variant is a jstring_t
    // source variant is something else
    int retval = -1;
    variant_json_t* dest_var_json = (variant_json_t*) dest->data.data;

    when_true(src->type_id >= AMXC_VAR_ID_CUSTOM_BASE, exit);

    retval = variant_json_convert_from_impl(dest_var_json, src);

exit:
    return retval;
}

yajl_gen amxj_get_json_gen(const amxc_var_t* const jvar) {
    yajl_gen handle = NULL;
    variant_json_t* json = NULL;
    when_null(jvar, exit);
    when_true(amxc_var_type_of(jvar) != AMXC_VAR_ID_JSON, exit);
    when_null(jvar->data.data, exit);
    json = (variant_json_t*) jvar->data.data;
    when_null(json->gen, exit);
    handle = json->gen;

exit:
    return handle;
}

int amxj_writer_new(variant_json_t** writer, const amxc_var_t* const var) {
    int retval = -1;
    when_null(writer, exit);
    when_null(var, exit);

    *writer = (variant_json_t*) calloc(1, sizeof(variant_json_t));
    when_null(*writer, exit);
    (*writer)->gen = yajl_gen_alloc(NULL);
    when_null((*writer)->gen, exit);
    amxc_string_init(&(*writer)->buffer, buffer_size);

    yajl_gen_config((*writer)->gen, yajl_gen_beautify, 1);
    yajl_gen_config((*writer)->gen, yajl_gen_validate_utf8, 1);
    yajl_gen_config((*writer)->gen,
                    yajl_gen_print_callback,
                    variant_json_print,
                    *writer);

    (*writer)->var = var;

    retval = 0;

exit:
    if((retval != 0) && (writer != NULL)) {
        if((*writer != NULL) && ((*writer)->gen != NULL)) {
            yajl_gen_free((*writer)->gen);
        }
        free(*writer);
        *writer = NULL;
    }
    return retval;
}

ssize_t amxj_write(variant_json_t* const writer, int fd) {
    ssize_t retval = 0;
    when_null(writer, exit);

    writer->fd = fd;

    variant_json_convert_from_impl(writer, writer->var);

    variant_json_flush_buffer(writer);
    retval = writer->length;

exit:
    return retval;
}

void amxj_writer_delete(variant_json_t** writer) {
    when_null(writer, exit);
    when_null(*writer, exit);

    if(*writer) {
        amxc_string_clean(&(*writer)->buffer);
        if((*writer)->gen) {
            yajl_gen_free((*writer)->gen);
        }
        (*writer)->gen = NULL;
    }
    free(*writer);
    *writer = NULL;

exit:
    return;
}
