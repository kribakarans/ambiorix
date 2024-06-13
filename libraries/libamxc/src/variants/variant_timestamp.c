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

#include <amxc_variant_priv.h>

static int variant_ts_init(amxc_var_t* const var) {
    return amxc_ts_parse(&var->data.ts, "0001-01-01T00:00:00Z", 20);
}


static int variant_ts_to_string(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    int retval = -1;
    dest->data.s = (char*) calloc(40, sizeof(char));

    when_null(dest->data.s, exit);

    retval = amxc_ts_format(&src->data.ts, dest->data.s, 40);
    retval = retval != 0 ? 0 : -1;

exit:
    return retval;
}

static int variant_ts_to_int(amxc_var_t* const dest,
                             const amxc_var_t* const src) {
    dest->data.i64 = src->data.ts.sec;
    return 0;
}

static int variant_ts_to_double(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    dest->data.d = src->data.ts.sec + src->data.ts.nsec / 1000000000;
    return 0;
}

static int variant_ts_convert_to(amxc_var_t* const dest,
                                 const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,       // NULL
        variant_ts_to_string,                   // cstring_t
        NULL,                                   // int8_t
        NULL,                                   // int16_t
        NULL,                                   // int32_t
        variant_ts_to_int,                      // int64_t
        NULL,                                   // uint8_t
        NULL,                                   // uint16_t
        NULL,                                   // uint32_t
        NULL,                                   // uint64_t
        NULL,                                   // float
        variant_ts_to_double,                   // double
        NULL,                                   // bool
        amxc_var_default_convert_to_list,       // amxc_llist_t
        amxc_var_default_convert_to_htable,     // amxc_htable_t
        NULL,                                   // fd_t
        amxc_var_default_copy,                  // amxc_ts_t
        variant_ts_to_string,                   // csvstring_t
        variant_ts_to_string,                   // ssvstring_t
        amxc_var_default_copy,                  // any
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        if(dest->type_id == AMXC_VAR_ID_ANY) {
            amxc_var_set_type(dest, AMXC_VAR_ID_TIMESTAMP);
        }
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static int variant_ts_compare(const amxc_var_t* const lval,
                              const amxc_var_t* const rval,
                              int* const result) {
    *result = amxc_ts_compare(&lval->data.ts, &rval->data.ts);

    return 0;
}

static amxc_var_type_t amxc_variant_ts = {
    .init = variant_ts_init,
    .del = NULL,
    .copy = amxc_var_default_copy,
    .move = amxc_var_default_move,
    .convert_from = NULL,
    .convert_to = variant_ts_convert_to,
    .compare = variant_ts_compare,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = NULL,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_TIMESTAMP
};

CONSTRUCTOR static void amxc_var_ts_init(void) {
    amxc_var_add_type(&amxc_variant_ts, AMXC_VAR_ID_TIMESTAMP);
}

DESTRUCTOR static void amxc_var_ts_cleanup(void) {
    amxc_var_remove_type(&amxc_variant_ts);
}

int amxc_var_set_amxc_ts_t(amxc_var_t* var, amxc_ts_t* ts) {
    int retval = -1;
    when_null(var, exit);
    when_null(ts, exit);

    amxc_var_set_type(var, AMXC_VAR_ID_TIMESTAMP);

    var->data.ts.sec = ts->sec;
    var->data.ts.nsec = ts->nsec;
    var->data.ts.offset = ts->offset;

    retval = 0;

exit:
    return retval;
}

amxc_ts_t* amxc_var_get_amxc_ts_t(const amxc_var_t* var) {
    amxc_ts_t* ts = NULL;
    amxc_var_t variant;
    when_null(var, exit);

    amxc_var_init(&variant);
    when_failed(amxc_var_convert(&variant, var, AMXC_VAR_ID_TIMESTAMP), exit);
    ts = (amxc_ts_t*) calloc(1, sizeof(amxc_ts_t));
    when_null(ts, exit);

    ts->sec = variant.data.ts.sec;
    ts->nsec = variant.data.ts.nsec;
    ts->offset = variant.data.ts.offset;

    amxc_var_clean(&variant);

exit:
    return ts;
}

const amxc_ts_t* amxc_var_get_const_amxc_ts_t(const amxc_var_t* const var) {
    const amxc_ts_t* retval = NULL;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_TIMESTAMP, exit);

    retval = &var->data.ts;

exit:
    return retval;
}

amxc_var_t* amxc_var_add_new_amxc_ts_t(amxc_var_t* const var, amxc_ts_t* ts) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    if(ts == NULL) {
        amxc_var_set_type(subvar, AMXC_VAR_ID_TIMESTAMP);
    } else {
        if(amxc_var_set_amxc_ts_t(subvar, ts) != 0) {
            amxc_var_delete(&subvar);
        }
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_amxc_ts_t(amxc_var_t* const var,
                                           const char* key,
                                           amxc_ts_t* ts) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    if(ts == NULL) {
        amxc_var_set_type(subvar, AMXC_VAR_ID_TIMESTAMP);
    } else {
        if(amxc_var_set_amxc_ts_t(subvar, ts) != 0) {
            amxc_var_delete(&subvar);
        }
    }

exit:
    return subvar;
}