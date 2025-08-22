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

#include <sys/resource.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <math.h>

#include <amxc_variant_priv.h>

static int variant_double_to_string(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;
    int check = 0;
    int size_needed = snprintf(NULL, 0, "%f", src->data.d);
    dest->data.s = (char*) calloc(size_needed + 1, sizeof(char));

    when_null(dest->data.s, exit);

    check = snprintf(dest->data.s, size_needed + 1, "%f", src->data.d);
    if(check < 0) {
        free(dest->data.s);
        dest->data.s = NULL;
        goto exit;
    }

    retval = 0;

exit:
    return retval;
}

static int variant_double_to_int8(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(src->data.d > INT8_MAX || src->data.d < INT8_MIN, exit);

    dest->data.i8 = (int8_t) src->data.d;
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_int16(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(src->data.d > INT16_MAX || src->data.d < INT16_MIN, exit);

    dest->data.i16 = (int16_t) src->data.d;
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_int32(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(src->data.d > INT32_MAX || src->data.d < INT32_MIN, exit);

    dest->data.i32 = (int32_t) src->data.d;
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_int64(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(src->data.d > INT64_MAX || src->data.d < INT64_MIN, exit);

    dest->data.i64 = (int64_t) src->data.d;
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_uint8(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(fabs(src->data.d) > UINT8_MAX, exit);

    dest->data.ui8 = (uint8_t) fabs(src->data.d);
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_uint16(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(fabs(src->data.d) > UINT16_MAX, exit);

    dest->data.ui16 = (uint16_t) fabs(src->data.d);
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_uint32(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(fabs(src->data.d) > UINT32_MAX, exit);

    dest->data.ui32 = (uint32_t) fabs(src->data.d);
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_uint64(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;

    /* verify overflow or underflow */
    when_true(fabs(src->data.d) > UINT64_MAX, exit);

    dest->data.ui64 = (uint64_t) fabs(src->data.d);
    retval = 0;

exit:
    return retval;
}

static int variant_double_to_float(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    dest->data.f = (float) src->data.d;

    retval = 0;

    return retval;
}

static int variant_double_to_bool(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    int retval = -1;

    dest->data.b = src->data.d == 0 ? false : true;

    retval = 0;

    return retval;
}

static int variant_double_convert_to(amxc_var_t* const dest,
                                     const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,
        variant_double_to_string,
        variant_double_to_int8,
        variant_double_to_int16,
        variant_double_to_int32,
        variant_double_to_int64,
        variant_double_to_uint8,
        variant_double_to_uint16,
        variant_double_to_uint32,
        variant_double_to_uint64,
        variant_double_to_float,
        amxc_var_default_copy,
        variant_double_to_bool,
        amxc_var_default_convert_to_list,
        amxc_var_default_convert_to_htable,
        NULL,
        NULL,
        variant_double_to_string,
        variant_double_to_string,
        amxc_var_default_copy,
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        if(dest->type_id == AMXC_VAR_ID_ANY) {
            amxc_var_set_type(dest, AMXC_VAR_ID_DOUBLE);
        }
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static int variant_double_compare(const amxc_var_t* const lval,
                                  const amxc_var_t* const rval,
                                  int* const result) {
    if(lval->data.d == rval->data.d) {
        *result = 0;
    } else if(lval->data.d > rval->data.d) {
        *result = 1;
    } else {
        *result = -1;
    }
    return 0;
}

static int variant_double_add_value(amxc_var_t* const dest,
                                    const amxc_var_t* const value) {
    int retval = -1;
    when_false(dest != NULL
               && value != NULL
               && value->type_id == AMXC_VAR_ID_DOUBLE
               && dest->type_id == dest->type_id,
               exit);

    dest->data.d += value->data.d;
    retval = 0;

exit:
    return retval;
}

static amxc_var_type_t amxc_variant_double = {
    .init = NULL,
    .del = NULL,
    .copy = amxc_var_default_copy,
    .move = amxc_var_default_move,
    .convert_from = NULL,
    .convert_to = variant_double_convert_to,
    .compare = variant_double_compare,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = variant_double_add_value,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_DOUBLE
};

CONSTRUCTOR static void amxc_var_double_init(void) {
    amxc_var_add_type(&amxc_variant_double, AMXC_VAR_ID_DOUBLE);
}

DESTRUCTOR static void amxc_var_double_cleanup(void) {
    amxc_var_remove_type(&amxc_variant_double);
}

int amxc_var_set_double(amxc_var_t* var, double val) {
    int retval = -1;
    when_null(var, exit);

    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_DOUBLE), exit);

    var->data.d = val;
    retval = 0;

exit:
    return retval;
}

double amxc_var_get_double(const amxc_var_t* var) {
    double retval = 0;
    amxc_var_t variant;

    when_null(var, exit);

    amxc_var_init(&variant);
    when_failed(amxc_var_convert(&variant, var, AMXC_VAR_ID_DOUBLE), exit);
    retval = variant.data.d;
    amxc_var_clean(&variant);

exit:
    return retval;
}

double amxc_var_get_const_double(const amxc_var_t* const var) {
    double retval = 0;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_DOUBLE, exit);

    retval = var->data.d;

exit:
    return retval;
}

amxc_var_t* amxc_var_add_new_double(amxc_var_t* const var, double val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    if(amxc_var_set_double(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_double(amxc_var_t* const var, const char* key, double val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    if(amxc_var_set_double(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}