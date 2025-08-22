/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
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

#include "test_amxc_var_conversion_table.h"
#include <limits.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>
#include <amxc/amxc_macros.h>
#include <amxc/amxc_variant.h>
#include <sys/resource.h>
#include "../common/newvar.h"
#include "../common/test_common_util.h"

#define HIGHEST_TYPE_ID AMXC_VAR_ID_SSV_STRING

/** We're running out of space with a big table with long names, so use shorter names. */
static const char* s_name_of_type(int type) {
    // return amxc_var_get_type_name_from_id(type); // <-- for long names
    const char* names[] =
    {
        "null",
        "str ",
        "i8 ",
        "i16 ",
        "i32 ",
        "i64 ",
        "u8 ",
        "u16 ",
        "u32 ",
        "u64 ",
        "f32 ",
        "f64 ",
        "bool",
        "list",
        "htable",
        "fd ",
        "ts  ",
        "csv ",
        "ssv "
    };
    assert_true(type >= 0);
    assert_true((size_t) type < ARRAY_SIZE(names));
    return names[type];
}

/**
 * Create variant values that are used to try to convert to different types.
 *
 * Since we detect whether converting and converting back yields the same value, the values
 * returned by this function are crafted to be not easy to convert back.
 * For example: "on" instead of "true", since "on" (string) converts to true (bool) converts to "true" which
 * is not equal to "on".
 *
 * It is not necessary to add values that can be obtained by converting values from this list,
 * because that is done automatically.
 *
 * @return A list of values. Each elemetn in this list is a value that will be attempted to
 *   convert to other types.
 */
static amxc_var_t* s_create_sample_variants() {

    struct rlimit nofile = { 0, 1048576 };
    getrlimit(RLIMIT_NOFILE, &nofile);

    amxc_var_t* values = newvar_list((amxc_var_t*[]) {
        newvar_null(),
        newvar_bool(true), newvar_cstring_t("on"),
        newvar_int8_t(-128), newvar_cstring_t(" -128"),
        newvar_int16_t(-32768), newvar_cstring_t(" -32768"),
        newvar_int32_t(-2147483648), newvar_cstring_t(" -2147483648"),
        newvar_int64_t(INT64_MIN), newvar_cstring_t(" -9223372036854775807"),
        newvar_uint8_t(255), newvar_cstring_t(" 255"),
        newvar_uint16_t(65535), newvar_cstring_t(" 65535"),
        newvar_uint32_t(4294967295), newvar_cstring_t(" 4294967295"),
        newvar_uint64_t(18446744073709551615ULL), newvar_cstring_t(" 18446744073709551615"),
        newvar_double(1.18973149535723176502e+4932L),
        newvar_double(1E50),
        newvar_double(-1),
        newvar_double(1),
        newvar_double(0),
        newvar_list((amxc_var_t*[]) {NULL}),
        // {"mykey", <NULL>} cannot be converted to string, so one would expect that
        //   [{"mykey", <NULL>}] also cannot, but it can. So it's not needed to be included here,
        //   but let's keep it for clarity.
        newvar_list((amxc_var_t*[]) {
            newvar_htable((newvar_kv_t*[]) {
                &(newvar_kv_t) { "mykey", newvar_null()},
                NULL
            }),
            NULL,
        }),
        newvar_list((amxc_var_t*[]) {newvar_null(), NULL}),
        newvar_cstring_t("2020-01-02T03:04:05.6+07:08"),
        newvar_cstring_t("1970-01-01T00:00:00Z"),
        newvar_fd_t(nofile.rlim_max),
        newvar_fd_t(0),
        NULL
    });

    // Add the list to itself as a sublist
    amxc_var_t* list_value = NULL;
    amxc_var_new(&list_value);
    amxc_var_copy(list_value, values);
    amxc_var_t* list_value_entry = amxc_var_add_new(values);
    amxc_var_move(list_value_entry, list_value);
    amxc_var_delete(&list_value);

    // Add to the list a sublist with more than 255 values
    list_value_entry = amxc_var_add_new(values);
    amxc_var_set_type(list_value_entry, AMXC_VAR_ID_LIST);
    for(int i = 0; i < 257; i++) {
        amxc_var_add(int8_t, list_value_entry, 1);
    }

    return values;
}

/**
 * Add to given list of variants, all variants that can be obtained by converting a value of
 * the given list to another type.
 *
 * This is not done recursively, after converting X to Y, this function does not attempt to
 * convert Y to Z.
 */
static void s_extend_sample_variants(amxc_var_t* sample_variants) {
    amxc_var_t extension_sample_variants;
    amxc_var_init(&extension_sample_variants);
    amxc_var_set_type(&extension_sample_variants, AMXC_VAR_ID_LIST);
    for(amxc_var_type_id_t type_id = 0; type_id <= HIGHEST_TYPE_ID; type_id++) {
        amxc_var_for_each(sample_variant, sample_variants) {
            amxc_var_t* dest = NULL;
            amxc_var_new(&dest);
            amxc_var_init(dest);
            amxc_var_set_type(dest, type_id);
            int status = amxc_var_convert(dest, sample_variant, type_id);
            if(status == 0) {
                assert_int_equal(amxc_var_type_of(dest), type_id);
                amxc_var_t* dest_in_list = amxc_var_add_new(&extension_sample_variants);
                amxc_var_move(dest_in_list, dest);
            }
            amxc_var_delete(&dest);
        }
    }

    amxc_var_add_value(sample_variants, &extension_sample_variants);
    amxc_var_clean(&extension_sample_variants);
}

/**
 * Does nothing.
 *
 * Used to workaround that we cannot put brakepoints on empty lines,
 * so we can put it on a `s_no_op();` line.
 */
static void s_no_op(void) {
}

static void s_write_entry(int nb_fail, int nb_unidir, int nb_bidir, amxc_string_t* append_to) {
    if((nb_fail == 0) && (nb_bidir == 0) && (nb_unidir == 0)) {
        amxc_string_appendf(append_to, "?");
    } else if((nb_fail == 0) && ((nb_bidir > 0) || (nb_unidir > 0))) {
        amxc_string_appendf(append_to, "✅");
    } else if((nb_fail > 0) && ((nb_bidir > 0) || (nb_unidir > 0))) {
        amxc_string_appendf(append_to, "🟠");
    } else if((nb_fail > 0) && ((nb_bidir == 0) && (nb_unidir == 0))) {
        amxc_string_appendf(append_to, "⛔");
    }
    if(nb_unidir > 0) {
        amxc_string_appendf(append_to, "!  ");
    } else {
        amxc_string_appendf(append_to, "   ");
    }

}


static void s_construct_and_write_entry(amxc_var_type_id_t from, amxc_var_type_id_t to, amxc_var_t* sample_variants, amxc_string_t* append_to) {
    int nb_fail = 0;
    amxc_var_t fail_source;
    int nb_unidir = 0;
    int nb_bidir = 0;
    amxc_var_init(&fail_source);
    amxc_var_for_each(sample, sample_variants) {
        amxc_var_t dest_forth;
        amxc_var_t dest_back;
        int status_forth = -1;
        int status_back = -1;
        bool debug = false;
        if(amxc_var_type_of(sample) != from) {
            continue;
        }

        // debug = from == AMXC_VAR_ID_LIST && to == AMXC_VAR_ID_INT8;
        if(debug) {
            s_no_op();      // <-- possibility to put breakpoint.
        }

        amxc_var_init(&dest_back);
        amxc_var_init(&dest_forth);
        amxc_var_set_type(&dest_forth, to);
        amxc_var_set_type(&dest_back, from);
        status_forth = amxc_var_convert(&dest_forth, sample, to);
        status_back = amxc_var_convert(&dest_back, &dest_forth, from);
        bool equal = test_common_util_equals(&dest_back, sample);

        if(debug) {
            amxc_var_dump(sample, 0);
            amxc_var_dump(&dest_forth, 0);
            amxc_var_dump(&dest_back, 0);
            printf("-----\n");
        }

        if((status_forth == 0) && (status_back == 0) && equal) {
            nb_bidir++;
        } else if(status_forth == 0) {
            nb_unidir++;
        } else {
            nb_fail++;
        }
        amxc_var_clean(&dest_forth);
        amxc_var_clean(&dest_back);
    }

    s_write_entry(nb_fail, nb_unidir, nb_bidir, append_to);
}

void test_amxc_var_conversion_table(UNUSED void** state) {
    amxc_var_t* samples = s_create_sample_variants();
    s_extend_sample_variants(samples);

    amxc_string_t str;
    amxc_string_init(&str, 1024);

    // Build header
    amxc_string_appendf(&str, "%s", "<!-- THE TABLE BELOW IS AUTOGENERATED by " __FILE__ " - please do not edit by hand -->\n");
    amxc_string_appendf(&str, "%s", "|↓to→|");
    for(int to = 0; to <= HIGHEST_TYPE_ID; to++) {
        amxc_string_appendf(&str, "%s|", s_name_of_type(to));
    }
    amxc_string_appendf(&str, "%s", "\n");

    // build header separator "|---|---|---|"
    amxc_string_appendf(&str, "%s", "|----|");
    for(int to = 0; to <= HIGHEST_TYPE_ID; to++) {
        amxc_string_appendf(&str, "----|");
    }
    amxc_string_appendf(&str, "%s", "\n");

    // build all rows
    for(amxc_var_type_id_t from = 0; from <= HIGHEST_TYPE_ID; from++) {
        // build one row "|CSTRING   |    |✅  |    |"
        amxc_string_appendf(&str, "|%s|", s_name_of_type(from));
        for(int to = 0; to <= HIGHEST_TYPE_ID; to++) {
            s_construct_and_write_entry(from, to, samples, &str);
            amxc_string_appendf(&str, "|");
        }
        amxc_string_appendf(&str, "%s", "\n");
    }

    // build footer
    amxc_string_appendf(&str, "%s", "<!-- THE TABLE ABOVE IS AUTOGENERATED by " __FILE__ " - please do not edit by hand -->\n");

    printf("The table below can be put in varant.md documentation:\n\n%s\n", amxc_string_get(&str, 0));

    amxc_string_clean(&str);
    amxc_var_delete(&samples);
}
