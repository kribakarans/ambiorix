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

#include "test_amxc_var_convert.h"
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


typedef struct {
    amxc_var_t* from;
    amxc_var_type_id_t to_type;
    amxc_var_t* expected_to;
} conversion_test_t;

static void s_assert_conversions(conversion_test_t* conversions, size_t conversions_size) {
    for(size_t i = 0; i < conversions_size; i++) {
        int convert_status = -1;
        amxc_var_t dest;
        amxc_var_init(&dest);
        amxc_var_set_type(&dest, conversions[i].to_type);
        convert_status = amxc_var_convert(&dest, conversions[i].from, conversions[i].to_type);
        bool ok =
            conversions[i].expected_to == NULL ? convert_status != 0
            : convert_status == 0 && test_common_util_equals(&dest, conversions[i].expected_to);
        if(!ok) {
            amxc_var_dump(conversions[i].from, 0);
            amxc_var_dump(conversions[i].expected_to, 0);
            amxc_var_dump(&dest, 0);
            fail_msg("Conversion not as expected. from_type=%d, to_type=%d, convert_status=%d",
                     amxc_var_type_of(conversions[i].from),
                     conversions[i].to_type,
                     convert_status);
        }
        amxc_var_clean(&dest);
    }
}

static void s_clean_conversions(conversion_test_t* conversions, size_t conversions_size) {
    for(size_t i = 0; i < conversions_size; i++) {
        amxc_var_delete(&conversions[i].from);
        amxc_var_delete(&conversions[i].expected_to);
    }
}

void test_amxc_var_convert__between_signedness(UNUSED void** state) {
    conversion_test_t conversions[] = {
        // Signed to unsigned: 8bit
        { newvar_int8_t(10), AMXC_VAR_ID_UINT8, newvar_uint8_t(10) },
        { newvar_int8_t(-10), AMXC_VAR_ID_UINT8, newvar_uint8_t(10) },
        { newvar_int8_t(0), AMXC_VAR_ID_UINT8, newvar_uint8_t(0) },
        { newvar_int8_t(-128), AMXC_VAR_ID_UINT8, newvar_uint8_t(128) },
        { newvar_int8_t(127), AMXC_VAR_ID_UINT8, newvar_uint8_t(127) },

        // Signed to unsigned: 16bit
        { newvar_int16_t(10), AMXC_VAR_ID_UINT16, newvar_uint16_t(10) },
        { newvar_int16_t(-10), AMXC_VAR_ID_UINT16, newvar_uint16_t(10) },
        { newvar_int16_t(0), AMXC_VAR_ID_UINT16, newvar_uint16_t(0) },
        { newvar_int16_t(-32768), AMXC_VAR_ID_UINT16, newvar_uint16_t(32768) },
        { newvar_int16_t(32767), AMXC_VAR_ID_UINT16, newvar_uint16_t(32767) },

        // Signed to unsigned: 32bit
        { newvar_int32_t(10), AMXC_VAR_ID_UINT32, newvar_uint32_t(10) },
        { newvar_int32_t(-10), AMXC_VAR_ID_UINT32, newvar_uint32_t(10) },
        { newvar_int32_t(0), AMXC_VAR_ID_UINT32, newvar_uint32_t(0) },
        { newvar_int32_t(-2147483648), AMXC_VAR_ID_UINT32, newvar_uint32_t(2147483648) },
        { newvar_int32_t(2147483647), AMXC_VAR_ID_UINT32, newvar_uint32_t(2147483647) },

        // Signed to unsigned: 64bit
        { newvar_int64_t(10), AMXC_VAR_ID_UINT64, newvar_uint64_t(10) },
        { newvar_int64_t(-10), AMXC_VAR_ID_UINT64, newvar_uint64_t(10) },
        { newvar_int64_t(0), AMXC_VAR_ID_UINT64, newvar_uint64_t(0) },
        { newvar_int64_t(INT64_MIN), AMXC_VAR_ID_UINT64, newvar_uint64_t(9223372036854775808ULL) },
        { newvar_int64_t(9223372036854775807), AMXC_VAR_ID_UINT64, newvar_uint64_t(9223372036854775807ULL) },

        // Unsigned to signed: 8 bit
        { newvar_uint8_t(0), AMXC_VAR_ID_INT8, newvar_int8_t(0) },
        { newvar_uint8_t(10), AMXC_VAR_ID_INT8, newvar_int8_t(10) },
        { newvar_uint8_t(127), AMXC_VAR_ID_INT8, newvar_int8_t(127) },
        { newvar_uint8_t(128), AMXC_VAR_ID_INT8, NULL },
        { newvar_uint8_t(255), AMXC_VAR_ID_INT8, NULL },

        // Unsigned to signed: 16 bit
        { newvar_uint16_t(0), AMXC_VAR_ID_INT16, newvar_int16_t(0) },
        { newvar_uint16_t(10), AMXC_VAR_ID_INT16, newvar_int16_t(10) },
        { newvar_uint16_t(32767), AMXC_VAR_ID_INT16, newvar_int16_t(32767) },
        { newvar_uint16_t(32768), AMXC_VAR_ID_INT16, NULL },
        { newvar_uint16_t(65535), AMXC_VAR_ID_INT16, NULL },

        // Unsigned to signed: 32 bit
        { newvar_uint32_t(0), AMXC_VAR_ID_INT32, newvar_int32_t(0) },
        { newvar_uint32_t(10), AMXC_VAR_ID_INT32, newvar_int32_t(10) },
        { newvar_uint32_t(2147483647), AMXC_VAR_ID_INT32, newvar_int32_t(2147483647) },
        { newvar_uint32_t(2147483648), AMXC_VAR_ID_INT32, NULL },
        { newvar_uint32_t(4294967295), AMXC_VAR_ID_INT32, NULL },

        // Unsigned to signed: 64 bit
        { newvar_uint64_t(0), AMXC_VAR_ID_INT64, newvar_int64_t(0) },
        { newvar_uint64_t(10), AMXC_VAR_ID_INT64, newvar_int64_t(10) },
        { newvar_uint64_t(9223372036854775807ULL), AMXC_VAR_ID_INT64, newvar_int64_t(9223372036854775807LL) },
        { newvar_uint64_t(9223372036854775808ULL), AMXC_VAR_ID_INT64, NULL },
        { newvar_uint64_t(UINT64_MAX), AMXC_VAR_ID_INT64, NULL },
    };

    s_assert_conversions(conversions, ARRAY_SIZE(conversions));
    s_clean_conversions(conversions, ARRAY_SIZE(conversions));
}

void test_amxc_var_convert__noteworthy_cases(UNUSED void** state) {
    conversion_test_t conversions[] = {

        // A htable with a NULL value cannot be converted to string:
        {
            .from = newvar_htable((newvar_kv_t*[]) {
                &(newvar_kv_t) { "mykey", newvar_null()},
                NULL
            }),
            .to_type = AMXC_VAR_ID_CSTRING,
            .expected_to = NULL,
        },

        // A list can always be converted to a string, even if it contains a value
        //   that cannot be converted to a string.
        {
            .from = newvar_list((amxc_var_t*[]) {
                newvar_htable((newvar_kv_t*[]) {
                    &(newvar_kv_t) { "mykey", newvar_null()},
                    NULL
                }),
                NULL,
            }),
            .to_type = AMXC_VAR_ID_CSTRING,
            .expected_to = newvar_cstring_t("(null)")
        },

        // Given a list containing an empty string. The csv representation for this is "".
        // However, "" is also the representation for the empty list.
        // So when going from the list containing the empty string to a csv, and the going back to a list,
        // we don't get the same list back.
        // This is also not solved by https://data-model-template.broadband-forum.org/#sec:comma-separated-lists
        { newvar_list((amxc_var_t*[]) {newvar_cstring_t(""), NULL}), AMXC_VAR_ID_CSTRING, newvar_csv_string_t("") },
        { newvar_csv_string_t(""), AMXC_VAR_ID_LIST, newvar_list((amxc_var_t*[]) { NULL}), },
    };

    s_assert_conversions(conversions, ARRAY_SIZE(conversions));
    s_clean_conversions(conversions, ARRAY_SIZE(conversions));
}