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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "test_variant_json.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_variant_json_init),
        cmocka_unit_test(test_variant_json_copy),
        cmocka_unit_test(test_variant_json_move),
        cmocka_unit_test(test_variant_json_from_null),
        cmocka_unit_test(test_variant_json_from_string),
        cmocka_unit_test(test_variant_json_from_number),
        cmocka_unit_test(test_variant_json_from_bool),
        cmocka_unit_test(test_variant_json_from_ts),
        cmocka_unit_test(test_variant_json_from_llist),
        cmocka_unit_test(test_variant_json_from_htable),
        cmocka_unit_test(test_variant_json_from_jstring),
        cmocka_unit_test(test_variant_json_set_get),
        cmocka_unit_test(test_variant_json_convert_to_htable),
        cmocka_unit_test(test_variant_json_convert_to_list),
        cmocka_unit_test(test_variant_json_convert_to_null),
        cmocka_unit_test(test_variant_json_convert_to_bool),
        cmocka_unit_test(test_variant_json_convert_to_number),
        cmocka_unit_test(test_variant_json_convert_to_double),
        cmocka_unit_test(test_variant_json_convert_to_string),
        cmocka_unit_test(test_variant_json_convert_to_any),
        cmocka_unit_test(test_variant_json_convert_empty_string_to_any),
        cmocka_unit_test(test_variant_json_cast),
        cmocka_unit_test(test_variant_json_from_null_string),
    };
    return cmocka_run_group_tests_name("amxj-variant-json", tests, NULL, NULL);
}
