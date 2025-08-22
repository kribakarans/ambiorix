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

#include "test_expression.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_can_create_expression),
        cmocka_unit_test(test_can_evaluate_expression),
        cmocka_unit_test(test_precedence_is_respected),
        cmocka_unit_test(test_comperators_are_correct),
        cmocka_unit_test(test_invalid_syntax),
        cmocka_unit_test(test_invalid_value_types),
        cmocka_unit_test(test_can_fetch_fields),
        cmocka_unit_test(test_invalid_field_names),
        cmocka_unit_test(test_can_use_custom_field_fetcher),
        cmocka_unit_test(test_api_arguments_validation),
        cmocka_unit_test(test_selects_first_in_first_existing),
        cmocka_unit_test(test_fails_with_invalid_regexp),
        cmocka_unit_test(test_is_empty_function),
        cmocka_unit_test(test_is_empty_function_with_var),
        cmocka_unit_test(test_contains),
        cmocka_unit_test(test_contains_no_get_field),
        cmocka_unit_test(test_contains_no_data),
        cmocka_unit_test(test_contains_invalid_usage),
        cmocka_unit_test(test_flag_expressions),
        cmocka_unit_test(test_flag_expressions_no_operators),
        cmocka_unit_test(test_in_operators),
        cmocka_unit_test(test_equals_ignorecase),
        cmocka_unit_test(test_buildf_expression),
        cmocka_unit_test(test_buildf_expression_allocate),
        cmocka_unit_test(test_buildf_expression_invalid_value),
        cmocka_unit_test(test_buildf_expression_all_whitelisted),
        cmocka_unit_test(test_buildf_expression_invalid_args),
        cmocka_unit_test(test_buildf_are_strings_safe),
        cmocka_unit_test(test_get_string),
        cmocka_unit_test(test_get_string_null),
        cmocka_unit_test(test_expression_with_invalid_list_does_not_memory_leak),
    };
    return cmocka_run_group_tests_name("amxp-expression", tests, NULL, NULL);
}
