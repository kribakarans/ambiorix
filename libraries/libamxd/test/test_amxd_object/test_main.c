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

#include "test_amxd_object.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_amxd_object_new_singleton),
        cmocka_unit_test(test_amxd_object_new_template),
        cmocka_unit_test(test_amxd_object_new_mib),
        cmocka_unit_test(test_amxd_object_new_invalid_type),
        cmocka_unit_test(test_amxd_object_new_invalid_name),
        cmocka_unit_test(test_amxd_object_new_instance),
        cmocka_unit_test(test_amxd_object_new_instance_invalid_name_index),
        cmocka_unit_test(test_amxd_object_new_instance_of_singelton),
        cmocka_unit_test(test_amxd_object_new_instance_with_children),
        cmocka_unit_test(test_amxd_object_new_delete_invalid_args),
        cmocka_unit_test(test_amxd_object_get_name),
        cmocka_unit_test(test_amxd_object_get_name_of_indexed_instance),

        cmocka_unit_test(test_amxd_object_add_object),
        cmocka_unit_test(test_amxd_object_add_object_invalid_args),
        cmocka_unit_test(test_amxd_object_get_parent),
        cmocka_unit_test(test_amxd_object_get_root),
        cmocka_unit_test(test_amxd_object_get_dm),
        cmocka_unit_test(test_amxd_object_get_child),
        cmocka_unit_test(test_amxd_object_get_instance),
        cmocka_unit_test(test_amxd_object_get_instance_difficult_alias_name),
        cmocka_unit_test(test_amxd_object_get),
        cmocka_unit_test(test_amxd_object_find),
        cmocka_unit_test(test_amxd_object_findf),
        cmocka_unit_test(test_amxd_object_get_path),
        cmocka_unit_test(test_amxd_object_walk),
        cmocka_unit_test(test_amxd_object_walk_filtered),
        cmocka_unit_test(test_amxd_object_walk_depth),
        cmocka_unit_test(test_amxd_object_walk_invalid_args),
        cmocka_unit_test(test_amxd_object_attributes),
        cmocka_unit_test(test_amxd_object_is_child_of),

        cmocka_unit_test(test_amxd_object_add_function),
        cmocka_unit_test(test_amxd_object_add_function_invalid_arg),
        cmocka_unit_test(test_amxd_object_change_function),
        cmocka_unit_test(test_amxd_object_change_function_invalid_args),
        cmocka_unit_test(test_amxd_object_get_function),
        cmocka_unit_test(test_amxd_object_get_function_invalid_args),
        cmocka_unit_test(test_amxd_object_get_functions),
        cmocka_unit_test(test_amxd_object_invoke_function),
        cmocka_unit_test(test_amxd_object_deferred_function_no_callbacks),
        cmocka_unit_test(test_amxd_object_deferred_function_cancel_callback),
        cmocka_unit_test(test_amxd_object_deferred_function_done_callback),
        cmocka_unit_test(test_amxd_object_count_functions),

        cmocka_unit_test(test_amxd_object_add_parameter),
        cmocka_unit_test(test_amxd_object_add_param_invalid_arg),
        cmocka_unit_test(test_amxd_object_get_parameter),
        cmocka_unit_test(test_amxd_object_get_parameter_value_type),
        cmocka_unit_test(test_amxd_object_get_parameter_value),
        cmocka_unit_test(test_amxd_object_get_parameter_value_with_cb),
        cmocka_unit_test(test_amxd_object_set_parameter_value),
        cmocka_unit_test(test_amxd_object_set_parameter_value_type),
        cmocka_unit_test(test_amxd_object_set_parameters_value),
        cmocka_unit_test(test_amxd_object_set_parameter_value_with_cb),
        cmocka_unit_test(test_amxd_object_set_parameters_value_with_cb),
        cmocka_unit_test(test_amxd_object_get_parameters_value),
        cmocka_unit_test(test_amxd_object_get_parameters_value_with_cb),
        cmocka_unit_test(test_amxd_object_list_parameters),
        cmocka_unit_test(test_amxd_object_count_parameters),
        cmocka_unit_test(test_amxd_object_count_parameters_with_cb),
        cmocka_unit_test(test_amxd_object_get_params_filtered),
        cmocka_unit_test(test_amxd_object_get_params_invalid_expr_filter),
        cmocka_unit_test(test_amxd_object_parameter_flags),
        cmocka_unit_test(test_amxd_object_set),
        cmocka_unit_test(test_amxd_object_get_helpers),

        cmocka_unit_test(test_can_set_max_instances),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
