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

#ifndef __TEST_AMXD_OBJECT_H__
#define __TEST_AMXD_OBJECT_H__

#define SINGELTON_DEFAULT_FUNCS 9
#define TEMPLATE_DEFAULT_FUNCS  9
#define INSTANCE_DEFAULT_FUNCS  9

void test_amxd_object_new_singleton(void** state);
void test_amxd_object_new_template(void** state);
void test_amxd_object_new_mib(void** state);
void test_amxd_object_new_invalid_type(void** state);
void test_amxd_object_new_invalid_name(void** state);
void test_amxd_object_new_instance(void** state);
void test_amxd_object_new_instance_invalid_name_index(void** state);
void test_amxd_object_new_instance_of_singelton(void** state);
void test_amxd_object_new_instance_with_children(void** state);
void test_amxd_object_new_delete_invalid_args(void** state);
void test_amxd_object_get_name(void** state);
void test_amxd_object_get_name_of_indexed_instance(void** state);

void test_amxd_object_add_object(void** state);
void test_amxd_object_add_object_invalid_args(void** state);
void test_amxd_object_get_parent(void** state);
void test_amxd_object_get_root(void** state);
void test_amxd_object_get_dm(void** state);
void test_amxd_object_get_child(void** state);
void test_amxd_object_get_instance(void** state);
void test_amxd_object_get_instance_difficult_alias_name(void** state);
void test_amxd_object_get(void** state);
void test_amxd_object_find(void** state);
void test_amxd_object_findf(void** state);
void test_amxd_object_get_path(void** state);
void test_amxd_object_walk(void** state);
void test_amxd_object_walk_filtered(void** state);
void test_amxd_object_walk_depth(void** state);
void test_amxd_object_walk_invalid_args(void** state);
void test_amxd_object_attributes(void** state);
void test_amxd_object_is_child_of(void** state);

void test_amxd_object_add_function(void** state);
void test_amxd_object_add_function_invalid_arg(void** state);
void test_amxd_object_change_function(void** state);
void test_amxd_object_change_function_invalid_args(void** state);
void test_amxd_object_get_function(void** state);
void test_amxd_object_get_function_invalid_args(void** state);
void test_amxd_object_get_functions(void** state);
void test_amxd_object_invoke_function(void** state);
void test_amxd_object_deferred_function_no_callbacks(void** state);
void test_amxd_object_deferred_function_cancel_callback(void** state);
void test_amxd_object_deferred_function_done_callback(void** state);
void test_amxd_object_count_functions(void** state);

void test_amxd_object_add_parameter(void** state);
void test_amxd_object_add_param_invalid_arg(void** state);
void test_amxd_object_get_parameter(void** state);
void test_amxd_object_get_parameter_value_type(void** state);
void test_amxd_object_get_parameter_value_with_cb(void** state);
void test_amxd_object_get_parameter_value(void** state);
void test_amxd_object_set_parameter_value(void** state);
void test_amxd_object_set_parameter_value_type(void** state);
void test_amxd_object_set_parameters_value(void** state);
void test_amxd_object_set_parameter_value_with_cb(void** state);
void test_amxd_object_set_parameters_value_with_cb(void** state);
void test_amxd_object_get_parameters_value(void** state);
void test_amxd_object_get_parameters_value_with_cb(void** state);
void test_amxd_object_list_parameters(void** state);
void test_amxd_object_count_parameters(void** state);
void test_amxd_object_count_parameters_with_cb(void** state);
void test_amxd_object_get_params_filtered(void** state);
void test_amxd_object_get_params_invalid_expr_filter(void** state);
void test_amxd_object_parameter_flags(void** state);
void test_amxd_object_set(void** state);
void test_amxd_object_get_helpers(void** state);

void test_can_set_max_instances(void** state);

#endif // __TEST_TEST_AMXD_DM_H__