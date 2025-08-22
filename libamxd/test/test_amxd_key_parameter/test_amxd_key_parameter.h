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

#ifndef __TEST_AMXD_KEY_PARAMETER_H__
#define __TEST_AMXD_KEY_PARAMETER_H__

int test_key_parameter_setup(void** state);
int test_key_parameter_teardown(void** state);

void test_key_flag_is_set(void** state);
void test_can_add_key_param_if_no_instances_exist(void** state);
void test_key_parameters_must_be_set(void** state);
void test_key_parameters_must_be_unique(void** state);
void test_can_not_add_key_params_if_instances_exist(void** state);
void test_can_not_unset_key_attr(void** state);
void test_can_not_delete_key_parameter(void** state);
void test_can_not_add_key_param_to(void** state);
void test_can_not_set_key_attr_on_params_of(void** state);
void test_object_has_key_parameters(void** state);
void test_key_parameter_values_are_immutable(void** state);
void test_can_build_key_expression(void** state);
void test_amxd_object_add_instance_verifies_keys(void** state);
void test_can_check_object_has_key_parameters(void** state);
void test_can_create_instance_with_unique_keys(void** state);
void test_can_find_object_with_keys(void** state);
void test_find_fails_with_invalid_expression_part(void** state);
void test_find_fails_with_wildcard(void** state);
void test_can_create_instance_with_alias(void** state);
void test_can_create_instance_with_non_key_alias(void** state);
void test_creation_fails_when_alias_value_is_wrong_type(void** state);
void test_creation_fails_when_alias_starts_with_number(void** state);
void test_can_find_instances_with_alias(void** state);
void test_can_create_instances_with_keys_that_has_validation(void** state);
void test_can_change_mutable_key(void** state);
void test_adding_duplicate_fails(void** state);
void test_changing_mutable_key_fails_if_duplicate(void** state);

#endif // __TEST_AMXD_KEY_PARAMETER_H__