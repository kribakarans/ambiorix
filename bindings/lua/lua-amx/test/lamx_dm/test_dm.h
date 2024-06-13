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

#ifndef __TEST_LAMX_DM_H__
#define __TEST_LAMX_DM_H__

#include <amxc/amxc_macros.h>

int test_lamx_setup(void** state);
int test_lamx_teardown(void** state);

void test_get_config_without_datamodel_created(void** state);
void test_can_create_dm(void** state);
void test_can_load_odl(void** state);
void test_load_odl_can_fail(void** state);
void test_can_get_config_option(void** state);
void test_can_get_config_option_fails_if_not_existing(void** state);
void test_can_set_config_option(void** state);
void test_set_config_option_fails_without_value(void** state);
void test_set_adds_config_option_if_not_existing(void** state);
void test_can_get_dm_object(void** state);
void test_get_dm_object_fails_if_not_existing(void** state);
void test_can_get_dm_object_name(void** state);
void test_can_get_dm_child_object(void** state);
void test_can_get_dm_child_object_name(void** state);
void test_can_get_dm_path(void** state);
void test_can_get_dm_index(void** state);
void test_can_get_parent(void** state);
void test_can_loop_over_instances(void** state);
void test_can_use_for_all(void** state);
void test_for_all_fails_if_no_function(void** state);
void test_can_add_instance(void** state);
void test_can_add_instance_with_args(void** state);
void test_add_instance_can_fail(void** state);
void test_can_add_mib(void** state);
void test_add_mib_fails_when_dupicate_param(void** state);
void test_can_set_and_read_param(void** state);
void test_can_get_instance_count(void** state);
void test_can_save_dm(void** state);
void test_save_dm_can_fail(void** state);
void test_can_remove_mib(void** state);
void test_remove_mib_fails_if_mib_not_found(void** state);
void test_can_del_instance(void** state);
void test_get_parent_fails_if_object_deleted(void** state);
void test_can_add_instance_with_params(void** state);
void test_fetch_parent_fails(void** state);
void test_can_fetch_parameter_def(void** state);
void test_can_set_value_using_parameter_def(void** state);
void test_param_methods_fail_when_owner_is_deleted(void** state);
void test_param_methods_fail_when_parameter_is_deleted(void** state);
void test_dm_functions_throws_error_when_referenced_dm_object_is_gone(void** state);
void test_call_not_existing_param_method_fails(void** state);
void test_can_send_change_event(void** state);
void test_can_call_rpc_method(void** state);
void test_call_rpc_method_fails_when_args_not_in_table(void** state);
void test_call_rpc_method_fails_when_rpc_fails(void** state);
void test_can_destroy_dm(void** state);
void test_load_fails_if_no_dm_available(void** state);
void test_save_fails_if_no_dm_available(void** state);

#endif //__TEST_LAMX_DM_H__