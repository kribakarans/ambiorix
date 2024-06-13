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

#ifndef __TEST_CLI_MOD_AMX_H__
#define __TEST_CLI_MOD_AMX_H__

int test_cli_mod_amx_setup(void** state);
int test_cli_mod_amx_teardown(void** state);

void test_can_invoke_help(void** state);
void test_can_complete_help_command(void** state);
void test_can_describe(void** state);
void test_can_add_variable(void** state);
void test_can_add_list_variable(void** state);
void test_can_add_table_variable(void** state);
void test_can_dump_variables(void** state);
void test_variable_dump_fails_if_not_found(void** state);
void test_can_dump_single_variable(void** state);
void test_can_get_list_value(void** state);
void test_can_get_table_value(void** state);
void test_can_complete_variable(void** state);
void test_can_delete_variable(void** state);
void test_can_delete_list_item(void** state);
void test_can_delete_table_item(void** state);
void test_can_set_list_item(void** state);
void test_can_set_table_item(void** state);
void test_set_fails_when_invalid_variable_name(void** state);
void test_set_fails_when_name_omitted(void** state);
void test_set_fails_on_composite_when_not_found(void** state);
void test_can_build_composite_variable(void** state);
void test_can_dump_composite_variable_part(void** state);
void test_can_add_alias(void** state);
void test_add_fails_when_empty_or_invalid_alias_name(void** state);
void test_can_dump_aliases(void** state);
void test_can_complete_alias(void** state);
void test_can_delete_alias(void** state);
void test_can_invoke_exit(void** state);
void test_can_switch_silent_mode(void** state);
void test_set_silent_mode_fails_with_invalid_value(void** state);
void test_can_toggle_log(void** state);
void test_set_log_fails_with_invalid_value(void** state);
void test_set_log_fails_without_options(void** state);
void test_set_log_fails_with_invalid_options(void** state);
void test_can_set_prompt(void** state);

#endif // __TEST_CLI_MOD_AMX_H__