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

#include "test_synchronize.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_can_parser_synchronize_definition),
        cmocka_unit_test(test_can_parser_synchronize_definition_alternate),
        cmocka_unit_test(test_can_parser_synchronize_definition_with_vars),
        cmocka_unit_test(test_can_parser_synchronize_definition_with_cb),
        cmocka_unit_test(test_parser_sync_duplicates_fails),
        cmocka_unit_test(test_parse_empty_synchronize_context_fails),
        cmocka_unit_test(test_parse_sync_invalid_context_paths_fails),
        cmocka_unit_test(test_parse_empty_synchronize_object_fails),
        cmocka_unit_test(test_parse_synchronize_object_fails_without_entries),
        cmocka_unit_test(test_parse_batch_parameter_with_cb_fails),
        cmocka_unit_test(test_create_sync_tree_fails_with_conflicting_directions),
        cmocka_unit_test(test_parse_synchronize_with_invalid_action_fails),
        cmocka_unit_test(test_synchronize_start_fails_when_no_bus_connections),
        cmocka_unit_test_setup_teardown(test_can_setup_synchronization, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_can_setup_synchronization_with_vars, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_respects_direction, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_respects_direction_2, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_respects_direction_3, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_can_set_readonly, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_can_use_template, amxut_bus_setup, amxut_bus_teardown),
        cmocka_unit_test_setup_teardown(test_synchronization_template_must_use_supported_path, amxut_bus_setup, amxut_bus_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
