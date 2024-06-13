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

#include "test_mod_pcb_cli.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_can_invoke_help),
        cmocka_unit_test(test_can_describe),
        cmocka_unit_test(test_can_activate),
        cmocka_unit_test(test_can_cd_into_object),
        cmocka_unit_test(test_can_cd_to_root),
        cmocka_unit_test(test_cd_fails_when_invalid_path),
        cmocka_unit_test(test_cd_not_existing_object_fails),
        cmocka_unit_test(test_can_list_objects),
        cmocka_unit_test(test_can_complete_list_options),
        cmocka_unit_test(test_complete_always_provides_all_options),
        cmocka_unit_test(test_can_dump_object),
        cmocka_unit_test(test_dump_invalid_object_fails),
        cmocka_unit_test(test_can_dump_protected_members),
        cmocka_unit_test(test_can_get_supported_dm),
        cmocka_unit_test(test_gsdm_invalid_object_fails),
        cmocka_unit_test(test_can_get_instances),
        cmocka_unit_test(test_execute_fails_when_missing_operator),
        cmocka_unit_test(test_execute_fails_when_missing_path),
        cmocka_unit_test(test_can_complete_object_path),
        cmocka_unit_test(test_can_complete_object_path_in_cd_context),
        cmocka_unit_test(test_completes_is_empty_when_not_found),
        cmocka_unit_test(test_can_complete_object_parameters),
        cmocka_unit_test(test_parameter_complete_skips_used_parameters),
        cmocka_unit_test(test_can_complete_function_arguments),
        cmocka_unit_test(test_can_get_objects),
        cmocka_unit_test(test_can_get_referenced_object),
        cmocka_unit_test(test_get_fails_when_object_does_not_exist),
        cmocka_unit_test(test_can_set_parameters),
        cmocka_unit_test(test_set_fails_when_invalid_syntax_is_used),
        cmocka_unit_test(test_set_fails_when_setting_unknown_parameters),
        cmocka_unit_test(test_can_add_instance),
        cmocka_unit_test(test_add_instance_fails_when_invalid_syntax_used),
        cmocka_unit_test(test_add_instance_fails_on_invalid_object),
        cmocka_unit_test(test_can_del_instance),
        cmocka_unit_test(test_del_instance_fails_on_invalid_object),
        cmocka_unit_test(test_can_invoke_function),
        cmocka_unit_test(test_can_invoke_function_with_search_path),
        cmocka_unit_test(test_can_list_pending_invokes),
        cmocka_unit_test(test_invoke_fails_when_rpc_fails),
        cmocka_unit_test(test_invoke_fails_when_request_can_not_be_created),
        cmocka_unit_test(test_invoke_fails_on_invalid_syntax),
        cmocka_unit_test(test_parser_fails_on_invalid_operator),
        cmocka_unit_test(test_can_list_empty_subscriptions),
        cmocka_unit_test(test_can_subscribe),
        cmocka_unit_test(test_can_subscribe_using_search_path),
        cmocka_unit_test(test_can_subscribe_on_parameter),
        cmocka_unit_test(test_can_subscribe_with_filter),
        cmocka_unit_test(test_subscribe_can_fail),
        cmocka_unit_test(test_can_receive_changed_events),
        cmocka_unit_test(test_can_receive_add_events),
        cmocka_unit_test(test_can_receive_del_events),
        cmocka_unit_test(test_can_receive_periodic_inform),
        cmocka_unit_test(test_can_receive_custom_event),
        cmocka_unit_test(test_can_list_subscriptions),
        cmocka_unit_test(test_can_unsubscribe),
        cmocka_unit_test(test_unsubscribe_can_fail),
        cmocka_unit_test(test_unsubscribe_on_search_path_fails),
        cmocka_unit_test(test_del_instance_prints_message_if_nothing_deleted),
        cmocka_unit_test(test_can_resolve_paths),
        // MUST BE LAST
        cmocka_unit_test(test_pending_invokes_are_closed_when_connection_is_closed),
    };
    return cmocka_run_group_tests(tests, test_mod_pcb_cli_setup, test_mod_pcb_cli_teardown);
}
