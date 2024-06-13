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

#include "test_ocg_args.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_can_print_help),
        cmocka_unit_test(test_can_print_xml_generator_help),
        cmocka_unit_test(test_can_print_dmm_generator_help),
        cmocka_unit_test(test_can_add_include_dir),
        cmocka_unit_test(test_can_add_import_dir),
        cmocka_unit_test(test_duplicate_dis_are_ignored),
        cmocka_unit_test(test_can_enable_resolving),
        cmocka_unit_test(test_can_add_generator),
        cmocka_unit_test(test_fails_with_invalid_generator),
        cmocka_unit_test(test_fails_with_duplicate_generator),
        cmocka_unit_test(test_can_add_directory_to_generator),
        cmocka_unit_test(test_can_add_absolute_directory_to_generator),
        cmocka_unit_test(test_can_enable_silent_mode),
        cmocka_unit_test(test_can_enable_reset_mode),
        cmocka_unit_test(test_can_disable_warnings),
        cmocka_unit_test(test_can_enable_continue_on_error),
        cmocka_unit_test(test_can_disable_colors),
        cmocka_unit_test(test_can_enable_verbose),
        cmocka_unit_test(test_fails_when_invalid_argument_given),
        cmocka_unit_test(test_merge_command_line_options_and_parser_config),
        cmocka_unit_test(test_can_dump_config),
        cmocka_unit_test(test_does_not_dump_config_when_silent),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
