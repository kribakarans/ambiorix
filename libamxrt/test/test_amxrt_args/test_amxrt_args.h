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

#ifndef __TEST_AMXRT_ARGS_H__
#define __TEST_AMXRT_ARGS_H__

#include <amxrt/amxrt.h>

int test_args_setup(UNUSED void** state);
int test_args_teardown(UNUSED void** state);

void test_can_print_help(UNUSED void** state);
void test_can_print_extended_help(UNUSED void** state);
void test_can_add_include_dir(UNUSED void** state);
void test_can_add_import_dir(UNUSED void** state);
void test_can_add_backend(UNUSED void** state);
void test_can_add_uri(UNUSED void** state);
void test_can_accept_option(UNUSED void** state);
void test_can_overwrite_option(UNUSED void** state);
void test_ignores_invalid_options(UNUSED void** state);
void test_can_disable_auto_detect(UNUSED void** state);
void test_can_disable_auto_connect(UNUSED void** state);
void test_can_enable_daemonize(UNUSED void** state);
void test_can_enable_eventing(UNUSED void** state);
void test_can_enable_dump_config(UNUSED void** state);
void test_can_set_nice_level(UNUSED void** state);
void test_can_disable_pid_file_creation(UNUSED void** state);
void test_can_pass_odl_string(UNUSED void** state);
void test_can_enable_syslog(UNUSED void** state);
void test_can_add_required_objects(UNUSED void** state);
void test_can_add_forced_option(UNUSED void** state);
void test_can_add_custom_options(UNUSED void** state);
void test_cmd_line_parse_fails_after_reset(UNUSED void** state);
void test_can_set_usage_doc(UNUSED void** state);

#endif // __TEST_AMXRT_ARGS_H__