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

#ifndef __TEST_AMXRT_SAVE_LOAD_H__
#define __TEST_AMXRT_SAVE_LOAD_H__

#include <amxrt/amxrt.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxo/amxo.h>


int test_save_load_setup(UNUSED void** state);
int test_save_load_teardown(UNUSED void** state);

void test_can_start_with_no_storage_type(UNUSED void** state);
void test_can_start_with_no_odl_storage_type(UNUSED void** state);
void test_can_start_with_odl_storage_type(UNUSED void** state);
void test_can_start_with_no_storage_path(UNUSED void** state);
void test_can_start_with_directory_configured(UNUSED void** state);
void test_can_load_files_with_eventing_on_or_off(void** state);
void test_start_fails_with_invalid_directory_configured(UNUSED void** state);
void test_loads_default_when_valid_dir_is_used(UNUSED void** state);
void test_load_fails_with_invalid_dir_and_invalid_defaults(UNUSED void** state);
void test_can_save_all_objects(UNUSED void** state);
void test_save_fails_when_invalid_dir(UNUSED void** state);
void test_can_save_separate_objects_csv(UNUSED void** state);
void test_save_separate_objects_fail_when_invalid_dir(UNUSED void** state);
void test_can_save_separate_objects_string(UNUSED void** state);
void test_does_not_save_when_invalid_objects(UNUSED void** state);
void test_save_skips_unknown_objects(UNUSED void** state);
void test_can_save_on_changes(UNUSED void** state);
void test_saves_when_persistent_parameter_changes(UNUSED void** state);
void test_does_not_save_when_not_persistent_parameter_changes(UNUSED void** state);
void test_saves_when_instance_deleted(UNUSED void** state);
void test_can_save_on_changes_with_object_list(UNUSED void** state);
void test_does_not_save_on_changed_when_invalid_objects(UNUSED void** state);

#endif // __TEST_AMXRT_SAVE_LOAD_H__