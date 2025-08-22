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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>
#include <unistd.h>
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "test_amxd_path.h"

#include <amxc/amxc_macros.h>
void test_can_create_delete_path(UNUSED void** state) {
    amxd_path_t* path = NULL;

    int index = 0;
    const char* verify[] = {
        "Device.", "Interface.", "1.", "Stats."
    };

    assert_int_equal(amxd_path_new(&path, "Device.Interface.1.Stats."), 0);
    assert_non_null(path);
    assert_int_equal(amxc_llist_size(&path->parts.data.vl), 4);

    amxc_var_for_each(var, (&path->parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
        assert_string_equal(txt, verify[index]);
        index++;
    }

    assert_string_equal(amxd_path_get(path, AMXD_OBJECT_TERMINATE), "Device.Interface.1.Stats.");

    amxd_path_delete(&path);
    assert_null(path);
}

void test_can_split_path(UNUSED void** state) {
    amxd_path_t path;

    int index = 0;
    const char* verify[] = {
        "Device.", "Interface.", "1.", "Stats."
    };

    assert_int_equal(amxd_path_init(&path, "Device.Interface.1.Stats."), 0);
    assert_int_equal(amxc_llist_size(&path.parts.data.vl), 4);

    amxc_var_for_each(var, (&path.parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
        assert_string_equal(txt, verify[index]);
        index++;
    }

    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "Device.Interface.1.Stats.");
    assert_string_equal(amxd_path_get(&path, 0), "Device.Interface.1.Stats");
    amxd_path_clean(&path);

    assert_int_not_equal(amxd_path_init(&path, "Device.Interface.'Test#1+'.Stats."), 0);

    amxd_path_clean(&path);
}

void test_can_split_search_path_wildcard(UNUSED void** state) {
    amxd_path_t path;

    int index = 0;
    const char* verify[] = {
        "Device.", "Interface.", "*", ".", "Stats."
    };

    assert_int_equal(amxd_path_init(&path, "Device.Interface.*.Stats."), 0);

    amxc_var_for_each(var, (&path.parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
        assert_string_equal(txt, verify[index]);
        index++;
    }

    assert_int_equal(amxc_llist_size(&path.parts.data.vl), 5);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "Device.Interface.*.Stats.");
    assert_string_equal(amxd_path_get(&path, 0), "Device.Interface.*.Stats");

    amxd_path_clean(&path);
}

void test_can_split_search_path_expression(UNUSED void** state) {
    amxd_path_t path;

    int index = 0;
    const char* verify[] = {
        "Device.", "Interface.", "[Enable==true]", ".", "Stats."
    };

    assert_int_equal(amxd_path_init(&path, "Device.Interface.[Enable==true].Stats.PacketsReceived"), 0);

    amxc_var_for_each(var, (&path.parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
        assert_string_equal(txt, verify[index]);
        index++;
    }

    assert_int_equal(amxc_llist_size(&path.parts.data.vl), 5);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "Device.Interface.[Enable==true].Stats.");
    assert_string_equal(amxd_path_get(&path, 0), "Device.Interface.[Enable==true].Stats");
    assert_string_equal(amxd_path_get_param(&path), "PacketsReceived");

    amxd_path_clean(&path);
}

void test_is_search_path(UNUSED void** state) {
    amxd_path_t path;
    char* fixed = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.Interface.[Enable==true].Stats.PacketsReceived"), 0);
    assert_true(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));

    fixed = amxd_path_get_fixed_part(&path, false);
    assert_string_equal(fixed, "Device.Interface.");
    free(fixed);

    amxd_path_setf(&path, false, "Device.Interface.1.Stats.PacketsReceived");
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));

    amxd_path_setf(&path, false, "Device.Interface.[Name == \"Eth0\"].Stats.PacketsReceived");
    assert_true(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));

    amxd_path_setf(&path, false, "Device.Interface.[Name == \"{alpha.1}\"].Stats.PacketsReceived");
    assert_true(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_true(amxd_path_is_valid(&path));

    amxd_path_clean(&path);
}

void test_is_object_path(UNUSED void** state) {
    amxd_path_t path;
    char* fixed = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.Interface.1.Stats.PacketsReceived"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_true(amxd_path_is_object_path(&path));

    fixed = amxd_path_get_fixed_part(&path, false);
    assert_string_equal(fixed, "Device.Interface.1.Stats.");
    free(fixed);

    amxd_path_clean(&path);
}

void test_can_split_empty_path(UNUSED void** state) {
    amxd_path_t path;

    assert_int_equal(amxd_path_init(&path, ""), 0);
    assert_true(amxc_llist_is_empty(&path.parts.data.vl));
    amxd_path_clean(&path);

    amxd_path_init(&path, NULL);
    assert_true(amxc_llist_is_empty(&path.parts.data.vl));
    amxd_path_clean(&path);
}

void test_is_supported_path(UNUSED void** state) {
    amxd_path_t path;
    char* fixed = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.Interface.{i}.Stats.PacketsReceived"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_true(amxd_path_is_supported_path(&path));

    fixed = amxd_path_get_fixed_part(&path, false);
    assert_string_equal(fixed, "Device.Interface.");

    free(fixed);

    assert_int_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_true(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_true(amxd_path_is_valid(&path));

    amxd_path_clean(&path);
}

void test_can_clean_supported_path(UNUSED void** state) {
    amxd_path_t path;
    char* clean_path = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice."), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    clean_path = amxd_path_get_supported_path(&path);
    assert_string_equal(clean_path, "Device.WiFi.AccessPoint.AssociatedDevice.");
    free(clean_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.");
    clean_path = amxd_path_get_supported_path(&path);
    assert_string_equal(clean_path, "Device.WiFi.AccessPoint.AssociatedDevice.");
    free(clean_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MAC");
    clean_path = amxd_path_get_supported_path(&path);
    assert_string_equal(clean_path, "Device.WiFi.AccessPoint.AssociatedDevice.");
    free(clean_path);
    amxd_path_clean(&path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.2.MAC");
    clean_path = amxd_path_get_supported_path(&path);
    assert_string_equal(clean_path, "Device.WiFi.AccessPoint.AssociatedDevice.");
    free(clean_path);
    amxd_path_clean(&path);

    clean_path = amxd_path_get_supported_path(&path);
    assert_null(clean_path);

    amxd_path_clean(&path);
}

void test_build_supported_path_from_search_path(UNUSED void** state) {
    amxd_path_t path;
    char* sup_path = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.*.AssociatedDevice."), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    sup_path = amxd_path_build_supported_path(&path);
    assert_string_equal(sup_path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.");
    free(sup_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[param == value].AssociatedDevice.*.");
    sup_path = amxd_path_build_supported_path(&path);
    assert_string_equal(sup_path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.");
    free(sup_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[param == value].AssociatedDevice.*.");
    sup_path = amxd_path_build_supported_path(&path);
    assert_string_equal(sup_path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.");
    free(sup_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.*.");
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    sup_path = amxd_path_build_supported_path(&path);
    assert_string_equal(sup_path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.");
    free(sup_path);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.2.");
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    sup_path = amxd_path_build_supported_path(&path);
    assert_string_equal(sup_path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.");
    free(sup_path);

    printf("Path = Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*\n");
    amxd_path_setf(&path, false, "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*.");
    fflush(stdout);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    sup_path = amxd_path_build_supported_path(&path);
    printf("Supported path = %s\n", sup_path);
    fflush(stdout);
    assert_string_equal(sup_path, "Phonebook.Contact.{i}.PhoneNumber.{i}.");
    free(sup_path);

    amxd_path_clean(&path);
}

void test_build_search_path_from_supported_path(UNUSED void** state) {
    amxd_path_t path;
    char* search_path = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice."), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    search_path = amxd_path_build_search_path(&path);
    assert_string_equal(search_path, "Device.WiFi.AccessPoint.*.AssociatedDevice.");
    free(search_path);

    assert_int_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.{i}."), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    search_path = amxd_path_build_search_path(&path);
    assert_string_equal(search_path, "Device.WiFi.AccessPoint.1.AssociatedDevice.*.");
    free(search_path);

    assert_int_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.{i}.MACAddress"), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    search_path = amxd_path_build_search_path(&path);
    assert_string_equal(search_path, "Device.WiFi.AccessPoint.1.AssociatedDevice.*.MACAddress");
    free(search_path);

    assert_int_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.1.AssociatedDevice.{i}"), 0);
    amxc_var_dump(&path.parts, STDOUT_FILENO);
    search_path = amxd_path_build_search_path(&path);
    assert_string_equal(search_path, "Device.WiFi.AccessPoint.1.AssociatedDevice.*.");
    free(search_path);

    amxd_path_clean(&path);
}

void test_is_invalid_path(UNUSED void** state) {
    amxd_path_t path;

    assert_int_not_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.{some_id}.AssociatedDevice."), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.{i}."), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.{i}"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.*."), 0);
    assert_true(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_true(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.[Name = \"test\"]"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.\"AccessPoint.{i}.AssociatedDevice\".*."), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.\"{i}\".AssociatedDevice.{i}."), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.{\"i\"}.AssociatedDevice."), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));

    assert_int_not_equal(amxd_path_setf(&path, false, "Phonebook.Contact.*"), 0);
    assert_false(amxd_path_is_search_path(&path));
    assert_false(amxd_path_is_supported_path(&path));
    assert_false(amxd_path_is_object_path(&path));
    assert_false(amxd_path_is_valid(&path));


    amxd_path_clean(&path);
}

void test_get_fixed_part(UNUSED void** state) {
    amxd_path_t path;
    const char* p = NULL;
    char* fixed = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.{i}.AssociatedDevice."), 0);
    fixed = amxd_path_get_fixed_part(&path, false);
    assert_string_equal(fixed, "Device.WiFi.AccessPoint.");
    free(fixed);

    p = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
    assert_string_equal(p, "Device.WiFi.AccessPoint.{i}.AssociatedDevice.");

    fixed = amxd_path_get_fixed_part(&path, true);
    assert_string_equal(fixed, "Device.WiFi.AccessPoint.");
    free(fixed);
    p = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
    assert_string_equal(p, "{i}.AssociatedDevice.");

    amxd_path_clean(&path);
}

void test_get_first(UNUSED void** state) {
    amxd_path_t path;
    char* part = NULL;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.2.AssociatedDevice."), 0);
    part = amxd_path_get_first(&path, false);
    assert_string_equal(part, "Device.");
    free(part);

    part = amxd_path_get_first(&path, true);
    assert_string_equal(part, "Device.");
    free(part);

    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "WiFi.AccessPoint.2.AssociatedDevice.");

    part = amxd_path_get_first(&path, true);
    assert_string_equal(part, "WiFi.");
    free(part);

    assert_null(amxd_path_get_first(NULL, true));

    amxd_path_clean(&path);
}

void test_get_depth(UNUSED void** state) {
    amxd_path_t path;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.2.AssociatedDevice."), 0);
    assert_int_equal(amxd_path_get_depth(&path), 5);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.");
    assert_int_equal(amxd_path_get_depth(&path), 5);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[Enabled == true].AssociatedDevice.");
    assert_int_equal(amxd_path_get_depth(&path), 5);

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[Stats.BytesRceived > 100].");
    assert_int_equal(amxd_path_get_depth(&path), 4);

    assert_int_equal(amxd_path_get_depth(NULL), 0);

    amxd_path_clean(&path);
}

void test_is_instance_path(UNUSED void** state) {
    amxd_path_t path;

    assert_int_equal(amxd_path_init(&path, "Device.WiFi.AccessPoint.2.AssociatedDevice."), 0);
    assert_false(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.*.AssociatedDevice.");
    assert_false(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[Enabled == true].AssociatedDevice.");
    assert_false(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[Enabled == true].AssociatedDevice.*.");
    assert_true(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Device.WiFi.AccessPoint.[Stats.BytesRceived > 100].");
    assert_true(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact. ");
    assert_false(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact.*.");
    assert_true(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact.1.");
    assert_true(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact.1");
    assert_false(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact.[FirstName == 'ward'].");
    assert_true(amxd_path_is_instance_path(&path));

    amxd_path_setf(&path, false, "Phonebook.Contact.1.FirstName");
    assert_true(amxd_path_is_instance_path(&path));

    assert_false(amxd_path_is_instance_path(NULL));

    amxd_path_clean(&path);
}

void test_remove_last_can_update_path_type(UNUSED void** state) {
    amxd_path_t path;
    char* last = NULL;
    const char* initial_path = "DHCPv4.Client.[Enable == true].";

    amxd_path_init(&path, initial_path);
    assert_true(amxd_path_is_search_path(&path));
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), initial_path);

    last = amxd_path_get_last(&path, true);
    assert_string_equal(last, "[Enable == true].");
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "DHCPv4.Client.");
    free(last);
    assert_false(amxd_path_is_search_path(&path));

    amxd_path_clean(&path);
}

void test_can_append_path(UNUSED void** state) {
    amxd_path_t path;

    amxd_path_init(&path, NULL);

    assert_int_equal(amxd_path_append(NULL, "foo", false), amxd_status_unknown_error);
    assert_int_equal(amxd_path_append(&path, NULL, false), amxd_status_unknown_error);
    assert_int_equal(amxd_path_append(&path, "", false), amxd_status_unknown_error);

    assert_int_equal(amxd_path_append(&path, "First.", false), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "First.");
    assert_int_equal(path.type, amxd_path_object);

    assert_int_equal(amxd_path_append(&path, "Second.", false), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "First.Second.");
    assert_int_equal(path.type, amxd_path_object);

    assert_int_equal(amxd_path_append(&path, "Third", true), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "First.Second.Third.");
    assert_int_equal(path.type, amxd_path_object);

    assert_int_equal(amxd_path_append(&path, "*", true), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "First.Second.Third.*.");
    assert_int_equal(path.type, amxd_path_search);

    amxd_path_clean(&path);
}

void test_can_prepend_path(UNUSED void** state) {
    amxd_path_t path;

    amxd_path_init(&path, NULL);

    assert_int_equal(amxd_path_prepend(NULL, "foo"), amxd_status_unknown_error);
    assert_int_equal(amxd_path_prepend(&path, NULL), amxd_status_unknown_error);
    assert_int_equal(amxd_path_prepend(&path, ""), amxd_status_unknown_error);

    assert_int_equal(amxd_path_append(&path, "*", true), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "*.");
    assert_int_equal(path.type, amxd_path_search);

    assert_int_equal(amxd_path_prepend(&path, "Third."), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "Third.*.");
    assert_int_equal(path.type, amxd_path_search);

    assert_int_equal(amxd_path_prepend(&path, "Second."), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "Second.Third.*.");
    assert_int_equal(path.type, amxd_path_search);


    assert_int_equal(amxd_path_prepend(&path, "First."), amxd_status_ok);
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "First.Second.Third.*.");
    assert_int_equal(path.type, amxd_path_search);

    amxd_path_clean(&path);
}

void test_can_get_last_from_path(UNUSED void** state) {
    amxd_path_t path;
    char* last = NULL;

    amxd_path_init(&path, "DHCPv4.Server.Pool.*.");

    last = amxd_path_get_last(&path, false);
    assert_non_null(last);
    assert_string_equal(last, "*.");
    free(last);

    last = amxd_path_get_last(&path, true);
    assert_non_null(last);
    assert_string_equal(last, "*.");
    free(last);

    last = amxd_path_get_last(&path, false);
    assert_non_null(last);
    assert_string_equal(last, "Pool.");
    free(last);

    amxd_path_clean(&path);
}

void test_can_parse_reference_path(UNUSED void** state) {
    amxd_path_t path;
    char* ref_part = NULL;

    amxd_path_init(&path, "Device.NAT.PortMapping.1.Interface+.Name");

    amxc_var_for_each(var, (&path.parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
    }

    assert_int_equal(amxd_path_get_type(&path), amxd_path_reference);
    ref_part = amxd_path_get_reference_part(&path, false);
    assert_string_equal(ref_part, "Device.NAT.PortMapping.1.Interface");
    assert_int_equal(amxd_path_get_reference_index(&path), 1);
    assert_string_equal(amxd_path_get_param(&path), "Name");
    free(ref_part);

    ref_part = amxd_path_get_fixed_part(&path, false);
    assert_string_equal(ref_part, "Device.NAT.PortMapping.1.Interface");
    free(ref_part);

    amxd_path_clean(&path);

    amxd_path_init(&path, "Device.NAT.PortMapping.1.Interface#1+.Name");
    assert_int_equal(amxd_path_get_type(&path), amxd_path_reference);
    ref_part = amxd_path_get_reference_part(&path, true);

    free(ref_part);
    amxd_path_clean(&path);
}

void test_can_get_index_of_reference(UNUSED void** state) {
    amxd_path_t path;
    char* ref_part = NULL;

    amxd_path_init(&path, "Device.WiFi.SSID.1.LowerLayers#3+.Name");

    amxc_var_for_each(var, (&path.parts)) {
        const char* txt = amxc_var_constcast(cstring_t, var);
        printf("%s\n", txt);
    }

    assert_int_equal(amxd_path_get_type(&path), amxd_path_reference);
    ref_part = amxd_path_get_reference_part(&path, false);
    assert_string_equal(ref_part, "Device.WiFi.SSID.1.LowerLayers");
    assert_int_equal(amxd_path_get_reference_index(&path), 3);
    assert_string_equal(amxd_path_get_param(&path), "Name");
    free(ref_part);

    amxd_path_clean(&path);

}

void test_can_get_full_parameter_path(UNUSED void** state) {
    amxd_path_t path;
    const char* param_path = "Greeter.State";
    char* result = NULL;

    amxd_path_init(&path, param_path);

    result = amxd_path_get_param_path(&path);
    assert_string_equal(result, param_path);

    free(result);
    amxd_path_clean(&path);
}

void test_cannot_get_invalid_parameter_path(UNUSED void** state) {
    amxd_path_t path;
    const char* object_path = "Greeter.";

    amxd_path_init(&path, NULL);

    assert_null(amxd_path_get_param_path(NULL));
    assert_null(amxd_path_get_param_path(&path));

    amxd_path_setf(&path, false, "%s", object_path);
    assert_null(amxd_path_get_param_path(&path));

    amxd_path_clean(&path);

    amxd_path_init(&path, "NetModel.Intf.['Device.Bridging.Bridge.1.' in InterfacePath]");
    assert_string_equal(amxd_path_get(&path, AMXD_OBJECT_TERMINATE), "NetModel.Intf.['Device.Bridging.Bridge.1.' in InterfacePath].");

    amxd_path_clean(&path);
}
