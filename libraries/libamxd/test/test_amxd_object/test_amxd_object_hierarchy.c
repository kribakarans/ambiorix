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
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include "test_amxd_object.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

void test_amxd_object_add_object(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child"), 0);

    assert_int_equal(amxd_object_add_object(parent, child), 0);

    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_not_equal(amxd_object_add_object(child, child), 0);
    assert_int_not_equal(amxd_object_add_object(parent, parent), 0);

    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_not_equal(amxd_object_add_object(child, parent), 0);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(mib, child), 0);
    assert_int_not_equal(amxd_object_add_object(parent, mib), 0);

    amxd_object_delete(&mib);

    amxd_dm_clean(&dm);
}

void test_amxd_object_add_object_invalid_args(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_dm_t dm2;

    assert_int_equal(amxd_dm_init(&dm), 0);
    assert_int_equal(amxd_dm_init(&dm2), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_mib, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);

    assert_int_not_equal(amxd_object_add_object(parent, NULL), 0);
    assert_int_not_equal(amxd_object_add_object(NULL, child), 0);
    assert_int_not_equal(amxd_object_add_object(parent, child), 0);

    assert_int_not_equal(amxd_object_add_object(parent, amxd_dm_get_root(&dm2)), 0);

    amxd_object_delete(&child);

    amxd_dm_clean(&dm2);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parent(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child, "test", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get_parent(instance), child);
    assert_ptr_equal(amxd_object_get_parent(child), parent);
    assert_ptr_equal(amxd_object_get_parent(parent), amxd_dm_get_root(&dm));
    assert_ptr_equal(amxd_object_get_parent(amxd_dm_get_root(&dm)), NULL);
    assert_ptr_equal(amxd_object_findf(instance, "^"), child);
    assert_ptr_equal(amxd_object_findf(instance, "^.^"), parent);
    assert_ptr_equal(amxd_object_findf(instance, "^.^.^"), amxd_dm_get_root(&dm));
    assert_ptr_equal(amxd_object_findf(instance, "^.^.^.parent"), parent);
    assert_ptr_equal(amxd_object_findf(instance, "^.^.^.^"), NULL);
    assert_ptr_equal(amxd_object_findf(instance, "^.^.^.^.parent"), NULL);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_ptr_equal(amxd_object_get_parent(mib), NULL);
    assert_ptr_equal(amxd_object_get_parent(NULL), NULL);
    amxd_object_delete(&mib);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_root(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child, "test", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get_root(instance), amxd_dm_get_root(&dm));
    assert_ptr_equal(amxd_object_get_root(child), amxd_dm_get_root(&dm));
    assert_ptr_equal(amxd_object_get_root(parent), amxd_dm_get_root(&dm));
    assert_ptr_equal(amxd_object_get_root(amxd_dm_get_root(&dm)), NULL);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_ptr_equal(amxd_object_get_root(mib), NULL);
    assert_ptr_equal(amxd_object_get_root(NULL), NULL);
    amxd_object_delete(&mib);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_ptr_equal(amxd_object_get_root(child), NULL);
    assert_ptr_equal(amxd_object_get_root(parent), NULL);
    amxd_object_delete(&parent);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_dm(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child, "test", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get_dm(instance), &dm);
    assert_ptr_equal(amxd_object_get_dm(child), &dm);
    assert_ptr_equal(amxd_object_get_dm(parent), &dm);
    assert_ptr_equal(amxd_object_get_dm(amxd_dm_get_root(&dm)), &dm);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_ptr_equal(amxd_object_get_dm(mib), NULL);
    assert_ptr_equal(amxd_object_get_dm(NULL), NULL);
    amxd_object_delete(&mib);

    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child"), 0);
    assert_ptr_equal(amxd_object_get_dm(child), NULL);
    amxd_object_delete(&child);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_child(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get_child(parent, "child"), child1);
    assert_ptr_equal(amxd_object_get_child(parent, "chi"), NULL);
    assert_ptr_equal(amxd_object_get_child(parent, "invalid"), NULL);
    assert_ptr_equal(amxd_object_get_child(child1, "test"), NULL);
    assert_ptr_equal(amxd_object_get_child(child1, "sub-child"), child2);
    assert_ptr_equal(amxd_object_get_child(amxd_dm_get_root(&dm), "parent"), parent);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "mib-child"), 0);
    assert_int_equal(amxd_object_add_object(mib, child1), 0);
    assert_ptr_equal(amxd_object_get_child(mib, "mib-child"), child1);
    amxd_object_delete(&mib);

    assert_ptr_equal(amxd_object_get_child(parent, ""), NULL);
    assert_ptr_equal(amxd_object_get_child(parent, NULL), NULL);
    assert_ptr_equal(amxd_object_get_child(NULL, "test"), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_instance(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get_instance(parent, "child", 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(parent, "invalid", 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(child1, "test", 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(child1, "sub-child", 0), instance);
    assert_ptr_equal(amxd_object_get_instance(child1, "sub", 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(child1, NULL, 1), instance);
    assert_ptr_equal(amxd_object_get_instance(child1, "", 1), instance);
    assert_ptr_equal(amxd_object_get_instance(amxd_dm_get_root(&dm), "parent", 0), NULL);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "mib-child"), 0);
    assert_int_equal(amxd_object_add_object(mib, child1), 0);
    assert_ptr_equal(amxd_object_get_instance(mib, "mib-child", 0), NULL);
    amxd_object_delete(&mib);

    assert_ptr_equal(amxd_object_get_instance(parent, "", 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(parent, NULL, 0), NULL);
    assert_ptr_equal(amxd_object_get_instance(NULL, "test", 0), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_instance_difficult_alias_name(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;
    const char* names[] = {
        "normal_alias",
        "another_normal_alias",
        "we can use spaces",
        "dot.in_the_middle",
        "dot_at_the_end.",
        "[brackets]",
        "textbefore[brackets]",
        "utf8snowman☃",
        "quo'tes",
        "injectionattack\" || \"a\" == \"b",
        "injectionattack\" || \"a\" == \"b' || 'a' == 'b",
        "diversion_brackets",
        "[diversion_brackets]",
    };

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "MyRoot"), amxd_status_ok);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MyTemplate"), amxd_status_ok);
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_unique, true);
    amxd_param_set_attr(param, amxd_pattr_key, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), amxd_status_ok);
    assert_int_equal(amxd_object_add_object(root, template), amxd_status_ok);

    for(size_t i = 0; i < sizeof(names) / sizeof(names)[0]; i++) {
        amxd_object_t* instance = NULL;
        // GIVEN an instance object with a name that has tricky characters
        const char* name = names[i];
        amxd_object_t* retrieved_instance = NULL;
        amxd_status_t status = amxd_object_new_instance(&instance, template, name, 0, NULL);
        if(status == amxd_status_invalid_name) {
            // If a difficult name is refused, then we don't have to be able to fetch by that name.
            continue;
        }
        assert_int_equal(status, amxd_status_ok);
        assert_non_null(instance);
        printf("Instance name = %s\n", name);

        // WHEN retrieving that instance object by its name
        retrieved_instance = amxd_object_get_instance(template, name, 0);

        // THEN the instance object was retrieved successfully
        assert_non_null(retrieved_instance);
        assert_ptr_equal(retrieved_instance, instance);
    }

    for(size_t i = 0; i < sizeof(names) / sizeof(names)[0]; i++) {
        // GIVEN an instance object with a name that has tricky characters
        const char* name = names[i];
        amxd_object_t* retrieved_instance = NULL;
        printf("Instance name = %s\n", name);

        // WHEN retrieving that instance object by its name
        retrieved_instance = amxd_object_get_instance(template, name, 0);

        // THEN the instance object was retrieved successfully
        assert_non_null(retrieved_instance);
        assert_string_equal(amxd_object_get_name(retrieved_instance, AMXD_OBJECT_NAMED), name);
    }

    for(size_t i = 0; i < sizeof(names) / sizeof(names)[0]; i++) {
        // GIVEN an instance object with a name that has tricky characters
        const char* name = names[i];
        amxd_object_t* retrieved_instance = NULL;
        printf("Instance name = %s\n", name);

        // WHEN retrieving that instance object by its alias
        // This triggers a memory leak in libamxp expression parser
        // the problem needs to be investigated, when fixed this test can be enabled again
        retrieved_instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate.[%s].", name);
        if(retrieved_instance == NULL) {
            retrieved_instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate.[Alias == '%s'].", name);
        }
        if(retrieved_instance == NULL) {
            retrieved_instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate.[Alias == \"%s\"].", name);
        }
        // THEN the instance object was retrieved successfully
        assert_non_null(retrieved_instance);
        assert_string_equal(amxd_object_get_name(retrieved_instance, AMXD_OBJECT_NAMED), name);
    }

    amxd_dm_clean(&dm);
}

void test_amxd_object_get(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* mib = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_ptr_equal(amxd_object_get(parent, "child"), child1);
    assert_ptr_equal(amxd_object_get(parent, "invalid"), NULL);
    assert_ptr_equal(amxd_object_get(child1, "test"), NULL);
    assert_ptr_equal(amxd_object_get(child1, "sub-child"), instance);
    assert_ptr_equal(amxd_object_get(child1, "1"), instance);
    assert_ptr_equal(amxd_object_get(amxd_dm_get_root(&dm), "parent"), parent);

    assert_int_equal(amxd_object_new(&mib, amxd_object_mib, "test-mib"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "mib-child"), 0);
    assert_int_equal(amxd_object_add_object(mib, child1), 0);
    assert_ptr_equal(amxd_object_get(mib, "mib-child"), child1);
    amxd_object_delete(&mib);

    assert_ptr_equal(amxd_object_get(parent, ""), NULL);
    assert_ptr_equal(amxd_object_get(parent, NULL), NULL);
    assert_ptr_equal(amxd_object_get(NULL, "test"), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_find(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent"), parent);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child"), child1);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.sub-child"), child2);
    assert_ptr_equal(amxd_object_findf(parent, "child.sub-child"), child2);
    assert_ptr_equal(amxd_object_findf(parent, ".child.sub-child"), child2);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[sub-child]"), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[1]"), instance);

    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[2]"), NULL);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[not-existing]"), NULL);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.not-existing"), NULL);

    assert_ptr_equal(amxd_object_findf(NULL, "parent.child.[2]"), NULL);
    assert_ptr_equal(amxd_object_findf(parent, NULL), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_findf(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "%s", "parent"), parent);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "%s.child", "parent"), child1);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.%s", "sub-child"), child2);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[%s]", "sub-child"), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[%d]", 1), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.%d", 1), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent..child..%d.", 1), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child..[%s].", "sub-child"), instance);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "..."), amxd_dm_get_root(&dm));

    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[%d]", 2), NULL);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.[%s]", "not-existing"), NULL);
    assert_ptr_equal(amxd_object_findf(amxd_dm_get_root(&dm), "parent.child.%s", "not-existing"), NULL);

    assert_ptr_equal(amxd_object_findf(NULL, "%s.child.[2]", "parent"), NULL);
    assert_ptr_equal(amxd_object_findf(parent, NULL), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_path(UNUSED void** state) {
    char* path = NULL;
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance_child2 = NULL;
    amxd_object_t* instance = NULL;
    amxc_llist_t paths;

    amxc_llist_init(&paths);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    path = amxd_object_get_path(parent, AMXD_OBJECT_NAMED);
    assert_string_equal(path, "parent");
    free(path);

    path = amxd_object_get_path(child1, AMXD_OBJECT_NAMED);
    assert_string_equal(path, "parent.child");
    free(path);

    path = amxd_object_get_rel_path(child1, parent, AMXD_OBJECT_NAMED);
    assert_string_equal(path, "child");
    free(path);

    path = amxd_object_get_rel_path(child1, child1, AMXD_OBJECT_NAMED);
    assert_null(path);
    free(path);

    path = amxd_object_get_path(child2, AMXD_OBJECT_NAMED);
    assert_string_equal(path, "parent.child.sub-child");
    free(path);

    path = amxd_object_get_path(child1, AMXD_OBJECT_SUPPORTED);
    assert_string_equal(path, "parent.child.{i}");
    free(path);

    path = amxd_object_get_path(child1, AMXD_OBJECT_SUPPORTED | AMXD_OBJECT_TERMINATE);
    assert_string_equal(path, "parent.child.{i}.");
    free(path);

    path = amxd_object_get_path(instance, AMXD_OBJECT_SUPPORTED | AMXD_OBJECT_TERMINATE);
    assert_string_equal(path, "parent.child.{i}.");
    free(path);

    path = amxd_object_get_path(child2, AMXD_OBJECT_NAMED | AMXD_OBJECT_TERMINATE);
    assert_string_equal(path, "parent.child.sub-child.");
    free(path);

    path = amxd_object_get_path(instance, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED);
    assert_string_equal(path, "parent.child.[sub-child]");
    free(path);
    path = amxd_object_get_path(instance, AMXD_OBJECT_INDEXED | AMXD_OBJECT_EXTENDED);
    assert_string_equal(path, "parent.child.[1]");
    free(path);

    path = amxd_object_get_path(instance, AMXD_OBJECT_NAMED);
    assert_string_equal(path, "parent.child.sub-child");
    free(path);
    path = amxd_object_get_path(instance, AMXD_OBJECT_INDEXED);
    assert_string_equal(path, "parent.child.1");
    free(path);

    path = amxd_object_get_path(instance, AMXD_OBJECT_NAMED | AMXD_OBJECT_REGEXP);
    assert_string_equal(path, "parent\\.child\\.sub-child");
    free(path);
    path = amxd_object_get_path(instance, AMXD_OBJECT_INDEXED | AMXD_OBJECT_REGEXP);
    assert_string_equal(path, "parent\\.child\\.1");
    free(path);

    path = amxd_object_get_path(instance, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED | AMXD_OBJECT_REGEXP);
    assert_string_equal(path, "parent\\.child\\.\\[sub-child\\]");
    free(path);
    path = amxd_object_get_path(instance, AMXD_OBJECT_INDEXED | AMXD_OBJECT_EXTENDED | AMXD_OBJECT_REGEXP);
    assert_string_equal(path, "parent\\.child\\.\\[1\\]");
    free(path);

    path = amxd_object_get_path(amxd_dm_get_root(&dm), AMXD_OBJECT_NAMED);
    assert_ptr_equal(path, NULL);
    free(path);

    instance_child2 = amxd_object_findf(instance, "sub-child");
    assert_ptr_not_equal(instance_child2, NULL);
    assert_ptr_not_equal(instance_child2, child2);

    path = amxd_object_get_path(instance_child2, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED);
    assert_string_equal(path, "parent.child.[sub-child].sub-child");
    free(path);

    child2 = amxd_dm_findf(&dm, "parent.child.{i}.sub-child.");
    assert_non_null(child2);
    child2 = amxd_dm_findf(&dm, "parent.{i}.1.sub-child.");
    assert_null(child2);

    child1 = amxd_dm_findf(&dm, "parent.child.");
    assert_non_null(child1);
    child2 = amxd_object_findf(child1, ".sub-child.");
    assert_non_null(child2);
    assert_int_equal(amxd_object_resolve_pathf(child1, &paths, ".sub2-child."), 0);

    assert_ptr_equal(amxd_object_get_path(NULL, 0), NULL);
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    amxd_dm_clean(&dm);
}

static int pos = 0;
static char* expected_paths_down[] = {
    NULL,
    "parent",
    "parent.child_1",
    "parent.child_2",
    "parent.child_2.child_2_1",
    "parent.child_2.child_2_2",
    "parent.child_2.[instance_1]",
    "parent.child_2.[instance_1].child_2_1",
    "parent.child_2.[instance_1].child_2_2",
    "parent.child_2.[instance_2]",
    "parent.child_2.[instance_2].child_2_1",
    "parent.child_2.[instance_2].child_2_2",
};

static void check_path_down(amxd_object_t* const object,
                            UNUSED int32_t depth,
                            void* priv) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED);
    assert_ptr_equal(priv, NULL);

    printf("%s == %s?\n", expected_paths_down[pos], path);

    if(path == NULL) {
        assert_ptr_equal(expected_paths_down[pos], NULL);
    } else {
        assert_string_equal(path, expected_paths_down[pos]);
    }
    free(path);
    pos++;
}

static char* expected_paths_up[] = {
    "parent.child_2.[instance_2]",
    "parent.child_2",
    "parent",
    NULL,
};

static void check_path_up(amxd_object_t* const object,
                          UNUSED int32_t depth,
                          void* priv) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED);
    assert_ptr_equal(priv, NULL);

    printf("%s == %s?\n", expected_paths_up[pos], path);

    if(path == NULL) {
        assert_ptr_equal(expected_paths_up[pos], NULL);
    } else {
        assert_string_equal(path, expected_paths_up[pos]);
    }
    free(path);
    pos++;
}

void test_amxd_object_walk(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);

    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    parent = child;
    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_2", 0, NULL), 0);

    pos = 0;
    amxd_object_hierarchy_walk(amxd_dm_get_root(&dm), amxd_direction_down, NULL, check_path_down, INT32_MAX, NULL);
    pos = 0;
    amxd_object_hierarchy_walk(instance, amxd_direction_up, NULL, check_path_up, INT32_MAX, NULL);

    amxd_dm_clean(&dm);
}

static char* expected_paths_down_filtered[] = {
    NULL,
    "parent",
    "parent.child_1",
    "parent.child_2",
    "parent.child_2.instance_1",
    "parent.child_2.instance_1.child_2_1",
    "parent.child_2.instance_1.child_2_2",
    "parent.child_2.instance_2",
    "parent.child_2.instance_2.child_2_1",
    "parent.child_2.instance_2.child_2_2",
};

static bool no_tempate_child_objects(amxd_object_t* const object,
                                     UNUSED int32_t depth,
                                     void* priv) {
    assert_ptr_equal(priv, NULL);
    if((object->type == amxd_object_instance) ||
       ( object->type == amxd_object_template) ||
       ( object->type == amxd_object_root)) {
        return true;
    }

    if((amxd_object_get_parent(object) != NULL) &&
       ( amxd_object_get_parent(object)->type != amxd_object_template)) {
        return true;
    }

    return false;
}

static bool no_root_objects(amxd_object_t* const object,
                            UNUSED int32_t depth,
                            void* priv) {
    assert_ptr_equal(priv, NULL);
    return object->type != amxd_object_root;
}

static void check_path_down_filtered(amxd_object_t* const object,
                                     UNUSED int32_t depth,
                                     void* priv) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED);
    assert_ptr_equal(priv, NULL);

    printf("%s == %s?\n", expected_paths_down_filtered[pos], path);

    if(path == NULL) {
        assert_ptr_equal(expected_paths_down_filtered[pos], NULL);
    } else {
        assert_string_equal(path, expected_paths_down_filtered[pos]);
    }
    free(path);
    pos++;
}

void test_amxd_object_walk_filtered(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);

    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    parent = child;
    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_2", 0, NULL), 0);

    pos = 0;
    amxd_object_hierarchy_walk(amxd_dm_get_root(&dm), amxd_direction_down, no_tempate_child_objects, check_path_down_filtered, INT32_MAX, NULL);
    pos = 0;
    amxd_object_hierarchy_walk(instance, amxd_direction_up, no_root_objects, check_path_up, INT32_MAX, NULL);

    amxd_dm_clean(&dm);
}

static char* expected_paths_down_depth[] = {
    NULL,
    "parent",
};

static void check_path_down_depth(amxd_object_t* const object,
                                  UNUSED int32_t depth,
                                  void* priv) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED);
    assert_ptr_equal(priv, NULL);

    printf("%s == %s?\n", expected_paths_down_depth[pos], path);

    if(path == NULL) {
        assert_ptr_equal(expected_paths_down_depth[pos], NULL);
    } else {
        assert_string_equal(path, expected_paths_down_depth[pos]);
    }
    free(path);
    pos++;
}

static char* expected_paths_up_depth[] = {
    "parent.child_2.[2]",
    "parent.child_2",
};

static void check_path_up_depth(amxd_object_t* const object,
                                UNUSED int32_t depth,
                                void* priv) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED | AMXD_OBJECT_EXTENDED);
    assert_ptr_equal(priv, NULL);

    printf("%s == %s?\n", expected_paths_up_depth[pos], path);

    if(path == NULL) {
        assert_ptr_equal(expected_paths_up_depth[pos], NULL);
    } else {
        assert_string_equal(path, expected_paths_up_depth[pos]);
    }
    free(path);
    pos++;
}

void test_amxd_object_walk_depth(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);

    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "child_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    parent = child;
    printf("Current parent = %s\n", parent->name);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child_2_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child), 0);

    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, parent, "instance_2", 0, NULL), 0);

    pos = 0;
    amxd_object_hierarchy_walk(amxd_dm_get_root(&dm), amxd_direction_down, NULL, check_path_down_depth, 1, NULL);
    pos = 0;
    amxd_object_hierarchy_walk(instance, amxd_direction_up, NULL, check_path_up_depth, 1, NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_walk_invalid_args(UNUSED void** state) {
    amxd_object_hierarchy_walk(amxd_dm_get_root(&dm), amxd_direction_down, NULL, NULL, INT32_MAX, NULL);
    amxd_object_hierarchy_walk(NULL, amxd_direction_down, NULL, check_path_up_depth, INT32_MAX, NULL);
}

void test_amxd_object_is_child_of(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);

    assert_int_equal(amxd_object_new(&child1, amxd_object_singleton, "child_1"), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "child_2"), 0);
    assert_int_equal(amxd_object_add_object(parent, child2), 0);

    assert_int_equal(amxd_object_new_instance(&instance, child2, "instance_1", 0, NULL), 0);

    assert_true(amxd_object_is_child_of(instance, parent));
    assert_true(amxd_object_is_child_of(child2, parent));
    assert_true(amxd_object_is_child_of(child1, parent));
    assert_false(amxd_object_is_child_of(child1, child2));
    assert_false(amxd_object_is_child_of(child2, child1));
    assert_false(amxd_object_is_child_of(parent, child2));
    assert_true(amxd_object_is_child_of(instance, child2));
    assert_false(amxd_object_is_child_of(instance, child1));

    assert_false(amxd_object_is_child_of(NULL, parent));
    assert_false(amxd_object_is_child_of(child1, NULL));

    amxd_dm_clean(&dm);
}
