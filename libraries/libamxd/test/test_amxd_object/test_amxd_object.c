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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include "test_amxd_object.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

void test_amxd_object_new_singleton(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->name, "test_object");
    assert_int_equal(object->type, amxd_object_singleton);
    assert_false(object->attr.read_only);
    assert_false(object->attr.priv);
    assert_false(object->attr.persistent);
    assert_false(object->attr.locked);
    assert_int_equal(object->index, 0);
    assert_true(amxc_llist_is_empty(&object->objects));
    assert_true(amxc_llist_is_empty(&object->instances));
    assert_int_equal(amxc_llist_size(&object->functions), 0);
    assert_true(amxc_llist_is_empty(&object->derived_objects));
    assert_ptr_not_equal(object->derived_from.llist, NULL);
    assert_ptr_equal(object->it.llist, NULL);
    amxd_object_delete(&object);
    assert_ptr_equal(object, NULL);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "_test-object2"), 0);
    assert_ptr_not_equal(object, NULL);
    amxd_object_delete(&object);
    assert_ptr_equal(object, NULL);
}

void test_amxd_object_new_template(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "test_object"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->name, "test_object");
    assert_int_equal(object->type, amxd_object_template);
    assert_false(object->attr.read_only);
    assert_false(object->attr.priv);
    assert_false(object->attr.persistent);
    assert_false(object->attr.locked);
    assert_int_equal(object->index, 0);
    assert_true(amxc_llist_is_empty(&object->objects));
    assert_true(amxc_llist_is_empty(&object->instances));
    assert_int_equal(amxc_llist_size(&object->functions), 0);
    assert_true(amxc_llist_is_empty(&object->derived_objects));
    assert_ptr_not_equal(object->derived_from.llist, NULL);
    assert_ptr_equal(object->it.llist, NULL);
    amxd_object_delete(&object);
    assert_ptr_equal(object, NULL);

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "_test-object2"), 0);
    assert_ptr_not_equal(object, NULL);
    amxd_object_delete(&object);
    assert_ptr_equal(object, NULL);
}

void test_amxd_object_new_mib(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_mib, "test-object"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->name, "test-object");
    assert_int_equal(object->type, amxd_object_mib);
    assert_false(object->attr.read_only);
    assert_false(object->attr.priv);
    assert_false(object->attr.persistent);
    assert_false(object->attr.locked);
    assert_int_equal(object->index, 0);
    assert_true(amxc_llist_is_empty(&object->objects));
    assert_true(amxc_llist_is_empty(&object->instances));
    assert_true(amxc_llist_is_empty(&object->functions));
    assert_true(amxc_llist_is_empty(&object->derived_objects));
    assert_ptr_equal(object->derived_from.llist, NULL);
    assert_ptr_equal(object->it.llist, NULL);
    amxd_object_delete(&object);
    assert_ptr_equal(object, NULL);
}

void test_amxd_object_new_invalid_type(UNUSED void** state) {
    amxd_object_t* object = NULL;
    assert_int_not_equal(amxd_object_new(&object, amxd_object_root, "test_object"), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_instance, "test_object"), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_invalid, "test_object"), 0);
    assert_ptr_equal(object, NULL);
}

void test_amxd_object_new_invalid_name(UNUSED void** state) {
    amxd_object_t* object = NULL;
    assert_int_not_equal(amxd_object_new(&object, amxd_object_template, "1_test_object"), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_template, "test&object"), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_template, "-test_object"), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_template, ""), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new(&object, amxd_object_template, NULL), 0);
    assert_ptr_equal(object, NULL);
}

void test_amxd_object_new_instance(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "test_object"), 0);
    assert_ptr_not_equal(template, NULL);

    assert_int_equal(amxd_object_new_instance(&object, template, "test_instance1", 0, NULL), 0);
    assert_ptr_not_equal(object, NULL);
    assert_string_equal(object->name, "test_instance1");
    assert_int_equal(object->type, amxd_object_instance);
    assert_false(object->attr.read_only);
    assert_false(object->attr.priv);
    assert_false(object->attr.persistent);
    assert_false(object->attr.locked);
    assert_int_equal(object->index, 1);
    assert_true(amxc_llist_is_empty(&object->objects));
    assert_true(amxc_llist_is_empty(&object->instances));
    assert_true(amxc_llist_is_empty(&object->functions));
    assert_true(amxc_llist_is_empty(&object->derived_objects));
    assert_ptr_equal(object->derived_from.llist, NULL);
    assert_ptr_equal(object->it.llist, &template->instances);
    amxd_object_delete(&template);

    amxd_object_delete(&template);
}

void test_amxd_object_new_instance_invalid_name_index(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "test_object"), 0);
    assert_ptr_not_equal(template, NULL);

    assert_int_equal(amxd_object_new_instance(&object, template, "test-instance1", 0, NULL), 0);
    assert_int_equal(object->index, 1);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "test-instance2", 1, NULL), 0);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "test-instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&object, template, NULL, 0, NULL), 0);
    assert_int_equal(object->index, 2);
    assert_int_equal(amxd_object_new_instance(&object, template, NULL, 5, NULL), 0);
    assert_int_equal(object->index, 5);
    assert_int_equal(amxd_object_new_instance(&object, template, "", 0, NULL), 0);
    assert_int_equal(object->index, 6);

    assert_int_not_equal(amxd_object_new_instance(&object, template, "1", 0, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "Test#Instance", 0, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "Test.Instance", 0, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "Test/Instance", 0, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new_instance(&object, template, "1Q", 0, NULL), 0);
    assert_ptr_equal(object, NULL);

    amxd_object_delete(&template);
}

void test_amxd_object_new_instance_of_singelton(UNUSED void** state) {
    amxd_object_t* singelton = NULL;
    amxd_object_t* object = NULL;
    assert_int_equal(amxd_object_new(&singelton, amxd_object_singleton, "test_object"), 0);
    assert_ptr_not_equal(singelton, NULL);

    assert_int_not_equal(amxd_object_new_instance(&object, singelton, "instance1", 0, NULL), 0);
    assert_ptr_equal(object, NULL);

    amxd_object_delete(&singelton);
}

void test_amxd_object_new_instance_with_children(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* child_object = NULL;
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "test_object"), 0);
    assert_ptr_not_equal(template, NULL);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "sub-object-1"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_object_new(&child_object, amxd_object_singleton, "sub-object-2"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_add_object(template, child_object), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "sub-object-3"), 0);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxc_llist_size(&template->objects), 3);

    assert_int_equal(amxd_object_new_instance(&object, template, "instance-1", 0, NULL), 0);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxc_llist_size(&object->objects), 3);
    assert_int_equal(amxc_llist_size(&child_object->derived_objects), 1);

    amxd_object_delete(&child_object);

    amxd_dm_clean(&dm);
}

void test_amxd_object_new_delete_invalid_args(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "test_object"), 0);
    assert_ptr_not_equal(template, NULL);

    assert_int_not_equal(amxd_object_new_instance(&object, NULL, "instance1", 0, NULL), 0);
    assert_ptr_equal(object, NULL);
    assert_int_not_equal(amxd_object_new_instance(NULL, template, "instance1", 0, NULL), 0);

    amxd_object_delete(&template);
    amxd_object_delete(&template);
    amxd_object_delete(NULL);

    assert_int_not_equal(amxd_object_new(NULL, amxd_object_template, "test_object"), 0);
}

void test_amxd_object_get_name(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* child1 = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* instance_child2 = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&parent, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_object_new(&child1, amxd_object_template, "child"), 0);
    assert_int_equal(amxd_object_new(&child2, amxd_object_template, "sub-child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_add_object(parent, child1), 0);
    assert_int_equal(amxd_object_add_object(child1, child2), 0);
    assert_int_equal(amxd_object_new_instance(&instance, child1, "sub-child", 0, NULL), 0);

    assert_string_equal(amxd_object_get_name(parent, AMXD_OBJECT_NAMED), "parent");
    assert_string_equal(amxd_object_get_name(child1, AMXD_OBJECT_NAMED), "child");
    assert_string_equal(amxd_object_get_name(child2, AMXD_OBJECT_NAMED), "sub-child");
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "sub-child");
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_INDEXED), "1");
    assert_ptr_equal(amxd_object_get_name(amxd_dm_get_root(&dm), AMXD_OBJECT_NAMED), NULL);

    instance_child2 = amxd_object_findf(instance, "sub-child");
    assert_ptr_not_equal(instance_child2, NULL);
    assert_ptr_not_equal(instance_child2, child2);
    assert_string_equal(amxd_object_get_name(instance_child2, AMXD_OBJECT_NAMED), "sub-child");

    assert_ptr_equal(amxd_object_get_name(NULL, 0), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_name_of_indexed_instance(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxd_object_t* instance = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);
    assert_int_equal(amxd_object_new(&parent, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, parent), 0);
    assert_int_equal(amxd_object_new_instance(&instance, parent, NULL, 5, NULL), 0);

    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "5");

    amxd_dm_clean(&dm);
}

void test_amxd_object_attributes(UNUSED void** state) {
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "test_object"), 0);
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_read_only));
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_persistent));
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_private));
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_locked));
    assert_false(amxd_object_is_attr_set(object, 999));

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_read_only, true), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_read_only));
    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_read_only, false), 0);
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_read_only));

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_persistent, true), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_persistent));
    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_persistent, false), 0);
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_persistent));

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_private, true), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_private));
    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_private, false), 0);
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_private));

    assert_int_not_equal(amxd_object_set_attr(object, 999, false), 0);
    assert_false(amxd_object_is_attr_set(object, 999));

    assert_int_equal(amxd_object_set_attrs(object,
                                           SET_BIT(amxd_oattr_read_only) |
                                           SET_BIT(amxd_oattr_persistent) |
                                           SET_BIT(amxd_oattr_private),
                                           true), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_read_only));
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_persistent));
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_private));

    assert_int_equal(amxd_object_set_attrs(object,
                                           SET_BIT(amxd_oattr_read_only) |
                                           SET_BIT(amxd_oattr_persistent) |
                                           SET_BIT(amxd_oattr_private),
                                           false), 0);
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_read_only));
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_persistent));
    assert_false(amxd_object_is_attr_set(object, amxd_oattr_private));

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_locked, true), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_locked));
    assert_int_not_equal(amxd_object_set_attr(object, amxd_oattr_locked, false), 0);
    assert_true(amxd_object_is_attr_set(object, amxd_oattr_locked));

    assert_int_not_equal(amxd_object_set_attrs(object,
                                               SET_BIT(amxd_oattr_read_only) |
                                               SET_BIT(amxd_oattr_persistent) |
                                               SET_BIT((amxd_oattr_max + 1)),
                                               true), 0);

    amxd_object_delete(&object);

    assert_int_not_equal(amxd_object_set_attrs(NULL,
                                               SET_BIT(amxd_oattr_read_only) |
                                               SET_BIT(amxd_oattr_persistent) |
                                               SET_BIT(amxd_oattr_private),
                                               false), 0);

    assert_false(amxd_object_is_attr_set(NULL, amxd_oattr_locked));
    amxd_object_set_attr(NULL, amxd_oattr_locked, true);
}
