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
#include <amxp/amxp_timer.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include "test_amxd_instance_counter.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* subobject = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MainObject1"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    assert_int_equal(amxd_object_add_object(object, template), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MainObject2"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_object_new(&subobject, amxd_object_singleton, "SubObject"), 0);
    assert_int_equal(amxd_object_add_object(object, subobject), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "MainObject3"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MainObject4"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    assert_int_equal(amxd_object_add_object(object, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "Child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "ChildTemplate"), 0);
    assert_int_equal(amxd_object_add_object(object, template), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MainObject5"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    assert_int_equal(amxd_object_add_object(object, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_template, "Template"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    template = amxd_dm_findf(&dm, "MainObject1.Template");
    return template;
}

void test_amxd_set_counter(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* childtemplate = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_param_t* counter = NULL;

    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    counter = amxd_object_get_param_def(main_obj, "TemplateInstances");
    assert_ptr_not_equal(counter, NULL);
    assert_int_equal(amxd_param_get_type(counter), AMXC_VAR_ID_UINT32);
    assert_true(amxd_param_is_attr_set(counter, amxd_pattr_read_only));
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstance", NULL), 0);

    template = amxd_dm_findf(&dm, "MainObject2.SubObject");
    main_obj = amxd_object_get_parent(template);
    assert_int_not_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_ptr_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);

    template = amxd_dm_findf(&dm, "MainObject3");
    main_obj = amxd_object_get_parent(template);
    assert_int_not_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_ptr_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);

    template = amxd_dm_findf(&dm, "MainObject4.Template.Child.ChildTemplate");
    main_obj = amxd_object_get_parent(template);
    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);

    template = amxd_dm_findf(&dm, "MainObject4.Template");
    assert_int_equal(amxd_object_new_instance(&childtemplate, template, NULL, 0, NULL), 0);
    main_obj = amxd_dm_findf(&dm, "MainObject4.Template.1.Child");
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_set_predefined_counter(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* parent = NULL;
    amxd_param_t* counter = NULL;

    template = test_build_dm();
    parent = amxd_object_get_parent(template);

    assert_int_equal(amxd_param_new(&counter, "MyCounter", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(counter, amxd_pattr_counter, true);
    assert_int_equal(amxd_object_add_param(parent, counter), 0);

    assert_int_equal(amxd_object_set_counter(template, "MyCounter"), 0);

    amxd_dm_clean(&dm);

    template = test_build_dm();
    parent = amxd_object_get_parent(template);

    assert_int_equal(amxd_param_new(&counter, "MyCounter", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(parent, counter), 0);

    assert_int_not_equal(amxd_object_set_counter(template, "MyCounter"), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_set_counter_invalid(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_param_t* counter = NULL;

    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_not_equal(amxd_object_set_counter(NULL, "TemplateInstances"), 0);
    assert_int_not_equal(amxd_object_set_counter(template, NULL), 0);
    assert_int_not_equal(amxd_object_set_counter(template, ""), 0);
    assert_int_not_equal(amxd_object_set_counter(amxd_dm_get_root(&dm), "TestCounter"), 0);

    amxd_param_new(&counter, "MyCounter", AMXC_VAR_ID_UINT32);
    amxd_object_add_param(main_obj, counter);
    assert_int_not_equal(amxd_object_set_counter(template, "MyCounter"), 0);

    assert_int_equal(amxd_param_set_attr(counter, amxd_pattr_counter, true), 0);
    assert_int_equal(amxd_object_set_counter(template, "MyCounter"), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_counter_has_correct_value(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* childtemplate = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_object_t* instance = NULL;

    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 2);

    template = amxd_dm_findf(&dm, "MainObject4.Template.Child.ChildTemplate");
    main_obj = amxd_object_get_parent(template);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 3);

    template = amxd_dm_findf(&dm, "MainObject4.Template");
    assert_int_equal(amxd_object_new_instance(&childtemplate, template, NULL, 0, NULL), 0);
    main_obj = amxd_dm_findf(&dm, "MainObject4.Template.1.Child");
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_counter_changes(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_object_t* instance = NULL;
    amxd_trans_t trans;


    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject1.Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    template = amxd_dm_findf(&dm, "MainObject4.Template.Child.ChildTemplate");
    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);

    template = amxd_dm_findf(&dm, "MainObject4.Template");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject4.Template.1.Child.ChildTemplate");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    main_obj = amxd_dm_findf(&dm, "MainObject4.Template.1.Child");
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject4.Template.1.Child.ChildTemplate");
    amxd_trans_del_inst(&trans, 1, NULL);
    amxd_trans_del_inst(&trans, 2, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    main_obj = amxd_dm_findf(&dm, "MainObject4.Template.1.Child");
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 2);


    amxd_dm_clean(&dm);
}

void test_amxd_counter_is_removed_when_template_deleted(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* main_obj = NULL;

    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    assert_ptr_not_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);
    amxd_object_emit_signal(template, "dm:object-removed", NULL);
    amxd_object_delete(&template);

    while(amxp_signal_read() == 0) {
    }
    assert_ptr_equal(amxd_object_get_param_def(main_obj, "TemplateInstances"), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_counter_stops_counting_when_attribute_is_removed(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_param_t* param = NULL;
    amxd_trans_t trans;


    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject1.Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    param = amxd_object_get_param_def(main_obj, "TemplateInstances");
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    amxd_param_set_attr(param, amxd_pattr_counter, false);
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject1.Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    amxd_dm_clean(&dm);
}

void test_amxd_counter_is_not_changed_on_any_event(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* main_obj = NULL;
    amxd_param_t* param = NULL;
    amxd_trans_t trans;

    template = test_build_dm();
    main_obj = amxd_object_get_parent(template);

    assert_int_equal(amxd_object_set_counter(template, "TemplateInstances"), 0);
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject1.Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    param = amxd_object_get_param_def(main_obj, "TemplateInstances");
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    amxd_object_emit_signal(template, "dm:instance-added", NULL);
    amxd_object_emit_signal(template, "dm:instance-added", NULL);

    while(amxp_signal_read() == 0) {
    }

    param = amxd_object_get_param_def(main_obj, "TemplateInstances");
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, main_obj, "TemplateInstances", NULL), 4);

    amxd_dm_clean(&dm);
}

void test_amxd_counter_has_correct_attributes(UNUSED void** state) {
    amxd_object_t* sub_template = NULL;
    amxd_object_t* top = NULL;
    amxd_param_t* param = NULL;
    amxd_trans_t trans;

    test_build_dm();
    sub_template = amxd_dm_findf(&dm, "MainObject5.Template.Template");
    top = amxd_dm_findf(&dm, "MainObject5.Template");

    assert_int_equal(amxd_object_set_counter(sub_template, "NumberOfInstances"), 0);
    param = amxd_object_get_param_def(top, "NumberOfInstances");
    amxd_param_set_attr(param, amxd_pattr_protected, true);
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MainObject5.Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".Template");
    amxd_trans_add_inst(&trans, 0, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    while(amxp_signal_read() == 0) {
    }

    top = amxd_dm_findf(&dm, "MainObject5.Template.1");
    param = amxd_object_get_param_def(top, "NumberOfInstances");
    assert_ptr_not_equal(param, NULL);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_counter));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_protected));
    assert_int_equal(amxd_object_get_value(uint32_t, top, "NumberOfInstances", NULL), 1);


    amxd_dm_clean(&dm);

}
