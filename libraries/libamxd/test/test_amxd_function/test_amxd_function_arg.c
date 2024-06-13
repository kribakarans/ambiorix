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
#include <amxd/amxd_function.h>

#include "test_amxd_function.h"

#include <amxc/amxc_macros.h>
static amxd_status_t test_func(amxd_object_t* object,
                               amxd_function_t* func,
                               amxc_var_t* args,
                               amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    return 0;
}

void test_amxd_function_new_del_arg(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxc_var_t def_val;
    amxc_var_init(&def_val);
    amxc_var_set(uint32_t, &def_val, 10);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_ANY, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);

    assert_int_not_equal(amxd_function_new_arg(function, "", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_not_equal(amxd_function_new_arg(function, NULL, AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_equal(amxd_function_new_arg(function, "123", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_not_equal(amxd_function_new_arg(NULL, "arg3", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_not_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_equal(amxc_llist_size(&function->args), 3);

    amxd_function_del_arg(function, "arg1");
    amxd_function_del_arg(NULL, "arg1");
    amxd_function_del_arg(function, "");
    amxd_function_del_arg(function, NULL);
    amxd_function_del_arg(function, "blabla");
    amxd_function_del_arg(function, "arg1");
    assert_int_equal(amxc_llist_size(&function->args), 2);

    amxc_var_clean(&def_val);
    amxd_function_delete(&function);
}

void test_amxd_function_arg_attributes(UNUSED void** state) {
    amxd_function_t* function = NULL;

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);

    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_in));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_out));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_mandatory));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_strict));

    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_in, true), 0);
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_in));
    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_in, false), 0);
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_in));

    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_out, true), 0);
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_out));
    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_out, false), 0);
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_out));

    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_mandatory, true), 0);
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_mandatory));
    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_mandatory, false), 0);
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_mandatory));

    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_strict, true), 0);
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_strict));
    assert_int_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_strict, false), 0);
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_strict));

    assert_int_equal(amxd_function_arg_set_attrs(function, "arg1", SET_BIT(amxd_aattr_in) |
                                                 SET_BIT(amxd_aattr_out) |
                                                 SET_BIT(amxd_aattr_mandatory) |
                                                 SET_BIT(amxd_aattr_strict), true), 0);
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_in));
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_out));
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_mandatory));
    assert_true(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_strict));

    assert_int_equal(amxd_function_arg_set_attrs(function, "arg1", SET_BIT(amxd_aattr_in) |
                                                 SET_BIT(amxd_aattr_out) |
                                                 SET_BIT(amxd_aattr_mandatory) |
                                                 SET_BIT(amxd_aattr_strict), false), 0);
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_in));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_out));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_mandatory));
    assert_false(amxd_function_arg_is_attr_set(function, "arg1", amxd_aattr_strict));

    amxd_function_arg_set_attr(NULL, "arg1", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(function, NULL, amxd_aattr_strict, true);
    assert_false(amxd_function_arg_is_attr_set(NULL, "arg1", amxd_aattr_mandatory));
    assert_false(amxd_function_arg_is_attr_set(function, NULL, amxd_aattr_mandatory));

    amxd_function_delete(&function);
}