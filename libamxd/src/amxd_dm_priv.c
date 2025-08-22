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
#include <string.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm_functions.h>

#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static amxc_llist_t base_objects;
static amxd_object_t base_singleton;
static amxd_object_t base_template;

static amxd_status_t amxd_object_add_list_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);
    amxc_var_set(bool, &def_val, true);

    retval = amxd_function_new(&func, "_list", AMXC_VAR_ID_HTABLE, amxd_object_func_list);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "functions", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "functions", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "objects", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "objects", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "instances", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "instances", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "template_info", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "template_info", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(bool, &def_val, false);
    retval = amxd_function_new_arg(func, "events", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "events", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_get_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);
    amxc_var_set(cstring_t, &def_val, ".");

    retval = amxd_function_new(&func, "_get", AMXC_VAR_ID_HTABLE, amxd_object_func_get);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    amxc_var_set_type(&def_val, AMXC_VAR_ID_LIST);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_LIST, &def_val);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, 0);
    retval = amxd_function_new_arg(func, "depth", AMXC_VAR_ID_INT32, &def_val);
    amxd_function_arg_set_attr(func, "depth", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "filter", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_arg_set_attr(func, "filter", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "filter", amxd_aattr_strict, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_get_instances_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);
    amxc_var_set(cstring_t, &def_val, ".");

    retval = amxd_function_new(&func, "_get_instances", AMXC_VAR_ID_HTABLE, amxd_object_func_get_instances);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, 0);
    retval = amxd_function_new_arg(func, "depth", AMXC_VAR_ID_INT32, &def_val);
    amxd_function_arg_set_attr(func, "depth", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_get_supported_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);
    amxc_var_set(bool, &def_val, true);

    retval = amxd_function_new(&func,
                               "_get_supported",
                               AMXC_VAR_ID_HTABLE,
                               amxd_object_func_get_supported);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "first_level_only", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "first_level_only", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(bool, &def_val, false);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "functions", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "functions", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "events", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "events", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_set_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);

    retval = amxd_function_new(&func, "_set", AMXC_VAR_ID_NULL, amxd_object_func_set);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    amxc_var_set_type(&def_val, AMXC_VAR_ID_HTABLE);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_HTABLE, &def_val);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "oparameters", AMXC_VAR_ID_HTABLE, &def_val);
    amxd_function_arg_set_attr(func, "oparameters", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(func, "oparameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(bool, &def_val, false);
    retval = amxd_function_new_arg(func, "allow_partial", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "allow_partial", amxd_aattr_in, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_add_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);

    retval = amxd_function_new(&func, "_add", AMXC_VAR_ID_NULL, amxd_object_func_add);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_HTABLE, NULL);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "index", AMXC_VAR_ID_UINT32, NULL);
    amxd_function_arg_set_attr(func, "index", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "name", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_arg_set_attr(func, "name", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_del_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t def_val;
    amxd_function_t* func = NULL;

    amxc_var_init(&def_val);

    retval = amxd_function_new(&func, "_del", AMXC_VAR_ID_NULL, amxd_object_func_del);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "index", AMXC_VAR_ID_UINT32, NULL);
    amxd_function_arg_set_attr(func, "index", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "name", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_arg_set_attr(func, "name", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_describe_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;

    amxc_var_init(&def_val);
    amxc_var_set(bool, &def_val, false);

    retval = amxd_function_new(&func, "_describe", AMXC_VAR_ID_HTABLE, amxd_object_func_describe);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "functions", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "functions", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "objects", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "objects", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "instances", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "instances", amxd_aattr_in, true);
    when_failed(retval, exit);
    retval = amxd_function_new_arg(func, "exists", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "exists", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(uint32_t, &def_val, amxd_dm_access_protected);
    retval = amxd_function_new_arg(func, "access", AMXC_VAR_ID_UINT32, &def_val);
    amxd_function_arg_set_attr(func, "access", amxd_aattr_in, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(bool, &def_val, false);
    retval = amxd_function_new_arg(func, "events", AMXC_VAR_ID_BOOL, &def_val);
    amxd_function_arg_set_attr(func, "events", amxd_aattr_in, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

static amxd_status_t amxd_object_add_exec_func(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;

    amxc_var_init(&def_val);
    amxc_var_set(bool, &def_val, false);

    retval = amxd_function_new(&func, "_exec", AMXC_VAR_ID_ANY, amxd_object_func_exec);
    when_failed(retval, exit);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    amxd_function_set_attr(func, amxd_fattr_protected, true);
    retval = amxd_function_new_arg(func, "method", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_arg_set_attr(func, "method", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "method", amxd_aattr_mandatory, true);
    amxd_function_arg_set_attr(func, "method", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set_type(&def_val, AMXC_VAR_ID_HTABLE);
    retval = amxd_function_new_arg(func, "args", AMXC_VAR_ID_HTABLE, &def_val);
    amxd_function_arg_set_attr(func, "args", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "args", amxd_aattr_out, true);
    amxd_function_arg_set_attr(func, "args", amxd_aattr_strict, true);
    when_failed(retval, exit);
    amxc_var_set(cstring_t, &def_val, "");
    retval = amxd_function_new_arg(func, "rel_path", AMXC_VAR_ID_CSTRING, &def_val);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "rel_path", amxd_aattr_strict, true);
    when_failed(retval, exit);

    retval = amxd_object_add_function(object, func);

exit:
    if(retval != 0) {
        amxd_function_delete(&func);
    }
    amxc_var_clean(&def_val);
    return retval;
}

void PRIVATE amxd_object_init_base(amxd_object_t* const object,
                                   const amxd_object_type_t type) {
    amxc_llist_it_init(&object->it);

    object->type = type;
    object->attr.read_only = 0;
    object->attr.priv = 0;
    object->attr.prot = 0;
    object->attr.persistent = 0;
    object->attr.locked = 0;

    object->index = 0;
    object->last_index = 0;

    object->name = NULL;
    object->index_name = NULL;

    amxc_llist_init(&object->objects);
    amxc_llist_init(&object->instances);
    amxc_llist_init(&object->functions);
    amxc_llist_init(&object->parameters);
    amxc_var_init(&object->events);
    amxc_var_set_type(&object->events, AMXC_VAR_ID_HTABLE);

    amxc_llist_init(&object->cb_fns);

    amxc_llist_init(&object->derived_objects);
    amxc_llist_it_init(&object->derived_from);

    amxc_array_init(&object->mib_names, 0);
}

bool PRIVATE amxd_object_is_base(const amxd_object_t* const object) {
    return ((object == &base_singleton) || (object == &base_template));
}

amxd_status_t PRIVATE amxd_dm_base_add_funcs(amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;

    // list function
    retval = amxd_object_add_list_func(object);
    when_failed(retval, exit);

    // describe function
    retval = amxd_object_add_describe_func(object);
    when_failed(retval, exit);

    // get function
    retval = amxd_object_add_get_func(object);
    when_failed(retval, exit);

    // get instances function
    retval = amxd_object_add_get_instances_func(object);
    when_failed(retval, exit);

    // get_supported dm function
    retval = amxd_object_add_get_supported_func(object);
    when_failed(retval, exit);

    // set function
    retval = amxd_object_add_set_func(object);
    when_failed(retval, exit);

    // add (inst) function
    retval = amxd_object_add_add_func(object);
    when_failed(retval, exit);

    // del (inst) function
    retval = amxd_object_add_del_func(object);
    when_failed(retval, exit);

    // del (inst) function
    retval = amxd_object_add_exec_func(object);

exit:
    return retval;
}

void PRIVATE amxd_dm_event(const char* signal,
                           const amxd_object_t* const object,
                           amxc_var_t* const data,
                           bool trigger) {
    amxd_dm_t* dm = amxd_object_get_dm(object);
    char* path = NULL;
    char* epath = NULL;
    char* index_path = NULL;
    amxc_var_t signal_data;

    when_null(dm, exit);

    path = amxd_object_get_path(object, AMXD_OBJECT_NAMED | AMXD_OBJECT_TERMINATE);
    epath = amxd_object_get_path(object, AMXD_OBJECT_NAMED | AMXD_OBJECT_EXTENDED | AMXD_OBJECT_TERMINATE);
    index_path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
    amxc_var_init(&signal_data);

    amxc_var_set_type(&signal_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &signal_data, "object", path);
    amxc_var_add_key(cstring_t, &signal_data, "path", index_path);
    amxc_var_add_key(cstring_t, &signal_data, "eobject", epath);
    if(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) {
        const amxc_htable_t* table_data = amxc_var_constcast(amxc_htable_t, data);
        amxc_htable_it_t* hit = amxc_htable_get_first(table_data);
        while(hit) {
            amxc_var_t* part = amxc_var_from_htable_it(hit);
            const char* key = amxc_htable_it_get_key(hit);
            if(GET_ARG(&signal_data, key) == NULL) {
                amxc_var_set_key(&signal_data, key, part, AMXC_VAR_FLAG_DEFAULT);
            } else {
                amxc_var_delete(&part);
            }
            hit = amxc_htable_get_first(table_data);
        }
    } else {
        amxc_var_set_key(&signal_data, "data", data, AMXC_VAR_FLAG_COPY);
    }
    if(trigger) {
        amxp_sigmngr_trigger_signal(&dm->sigmngr, signal, &signal_data);
    } else {
        amxp_sigmngr_emit_signal(&dm->sigmngr, signal, &signal_data);
    }

    amxc_var_clean(&signal_data);
    free(path);
    free(epath);
    free(index_path);

exit:
    return;
}

void PRIVATE amxd_dm_set_derived_from(amxd_object_t* const object) {
    amxd_object_type_t type = amxd_object_get_type(object);
    switch(type) {
    case amxd_object_singleton:
    case amxd_object_root:
        amxc_llist_append(&base_singleton.derived_objects, &object->derived_from);
        break;
    case amxd_object_template:
        amxc_llist_append(&base_template.derived_objects, &object->derived_from);
        break;
    default:
        break;
    }
}

void PRIVATE amxd_common_set_flag(amxc_var_t** flags, const char* flag) {
    amxc_var_t* f = NULL;

    if((*flags) == NULL) {
        amxc_var_new(flags);
        amxc_var_set_type((*flags), AMXC_VAR_ID_HTABLE);
    }
    f = GET_ARG((*flags), flag);
    if(f == NULL) {
        amxc_var_add_key(bool, (*flags), flag, true);
    } else {
        amxc_var_set(bool, f, true);
    }

    return;
}

void PRIVATE amxd_common_unset_flag(amxc_var_t** flags, const char* flag) {
    amxc_var_t* f = NULL;
    const amxc_htable_t* ht_flags = NULL;

    when_null((*flags), exit);

    ht_flags = amxc_var_constcast(amxc_htable_t, *flags);
    f = GET_ARG((*flags), flag);
    amxc_var_delete(&f);

    if(amxc_htable_is_empty(ht_flags)) {
        amxc_var_delete(flags);
    }

exit:
    return;
}

bool PRIVATE amxd_common_has_flag(const amxc_var_t* const flags, const char* flag) {
    bool retval = false;
    const amxc_htable_t* ht_flags = NULL;

    when_null(flags, exit);

    ht_flags = amxc_var_constcast(amxc_htable_t, flags);
    retval = amxc_htable_contains(ht_flags, flag);

exit:
    return retval;
}

void amxd_init_base(void) {
    if(amxc_llist_is_empty(&base_singleton.functions)) {
        amxc_llist_init(&base_objects);

        amxd_object_init_base(&base_singleton, amxd_object_singleton);
        amxd_dm_base_add_funcs(&base_singleton);
        amxc_llist_append(&base_objects, &base_singleton.it);

        amxd_object_init_base(&base_template, amxd_object_template);
        amxc_llist_append(&base_objects, &base_template.it);
        amxc_llist_append(&base_singleton.derived_objects, &base_template.derived_from);
    }
}

CONSTRUCTOR static void amxd_base_objects_init(void) {
    amxd_init_base();
}

DESTRUCTOR static void amxd_base_objects_cleanup(void) {
    amxc_llist_clean(&base_singleton.functions, amxd_object_free_func_it);
    amxc_var_clean(&base_singleton.events);
    amxc_llist_clean(&base_template.functions, amxd_object_free_func_it);
    amxc_var_clean(&base_template.events);
}
