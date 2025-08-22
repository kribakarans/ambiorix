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
#include <amxd/amxd_path.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_object_parameter.h>
#include <amxd/amxd_object_hierarchy.h>

#include "amxd_assert.h"

static amxd_status_t amxd_param_check_minimum(amxd_param_t* param,
                                              amxc_var_t* data,
                                              const amxc_var_t* value) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t def_val;
    amxc_var_init(&def_val);
    amxc_var_copy(&def_val, data);
    if(amxc_var_cast(&def_val, amxd_param_get_type(param)) != 0) {
        amxc_var_set_type(&def_val, amxd_param_get_type(param));
    }

    if(amxc_var_type_of(data) == AMXC_VAR_ID_CSTRING) {
        amxd_object_t* object = amxd_param_get_owner(param);
        amxc_var_t* ref_value = amxd_resolve_param_ref(object, data);
        data = ref_value == NULL ? &def_val : ref_value;
    }

    if((amxd_param_get_type(param) == AMXC_VAR_ID_CSTRING) ||
       ( amxd_param_get_type(param) == AMXC_VAR_ID_CSV_STRING) ||
       ( amxd_param_get_type(param) == AMXC_VAR_ID_SSV_STRING)) {
        int64_t min = amxc_var_dyncast(int64_t, data);
        char* text = amxc_var_dyncast(cstring_t, value);
        int64_t length = text == NULL ? 0 : strlen(text);
        if(length < min) {
            status = amxd_status_invalid_value;
        }
        free(text);
    } else {
        int result = 0;
        amxc_var_compare(data, value, &result);
        if(result > 0) {
            status = amxd_status_invalid_value;
        }
    }

    amxc_var_clean(&def_val);
    return status;
}

static amxd_status_t amxd_param_check_maximum(amxd_param_t* param,
                                              amxc_var_t* data,
                                              const amxc_var_t* value) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t def_val;
    amxc_var_init(&def_val);
    amxc_var_copy(&def_val, data);
    if(amxc_var_cast(&def_val, amxd_param_get_type(param)) != 0) {
        amxc_var_set_type(&def_val, amxd_param_get_type(param));
    }

    if(amxc_var_type_of(data) == AMXC_VAR_ID_CSTRING) {
        amxd_object_t* object = amxd_param_get_owner(param);
        amxc_var_t* ref_value = amxd_resolve_param_ref(object, data);
        data = ref_value == NULL ? data : ref_value;
    }

    if((amxd_param_get_type(param) == AMXC_VAR_ID_CSTRING) ||
       ( amxd_param_get_type(param) == AMXC_VAR_ID_CSV_STRING) ||
       ( amxd_param_get_type(param) == AMXC_VAR_ID_SSV_STRING)) {
        int64_t max = amxc_var_dyncast(int64_t, data);
        char* text = amxc_var_dyncast(cstring_t, value);
        int64_t length = text == NULL ? 0 : strlen(text);
        if(length > max) {
            status = amxd_status_invalid_value;
        }
        free(text);
    } else {
        int result = 0;
        amxc_var_compare(data, value, &result);
        if(result < 0) {
            status = amxd_status_invalid_value;
        }
    }

    amxc_var_clean(&def_val);
    return status;
}

static bool is_value_in(amxc_var_t* value, const amxc_llist_t* values) {
    bool is_in = false;
    int result = 0;

    if((amxc_var_type_of(value) == AMXC_VAR_ID_SSV_STRING) ||
       (amxc_var_type_of(value) == AMXC_VAR_ID_CSV_STRING)) {
        amxc_var_cast(value, AMXC_VAR_ID_LIST);
        is_in = true;
        amxc_var_for_each(v, value) {
            is_in &= is_value_in(v, values);
            if(!is_in) {
                break;
            }
        }
    } else {
        amxc_llist_for_each(it, values) {
            amxc_var_t* check = amxc_var_from_llist_it(it);
            amxc_var_compare(value, check, &result);
            if(result == 0) {
                is_in = true;
                break;
            }
        }
    }

    return is_in;
}

static bool is_string_empty(const amxc_var_t* value) {
    char* v = amxc_var_dyncast(cstring_t, value);
    bool retval = (v == NULL || *v == 0);
    free(v);
    return retval;
}

static bool is_key_in_template(const amxd_object_t* object,
                               const amxd_param_t* param) {
    return (amxd_param_is_attr_set(param, amxd_pattr_key) &&
            amxd_object_get_type(object) == amxd_object_template);
}

amxc_var_t* amxd_resolve_param_ref(amxd_object_t* obj,
                                   amxc_var_t* ref) {
    amxd_object_t* ref_object = NULL;
    amxd_param_t* ref_param = NULL;
    amxc_var_t* ref_value = NULL;
    amxd_dm_t* dm = amxd_object_get_dm(obj);
    char* full_ref = amxc_var_dyncast(cstring_t, ref);
    int ref_len = strlen(full_ref);
    char* object = full_ref;
    char* param = NULL;

    for(int i = ref_len; i >= 0; i--) {
        if(full_ref[i] == '.') {
            full_ref[i] = 0;
            param = full_ref + i + 1;
            break;
        }
    }

    when_str_empty(param, exit);

    if(object[0] == 0) {
        ref_object = obj;
    } else {
        if(object[0] == '.') {
            ref_object = amxd_object_findf(obj, "%s", object);
        } else {
            ref_object = amxd_dm_findf(dm, "%s", object);
        }
    }
    ref_param = amxd_object_get_param_def(ref_object, param);
    when_null(ref_param, exit);
    ref_value = &ref_param->value;

exit:
    free(full_ref);
    return ref_value;
}

amxd_status_t amxd_action_param_validate(UNUSED amxd_object_t* object,
                                         amxd_param_t* param,
                                         amxd_action_t reason,
                                         const amxc_var_t* const args,
                                         UNUSED amxc_var_t* const retval,
                                         UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t temp;

    amxc_var_init(&temp);
    when_null(param, exit);
    when_true_status(reason != action_param_validate,
                     exit,
                     status = amxd_status_function_not_implemented);

    when_true_status((args == NULL ||
                      amxc_var_type_of(args) == AMXC_VAR_ID_NULL),
                     exit,
                     status = amxd_status_invalid_value);

    // TODO: Change in amxc_var_can_covert when the function is available
    when_failed_status(amxc_var_convert(&temp,
                                        args,
                                        amxc_var_type_of(&param->value)),
                       exit,
                       status = amxd_status_invalid_value);

    status = amxd_status_ok;

exit:
    amxc_var_clean(&temp);
    return status;
}

amxd_status_t amxd_action_param_check_range(amxd_object_t* object,
                                            amxd_param_t* param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            amxc_var_t* const retval,
                                            void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    amxc_var_t* min_var = NULL;
    amxc_var_t* max_var = NULL;

    if(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) {
        min_var = amxc_var_get_key(data, "min", AMXC_VAR_FLAG_DEFAULT);
        max_var = amxc_var_get_key(data, "max", AMXC_VAR_FLAG_DEFAULT);
    } else if(amxc_var_type_of(data) == AMXC_VAR_ID_LIST) {
        min_var = amxc_var_get_path(data, "0", AMXC_VAR_FLAG_DEFAULT);
        max_var = amxc_var_get_path(data, "1", AMXC_VAR_FLAG_DEFAULT);
    } else {
        status = amxd_status_invalid_type;
        goto exit;
    }

    status = amxd_action_describe_action(reason, retval, "check_range", priv);
    when_true(status == amxd_status_ok, exit);

    status = amxd_action_param_validate(object, param, reason, args, retval, priv);
    when_failed(status, exit);

    when_true_status(is_key_in_template(object, param), exit, status = amxd_status_ok);

    status = amxd_param_check_minimum(param, min_var, args);
    when_failed(status, exit);

    status = amxd_param_check_maximum(param, max_var, args);
    when_failed(status, exit);

exit:
    return status;
}

amxd_status_t amxd_action_param_check_minimum(amxd_object_t* object,
                                              amxd_param_t* param,
                                              amxd_action_t reason,
                                              const amxc_var_t* const args,
                                              amxc_var_t* const retval,
                                              void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    const char* name = "check_minimum";

    when_null_status(param, exit, status = amxd_status_parameter_not_found);
    when_null_status(data, exit, status = amxd_status_invalid_value);

    if((amxc_var_type_of(&param->value) == AMXC_VAR_ID_CSTRING) ||
       (amxc_var_type_of(&param->value) == AMXC_VAR_ID_CSV_STRING) ||
       (amxc_var_type_of(&param->value) == AMXC_VAR_ID_SSV_STRING)) {
        name = "check_minimum_length";
    }
    status = amxd_action_describe_action(reason, retval, name, priv);
    when_true(status == amxd_status_ok, exit);

    status = amxd_action_param_validate(object, param, reason, args, retval, priv);
    when_failed(status, exit);

    when_true_status(is_key_in_template(object, param), exit, status = amxd_status_ok);

    status = amxd_param_check_minimum(param, data, args);
    when_failed(status, exit);

exit:
    return status;
}

amxd_status_t amxd_action_param_check_maximum(amxd_object_t* object,
                                              amxd_param_t* param,
                                              amxd_action_t reason,
                                              const amxc_var_t* const args,
                                              amxc_var_t* const retval,
                                              void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    const char* name = "check_maximum";

    when_null_status(param, exit, status = amxd_status_parameter_not_found);
    when_null_status(data, exit, status = amxd_status_invalid_value);

    if((amxc_var_type_of(&param->value) == AMXC_VAR_ID_CSTRING) ||
       (amxc_var_type_of(&param->value) == AMXC_VAR_ID_CSV_STRING) ||
       (amxc_var_type_of(&param->value) == AMXC_VAR_ID_SSV_STRING)) {
        name = "check_maximum_length";
    }

    status = amxd_action_describe_action(reason, retval, name, priv);
    when_true(status == amxd_status_ok, exit);

    status = amxd_action_param_validate(object, param, reason, args, retval, priv);
    when_failed(status, exit);

    when_true_status(is_key_in_template(object, param), exit, status = amxd_status_ok);

    status = amxd_param_check_maximum(param, data, args);
    when_failed(status, exit);

exit:
    return status;
}

amxd_status_t amxd_action_param_check_enum(amxd_object_t* object,
                                           amxd_param_t* param,
                                           amxd_action_t reason,
                                           const amxc_var_t* const args,
                                           amxc_var_t* const retval,
                                           void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    const amxc_llist_t* values = NULL;
    amxc_var_t check_value;

    amxc_var_init(&check_value);
    when_true_status(amxc_var_type_of(data) != AMXC_VAR_ID_LIST,
                     exit,
                     status = amxd_status_invalid_type);

    status = amxd_action_describe_action(reason, retval, "check_enum", priv);
    when_true(status == amxd_status_ok, exit);

    status = amxd_action_param_validate(object, param, reason, args, retval, priv);
    when_failed(status, exit);

    when_true_status(is_key_in_template(object, param), exit, status = amxd_status_ok);

    amxc_var_convert(&check_value, args, amxd_param_get_type(param));
    values = amxc_var_constcast(amxc_llist_t, data);
    when_false_status(is_value_in(&check_value, values),
                      exit,
                      status = amxd_status_invalid_value);

exit:
    amxc_var_clean(&check_value);
    return status;
}

amxd_status_t amxd_action_param_check_is_in(amxd_object_t* object,
                                            amxd_param_t* param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            amxc_var_t* const retval,
                                            void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    amxc_var_t* ref_value = NULL;
    amxc_llist_t* values = NULL;
    amxc_var_t check_value;

    amxc_var_init(&check_value);
    when_true_status(amxc_var_type_of(data) != AMXC_VAR_ID_CSTRING,
                     exit,
                     status = amxd_status_invalid_type);

    status = amxd_action_describe_action(reason, retval, "check_is_in", priv);
    when_true(status == amxd_status_ok, exit);

    status = amxd_action_param_validate(object, param, reason, args, retval, priv);
    when_failed(status, exit);

    when_true_status(is_key_in_template(object, param), exit, status = amxd_status_ok);

    ref_value = amxd_resolve_param_ref(object, data);
    when_true_status(ref_value == NULL &&
                     amxd_object_get_type(object) == amxd_object_template,
                     exit, status = amxd_status_ok);
    when_null_status(ref_value, exit, status = amxd_status_invalid_value);
    when_true_status(is_string_empty(ref_value), exit, status = amxd_status_ok);

    amxc_var_convert(&check_value, args, amxd_param_get_type(param));
    values = amxc_var_dyncast(amxc_llist_t, ref_value);
    when_false_status(is_value_in(&check_value, values),
                      exit,
                      status = amxd_status_invalid_value);

exit:
    amxc_var_clean(&check_value);
    amxc_llist_delete(&values, variant_list_it_free);
    return status;
}

amxd_status_t amxd_param_validate(amxd_param_t* const param,
                                  const amxc_var_t* const value) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_object_t* object = NULL;
    when_null(param, exit);

    object = amxd_param_get_owner(param);
    retval = amxd_dm_invoke_action(object,
                                   param,
                                   action_param_validate,
                                   value,
                                   NULL);

exit:
    return retval;
}
