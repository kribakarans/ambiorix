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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "amxd_priv.h"

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_path.h>

#include "amxd_priv.h"
#include "amxd_assert.h"

static amxd_status_t amxd_object_check_key_param(amxd_object_t* const object,
                                                 amxd_param_t* const param) {
    amxd_status_t retval = amxd_status_ok;

    if(amxd_param_is_attr_set(param, amxd_pattr_key)) {
        if(((amxd_object_get_type(object) == amxd_object_template) &&
            !amxc_llist_is_empty(&object->instances)) ||
           (amxd_object_get_type(object) == amxd_object_instance) ||
           ( amxd_object_get_type(object) == amxd_object_mib) ||
           ( amxd_object_get_type(object) == amxd_object_singleton)) {
            // key parameters can not be added to
            // - template objects with instances
            // - instance objects
            // - mibs
            // - singletons
            retval = amxd_status_invalid_attr;
        }
    }

    return retval;
}

amxd_status_t amxd_object_add_param(amxd_object_t* const object,
                                    amxd_param_t* const param) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_param_t* object_param = NULL;
    when_null(object, exit);
    when_null(param, exit);
    when_not_null(param->it.llist, exit);

    when_true(amxd_object_is_attr_set(object, amxd_oattr_locked), exit);

    retval = amxd_object_check_key_param(object, param);
    when_failed(retval, exit);

    amxc_llist_for_each(it, (&object->parameters)) {
        const char* object_param_name = NULL;
        const char* param_name = NULL;
        object_param = amxc_llist_it_get_data(it, amxd_param_t, it);
        object_param_name = amxd_param_get_name(object_param);
        param_name = amxd_param_get_name(param);
        if(strcmp(param_name, object_param_name) == 0) {
            retval = amxd_status_duplicate;
            goto exit;
        }
        object_param = NULL;
    }

    // parameters added to template object by default only work on
    // instances. This is a design descision.
    // For other behavior set the attributes before adding the parameter
    // to the object
    if((amxd_object_get_type(object) == amxd_object_template) ||
       (amxd_object_get_type(object) == amxd_object_instance)) {
        if((param->attr.instance == 0) && (param->attr.templ == 0)) {
            param->attr.instance = 1;
        }
    }

    if(amxd_object_get_type(object) == amxd_object_instance) {
        if((param->attr.templ == 1) && (param->attr.instance == 0)) {
            retval = amxd_status_invalid_attr;
            goto exit;
        }
    }

    amxc_llist_append(&object->parameters, &param->it);

exit:
    return retval;
}

amxd_param_t* amxd_object_get_param_def(const amxd_object_t* const object,
                                        const char* name) {
    amxd_param_t* param = NULL;
    amxd_object_t* real_obj = (amxd_object_t*) object;
    char* real_param = NULL;
    const char* rel_path = NULL;

    when_null(object, exit);
    when_str_empty(name, exit);
    when_true(object->type == amxd_object_root, exit);

    if(strchr(name, '.') != NULL) {
        amxd_path_t param_path;
        amxd_path_init(&param_path, name);
        rel_path = amxd_path_get(&param_path, AMXD_OBJECT_TERMINATE);
        real_obj = amxd_object_findf(real_obj, "%s", rel_path);
        real_param = strdup(amxd_path_get_param(&param_path));
        amxd_path_clean(&param_path);
        when_null(real_obj, exit);
    }

    amxc_llist_for_each(it, (&real_obj->parameters)) {
        const char* param_name = NULL;
        param = amxc_llist_it_get_data(it, amxd_param_t, it);
        param_name = amxd_param_get_name(param);
        if(strcmp(param_name, (real_param == NULL)? name:real_param) == 0) {
            break;
        }
        param = NULL;
    }

exit:
    free(real_param);
    return param;
}

static const char* amxd_param_get_counted_object_name(const amxd_param_t* const param) {
    return param == NULL ? NULL : (const char* ) param->priv;
}

amxd_param_t* amxd_object_get_param_counter_by_counted_object(const amxd_object_t* const object) {
    amxd_param_t* param = NULL;
    amxd_object_t* container = NULL;
    const amxd_object_t* templ_obj = object;

    when_null(object, exit);
    when_false(amxd_object_get_type(object) == amxd_object_instance ||
               amxd_object_get_type(object) == amxd_object_template, exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        templ_obj = amxd_object_get_parent(object);

        when_null(templ_obj, exit);
        when_true(amxd_object_get_type(templ_obj) != amxd_object_template, exit);
    }

    container = amxd_object_get_parent(templ_obj);

    when_null(container, exit);
    when_true(container->type == amxd_object_root, exit);
    when_false((amxd_object_get_type(container) == amxd_object_instance) ||
               (amxd_object_get_type(container) == amxd_object_singleton), exit);

    amxc_llist_for_each(it, (&container->parameters)) {
        const char* counted_object_name = NULL;
        param = amxc_llist_it_get_data(it, amxd_param_t, it);
        counted_object_name = amxd_param_get_counted_object_name(param);
        if((counted_object_name != NULL) &&
           (strcmp(counted_object_name, amxd_object_get_name(templ_obj, AMXD_OBJECT_NAMED)) == 0) &&
           amxd_param_is_attr_set(param, amxd_pattr_counter)) {
            break;
        }
        param = NULL;
    }

exit:
    return param;
}

amxd_status_t amxd_object_set_param(amxd_object_t* const object,
                                    const char* name,
                                    amxc_var_t* const value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* params = NULL;
    amxc_var_t args;
    amxc_var_t retval;

    amxc_var_init(&args);
    amxc_var_init(&retval);
    when_null(object, exit);
    when_null(value, exit);
    when_str_empty(name, exit);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_set_key(params, name, value, AMXC_VAR_FLAG_COPY);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_add_key(bool, &args, "set_read_only", true);
    status = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_write,
                                   &args,
                                   &retval);

exit:
    amxc_var_clean(&retval);
    amxc_var_clean(&args);
    return status;
}

amxd_status_t amxd_object_get_param(amxd_object_t* const object,
                                    const char* name,
                                    amxc_var_t* const value) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxc_var_t params_value;
    amxd_param_t* def = NULL;

    amxc_var_init(&args);
    amxc_var_init(&params_value);
    when_null(object, exit);
    when_null(value, exit);
    when_str_empty(name, exit);

    def = amxd_object_get_param_def(object, name);
    if(def != NULL) {
        if(!amxd_param_has_action(def, action_param_read)) {
            if(!amxd_object_has_action(object, action_object_read)) {
                amxc_var_copy(value, &def->value);
                retval = amxd_status_ok;
                goto exit;
            }
        }
    }

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, name);
    retval = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_read,
                                   &args,
                                   &params_value);
    if(retval == amxd_status_ok) {
        amxc_var_t* param_val = amxc_var_get_path(&params_value,
                                                  name,
                                                  AMXC_VAR_FLAG_DEFAULT);
        when_null_status(param_val, exit, retval = amxd_status_parameter_not_found);
        amxc_var_copy(value, param_val);
    }

exit:
    amxc_var_clean(&params_value);
    amxc_var_clean(&args);
    return retval;
}

const amxc_var_t* amxd_object_get_param_value(const amxd_object_t* const object,
                                              const char* name) {
    amxc_var_t* value = NULL;
    amxd_param_t* param = amxd_object_get_param_def(object, name);
    if(param != NULL) {
        value = &param->value;
    }

    return value;
}

uint32_t amxd_object_get_param_count(amxd_object_t* object, amxd_dm_access_t access) {
    uint32_t count = 0;
    amxc_var_t list;

    amxc_var_init(&list);
    when_failed(amxd_object_list_params(object, &list, access), exit);
    count = amxc_llist_size(amxc_var_constcast(amxc_llist_t, &list));

exit:
    amxc_var_clean(&list);
    return count;
}

amxd_status_t amxd_object_set_cstring_t(amxd_object_t* const object,
                                        const char* name,
                                        const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(cstring_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_csv_string_t(amxd_object_t* const object,
                                           const char* name,
                                           const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(csv_string_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_ssv_string_t(amxd_object_t* const object,
                                           const char* name,
                                           const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(ssv_string_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_bool(amxd_object_t* const object,
                                   const char* name,
                                   bool value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(bool, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_int8_t(amxd_object_t* const object,
                                     const char* name,
                                     int8_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int8_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_uint8_t(amxd_object_t* const object,
                                      const char* name,
                                      uint8_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint8_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_int16_t(amxd_object_t* const object,
                                      const char* name,
                                      int16_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int16_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_uint16_t(amxd_object_t* const object,
                                       const char* name,
                                       uint16_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint16_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_int32_t(amxd_object_t* const object,
                                      const char* name,
                                      int32_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int32_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_uint32_t(amxd_object_t* const object,
                                       const char* name,
                                       uint32_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint32_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_int64_t(amxd_object_t* const object,
                                      const char* name,
                                      int64_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int64_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_uint64_t(amxd_object_t* const object,
                                       const char* name,
                                       uint64_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint64_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_double(amxd_object_t* const object,
                                     const char* name,
                                     double value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(double, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

amxd_status_t amxd_object_set_amxc_ts_t(amxd_object_t* const object,
                                        const char* name,
                                        amxc_ts_t* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(amxc_ts_t, &new_value, value);
    status = amxd_object_set_param(object, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

char* amxd_object_get_cstring_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    char* retval = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(cstring_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

bool amxd_object_get_bool(amxd_object_t* const object,
                          const char* name,
                          amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    bool retval = false;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(bool, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

int8_t amxd_object_get_int8_t(amxd_object_t* const object,
                              const char* name,
                              amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    int8_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(int8_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

uint8_t amxd_object_get_uint8_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    uint8_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(uint8_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

int16_t amxd_object_get_int16_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    int16_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(int16_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

uint16_t amxd_object_get_uint16_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    uint16_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(uint16_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

int32_t amxd_object_get_int32_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    int32_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(int32_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

uint32_t amxd_object_get_uint32_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    uint32_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(uint32_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

int64_t amxd_object_get_int64_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    int64_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(int64_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

uint64_t amxd_object_get_uint64_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    uint64_t retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(uint64_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

double amxd_object_get_double(amxd_object_t* const object,
                              const char* name,
                              amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    double retval = 0;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(double, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}

amxc_ts_t* amxd_object_get_amxc_ts_t(amxd_object_t* const object,
                                     const char* name,
                                     amxd_status_t* status) {
    amxd_status_t s = amxd_status_unknown_error;
    amxc_ts_t* retval = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    s = amxd_object_get_param(object, name, &value);
    if(s == amxd_status_ok) {
        retval = amxc_var_dyncast(amxc_ts_t, &value);
    }

    if(status != NULL) {
        *status = s;
    }
    amxc_var_clean(&value);
    return retval;
}
