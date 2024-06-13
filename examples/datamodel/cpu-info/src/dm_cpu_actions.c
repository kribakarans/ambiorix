/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cpu_info.h"
#include "dm_cpu_info.h"

static amxc_var_t* dm_describe_param(amxc_var_t* ht_params,
                                     const char* name,
                                     amxc_var_t* value) {
    amxc_var_t* param = amxc_var_add_key(amxc_htable_t,
                                         ht_params,
                                         name,
                                         NULL);

    amxd_param_build_description(param, name, amxc_var_type_of(value),
                                 SET_BIT(amxd_pattr_read_only) |
                                 SET_BIT(amxd_pattr_variable),
                                 NULL);

    amxc_var_set_key(param, "value", value, AMXC_VAR_FLAG_COPY | AMXC_VAR_FLAG_UPDATE);

    return param;
}

static amxd_status_t dm_filter_params(amxc_var_t* dest,
                                      amxc_var_t* src,
                                      const char* filter) {
    amxd_status_t status = amxd_status_parameter_not_found;
    amxp_expr_t expr;
    amxp_expr_status_t expr_status = amxp_expr_status_ok;
    amxc_var_t description;

    amxc_var_init(&description);
    amxc_var_set_type(&description, AMXC_VAR_ID_HTABLE);

    if(filter != NULL) {
        amxp_expr_init(&expr, filter);
    } else {
        amxc_var_move(dest, src);
        status = amxd_status_ok;
        goto exit;
    }

    amxc_var_set_type(dest, AMXC_VAR_ID_HTABLE);
    amxc_var_for_each(value, src) {
        const char* param_name = amxc_var_key(value);
        amxc_var_t* param = dm_describe_param(&description, param_name, value);
        if(!amxp_expr_eval_var(&expr, param, &expr_status)) {
            amxc_var_delete(&param);
            continue;
        }
        amxc_var_delete(&param);
        amxc_var_set_key(dest, param_name, value, AMXC_VAR_FLAG_DEFAULT);
    }

    amxp_expr_clean(&expr);

exit:
    if(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, dest))) {
        amxc_var_clean(dest);
    }
    amxc_var_clean(&description);
    return status;
}

amxd_status_t _cpu_read(amxd_object_t* object,
                        amxd_param_t* param,
                        amxd_action_t reason,
                        const amxc_var_t* const args,
                        amxc_var_t* const retval,
                        void* priv) {
    amxc_var_t temp;
    uint64_t percentage = 0;
    amxd_status_t status = amxd_action_object_read(object, param, reason,
                                                   args, retval, priv);
    amxc_string_t filter;

    amxc_var_init(&temp);
    amxc_string_init(&filter, 0);

    when_true(status != amxd_status_ok && status != amxd_status_parameter_not_found, exit);
    when_true(amxd_object_get_type(object) != amxd_object_instance, exit);

    status = amxd_action_object_read_filter(&filter, args);

    cpu_info_read(&temp, amxd_object_get_index(object));
    percentage = cpu_dm_get_stats(object, NULL);
    amxc_var_add_key(uint64_t, &temp, "Usage", percentage);

    dm_filter_params(retval, &temp, amxc_string_get(&filter, 0));

    if(amxc_var_is_null(retval)) {
        status = amxd_status_parameter_not_found;
    }

exit:
    amxc_string_clean(&filter);
    amxc_var_clean(&temp);
    return status;
}

amxd_status_t _cpu_list(amxd_object_t* object,
                        amxd_param_t* param,
                        amxd_action_t reason,
                        const amxc_var_t* const args,
                        amxc_var_t* const retval,
                        void* priv) {
    amxc_var_t temp;
    amxc_var_t* params = NULL;
    amxc_var_t* config = cpu_get_config();
    amxc_var_t* name_mapping = NULL;
    amxd_status_t status = amxd_action_object_list(object,
                                                   param,
                                                   reason,
                                                   args,
                                                   retval,
                                                   priv);

    amxc_var_init(&temp);

    when_false(status == amxd_status_ok, exit);
    when_true(amxd_object_get_type(object) != amxd_object_instance, exit);

    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    when_null(params, exit);

    when_null(config, exit);
    amxc_var_add(cstring_t, params, "Usage");

    name_mapping = GET_ARG(config, "cpu_field_names");
    if(name_mapping != NULL) {
        amxc_var_for_each(field, name_mapping) {
            amxc_var_add(cstring_t, params, GET_CHAR(field, NULL));
        }
    } else {
        cpu_info_read(&temp, amxd_object_get_index(object));
        amxc_var_for_each(value, &temp) {
            const char* param_name = amxc_var_key(value);
            amxc_var_add(cstring_t, params, param_name);
        }
    }

exit:
    amxc_var_clean(&temp);
    return status;
}

amxd_status_t _cpu_describe(amxd_object_t* object,
                            amxd_param_t* param,
                            amxd_action_t reason,
                            const amxc_var_t* const args,
                            amxc_var_t* const retval,
                            void* priv) {
    amxd_status_t status = amxd_action_object_describe(object, param, reason,
                                                       args, retval, priv);
    amxc_var_t* params = NULL;
    amxc_var_t cpu_data;
    uint64_t percentage = 0;

    amxc_var_init(&cpu_data);

    when_false(status == amxd_status_ok, exit);
    when_true(amxd_object_get_type(object) != amxd_object_instance, exit);

    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    when_null(params, exit);

    cpu_info_read(&cpu_data, amxd_object_get_index(object));
    percentage = cpu_dm_get_stats(object, NULL);
    amxc_var_add_key(uint64_t, &cpu_data, "Usage", percentage);

    amxc_var_for_each(value, &cpu_data) {
        const char* key = amxc_var_key(value);
        dm_describe_param(params, key, value);
    }

exit:
    amxc_var_clean(&cpu_data);
    return status;
}

amxd_status_t _cpu_cleanup(amxd_object_t* object,
                           UNUSED amxd_param_t* param,
                           amxd_action_t reason,
                           UNUSED const amxc_var_t* const args,
                           UNUSED amxc_var_t* const retval,
                           UNUSED void* priv) {
    amxd_status_t status = amxd_status_ok;

    if(reason != action_object_destroy) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }

    free(object->priv);
    object->priv = NULL;

exit:
    return status;
}


