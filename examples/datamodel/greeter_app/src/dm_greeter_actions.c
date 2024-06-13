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
#include <string.h>

#include "greeter.h"
#include "greeter_dm_funcs.h"

typedef struct _stat_refs {
    const char* name;
    uint32_t type;
    int32_t offset;
} stat_ref_t;

static stat_ref_t refs[] = {
    {"AddHistoryCount", AMXC_VAR_ID_UINT32, offsetof(greeter_stats_t, add_history) },
    {"DelHistoryCount", AMXC_VAR_ID_UINT32, offsetof(greeter_stats_t, del_history)},
    {"EventCount", AMXC_VAR_ID_UINT32, offsetof(greeter_stats_t, events)},
    { NULL, 0, 0 }
};

#define STATS_VAL(type, addr, offset) \
    ((addr == NULL) ? 0 :*((type*) (((char*) addr) + offset)))

static amxc_var_t* describe_statistic(amxc_var_t* ht_params,
                                      greeter_stats_t* stats,
                                      stat_ref_t* ref) {
    amxc_var_t* value = NULL;
    amxc_var_t* param = NULL;

    param = amxc_var_add_key(amxc_htable_t, ht_params, ref->name, NULL);

    amxd_param_build_description(param, ref->name, ref->type,
                                 SET_BIT(amxd_pattr_read_only) |
                                 SET_BIT(amxd_pattr_variable),
                                 NULL);

    value = GET_ARG(param, "value");
    amxc_var_set(uint32_t, value, STATS_VAL(uint32_t, stats, ref->offset));

    return param;
}

static amxd_status_t get_value_statistics(amxc_var_t* const retval,
                                          const char* filter,
                                          greeter_stats_t* stats) {
    amxd_status_t status = amxd_status_file_not_found;
    amxp_expr_t expr;
    amxc_var_t description;
    amxp_expr_status_t expr_status = amxp_expr_status_ok;

    amxc_var_init(&description);
    amxc_var_set_type(&description, AMXC_VAR_ID_HTABLE);

    if(filter != NULL) {
        if(amxp_expr_init(&expr, filter) != 0) {
            goto exit;
        }
    }

    for(int i = 0; refs[i].name != NULL; i++) {
        if(filter != NULL) {
            amxc_var_t* param = describe_statistic(&description, stats, &refs[i]);
            if(!amxp_expr_eval_var(&expr, param, &expr_status)) {
                amxc_var_delete(&param);
                continue;
            }
            amxc_var_delete(&param);
        }
        amxc_var_add_key(uint32_t, retval, refs[i].name,
                         STATS_VAL(uint32_t, stats, refs[i].offset));
        status = amxd_status_ok;
    }

    if(filter != NULL) {
        amxp_expr_clean(&expr);
    }

exit:
    amxc_var_clean(&description);
    return status;
}

amxd_status_t _State_check_change(UNUSED amxd_object_t* object,
                                  amxd_param_t* param,
                                  amxd_action_t reason,
                                  const amxc_var_t* const args,
                                  amxc_var_t* const retval,
                                  UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    const char* current_value = NULL;
    char* new_value = NULL;

    amxc_var_clean(retval);
    if(param == NULL) {
        goto exit;
    }
    if(reason != action_param_validate) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }
    if(amxc_var_is_null(args)) {
        status = amxd_status_invalid_value;
        goto exit;
    }

    current_value = amxc_var_constcast(cstring_t, &param->value);
    new_value = amxc_var_dyncast(cstring_t, args);

    // Allowed state changes are:
    // 1. "Idle" => "Start"
    // 2. "Running" => "Stop"
    if(strcmp(current_value, new_value) == 0) {  // no state chage
        status = amxd_status_ok;
        goto exit;
    }
    if((strcmp(current_value, "Idle") == 0) &&
       (strcmp(new_value, "Start") != 0)) {
        status = amxd_status_invalid_value;
        goto exit;
    }
    if((strcmp(current_value, "Running") == 0) &&
       (strcmp(new_value, "Stop") != 0)) {
        status = amxd_status_invalid_value;
        goto exit;
    }

    status = amxd_status_ok;

exit:
    free(new_value);
    return status;
}

amxd_status_t _stats_read(amxd_object_t* object,
                          amxd_param_t* param,
                          amxd_action_t reason,
                          const amxc_var_t* const args,
                          amxc_var_t* const retval,
                          void* priv) {
    amxd_status_t status = amxd_action_object_read(object,
                                                   param,
                                                   reason,
                                                   args,
                                                   retval,
                                                   priv);
    greeter_stats_t* stats = greeter_get_stats();
    amxc_string_t filter;

    amxc_string_init(&filter, 0);

    if((status != amxd_status_ok) &&
       ( status != amxd_status_parameter_not_found)) {
        goto exit;
    }

    status = amxd_action_object_read_filter(&filter, args);
    if(status == 0) {
        status = get_value_statistics(retval,
                                      amxc_string_get(&filter, 0),
                                      stats);
    }

exit:
    amxc_string_clean(&filter);
    return status;
}

amxd_status_t _stats_list(amxd_object_t* object,
                          amxd_param_t* param,
                          amxd_action_t reason,
                          const amxc_var_t* const args,
                          amxc_var_t* const retval,
                          void* priv) {
    amxd_status_t status = amxd_action_object_list(object,
                                                   param,
                                                   reason,
                                                   args,
                                                   retval,
                                                   priv);
    amxc_var_t* params = NULL;
    if(status != amxd_status_ok) {
        goto exit;
    }
    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    for(int i = 0; refs[i].name != NULL; i++) {
        amxc_var_add(cstring_t, params, refs[i].name);
    }

exit:
    return status;
}

amxd_status_t _stats_describe(amxd_object_t* object,
                              amxd_param_t* param,
                              amxd_action_t reason,
                              const amxc_var_t* const args,
                              amxc_var_t* const retval,
                              void* priv) {
    amxd_status_t status = amxd_action_object_describe(object,
                                                       param,
                                                       reason,
                                                       args,
                                                       retval,
                                                       priv);
    greeter_stats_t* stats = greeter_get_stats();
    amxc_var_t* params = NULL;
    if(status != amxd_status_ok) {
        goto exit;
    }
    params = amxc_var_get_path(retval, "parameters", AMXC_VAR_FLAG_DEFAULT);
    for(int i = 0; refs[i].name != NULL; i++) {
        describe_statistic(params, stats, &refs[i]);
    }


exit:
    return status;
}