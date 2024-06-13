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

#include "threshold.h"
#include "dm_threshold.h"
#include "threshold_expr.h"

static amxc_var_t* threshold_get_new_value(const amxc_var_t* const data,
                                           const char* name) {
    amxc_var_t* sig_params = GET_ARG(data, "parameters");
    amxc_var_t* value = GET_ARG(sig_params, name);
    value = GET_ARG(value, "to");

    return value;
}

static bool threshold_build_trigger_event_data(amxc_var_t* event_data,
                                               amxd_object_t* threshold_obj,
                                               const amxc_var_t* sig_data) {
    bool disable = false;
    amxc_string_t full_path;
    amxc_var_t threshold_params;
    amxc_var_t* trigger_data = NULL;
    amxc_var_t* value = NULL;
    const char* ref_path = NULL;
    const char* ref_param = NULL;
    const char* op_mode = NULL;

    amxc_string_init(&full_path, 0);
    amxc_var_init(event_data);
    amxc_var_init(&threshold_params);
    amxd_object_get_params(threshold_obj, &threshold_params, amxd_dm_access_protected);
    ref_path = GET_CHAR(sig_data, "path");
    ref_param = GET_CHAR(&threshold_params, "ThresholdParam");
    op_mode = GET_CHAR(&threshold_params, "OperatingMode");
    amxc_string_appendf(&full_path, "%s%s", ref_path, ref_param);

    value = threshold_get_new_value(sig_data, ref_param);

    amxc_var_set_type(event_data, AMXC_VAR_ID_HTABLE);
    trigger_data = amxc_var_add_key(amxc_htable_t,
                                    event_data,
                                    "Trigger",
                                    NULL);
    amxc_var_add_key(cstring_t,
                     trigger_data,
                     "ParamPath",
                     amxc_string_get(&full_path, 0));

    amxc_var_set_key(trigger_data, "ParamValue", value, AMXC_VAR_FLAG_COPY);

    if(strcmp(op_mode, "Single") == 0) {
        disable = true;
    }
    amxc_string_clean(&full_path);
    amxc_var_clean(&threshold_params);

    return disable;
}

static void threshold_trigger(UNUSED const char* const sig_name,
                              const amxc_var_t* const data,
                              void* const priv) {
    amxd_object_t* threshold_obj = (amxd_object_t*) priv;
    amxc_var_t trigger_event_data;
    bool disable = false;

    amxc_var_init(&trigger_event_data);
    disable = threshold_build_trigger_event_data(&trigger_event_data,
                                                 threshold_obj,
                                                 data);
    amxd_object_send_signal(threshold_obj,
                            "Triggered",
                            &trigger_event_data,
                            true);

    if(disable) {
        amxd_trans_t trans;
        amxd_trans_init(&trans);
        amxd_trans_select_object(&trans, threshold_obj);
        amxd_trans_set_value(bool, &trans, "Enable", false);
        amxd_trans_apply(&trans, threshold_get_dm());
        amxd_trans_clean(&trans);
    }

    amxc_var_clean(&trigger_event_data);
}

static void threshold_subscribe(amxd_object_t* object,
                                amxc_var_t* params) {
    char* expr = NULL;
    char* object_path = NULL;
    amxd_path_t path;
    amxo_connection_t* con = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    const char* ref_path = GET_CHAR(params, "ReferencePath");
    const char* ref_param = GET_CHAR(params, "ThresholdParam");
    const char* oper = GET_CHAR(params, "ThresholdOperator");
    amxc_var_t* value = GET_ARG(params, "ThresholdValue");
    int retval = 0;

    amxd_path_init(&path, ref_path);
    expr = threshold_build_expression(ref_path, ref_param, oper, value);
    if((expr == NULL) || (*expr == 0)) {
        amxd_object_set_value(bool, object, "Enable", false);
    } else {
        object_path = amxd_path_get_fixed_part(&path, false);

        con = amxo_connection_get_first(threshold_get_parser(), AMXO_BUS);
        while(con != NULL) {
            bus_ctx = (amxb_bus_ctx_t*) con->priv;
            retval = amxb_subscribe(bus_ctx,
                                    object_path,
                                    expr,
                                    threshold_trigger,
                                    object);
            if(retval == 0) {
                object->priv = object_path;
                break;
            }
            con = amxo_connection_get_next(threshold_get_parser(), con, AMXO_BUS);
        }
    }

    free(expr);
    amxd_path_clean(&path);
}

void threshold_unsubscribe(amxd_object_t* object) {
    amxo_connection_t* con = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* object_path = (char*) object->priv;

    con = amxo_connection_get_first(threshold_get_parser(), AMXO_BUS);
    while(con != NULL) {
        bus_ctx = (amxb_bus_ctx_t*) con->priv;
        amxb_unsubscribe(bus_ctx, object_path, threshold_trigger, object);
        con = amxo_connection_get_next(threshold_get_parser(), con, AMXO_BUS);
    }
    object->priv = NULL;
    free(object_path);
}

void _print_event(const char* const sig_name,
                  const amxc_var_t* const data,
                  UNUSED void* const priv) {
    printf("event received - %s\n", sig_name);
    if(data != NULL) {
        printf("Event data = \n");
        fflush(stdout);
        amxc_var_dump(data, STDOUT_FILENO);
    }
}

void _threshold_changed(UNUSED const char* const sig_name,
                        const amxc_var_t* const data,
                        UNUSED void* const priv) {
    amxd_dm_t* dm = threshold_get_dm();
    amxd_object_t* object = amxd_dm_signal_get_object(dm, data);
    amxc_var_t params;
    bool enabled = false;

    amxc_var_init(&params);
    amxd_object_get_params(object, &params, amxd_dm_access_protected);
    enabled = GET_BOOL(&params, "Enable");

    if(object->priv != NULL) {
        threshold_unsubscribe(object);
    }

    if(enabled) {
        threshold_subscribe(object, &params);
    }

    amxc_var_clean(&params);
}

void _threshold_added(UNUSED const char* const sig_name,
                      const amxc_var_t* const data,
                      UNUSED void* const priv) {
    amxd_dm_t* dm = threshold_get_dm();
    amxd_object_t* object = amxd_dm_signal_get_object(dm, data);
    amxc_var_t* params = GET_ARG(data, "parameters");
    bool enabled = GET_BOOL(params, "Enable");
    uint32_t index = GET_UINT32(data, "index");

    object = amxd_object_get_instance(object, NULL, index);
    if(enabled) {
        threshold_subscribe(object, params);
    }
}
