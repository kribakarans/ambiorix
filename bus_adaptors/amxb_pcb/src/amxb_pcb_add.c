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

#include "amxb_pcb.h"

static int amxb_pcb_call_add(void* const ctx,
                             const char* object,
                             const char* search_path,
                             uint32_t index,
                             const char* name,
                             amxc_var_t* values,
                             uint32_t access,
                             amxc_var_t* ret,
                             int timeout) {
    int retval = -1;
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxb_request_t* request = NULL;

    amxc_var_init(&args);
    when_failed(amxb_request_new(&request), exit);

    request->result = ret;

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", search_path);
    amxc_var_add_key(uint32_t, &args, "index", index);
    amxc_var_add_key(cstring_t, &args, "name", name);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_move(params, values);
    amxc_var_add_key(uint32_t, &args, "access", access);

    retval = amxb_pcb_invoke_root(ctx, object, "_add", &args, request, true, timeout);

    request->result = GETI_ARG(ret, 0);
    if((amxc_var_type_of(request->result) == AMXC_VAR_ID_NULL) ||
       (amxc_llist_size(amxc_var_constcast(amxc_llist_t, request->result)) == 1)) {
        amxc_var_take_it(request->result);
        amxc_var_move(ret, request->result);
    } else {
        request->result = NULL;
    }

exit:
    amxb_close_request(&request);
    amxc_var_clean(&args);
    return retval;
}

static void amxb_pcb_object_to_add_var(object_t* obj,
                                       amxc_var_t* data,
                                       UNUSED void* priv) {
    amxc_string_t path;
    char* object_ipath = object_pathChar(obj, path_attr_default);
    char* object_kpath = object_pathChar(obj, path_attr_key_notation);
    uint32_t index = atol(object_name(obj, path_attr_default));
    const char* name = object_name(obj, path_attr_key_notation);
    amxc_var_t* var_params = NULL;
    parameter_t* pcb_param = NULL;

    amxc_string_init(&path, 0);

    amxc_string_push_buffer(&path, object_ipath, strlen(object_ipath) + 2);
    amxc_string_append(&path, ".", 1);
    amxc_var_add_key(cstring_t, data, "path", amxc_string_get(&path, 0));

    amxc_string_push_buffer(&path, object_kpath, strlen(object_kpath) + 2);
    amxc_string_append(&path, ".", 1);
    amxc_var_add_key(cstring_t, data, "object", amxc_string_get(&path, 0));

    amxc_var_add_key(cstring_t, data, "name", name);
    amxc_var_add_key(uint32_t, data, "index", index);

    var_params = amxc_var_add_key(amxc_htable_t, data, "parameters", NULL);
    object_for_each_parameter(pcb_param, obj) {
        const char* param_name = parameter_name(pcb_param);
        if((parameter_attributes(pcb_param) & parameter_attr_key) == parameter_attr_key) {
            amxc_var_t* value = amxc_var_add_new_key(var_params, param_name);
            amxb_pcb_from_pcb_var(parameter_getValue(pcb_param), value);
        }
    }

    amxc_string_clean(&path);
    return;
}

static int amxb_pcb_send_add_request(amxb_pcb_t* pcb_ctx,
                                     bool key_path,
                                     const char* object,
                                     uint32_t index,
                                     const char* name,
                                     amxc_var_t* values,
                                     amxc_var_t* ret) {
    request_t* req = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = pcb_ctx->peer;
    int retval = 0;
    const amxc_htable_t* hvalues = NULL;
    amxc_var_t* retobj = NULL;
    uint32_t flags = key_path ? request_common_path_key_notation : 0;

    req = request_create_addInstance(object,
                                     index,
                                     name,
                                     request_no_object_caching | flags);

    hvalues = amxc_var_constcast(amxc_htable_t, values);
    amxc_htable_for_each(it, hvalues) {
        amxc_var_t* data = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        variant_t pcb_arg;
        variant_initialize(&pcb_arg, variant_type_unknown);
        amxb_pcb_to_pcb_var(data, &pcb_arg);
        request_addParameter(req, key, &pcb_arg);
        variant_cleanup(&pcb_arg);
    }

    amxc_var_clean(values);
    retobj = amxc_var_add(amxc_htable_t, ret, NULL);

    retval = amxb_pcb_fetch_object(pcb, peer, req, retobj, amxb_pcb_object_to_add_var, NULL);
    request_destroy(req);

    return retval;
}

static int amxb_pcb_check_resolved(amxb_pcb_t* amxb_pcb,
                                   bool key_path,
                                   amxc_var_t* resolved_table,
                                   uint32_t index,
                                   const char* name,
                                   amxc_var_t* values,
                                   amxc_var_t* ret) {
    int retval = 0;
    const amxc_htable_t* tres = amxc_var_constcast(amxc_htable_t, resolved_table);
    uint32_t size = amxc_htable_size(tres);
    uint32_t type_id = 0;
    amxc_var_t* result = NULL;

    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    if(size > 1) {
        result = amxc_var_add(amxc_llist_t, ret, NULL);
        amxc_var_for_each(obj_data, resolved_table) {
            const char* object = amxc_var_key(obj_data);
            type_id = GET_UINT32(obj_data, "%type_id");
            if(type_id != amxd_object_template) {
                retval = amxd_status_invalid_arg;
                goto exit;
            }
            retval = amxb_pcb_send_add_request(amxb_pcb, key_path, object, index, name, values, result);
        }
    } else {
        amxc_htable_it_t* first = amxc_htable_get_first(tres);
        amxc_var_t* obj_data = amxc_var_from_htable_it(first);
        const char* object = amxc_htable_it_get_key(first);
        type_id = GET_UINT32(obj_data, "%type_id");
        if(type_id != amxd_object_template) {
            retval = amxd_status_invalid_arg;
            goto exit;
        }
        retval = amxb_pcb_send_add_request(amxb_pcb, key_path, object, index, name, values, ret);
    }

exit:
    return retval;
}

int amxb_pcb_add(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t index,
                 const char* name,
                 amxc_var_t* values,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout) {
    int retval = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    amxc_var_t resolved_table;
    bool key_path = false;

    amxc_var_init(&resolved_table);
    amxc_var_set_type(&resolved_table, AMXC_VAR_ID_HTABLE);

    retval = amxb_pcb_resolve(amxb_pcb, object, search_path, NULL, 0,
                              RESOLV_PARAMETERS | RESOLV_TEMPLATES | RESOLV_EXACT_DEPTH,
                              &key_path, &resolved_table);
    if(retval == -1) {
        amxc_var_clean(&resolved_table);
        retval = amxb_pcb_call_add(ctx, object, search_path, index, name,
                                   values, access, ret, timeout);
    } else if(retval == 0) {
        retval = amxb_pcb_check_resolved(amxb_pcb, false, &resolved_table,
                                         index, name, values, ret);
    }
    if(retval != 0) {
        amxc_var_clean(ret);
        goto exit;
    }

exit:
    amxc_var_clean(&resolved_table);
    return retval;
}
