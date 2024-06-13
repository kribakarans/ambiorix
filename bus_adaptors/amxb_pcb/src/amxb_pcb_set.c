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

static int amxb_pcb_call_set(void* const ctx,
                             const char* object,
                             const char* search_path,
                             amxc_var_t* values,
                             amxc_var_t* ovalues,
                             uint32_t access,
                             amxc_var_t* ret,
                             int timeout) {
    int retval = -1;
    amxc_var_t args;
    amxb_request_t* request = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* result = NULL;

    amxc_var_init(&args);
    when_failed(amxb_request_new(&request), exit);

    request->result = ret;

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", search_path);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_move(params, values);
    if(!amxc_var_is_null(ovalues)) {
        params = amxc_var_add_key(amxc_htable_t, &args, "oparameters", NULL);
        amxc_var_move(params, ovalues);
    }
    amxc_var_add_key(uint32_t, &args, "access", access);

    retval = amxb_pcb_invoke_root(ctx, object, "_set", &args, request, true, timeout);
    result = GETI_ARG(ret, 0);
    amxc_var_take_it(result);
    amxc_var_move(ret, result);
    amxc_var_delete(&result);

exit:
    request->result = NULL;
    amxb_close_request(&request);
    amxc_var_clean(&args);
    return retval;
}

static const char* amxb_pcb_get_failed_param(request_t* req) {
    reply_t* reply = NULL;
    reply_item_t* item = NULL;
    const char* retval = NULL;

    reply = request_reply(req);

    reply_for_each_item(item, reply) {
        if(reply_item_type(item) == reply_type_error) {
            retval = reply_item_errorInfo(item);
            break;
        }
    }

    return retval;
}

static int amxb_pcb_send_set_request(amxb_pcb_t* pcb_ctx,
                                     bool key_path,
                                     const char* object,
                                     amxc_var_t* values) {
    request_t* req = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = pcb_ctx->peer;
    int retval = 0;
    uint32_t flags = key_path ? request_common_path_key_notation : 0;

    req = request_create_setObject(object,
                                   flags |
                                   request_no_object_caching);

    amxc_var_for_each(data, values) {
        const char* key = amxc_var_key(data);
        variant_t pcb_arg;
        variant_initialize(&pcb_arg, variant_type_unknown);
        amxb_pcb_to_pcb_var(data, &pcb_arg);
        request_addParameter(req, key, &pcb_arg);
        variant_cleanup(&pcb_arg);
    }

    retval = amxb_pcb_fetch_object(pcb, peer, req, NULL, NULL, NULL);
    if(retval != 0) {
        const char* failed_param = amxb_pcb_get_failed_param(req);
        amxc_var_t* param = NULL;
        amxc_var_set_type(values, AMXC_VAR_ID_HTABLE);
        param = amxc_var_add_key(amxc_htable_t, values, failed_param, NULL);
        amxc_var_add_key(uint32_t, param, "error_code", retval);
        amxc_var_add_key(bool, param, "required", true);
    }
    request_destroy(req);

    return retval;
}

static int amxb_pcb_set_values(amxb_pcb_t* amxb_pcb,
                               bool key_path,
                               bool required,
                               const char* path,
                               amxc_var_t* values,
                               amxc_var_t* data) {
    int retval = 0;
    amxc_var_t value;
    amxc_var_init(&value);

    amxc_var_for_each(v, values) {
        const char* name = amxc_var_key(v);
        amxc_var_set_type(&value, AMXC_VAR_ID_HTABLE);
        amxc_var_set_key(&value, name, v, AMXC_VAR_FLAG_COPY);
        retval = amxb_pcb_send_set_request(amxb_pcb, key_path, path, &value);
        if(retval != 0) {
            amxc_var_t* param = amxc_var_add_key(amxc_htable_t, data, name, NULL);
            amxc_var_add_key(uint32_t, param, "error_code", retval);
            amxc_var_add_key(bool, param, "required", required);
        } else {
            amxc_var_set_key(data, name, GET_ARG(&value, name), AMXC_VAR_FLAG_DEFAULT);
        }
    }
    amxc_var_clean(&value);

    return retval;
}

static int amxb_pcb_check_resolved(amxb_pcb_t* amxb_pcb,
                                   bool key_path,
                                   uint32_t flags,
                                   amxc_var_t* resolved_table,
                                   amxc_var_t* values,
                                   amxc_var_t* ovalues) {
    int retval = 0;

    amxc_var_for_each(data, resolved_table) {
        const char* path = amxc_var_key(data);

        amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
        if((flags & AMXB_FLAG_PARTIAL) == 0) {
            if((values != NULL) &&
               !amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, values))) {
                retval = amxb_pcb_send_set_request(amxb_pcb, key_path, path, values);
                amxc_var_copy(data, values);
            }
        } else {
            if((values != NULL) &&
               !amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, values))) {
                retval = amxb_pcb_set_values(amxb_pcb, key_path, true, path, values, data);
            }
        }
        if((ovalues != NULL) &&
           !amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, ovalues))) {
            amxb_pcb_set_values(amxb_pcb, key_path, false, path, ovalues, data);
        }
    }

    return retval;
}

int amxb_pcb_set(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t flags,
                 amxc_var_t* values,
                 amxc_var_t* ovalues,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout) {
    int retval = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    amxc_var_t* resolved_table;
    bool key_path = false;

    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    resolved_table = amxc_var_add(amxc_htable_t, ret, NULL);

    retval = amxb_pcb_resolve(amxb_pcb, object, search_path, NULL, 0,
                              RESOLV_EXACT_DEPTH | RESOLV_PARAMETERS |
                              RESOLV_TEMPLATES | RESOLV_LIST,
                              &key_path, resolved_table);
    if(retval == -1) {
        retval = amxb_pcb_call_set(ctx, object, search_path,
                                   values, ovalues, access, resolved_table, timeout);
    } else if(retval == 0) {
        retval = amxb_pcb_check_resolved(amxb_pcb, false, flags, resolved_table, values, ovalues);
    }

    return retval;
}

