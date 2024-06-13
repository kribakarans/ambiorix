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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "amx_fcgi.h"

typedef struct _event_translation {
    const char* name;
    event_type_t type;
} event_transl_t;

static event_type_t amx_fcgi_get_event_type(const char* event_name) {
    event_transl_t translator[] = {
        { "dm:object-changed", EV_VALUE_CHANGED },
        { "dm:root-added", EV_IGNORE},
        { "dm:object-added", EV_IGNORE},
        { "dm:instance-added", EV_OBJECT_CREATED},
        { "dm:root-removed", EV_IGNORE},
        { "dm:object-removed", EV_IGNORE},
        { "dm:instance-removed", EV_OBJECT_DELETED},
        { "dm:mib-added", EV_IGNORE},
        { "dm:mid-removed", EV_IGNORE},
        { "dm:operation-complete", EV_OPERATION_COMPLETED},
    };

    event_type_t type = EV_EVENT;

    for(uint32_t i = 0; i < sizeof(translator) / sizeof(event_transl_t); i++) {
        if(strcmp(event_name, translator[i].name) == 0) {
            type = translator[i].type;
            break;
        }
    }

    return type;
}

static const char* amx_fcgi_event_name(event_type_t type, const char* name) {
    const char* names[] = {
        NULL, "ValueChange", "ObjectCreation", "ObjectDeletion",
        "OperationComplete", "Event", "Error"
    };

    if(type == EV_EVENT) {
        return name;
    }

    return names[type];
}

static void amx_fcgi_build_params_table(amxc_var_t* props, amxc_var_t* params) {
    amxc_var_for_each(param, params) {
        const char* param_name = amxc_var_key(param);
        amxc_var_t* value = amxc_var_add_new_key(props, param_name);
        if(amxc_var_is_null(GET_ARG(param, "to"))) {
            amxc_var_copy(value, param);
        } else {
            amxc_var_copy(value, GET_ARG(param, "to"));
        }
    }
}

static void amx_fcgi_filter_params(amxc_var_t* params, amxc_var_t* keys) {
    amxc_var_for_each(key, keys) {
        const char* name = amxc_var_key(key);
        amxc_var_t* param = GET_ARG(params, name);
        amxc_var_delete(&param);
    }
}

static void amx_fcgi_convert_value_changed(amxc_var_t* dst, const amxc_var_t* src) {
    amxc_var_t* properties = NULL;
    amxc_var_t* parameters = NULL;

    const char* name = amx_fcgi_event_name(EV_VALUE_CHANGED, GET_CHAR(src, "notification"));

    amxc_var_set_type(dst, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, dst, "path", GET_CHAR(src, "path"));
    amxc_var_add_key(cstring_t, dst, "event_name", name);

    properties = amxc_var_add_key(amxc_htable_t, dst, "parameters", NULL);
    parameters = GET_ARG(src, "parameters");
    amx_fcgi_build_params_table(properties, parameters);
}

static void amx_fcgi_convert_object_creation_deletion(amxc_var_t* dst,
                                                      const amxc_var_t* src) {
    amxc_var_t* properties = NULL;
    amxc_var_t* keylist = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* keys = NULL;
    amxc_string_t path;
    event_type_t type = amx_fcgi_get_event_type(GET_CHAR(src, "notification"));
    const char* name = amx_fcgi_event_name(type, GET_CHAR(src, "notification"));

    amxc_string_init(&path, 0);
    amxc_var_set_type(dst, AMXC_VAR_ID_HTABLE);

    amxc_string_setf(&path, "%s%d.", GET_CHAR(src, "path"), GET_UINT32(src, "index"));
    amxc_var_add_key(cstring_t, dst, "path", amxc_string_get(&path, 0));
    amxc_var_add_key(cstring_t, dst, "event_name", name);

    properties = amxc_var_add_key(amxc_htable_t, dst, "parameters", NULL);
    keylist = amxc_var_add_key(amxc_htable_t, dst, "uniqueKeyList", NULL);
    parameters = GET_ARG(src, "parameters");
    keys = GET_ARG(src, "keys");
    amx_fcgi_filter_params(parameters, keys);
    amx_fcgi_build_params_table(properties, parameters);
    amx_fcgi_build_params_table(keylist, keys);

    amxc_string_clean(&path);
}

static void amx_fcgi_convert_op_complete(amxc_var_t* dst,
                                         const amxc_var_t* src) {
    event_type_t type = amx_fcgi_get_event_type(GET_CHAR(src, "notification"));
    const char* name = amx_fcgi_event_name(type, GET_CHAR(src, "notification"));
    amxc_var_set_type(dst, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, dst, "event_name", name);
    amxc_var_set_key(dst, "path", GET_ARG(src, "path"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "output_args", GET_ARG(src, "output_args"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "command_key", GET_ARG(src, "command_key"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "command_name", GET_ARG(src, "command_name"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "err_msg", GET_ARG(src, "err_msg"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "err_code", GET_ARG(src, "err_code"), AMXC_VAR_FLAG_COPY);
}

static void amx_fcgi_convert_custom(amxc_var_t* dst,
                                    const amxc_var_t* src) {
    amxc_var_t* params = GET_ARG(src, "parameters");
    event_type_t type = amx_fcgi_get_event_type(GET_CHAR(src, "notification"));
    const char* name = amx_fcgi_event_name(type, GET_CHAR(src, "notification"));
    if(params == NULL) {
        params = GET_ARG(src, "data");
    }
    amxc_var_set_type(dst, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, dst, "event_name", name);
    amxc_var_set_key(dst, "path", GET_ARG(src, "path"), AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(dst, "parameters", params, AMXC_VAR_FLAG_COPY);
}

static void amx_fcgi_convert_event(event_type_t type,
                                   amxc_var_t* dst,
                                   const amxc_var_t* src) {
    switch(type) {
    case EV_VALUE_CHANGED:
        amx_fcgi_convert_value_changed(dst, src);
        break;
    case EV_OBJECT_CREATED:
    case EV_OBJECT_DELETED:
        amx_fcgi_convert_object_creation_deletion(dst, src);
        break;
    case EV_OPERATION_COMPLETED:
        amx_fcgi_convert_op_complete(dst, src);
        break;
    default:
        amx_fcgi_convert_custom(dst, src);
        break;
    }
}

static bool amx_fcgi_event_allowed(amxc_var_t* data, subscription_t* sub) {
    amxc_var_t* acls = NULL;
    bool allowed = false;
    const char* path = GET_CHAR(data, "path");
    amxb_bus_ctx_t* bus_ctx = amxb_be_who_has(path);

    when_str_empty(sub->acl_file, exit);

    acls = amxa_parse_files(sub->acl_file);
    when_null(acls, exit);
    amxa_resolve_search_paths(bus_ctx, acls, path);

    amxa_filter_notif(data, acls);

    allowed = !GET_BOOL(data, "filter-all");

exit:
    amxc_var_delete(&acls);
    return allowed;
}

int amx_fcgi_send_event(amx_fcgi_request_t* fcgi_req,
                        const char* name,
                        amxc_var_t* data) {
    FCGX_Request* request = &fcgi_req->request;
    int retval = 0;

    when_null(request, exit);

    FCGX_ClearError(request->out);
    FCGX_PutS("Content-type: text/event-stream\r\n", request->out);
    FCGX_PutS("Cache-Control: no-cache\r\n", request->out);

    if(data == NULL) {
        FCGX_FPrintF(request->out, "id: %d\r\n", fcgi_req->event_id);
        if((name != NULL) && (*name != 0)) {
            FCGX_FPrintF(request->out, "event: %s\r\n", name);
        }
        FCGX_PutS("data: \r\n\r\n", request->out);
    } else {
        const char* json_str = NULL;
        amxc_var_cast(data, AMXC_VAR_ID_JSON);
        json_str = amxc_var_constcast(jstring_t, data);

        FCGX_FPrintF(request->out, "id: %d\r\n", fcgi_req->event_id);
        FCGX_FPrintF(request->out, "event: %s\r\n", name);
        FCGX_FPrintF(request->out, "data: %s\r\n\r\n", json_str);
    }
    fcgi_req->event_id++;

    FCGX_FFlush(request->out);
    if(FCGX_GetError(request->out) != 0) {
        retval = -1;
    }

exit:
    return retval;
}

void amx_fcgi_handle_event(UNUSED const char* const sig_name,
                           const amxc_var_t* const data,
                           void* const priv) {
    subscription_t* sub = (subscription_t*) priv;
    event_stream_t* stream = amx_fcgi_subscription_get_stream(sub);
    const char* event_id = amxc_htable_it_get_key(&sub->it);
    amxc_var_t event;
    event_type_t type = EV_EVENT;
    bool acl_verify = !GET_BOOL(amx_fcgi_get_conf_opt("acl.disable"), NULL);

    amxc_var_init(&event);
    amxc_var_copy(&event, data);

    if(acl_verify) {
        when_false(amx_fcgi_event_allowed(&event, sub), exit);
    }

    type = amx_fcgi_get_event_type(GET_CHAR(data, "notification"));
    if(type != EV_IGNORE) {
        amx_fcgi_convert_event(type, &event, data);
        if(amx_fcgi_send_event(stream->fcgi_req, event_id, &event) < 0) {
            amx_fcgi_http_close_stream_request(stream);
        }
    }

exit:
    amxc_var_clean(&event);
}
