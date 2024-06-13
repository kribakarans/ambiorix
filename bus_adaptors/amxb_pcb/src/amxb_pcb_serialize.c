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

#include "amxb_pcb_serialize.h"

#define DDW_VERSION_01 0x01
#define EOV 0x10001 // EOV = End-Of-Variants

static int amxc_var_type_to_pcb_func_type(int amxc_type) {
    if(amxc_type > 9) {
        switch(amxc_type) {
        case AMXC_VAR_ID_FLOAT:
        case AMXC_VAR_ID_DOUBLE:
            amxc_type = function_type_double;
            break;
        case AMXC_VAR_ID_BOOL:
            amxc_type = function_type_bool;
            break;
        case AMXC_VAR_ID_LIST:
            amxc_type = function_type_list;
            break;
        case AMXC_VAR_ID_ANY:
        case AMXC_VAR_ID_HTABLE:
            amxc_type = function_type_variant;
            break;
        case AMXC_VAR_ID_FD:
            amxc_type = function_type_file_descriptor;
            break;
        case AMXC_VAR_ID_TIMESTAMP:
            amxc_type = function_type_date_time;
            break;
        case AMXC_VAR_ID_SSV_STRING:
        case AMXC_VAR_ID_CSV_STRING:
            amxc_type = function_type_string;
            break;
        default:
            amxc_type = function_type_custom;
            break;
        }
    }

    return amxc_type;
}

static int amxc_var_type_to_pcb_var_type(int amxc_type) {
    if(amxc_type > 9) {
        switch(amxc_type) {
        case AMXC_VAR_ID_FLOAT:
        case AMXC_VAR_ID_DOUBLE:
            amxc_type = variant_type_double;
            break;
        case AMXC_VAR_ID_BOOL:
            amxc_type = variant_type_bool;
            break;
        case AMXC_VAR_ID_LIST:
            amxc_type = variant_type_array;
            break;
        case AMXC_VAR_ID_HTABLE:
            amxc_type = variant_type_map;
            break;
        case AMXC_VAR_ID_FD:
            amxc_type = variant_type_file_descriptor;
            break;
        case AMXC_VAR_ID_TIMESTAMP:
            amxc_type = variant_type_date_time;
            break;
        case AMXC_VAR_ID_SSV_STRING:
        case AMXC_VAR_ID_CSV_STRING:
            amxc_type = variant_type_string;
            break;
        default:
            amxc_type = variant_type_unknown;
            break;
        }
    }

    return amxc_type;
}

static int amxc_var_type_to_pcb_param_type(int amxc_type) {
    if(amxc_type > 9) {
        switch(amxc_type) {
        case AMXC_VAR_ID_BOOL:
            amxc_type = parameter_type_bool;
            break;
        case AMXC_VAR_ID_TIMESTAMP:
            amxc_type = parameter_type_date_time;
            break;
        case AMXC_VAR_ID_SSV_STRING:
        case AMXC_VAR_ID_CSV_STRING:
            amxc_type = parameter_type_string;
            break;
        default:
            amxc_type = parameter_type_unknown;
            break;
        }
    }

    return amxc_type;
}

static inline void amxb_pcb_byte_swap(char* buf, int len) {
    static union {
        int i;
        char b[sizeof(int)];
    } test = { .i = 1 };
    if(test.b[0]) {
        int i;
        char c;
        for(i = 0; i < len / 2; i++) {
            c = buf[len - i - 1];
            buf[len - i - 1] = buf[i];
            buf[i] = c;
        }
    }
}

static inline void amxb_pcb_serialize_tag(peer_info_t* peer,
                                          char tag) {
    static char tagbuf[5] = { 'D', 'D', 'W', DDW_VERSION_01, '\0' };
    tagbuf[4] = tag;
    peer_fwrite(peer, tagbuf, 5, 1);
}

static inline void amxb_pcb_serialize_string(peer_info_t* peer, const char* s) {
    peer_fwrite(peer, s ? s : "", (s ? strlen(s) : 0) + 1, 1);
}

static inline void amxb_pcb_serialize_uint32(peer_info_t* peer, uint32_t u) {
    amxb_pcb_byte_swap((char*) &u, 4);
    peer_fwrite(peer, &u, 1, 4);
}

static inline void amxb_pcb_serialize_uint64(peer_info_t* peer, uint64_t u) {
    amxb_pcb_byte_swap((char*) &u, 8);
    peer_fwrite(peer, &u, 1, 8);
}

static inline void amxb_pcb_serialize_int32(peer_info_t* peer, int32_t i) {
    amxb_pcb_byte_swap((char*) &i, 4);
    peer_fwrite(peer, &i, 1, 4);
}

static inline void amxb_pcb_serialize_int64(peer_info_t* peer, int64_t i) {
    amxb_pcb_byte_swap((char*) &i, 8);
    peer_fwrite(peer, &i, 1, 8);
}

static inline void amxb_pcb_serialize_double(peer_info_t* peer, double d) {
    amxb_pcb_byte_swap((char*) &d, sizeof(double));
    peer_fwrite(peer, &d, 1, sizeof(double));
}

static void amxb_pcb_serialize_variant(peer_info_t* peer, const amxc_var_t* v) {
    int type = amxc_var_type_to_pcb_var_type(amxc_var_type_of(v));
    if(type == variant_type_unknown) {
        if(amxc_var_is_null(v)) {
            amxb_pcb_serialize_uint32(peer, type);
        } else {
            amxb_pcb_serialize_uint32(peer, variant_type_string);
        }
    } else {
        amxb_pcb_serialize_uint32(peer, type);
    }
    switch(type) {
    case variant_type_unknown:
        if(!amxc_var_is_null(v)) {
            char* str = amxc_var_dyncast(cstring_t, v);
            amxb_pcb_serialize_string(peer, str);
            free(str);
        }
        break;
    case variant_type_string:
        amxb_pcb_serialize_string(peer, amxc_var_constcast(cstring_t, v));
        break;
    case variant_type_date_time: {
        char* s = amxc_var_dyncast(cstring_t, v);
        amxb_pcb_serialize_string(peer, s);
        free(s);
        break;
    }
    case variant_type_int8:
    case variant_type_int16:
    case variant_type_int32:
        amxb_pcb_serialize_int32(peer, amxc_var_dyncast(int32_t, v));
        break;
    case variant_type_int64:
        amxb_pcb_serialize_int64(peer, amxc_var_dyncast(int64_t, v));
        break;
    case variant_type_bool:
    case variant_type_uint8:
    case variant_type_uint16:
    case variant_type_uint32:
        amxb_pcb_serialize_uint32(peer, amxc_var_dyncast(uint32_t, v));
        break;
    case variant_type_uint64:
        amxb_pcb_serialize_uint64(peer, amxc_var_dyncast(uint64_t, v));
        break;
    case variant_type_double:
        amxb_pcb_serialize_double(peer, amxc_var_dyncast(double, v));
        break;
    case variant_type_array: {
        const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, v);
        amxc_llist_for_each(it, list) {
            amxb_pcb_serialize_variant(peer, amxc_var_from_llist_it(it));
        }
        amxb_pcb_serialize_uint32(peer, EOV);
        break;
    }
    case variant_type_map: {
        const amxc_htable_t* table = amxc_var_constcast(amxc_htable_t, v);
        amxc_htable_for_each(it, table) {
            amxb_pcb_serialize_variant(peer, amxc_var_from_htable_it(it));
            amxb_pcb_serialize_string(peer, amxc_htable_it_get_key(it));
        }
        amxb_pcb_serialize_uint32(peer, EOV);
        break;
    }
    case variant_type_file_descriptor: {
        int fd = amxc_var_dyncast(fd_t, v);
        peer_attachFd(peer, fd);
    }
    break;
    }
}

static uint32_t amxb_pcb_function_attributes(amxd_function_t* func) {
    uint32_t attributes = 0;
    if((func->attr.templ == 1) && (func->attr.instance == 0)) {
        attributes |= function_attr_template_only;
    }
    if(func->attr.async == 1) {
        attributes |= function_attr_async;
    }

    return attributes;
}

static uint32_t amxb_pcb_function_attributes_v2(amxc_var_t* func) {
    uint32_t attributes = 0;

    if(GETP_BOOL(func, "attributes.template") && !GETP_BOOL(func, "attributes.instance")) {
        attributes |= function_attr_template_only;
    }

    if(GETP_BOOL(func, "attributes.asynchronous")) {
        attributes |= function_attr_async;
    }

    return attributes;
}

static uint32_t amxb_pcb_function_arg_attributes(amxd_func_arg_t* arg) {
    uint32_t attributes = 0;
    if(arg->attr.in == 1) {
        attributes |= argument_attr_in;
    }
    if(arg->attr.out == 1) {
        attributes |= argument_attr_out;
    }
    if(arg->attr.mandatory == 1) {
        attributes |= argument_attr_mandatory;
    }

    return attributes;
}

static uint32_t amxb_pcb_function_arg_attributes_v2(amxc_var_t* arg) {
    uint32_t attributes = 0;
    if(GETP_BOOL(arg, "attributes.in")) {
        attributes |= argument_attr_in;
    }
    if(GETP_BOOL(arg, "attributes.out")) {
        attributes |= argument_attr_out;
    }
    if(GETP_BOOL(arg, "attributes.mandatory")) {
        attributes |= argument_attr_mandatory;
    }

    return attributes;
}

static uint32_t amxb_pcb_parameter_attributes(amxc_var_t* attrs) {
    uint32_t attributes = 0;
    bool read_only = GET_BOOL(attrs, "read-only");
    bool templ = GET_BOOL(attrs, "template");
    bool instance = GET_BOOL(attrs, "instance");
    bool variable = GET_BOOL(attrs, "volatile");
    bool persistent = GET_BOOL(attrs, "persistent");
    bool key = GET_BOOL(attrs, "key");
    if(read_only) {
        attributes |= parameter_attr_read_only;
    }
    if(templ && !instance) {
        attributes |= parameter_attr_template_only;
    }
    if(variable) {
        attributes |= parameter_attr_volatile;
    }
    if(persistent) {
        attributes |= parameter_attr_persistent;
    }
    if(key) {
        attributes |= parameter_attr_key;
    }

    return attributes;
}

static void amxb_pcb_serialize_func_args(peer_info_t* peer,
                                         amxd_function_t* func) {
    amxc_llist_for_each(arg_it, (&func->args)) {
        amxd_func_arg_t* arg = amxc_llist_it_get_data(arg_it, amxd_func_arg_t, it);
        amxb_pcb_serialize_tag(peer, 'A');
        amxb_pcb_serialize_string(peer, arg->name);
        amxb_pcb_serialize_uint32(peer, amxb_pcb_function_arg_attributes(arg));
        amxb_pcb_serialize_uint32(peer, amxc_var_type_to_pcb_func_type(arg->type));
        amxb_pcb_serialize_string(peer, amxc_var_get_type_name_from_id(arg->type));
    }
}

static void amxb_pcb_serialize_func_args_v2(peer_info_t* peer,
                                            amxc_var_t* func) {
    amxc_var_for_each(arg, GET_ARG(func, "arguments")) {
        amxb_pcb_serialize_tag(peer, 'A');
        amxb_pcb_serialize_string(peer, GET_CHAR(arg, "name"));
        amxb_pcb_serialize_uint32(peer, amxb_pcb_function_arg_attributes_v2(arg));
        amxb_pcb_serialize_uint32(peer, amxc_var_type_to_pcb_func_type(GET_UINT32(arg, "type_id")));
        amxb_pcb_serialize_string(peer, amxc_var_get_type_name_from_id(GET_UINT32(arg, "type_id")));
    }
}

static void amxb_pcb_serialize_object_funcs(peer_info_t* peer,
                                            amxd_object_t* const object,
                                            amxd_dm_access_t access) {
    amxc_var_t funcs;
    const amxc_llist_t* lfuncs = NULL;
    amxc_var_init(&funcs);
    amxd_object_list_functions(object, &funcs, access);
    lfuncs = amxc_var_constcast(amxc_llist_t, &funcs);

    amxc_llist_for_each(it, lfuncs) {
        const char* func_name = amxc_var_constcast(cstring_t, amxc_var_from_llist_it(it));
        amxd_function_t* func = amxd_object_get_function(object, func_name);
        if(amxd_function_is_attr_set(func, amxd_fattr_private)) {
            continue;
        }
        amxb_pcb_serialize_tag(peer, 'F');
        amxb_pcb_serialize_string(peer, amxd_function_get_name(func));
        amxb_pcb_serialize_uint32(peer, amxb_pcb_function_attributes(func));             // attributes
        amxb_pcb_serialize_uint32(peer, amxc_var_type_to_pcb_func_type(func->ret_type)); // type
        amxb_pcb_serialize_string(peer, amxc_var_get_type_name_from_id(func->ret_type)); // typename
        amxb_pcb_serialize_string(peer, "");                                             // help description
        amxb_pcb_serialize_func_args(peer, func);
    }

    amxc_var_clean(&funcs);
}

static void amxb_pcb_serialize_object_funcs_v2(peer_info_t* peer,
                                               amxc_var_t* const object) {
    amxc_var_t* funcs = GET_ARG(object, "functions");

    amxc_var_for_each(func, funcs) {
        const char* func_name = amxc_var_key(func);
        amxb_pcb_serialize_tag(peer, 'F');
        amxb_pcb_serialize_string(peer, func_name);
        amxb_pcb_serialize_uint32(peer, amxb_pcb_function_attributes_v2(func)); // attributes
        amxb_pcb_serialize_uint32(peer, GET_UINT32(func, "type_id"));           // type
        amxb_pcb_serialize_string(peer, GET_CHAR(func, "type_name"));           // typename
        amxb_pcb_serialize_string(peer, "");                                    // help description
        amxb_pcb_serialize_func_args_v2(peer, func);
    }
}

static bool amxb_pcb_must_reply_funcs(const amxd_object_t* const object,
                                      uint32_t req_attrs) {

    if((amxd_object_get_type(object) == amxd_object_template) &&
       ((req_attrs & request_getObject_template_info) == 0)) {
        return false;
    }

    if((req_attrs & request_getObject_functions) == 0) {
        return false;
    }

    return true;
}

static bool amxb_pcb_must_reply_funcs_v2(const amxc_var_t* const object,
                                         uint32_t req_attrs) {

    if((GET_UINT32(object, "type_id") == amxd_object_template) &&
       ((req_attrs & request_getObject_template_info) == 0)) {
        return false;
    }

    if((req_attrs & request_getObject_functions) == 0) {
        return false;
    }

    return true;
}

static char* amxb_pcb_get_parent(const amxc_var_t* object, const char* type) {
    amxd_path_t path;
    char* p = NULL;
    char* n = NULL;

    amxd_path_init(&path, GET_CHAR(object, type));
    if(GET_UINT32(object, "type_id") != amxd_object_instance) {
        n = amxd_path_get_last(&path, true);
        p = strdup(amxd_path_get(&path, 0));
    } else {
        p = strdup(amxd_path_get(&path, 0));
    }

    amxd_path_clean(&path);
    free(n);
    if((p != NULL) && (*p == 0)) {
        free(p);
        p = NULL;
    }
    return p;
}

static uint32_t amxb_pcb_object_attributes_v2(amxc_var_t* object) {
    uint32_t attributes = 0;
    if(GETP_BOOL(object, "attributes.read-only")) {
        attributes |= object_attr_read_only;
    }
    if(GET_BOOL(object, "attributes.persistent")) {
        attributes |= object_attr_persistent;
    }
    if(GET_UINT32(object, "type_id") == amxd_object_template) {
        attributes |= object_attr_template;
    } else if(GET_UINT32(object, "type_id") == amxd_object_instance) {
        attributes |= object_attr_instance;
    }

    return attributes;
}

bool amxb_pcb_serialize_object_begin(peer_info_t* peer,
                                     request_t* req,
                                     amxd_object_t* object) {
    amxd_dm_access_t access = amxd_dm_access_public;
    amxd_object_t* parent = amxd_object_get_parent(object);
    char* indexpath = amxd_object_get_path(parent, AMXD_OBJECT_INDEXED);
    char* keypath = amxd_object_get_path(parent, AMXD_OBJECT_NAMED);
    amxc_var_t descr;
    const amxc_htable_t* params = NULL;

    amxb_pcb_serialize_tag(peer, 'O');
    if((request_attributes(req) & AMXB_PCB_PROTECTED_ACCESS) != 0) {
        access = amxd_dm_access_protected;
    }

    amxc_var_init(&descr);
    amxd_object_describe_params(object, &descr, access);
    params = amxc_var_constcast(amxc_htable_t, &descr);

    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_string(peer, indexpath);
    amxb_pcb_serialize_string(peer, keypath);

    amxb_pcb_serialize_string(peer, amxd_object_get_name(object, AMXD_OBJECT_INDEXED));
    amxb_pcb_serialize_string(peer, amxd_object_get_name(object, AMXD_OBJECT_NAMED));
    amxb_pcb_serialize_uint32(peer, amxb_pcb_object_attributes(object));
    amxb_pcb_serialize_uint32(peer, amxc_htable_size(params));                                      // parameter count
    amxb_pcb_serialize_uint32(peer, amxd_object_get_child_count(object));                           // child count
    amxb_pcb_serialize_uint32(peer, amxd_object_get_instance_count(object));                        // instance count
    amxb_pcb_serialize_uint32(peer, amxd_object_get_function_count(object, access));                // function count
    amxb_pcb_serialize_uint32(peer, object_state_ready);                                            // state
    amxb_pcb_serialize_uint32(peer, UINT32_MAX);                                                    // max instances
    amxb_pcb_serialize_string(peer, "");                                                            // help support

    free(indexpath);
    free(keypath);

    if(amxb_pcb_must_reply_funcs(object, request_attributes(req))) {
        amxb_pcb_serialize_object_funcs(peer, object, access);
    }

    amxb_pcb_serialize_tag(peer, 'O');

    amxc_var_clean(&descr);
    return true;
}

bool amxb_pcb_serialize_object_begin_v2(peer_info_t* peer,
                                        request_t* req,
                                        amxc_var_t* object) {
    char* indexpath = amxb_pcb_get_parent(object, "path");
    char* keypath = amxb_pcb_get_parent(object, "object");
    const char* index = GET_CHAR(object, "index") == NULL? GET_CHAR(object, "name"):GET_CHAR(object, "index");
    const char* name = GET_CHAR(object, "name");
    const amxc_htable_t* params = amxc_var_constcast(amxc_htable_t, GET_ARG(object, "parameters"));
    const amxc_htable_t* funcs = amxc_var_constcast(amxc_htable_t, GET_ARG(object, "functions"));
    const amxc_llist_t* objects = amxc_var_constcast(amxc_llist_t, GET_ARG(object, "objects"));
    const amxc_llist_t* instances = amxc_var_constcast(amxc_llist_t, GET_ARG(object, "instances"));
    amxb_pcb_serialize_tag(peer, 'O');

    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_string(peer, indexpath);
    amxb_pcb_serialize_string(peer, keypath);

    amxb_pcb_serialize_string(peer, index);
    amxb_pcb_serialize_string(peer, name);
    amxb_pcb_serialize_uint32(peer, amxb_pcb_object_attributes_v2(object));
    amxb_pcb_serialize_uint32(peer, amxc_htable_size(params));              // parameter count
    amxb_pcb_serialize_uint32(peer, amxc_llist_size(objects));              // child count
    amxb_pcb_serialize_uint32(peer, amxc_llist_size(instances));            // instance count
    amxb_pcb_serialize_uint32(peer, amxc_htable_size(funcs));               // function count
    amxb_pcb_serialize_uint32(peer, object_state_ready);                    // state
    amxb_pcb_serialize_uint32(peer, UINT32_MAX);                            // max instances
    amxb_pcb_serialize_string(peer, "");                                    // help support

    free(indexpath);
    free(keypath);

    if(amxb_pcb_must_reply_funcs_v2(object, request_attributes(req))) {
        amxb_pcb_serialize_object_funcs_v2(peer, object);
    }

    amxb_pcb_serialize_tag(peer, 'O');

    return true;
}

bool amxb_pcb_serialize_object_param(peer_info_t* peer,
                                     request_t* req,
                                     const amxc_var_t* param) {
    amxc_var_t* value = amxc_var_get_key(param, "value", AMXC_VAR_FLAG_DEFAULT);
    amxc_var_t* attrs = amxc_var_get_key(param, "attributes", AMXC_VAR_FLAG_DEFAULT);
    uint32_t type_id = amxc_var_type_of(value);
    const char* name = amxc_var_key(param);
    amxb_pcb_serialize_tag(peer, 'P');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_string(peer, name);
    amxb_pcb_serialize_uint32(peer, amxb_pcb_parameter_attributes(attrs));
    amxb_pcb_serialize_uint32(peer, amxc_var_type_to_pcb_param_type(type_id));
    amxb_pcb_serialize_uint32(peer, parameter_state_ready);
    amxb_pcb_serialize_string(peer, ""); // description
    amxb_pcb_serialize_variant(peer, value);
    amxb_pcb_serialize_tag(peer, 'N');

    return true;
}

bool amxb_pcb_serialize_object_event(peer_info_t* peer,
                                     request_t* req,
                                     const char* event,
                                     amxc_var_t* event_data) {
    amxc_var_cast(event_data, AMXC_VAR_ID_CSTRING);
    amxb_pcb_serialize_tag(peer, 'P');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_string(peer, event);
    amxb_pcb_serialize_uint32(peer, PARAMETER_ATTR_EVENT);
    amxb_pcb_serialize_uint32(peer, amxc_var_type_to_pcb_param_type(amxc_var_type_of(event_data)));
    amxb_pcb_serialize_uint32(peer, parameter_state_ready);
    amxb_pcb_serialize_string(peer, ""); // description
    amxb_pcb_serialize_variant(peer, event_data);
    amxb_pcb_serialize_tag(peer, 'N');

    return true;
}

bool amxb_pcb_serialize_object_end(peer_info_t* peer,
                                   request_t* req) {
    amxb_pcb_serialize_tag(peer, 'Q');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    return true;
}

bool amxb_pcb_serialize_error(peer_info_t* peer,
                              request_t* req,
                              uint32_t error,
                              const char* description,
                              const char* info) {
    amxb_pcb_serialize_tag(peer, 'E');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_uint32(peer, error);
    amxb_pcb_serialize_string(peer, description);
    amxb_pcb_serialize_string(peer, info);
    return true;
}

bool amxb_pcb_serialize_reply_end(peer_info_t* peer,
                                  request_t* req) {
    amxb_pcb_serialize_tag(peer, 'D');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    return true;
}

bool amxb_pcb_serialize_ret_val(peer_info_t* peer,
                                request_t* req,
                                const amxc_var_t* retval) {
    amxb_pcb_serialize_tag(peer, 'V');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_variant(peer, retval);
    return true;
}

bool amxb_pcb_serialize_out_args(peer_info_t* peer,
                                 request_t* req,
                                 amxc_var_t* args) {
    const amxc_htable_t* out_args = amxc_var_constcast(amxc_htable_t, args);
    if(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE) {
        return true;
    }

    amxb_pcb_serialize_tag(peer, 'A');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxc_htable_for_each(it, out_args) {
        amxc_var_t* arg = amxc_var_from_htable_it(it);
        const char* name = amxc_htable_it_get_key(it);
        amxb_pcb_serialize_variant(peer, arg);
        amxb_pcb_serialize_string(peer, name);
    }
    amxb_pcb_serialize_uint32(peer, EOV);
    return true;
}

bool amxb_pcb_serialize_notification(peer_info_t* peer,
                                     request_t* req,
                                     uint32_t type,
                                     const char* name,
                                     const char* object_path,
                                     const amxc_var_t* data) {
    const amxc_htable_t* notification_data = amxc_var_constcast(amxc_htable_t, data);
    amxb_pcb_serialize_tag(peer, 'N');
    amxb_pcb_serialize_uint32(peer, request_id(req));
    amxb_pcb_serialize_uint32(peer, type);
    amxb_pcb_serialize_string(peer, name);
    amxb_pcb_serialize_string(peer, object_path);
    amxc_htable_for_each(it, notification_data) {
        amxc_var_t* param = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        amxb_pcb_serialize_variant(peer, param);
        amxb_pcb_serialize_string(peer, key);
    }
    amxb_pcb_serialize_uint32(peer, EOV);
    return true;
}