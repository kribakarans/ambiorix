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


static int amxb_pcb_call_del(void* const ctx,
                             const char* object,
                             const char* search_path,
                             uint32_t index,
                             const char* name,
                             uint32_t access,
                             amxc_var_t* ret,
                             int timeout) {
    int retval = -1;
    amxc_var_t args;
    amxb_request_t* request = NULL;

    amxc_var_init(&args);
    when_failed(amxb_request_new(&request), exit);

    request->result = ret;

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", search_path);
    amxc_var_add_key(uint32_t, &args, "index", index);
    amxc_var_add_key(cstring_t, &args, "name", name);
    amxc_var_add_key(uint32_t, &args, "access", access);

    retval = amxb_pcb_invoke_root(ctx, object, "_del", &args, request, true, timeout);

    if(retval == 0) {
        amxc_var_t* result = GETI_ARG(ret, 0);
        amxc_var_take_it(result);
        amxc_var_move(ret, result);
        amxc_var_delete(&result);
    }

exit:
    request->result = NULL;
    amxb_close_request(&request);
    amxc_var_clean(&args);
    return retval;
}

static void amxb_pcb_fill_deleted(object_t* pcb_object,
                                  amxc_var_t* var,
                                  void* priv) {
    uint32_t* flags = (uint32_t*) priv;
    char* object = object_pathChar(pcb_object, *flags);
    amxd_path_t path;

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);
    amxc_var_add(cstring_t, var, amxd_path_get(&path, AMXD_OBJECT_TERMINATE));

    free(object);
    amxd_path_clean(&path);
    return;
}

static int amxb_pcb_collect_deleted(amxb_pcb_t* pcb_ctx,
                                    char* object,
                                    uint32_t flags,
                                    amxc_var_t* ret) {
    request_t* req = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = pcb_ctx->peer;
    int retval = 0;

    req = request_create_getObject(object, UINT32_MAX,
                                   flags |
                                   request_no_object_caching);

    retval = amxb_pcb_fetch_object(pcb, peer, req, ret, amxb_pcb_fill_deleted, &flags);
    request_destroy(req);

    return retval;

}

static int amxb_pcb_send_del_request(amxb_pcb_t* pcb_ctx,
                                     bool key_path,
                                     char* object,
                                     amxc_var_t* ret) {
    request_t* req = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = pcb_ctx->peer;
    int retval = 0;
    amxc_var_t del_objs;
    uint32_t flags = key_path ? request_common_path_key_notation : 0;

    amxc_var_init(&del_objs);
    amxc_var_set_type(&del_objs, AMXC_VAR_ID_LIST);

    amxb_pcb_collect_deleted(pcb_ctx, object, flags, &del_objs);

    req = request_create_deleteInstance(object,
                                        request_no_object_caching | flags);

    retval = amxb_pcb_fetch_object(pcb, peer, req, NULL, NULL, NULL);
    request_destroy(req);

    if(retval == 0) {
        amxc_var_for_each(var, (&del_objs)) {
            amxc_llist_append(&ret->data.vl, &var->lit);
        }
    } else {
        retval = 0;
    }

    amxc_var_clean(&del_objs);
    return retval;
}

static int amxb_pcb_build_obj_path(const char* path,
                                   bool* key_path,
                                   uint32_t obj_type,
                                   uint32_t index,
                                   const char* name,
                                   char** obj_path) {
    int retval = 0;
    amxc_string_t strpath;
    *obj_path = NULL;
    amxc_string_init(&strpath, 128);

    if(obj_type == amxd_object_instance) {
        amxc_string_set(&strpath, path);
        *obj_path = amxc_string_take_buffer(&strpath);
    } else if(obj_type == amxd_object_template) {
        if((name != NULL) && (*name != 0)) {
            *key_path = false;
            amxc_string_setf(&strpath, "%s$%s", path, name);
            *obj_path = amxc_string_take_buffer(&strpath);
        } else if(index != 0) {
            *key_path = false;
            amxc_string_setf(&strpath, "%s%d", path, index);
            *obj_path = amxc_string_take_buffer(&strpath);
        } else {
            retval = amxd_status_invalid_arg;
        }
    } else {
        retval = amxd_status_invalid_path;
    }

    amxc_string_clean(&strpath);

    return retval;
}

static int amxb_pcb_check_resolved(amxb_pcb_t* amxb_pcb,
                                   bool key_path,
                                   amxc_var_t* resolved_table,
                                   uint32_t index,
                                   const char* name,
                                   amxc_var_t* ret) {
    int retval = 0;
    const amxc_htable_t* tres = amxc_var_constcast(amxc_htable_t, resolved_table);

    amxc_htable_for_each(it, tres) {
        const char* path = amxc_htable_it_get_key(it);
        amxc_var_t* obj = amxc_var_from_htable_it(it);
        uint32_t obj_type = GET_UINT32(obj, "%type_id");
        char* obj_path = NULL;

        retval = amxb_pcb_build_obj_path(path, &key_path, obj_type, index, name, &obj_path);
        if(retval != 0) {
            free(obj_path);
            continue;
        }
        retval = amxb_pcb_send_del_request(amxb_pcb, key_path, obj_path, ret);
        if(retval != 0) {
            free(obj_path);
            continue;
        }
        free(obj_path);
    }

    return retval;
}

static int amxb_pcb_del_is_valid_path(amxb_pcb_t* amxb_pcb,
                                      const char* object,
                                      const char* search_path) {
    amxd_path_t path;
    char* last = NULL;
    const char* temp_path = NULL;
    amxc_var_t resolved_table;
    bool key_path = false;
    int retval = 0;
    bool is_valid = true;

    amxc_var_init(&resolved_table);
    amxc_var_set_type(&resolved_table, AMXC_VAR_ID_HTABLE);

    amxd_path_init(&path, search_path);
    last = amxd_path_get_last(&path, true);
    free(last);
    last = NULL;

    temp_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
    retval = amxb_pcb_resolve(amxb_pcb, object, temp_path, NULL, 0,
                              RESOLV_EXACT_DEPTH | RESOLV_PARAMETERS | RESOLV_TEMPLATES,
                              &key_path, &resolved_table);
    if(retval == 0) {
        const amxc_htable_t* tres = amxc_var_constcast(amxc_htable_t, &resolved_table);

        amxc_htable_for_each(it, tres) {
            amxc_var_t* obj = amxc_var_from_htable_it(it);
            uint32_t obj_type = GET_UINT32(obj, "%type_id");
            is_valid &= (obj_type == amxd_object_template);
        }
    }

    if(!is_valid) {
        retval = amxd_status_object_not_found;
    }

    amxc_var_clean(&resolved_table);
    amxd_path_clean(&path);
    return retval;
}

int amxb_pcb_del(void* const ctx,
                 const char* object,
                 const char* search_path,
                 uint32_t index,
                 const char* name,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout) {
    int retval = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    amxc_var_t resolved_table;
    bool key_path = false;

    amxc_var_init(&resolved_table);
    amxc_var_set_type(&resolved_table, AMXC_VAR_ID_HTABLE);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);

    retval = amxb_pcb_resolve(amxb_pcb, object, search_path, NULL, 0,
                              RESOLV_EXACT_DEPTH | RESOLV_PARAMETERS | RESOLV_TEMPLATES,
                              &key_path, &resolved_table);
    if(retval == amxd_status_object_not_found) {
        retval = amxb_pcb_del_is_valid_path(amxb_pcb, object, search_path);
    } else if(retval == -1) {
        retval = amxb_pcb_call_del(ctx, object, search_path, index,
                                   name, access, ret, timeout);
    } else if(retval == 0) {
        retval = amxb_pcb_check_resolved(amxb_pcb, false, &resolved_table, index, name, ret);
    }

    if(retval != 0) {
        amxc_var_clean(ret);
    }

    amxc_var_clean(&resolved_table);

    return retval;
}
