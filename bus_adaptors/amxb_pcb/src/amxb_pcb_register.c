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

static void amxb_pcb_register_args(amxc_var_t* args,
                                   amxd_dm_t* const dm) {
    amxc_var_t* objects = NULL;
    amxc_var_t* attributes = NULL;
    const amxc_var_t* register_name = amxb_pcb_get_config_option("register-name");
    const char* name = "amxb-test";

    if(register_name != NULL) {
        name = amxc_var_constcast(cstring_t, register_name);
        if((name == NULL) || (*name == 0)) {
            name = "amxb-test";
        }
    }

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, args, "name", name);
    amxc_var_add_key(bool, args, "sync", false);
    objects = amxc_var_add_key(amxc_llist_t, args, "objects", NULL);
    attributes = amxc_var_add_key(amxc_llist_t, args, "objectsattr", NULL);
    amxc_var_add_key(uint32_t, args, "tracelevel", 0);
    amxc_var_add_key(amxc_htable_t, args, "tracezones", NULL);
    amxc_var_add_key(cstring_t, args, "namespace", 0);

    amxd_object_for_each(child, it, amxd_dm_get_root(dm)) {
        amxd_object_t* child = amxc_container_of(it, amxd_object_t, it);
        amxc_var_add(cstring_t, objects, amxd_object_get_name(child, AMXD_OBJECT_NAMED));
        amxc_var_add(uint32_t, attributes, amxb_pcb_object_attributes(child));
    }
}

static void amxb_pcb_register_add(UNUSED const char* const sig_name,
                                  const amxc_var_t* const data,
                                  void* const priv) {

    amxb_pcb_t* amxb_pcb_ctx = (amxb_pcb_t*) priv;
    amxd_object_t* object = amxd_dm_signal_get_object(amxb_pcb_ctx->dm, data);
    amxd_object_t* parent = amxd_object_get_parent(object);
    amxc_var_t args;
    amxc_var_init(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    if((object != NULL) && (amxd_object_get_type(parent) == amxd_object_root)) {
        amxc_var_add_key(cstring_t, &args, "Object", amxd_object_get_name(object, 0));
        amxb_pcb_serialize_notification(amxb_pcb_ctx->peer, NULL, notify_application_root_added,
                                        "application_root_added", NULL, &args);
    }
    amxb_pcb_serialize_reply_end(amxb_pcb_ctx->peer, NULL);
    peer_flush(amxb_pcb_ctx->peer);

    amxc_var_clean(&args);
}

static void amxb_pcb_register_remove(UNUSED const char* const sig_name,
                                     const amxc_var_t* const data,
                                     void* const priv) {

    amxb_pcb_t* amxb_pcb_ctx = (amxb_pcb_t*) priv;
    amxd_object_t* object = amxd_dm_signal_get_object(amxb_pcb_ctx->dm, data);
    amxd_object_t* parent = amxd_object_get_parent(object);
    amxc_var_t args;
    amxc_var_init(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    if((object != NULL) && (amxd_object_get_type(parent) == amxd_object_root)) {
        amxc_var_add_key(cstring_t, &args, "Object", amxd_object_get_name(object, 0));
        amxb_pcb_serialize_notification(amxb_pcb_ctx->peer, NULL, notify_application_root_deleted,
                                        "application_root_deleted", NULL, &args);
    }
    amxb_pcb_serialize_reply_end(amxb_pcb_ctx->peer, NULL);
    peer_flush(amxb_pcb_ctx->peer);

    amxc_var_clean(&args);
}

uint32_t amxb_pcb_object_attributes(amxd_object_t* object) {
    uint32_t attributes = 0;
    if(object->attr.read_only == 1) {
        attributes |= object_attr_read_only;
    }
    if(object->attr.persistent == 1) {
        attributes |= object_attr_persistent;
    }
    if(object->type == amxd_object_template) {
        attributes |= object_attr_template;
    } else if(object->type == amxd_object_instance) {
        attributes |= object_attr_instance;
    }

    return attributes;
}

static void amxb_pcb_register_dm(UNUSED const char* const sig_name,
                                 UNUSED const amxc_var_t* const data,
                                 void* const priv) {
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) priv;
    amxd_dm_t* dm = amxb_pcb->dm;
    amxc_var_t args;
    amxc_var_t temp_var;
    amxb_request_t* request = NULL;
    request_t* pcb_req = NULL;
    struct timeval pcb_timeout = {
        .tv_sec = 5,
        .tv_usec = 0
    };

    amxp_slot_disconnect_with_priv(&dm->sigmngr, amxb_pcb_register_dm, priv);

    amxc_var_init(&args);
    amxc_var_init(&temp_var);
    when_failed(amxb_request_new(&request), exit);

    request->result = &temp_var;

    amxb_pcb_register_args(&args, dm);

    when_failed(amxb_pcb_invoke_base(&pcb_req,
                                     "Process",
                                     "register",
                                     &args,
                                     request,
                                     true), exit);

    request_setReplyItemHandler(pcb_req, amxb_pcb_result_data);
    request_setData(pcb_req, request);
    when_false(pcb_sendRequest(pcb_ctx, amxb_pcb->peer, pcb_req), exit);

    amxp_slot_connect(&dm->sigmngr, "dm:root-added", NULL,
                      amxb_pcb_register_add, amxb_pcb);
    amxp_slot_connect(&dm->sigmngr, "dm:root-removed", NULL,
                      amxb_pcb_register_remove, amxb_pcb);
    when_false(pcb_waitForReply(pcb_ctx, pcb_req, &pcb_timeout), exit);

exit:
    request->result = NULL;
    amxb_close_request(&request);
    amxc_var_clean(&args);
    amxc_var_clean(&temp_var);
    if(pcb_req != NULL) {
        request_destroy(pcb_req);
    }
}

int amxb_pcb_register(void* const ctx,
                      amxd_dm_t* const dm) {
    int status = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    const amxc_var_t* cfg_ros = amxb_pcb_get_config_option("register-on-start-event");

    when_not_null(amxb_pcb->dm, exit);
    amxb_pcb->dm = dm;

    if(peer_isListenSocket(amxb_pcb->peer)) {
        status = 0;
        goto exit;
    }

    if(amxc_var_dyncast(bool, cfg_ros)) {
        amxp_slot_connect(&dm->sigmngr,
                          "app:start",
                          NULL,
                          amxb_pcb_register_dm,
                          amxb_pcb);
    } else {
        amxb_pcb_register_dm(NULL, NULL, amxb_pcb);
    }

    status = 0;

exit:
    return status;
}
