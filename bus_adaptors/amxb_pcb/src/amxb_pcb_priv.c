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

static void amxb_pcb_empty_queue(const amxc_var_t* const data, UNUSED void* const priv) {
    int fd = amxc_var_constcast(fd_t, data);
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    peer_info_t* peer = NULL;
    when_null(pcb_ctx, exit);

    peer = connection_find(pcb_connection(pcb_ctx), fd);
    when_null(peer, exit);

    if(peer_needRead(peer)) {
        peer_handleRead(peer);
    }

exit:
    return;
}

static void amxb_pcb_object_is_amx(object_t* pcb_object,
                                   amxc_var_t* var,
                                   UNUSED void* priv) {
    function_t* func = NULL;
    int amx_counter = 0;

    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);

    object_for_each_function(func, pcb_object) {
        const char* name = function_name(func);
        if(strcmp(name, "_list") == 0) {
            amx_counter++;
            continue;
        }
        if(strcmp(name, "_describe") == 0) {
            amx_counter++;
            continue;
        }
        if(strcmp(name, "_get") == 0) {
            function_argument_t* arg = function_firstArgument(func);
            if(arg == NULL) {
                continue;
            }
            name = argument_name(arg);
            if(strcmp(name, "rel_path") == 0) {
                amx_counter++;
            }
        }
    }

    amxc_var_set(bool, var, (amx_counter == 3));
}

int amxb_pcb_fetch_object(pcb_t* pcb_ctx,
                          peer_info_t* peer,
                          request_t* req,
                          amxc_var_t* data,
                          amxb_pcb_convert_t fn,
                          void* priv) {
    reply_t* reply = NULL;
    reply_item_t* item = NULL;
    int retval = 0;

    struct timeval pcb_timeout = {
        .tv_sec = 5,
        .tv_usec = 0
    };

    pcb_sendRequest(pcb_ctx, peer, req);
    if(!pcb_waitForReply(pcb_ctx, req, &pcb_timeout)) {
        retval = -1;
        goto exit;
    }

    reply = request_reply(req);

    reply_sort_object_name(reply);

    reply_for_each_item(item, reply) {
        if(reply_item_type(item) == reply_type_error) {
            if((reply_item_error(item) & 0x10000000) != 0) {
                retval = reply_item_error(item);
            } else if(retval == 0) {
                retval = reply_item_error(item);
            }
            break;
        }
        if(reply_item_type(item) != reply_type_object) {
            continue;
        }
        if(fn != NULL) {
            fn(reply_item_object(item), data, priv);
        }
    }

exit:
    if(retval != 0) {
        if(retval & 0x10000000) {
            retval &= 0x0000FFFF;
        } else {
            retval = amxb_pcb_error_to_amxd_status(retval);
        }
    }

    if(peer_needRead(peer)) {
        amxc_var_t fd;
        amxc_var_init(&fd);
        amxc_var_set(fd_t, &fd, peer_getFd(peer));
        amxp_sigmngr_deferred_call(NULL, amxb_pcb_empty_queue, &fd, NULL);
        amxc_var_clean(&fd);
    }

    return retval;
}

bool amxb_pcb_remote_is_amx(pcb_t* pcb_ctx,
                            peer_info_t* peer,
                            const char* object,
                            int* status) {
    bool is_amx = false;
    request_t* req = NULL;
    amxc_var_t var;

    amxc_var_init(&var);
    req = request_create_getObject(object,
                                   0,
                                   request_common_path_key_notation |
                                   request_getObject_functions |
                                   request_getObject_template_info |
                                   request_no_object_caching |
                                   AMXB_PCB_PROTECTED_ACCESS); // protected

    *status = amxb_pcb_fetch_object(pcb_ctx,
                                    peer,
                                    req,
                                    &var,
                                    amxb_pcb_object_is_amx,
                                    NULL);

    amxb_pcb_request_destroy(req);

    is_amx = amxc_var_constcast(bool, &var);
    amxc_var_clean(&var);
    return is_amx;
}

void amxb_pcb_cleanup_objects(amxc_var_t* resolved_table) {
    const amxc_htable_t* htobjects = amxc_var_constcast(amxc_htable_t, resolved_table);
    amxc_htable_for_each(it, htobjects) {
        amxc_var_t* obj = amxc_var_from_htable_it(it);
        amxc_var_t* meta = amxc_var_get_key(obj, "%attributes", AMXC_VAR_FLAG_DEFAULT);
        amxc_var_delete(&meta);
        meta = amxc_var_get_key(obj, "%type_id", AMXC_VAR_FLAG_DEFAULT);
        amxc_var_delete(&meta);
    }
}

void amxb_pcb_request_destroy(request_t* req) {
    if(req != NULL) {
        if(request_state(req) != request_state_destroy) {
            request_destroy(req);
        }
        request_destroy(req);
    }
}
