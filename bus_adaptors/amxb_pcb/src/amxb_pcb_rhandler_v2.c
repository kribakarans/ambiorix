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

#include <amxc/amxc.h>

#include <amxa/amxa_merger.h>
#include <amxa/amxa_permissions.h>
#include <amxa/amxa_resolver.h>
#include <amxa/amxa_validator.h>

#include <usermngt/usermngt.h>

bool amxb_pcb_get_object_v2(peer_info_t* peer,
                            UNUSED datamodel_t* datamodel,
                            request_t* req) {
    bool retval = false;
    amxc_var_t args;
    amxc_var_init(&args);

    amxb_pcb_build_get_args(&args, req);
    if((request_attributes(req) & request_notify_only) == 0) {
        retval = amxb_pcb_handler_common(peer, req, &args, "_get");
        when_false(retval, exit);
    }
    if((request_attributes(req) & request_notify_all) != 0) {
        amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
        amxb_pcb_t* amxb_pcb = NULL;
        when_null(amxb_bus_ctx, exit);

        amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        retval = amxb_pcb_handler_common(peer, req, &args, "_subscribe");

        amxb_pcb_handle_subscription(req, NULL, amxb_pcb);
    }

exit:
    amxc_var_clean(&args);
    return retval;
}

bool amxb_pcb_set_object_v2(peer_info_t* peer,
                            UNUSED datamodel_t* datamodel,
                            request_t* req) {
    bool retval = false;
    amxc_var_t args;
    amxc_var_init(&args);

    amxb_pcb_build_set_args(&args, req);
    request_setAttributes(req, request_attributes(req) |
                          request_getObject_parameters |
                          request_getObject_instances);
    retval = amxb_pcb_handler_common(peer, req, &args, "_set");

    amxc_var_clean(&args);
    return retval;
}

bool amxb_pcb_add_instance_v2(peer_info_t* peer,
                              UNUSED datamodel_t* datamodel,
                              request_t* req) {
    bool retval = false;
    amxc_var_t args;
    amxc_var_init(&args);

    amxb_pcb_build_add_instance_args(&args, req);
    request_setAttributes(req, request_attributes(req) |
                          request_getObject_parameters |
                          request_getObject_instances);
    retval = amxb_pcb_handler_common(peer, req, &args, "_add");

    amxc_var_clean(&args);
    return retval;
}

bool amxb_pcb_del_instance_v2(peer_info_t* peer,
                              UNUSED datamodel_t* datamodel,
                              request_t* req) {
    bool retval = false;
    amxc_var_t args;
    amxc_var_init(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    retval = amxb_pcb_handler_common(peer, req, &args, "_del");

    amxc_var_clean(&args);
    return retval;
}

bool amxb_pcb_execute_v2(peer_info_t* peer,
                         UNUSED datamodel_t* datamodel,
                         request_t* req) {
    bool retval = false;
    llist_iterator_t* it = request_firstParameter(req);
    amxc_var_t args;
    amxc_var_init(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    if(((request_attributes(req) & request_function_args_by_name) == 0) &&
       (it != NULL)) {
        // troubles in paradise.
        // function arguments are passed in order, need to find the
        // argument names before translation can be done
        retval = amxb_pcb_fetch_function_def(peer, req);
    } else {
        amxb_pcb_build_exec_args(&args, req, NULL);
        retval = amxb_pcb_handler_common(peer, req, &args, "_exec");
    }

    amxc_var_clean(&args);
    return retval;
}