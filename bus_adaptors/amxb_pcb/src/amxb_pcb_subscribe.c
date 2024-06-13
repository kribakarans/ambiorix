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



int amxb_pcb_subscribe(void* const ctx,
                       const char* object) {
    int retval = -1;
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;
    request_t* sub_req = NULL;
    amxb_pcb_sub_t* amxb_pcb_sub = NULL;

    // parameters must be requested for pcb mappers, otherwise no events
    // are recieved
    sub_req = request_create_getObject(object,
                                       -1,
                                       request_getObject_parameters |
                                       request_getObject_children |
                                       request_getObject_instances |
                                       request_notify_values_changed |
                                       request_notify_object_added |
                                       request_notify_object_deleted |
                                       request_notify_custom |
                                       request_notify_only |
                                       AMXB_PCB_AMX_EVENTING |
                                       request_no_object_caching |
                                       request_notify_no_updates);

    when_false(pcb_sendRequest(pcb_ctx, peer, sub_req), exit);

    amxb_pcb_sub = (amxb_pcb_sub_t*) calloc(1, sizeof(amxb_pcb_sub_t));
    amxc_htable_insert(&amxb_pcb->subscriptions,
                       object,
                       &amxb_pcb_sub->it);

    amxb_pcb_sub->amxb_pcb = (amxb_pcb_t*) ctx;
    amxb_pcb_sub->sub_req = sub_req;
    amxb_pcb_sub->reference = 1;

    request_setData(sub_req, amxb_pcb_sub);
    request_setReplyItemHandler(sub_req, amxb_pcb_notification);

    retval = 0;

exit:
    if(retval != 0) {
        if(sub_req != NULL) {
            request_destroy(sub_req);
        }
    }

    return retval;
}

int amxb_pcb_unsubscribe(void* const ctx,
                         const char* object) {

    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    amxb_pcb_sub_t* amxb_pcb_sub = NULL;
    amxc_htable_it_t* it = NULL;
    request_t* sub_req = NULL;

    int ret = -1;

    it = amxc_htable_get(&amxb_pcb->subscriptions, object);
    when_null(it, exit);
    amxb_pcb_sub = amxc_htable_it_get_data(it, amxb_pcb_sub_t, it);

    sub_req = amxb_pcb_sub->sub_req;
    amxb_pcb_sub->sub_req = NULL;
    request_setData(sub_req, NULL);
    request_setReplyItemHandler(sub_req, NULL);
    request_destroy(sub_req);
    amxb_pcb_sub->reference--;

    if(amxb_pcb_sub->reference == 0) {
        amxc_htable_it_clean(it, NULL);
        free(amxb_pcb_sub);
    }

    ret = 0;

exit:
    return ret;
}