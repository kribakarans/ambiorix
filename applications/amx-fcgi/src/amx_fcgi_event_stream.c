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
#include <stdlib.h>
#include <string.h>

#include "amx_fcgi.h"

#define HEART_BEAT_TIME     120000 // milli seconds
#define HEART_BEAT_CHECK      5000 // milli seconds
#define HEART_BEAT_START      1000 // milli seconds

static amxc_htable_t streams;
static amxp_timer_t* keep_alive;

static void amx_fcgi_clean_subscription(UNUSED const char* key,
                                        amxc_htable_it_t* it) {
    subscription_t* sub = amxc_container_of(it, subscription_t, it);
    free(sub->acl_file);
    amxb_subscription_delete(&sub->subscription);
    free(sub);
}

static void amx_fcgi_clean_stream(UNUSED const char* key,
                                  amxc_htable_it_t* it) {
    event_stream_t* stream = amxc_container_of(it, event_stream_t, it);
    amxc_htable_it_clean(it, NULL);
    amxc_htable_clean(&stream->subscriptions, amx_fcgi_clean_subscription);
    free(stream);
}

static void amx_fcgi_send_empty(amxp_timer_t* timer, UNUSED void* priv) {
    unsigned int interval = HEART_BEAT_TIME;
    amxc_htable_for_each(it, &streams) {
        event_stream_t* stream = amxc_container_of(it, event_stream_t, it);
        if(stream->fcgi_req == NULL) {
            amxc_htable_it_take(it);
            amx_fcgi_clean_stream(amxc_htable_it_get_key(it), it);
            interval = HEART_BEAT_CHECK;
            continue;
        }
        if(amx_fcgi_send_event(stream->fcgi_req, "heart-beat", NULL) < 0) {
            amx_fcgi_http_close_stream_request(stream);
            interval = HEART_BEAT_CHECK;
        }
    }
    amxp_timer_set_interval(timer, interval);
}

event_stream_t* amx_fcgi_get_stream(const char* stream_id) {
    amxc_htable_it_t* it = amxc_htable_get(&streams, stream_id);
    event_stream_t* stream = NULL;

    when_null(it, exit);
    stream = amxc_container_of(it, event_stream_t, it);

exit:
    return stream;
}

int amx_fcgi_http_open_stream(amx_fcgi_request_t* fcgi_req,
                              UNUSED amxc_var_t* data,
                              UNUSED bool acl_verify) {
    const char* stream_id = fcgi_req->raw_path;
    int status = 200;
    event_stream_t* stream = NULL;
    amxc_htable_it_t* it = amxc_htable_get(&streams, stream_id);

    if(it != NULL) {
        stream = amxc_container_of(it, event_stream_t, it);
        if(stream->fcgi_req != NULL) {
            if(amx_fcgi_send_event(stream->fcgi_req, NULL, NULL) >= 0) {
                // previous stream is still active - duplicates are not allowed
                status = 400;
                goto exit;
            }
            // accept new one - close previous
            amx_fcgi_close(stream->fcgi_req);
            stream->fcgi_req = NULL;
        }
    } else {
        // create new one
        stream = (event_stream_t*) calloc(1, sizeof(event_stream_t));
        when_null_status(stream, exit, status = 500);
        amxc_htable_init(&stream->subscriptions, 10);
        amxc_htable_insert(&streams, stream_id, &stream->it);
    }

    stream->fcgi_req = fcgi_req;

    if(keep_alive == NULL) {
        amxp_timer_new(&keep_alive, amx_fcgi_send_empty, NULL);
        amxp_timer_set_interval(keep_alive, HEART_BEAT_TIME);
        amxp_timer_start(keep_alive, HEART_BEAT_START);
    }

exit:
    return status;
}

void amx_fcgi_http_close_stream_request(event_stream_t* stream) {
    amxc_llist_it_take(&stream->fcgi_req->it);
    FCGX_Free(&stream->fcgi_req->request, true);
    amxd_path_clean(&stream->fcgi_req->path);
    free(stream->fcgi_req);
    stream->fcgi_req = NULL;
}

static void CONSTRUCTOR amx_fcgi_stream_init(void) {
    amxc_htable_init(&streams, 15);
}

static void DESTRUCTOR amx_fcgi_stream_cleanup(void) {
    amxc_htable_clean(&streams, amx_fcgi_clean_stream);
    amxp_timer_delete(&keep_alive);
}