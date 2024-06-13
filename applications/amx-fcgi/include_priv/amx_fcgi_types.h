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

#if !defined(__AMX_FCGI_TYPES_H__)
#define __AMX_FCGI_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <fcgiapp.h>
#include <fcgios.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>

#include <yajl/yajl_gen.h>
#include <amxj/amxj_variant.h>

#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include <amxo/amxo.h>

#include <amxb/amxb.h>

#include "amxa/amxa_get.h"
#include <amxa/amxa_merger.h>
#include <amxa/amxa_validator.h>
#include <amxa/amxa_permissions.h>
#include <amxa/amxa_resolver.h>

#include <amxm/amxm.h>

typedef enum _request_method {
    METHOD_UNSUPORTED,
    METHOD_POST_PATH,                    // add
    METHOD_GET_PATH,                     // get
    METHOD_PATCH,                        // set
    METHOD_DELETE,                       // del
    METHOD_POST_CMD,                     // invoke (operate) (TODO async invoke)
    METHOD_OPEN_STREAM,                  // Open event stream
    METHOD_SUBSCRIBE,                    // Subscribe for events
    METHOD_UNSUBSCRIBE,                  // Unsubscribe
    METHOD_SE_BATCH,                     //
    METHOD_POST_UPLOAD,                  // upload file
    METHOD_GET_DOWNLOAD,                 // download file
    METHOD_SESSION_LOGIN,                // create websession
    METHOD_SESSION_LOGOUT,               // delete websession
    METHOD_LAST = METHOD_SESSION_LOGOUT, // last method
} request_method_t;

typedef struct _amx_fcgi {
    amxd_dm_t* dm;
    amxo_parser_t* parser;
    int socket;
    amxc_llist_t requests;
} amx_fcgi_t;

typedef struct _amx_fcgi_request {
    FCGX_Request request;
    request_method_t method;
    const char* raw_path;
    const char* info;
    amxd_path_t path;
    uint32_t event_id;
    amxc_llist_it_t it;
    bool authorized;
    amxc_var_t roles;
} amx_fcgi_request_t;

typedef enum _event_type {
    EV_IGNORE,
    EV_VALUE_CHANGED,
    EV_OBJECT_CREATED,
    EV_OBJECT_DELETED,
    EV_OPERATION_COMPLETED,
    EV_EVENT,
    EV_ERROR,
} event_type_t;

typedef struct _event_stream {
    amx_fcgi_request_t* fcgi_req;
    amxc_htable_t subscriptions;
    amxc_htable_it_t it;
} event_stream_t;

typedef struct _subscription {
    amxb_subscription_t* subscription;
    char* acl_file;
    amxc_htable_it_t it;
} subscription_t;

typedef int (* amx_fcgi_func_t) (amx_fcgi_request_t* fcgi_req,
                                 amxc_var_t* data,
                                 bool acl_verify);

#ifdef __cplusplus
}
#endif

#endif // __AMX_FCGI_TYPES_H__