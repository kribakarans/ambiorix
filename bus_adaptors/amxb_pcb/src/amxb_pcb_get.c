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


static int amxb_pcb_call_get(void* const ctx,
                             const char* object,
                             const char* search_path,
                             const char* filter,
                             int32_t depth,
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
    if((filter != NULL) && (*filter != 0)) {
        amxc_var_add_key(cstring_t, &args, "filter", filter);
    }
    amxc_var_add_key(int32_t, &args, "depth", depth);
    amxc_var_add_key(uint32_t, &args, "access", access);

    retval = amxb_pcb_invoke_root(ctx, object, "_get", &args, request, true, timeout);

exit:
    request->result = NULL;
    amxb_close_request(&request);
    amxc_var_clean(&args);
    return retval;
}

// The object path must end with '.'
int amxb_pcb_get(void* const ctx,
                 const char* object,
                 const char* search_path,
                 int32_t depth,
                 uint32_t access,
                 amxc_var_t* ret,
                 int timeout) {
    return amxb_pcb_get_filtered(ctx, object, search_path, NULL,
                                 depth, access, ret, timeout);
}

// The object path must end with '.'
int amxb_pcb_get_filtered(void* const ctx,
                          const char* object,
                          const char* search_path,
                          const char* filter,
                          int32_t depth,
                          uint32_t access,
                          amxc_var_t* ret,
                          int timeout) {
    int retval = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    amxc_var_t* resolved_table = NULL;
    bool key_path = false;
    uint32_t flags = RESOLV_PARAMETERS;

    if(access == AMXB_PROTECTED) {
        flags |= RESOLV_TEMPLATES;
    }

    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    resolved_table = amxc_var_add(amxc_htable_t, ret, NULL);
    retval = amxb_pcb_resolve(amxb_pcb, object, search_path, filter,
                              depth, flags, &key_path, resolved_table);
    if(retval == -1) {
        // when amxb_pcb_resolve returns -1 the remote is an ambiorix data model
        // implementation, just call _get method
        amxc_var_clean(ret);
        retval = amxb_pcb_call_get(ctx, object, search_path, filter,
                                   depth, access, ret, timeout);
    } else if(retval == 0) {
        amxb_pcb_cleanup_objects(resolved_table);
    }
    if(retval != 0) {
        amxc_var_clean(ret);
    }

    return retval;
}
