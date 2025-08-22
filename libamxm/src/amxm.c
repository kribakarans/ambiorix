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
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <amxc/amxc.h>
#include <amxm/amxm.h>

#include "amxm_priv.h"

/**
   @file
   @brief
   Ambiorix module API implementation
 */

static amxc_llist_t amxm_so_llist;

static void amxm_close_it(amxc_llist_it_t* it) {
    amxm_shared_object_t* so = amxc_htable_it_get_data(it, amxm_shared_object_t, it);
    amxm_so_close_internal(&so);
}

int amxm_add_so(amxm_shared_object_t* const so) {
    int retval = amxc_llist_append(&amxm_so_llist, &so->it);
    return retval;
}

bool amxm_contains_so(const amxm_shared_object_t* const so) {
    amxm_shared_object_t* reg_so = NULL;

    amxc_llist_for_each(it, (&amxm_so_llist)) {
        reg_so = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(reg_so == so) {
            break;
        }
        reg_so = NULL;
    }

    return (reg_so != NULL);
}

int amxm_close_so(const char* const shared_object_name) {
    int retval = -2;
    amxm_shared_object_t* so = NULL;

    when_str_empty(shared_object_name, exit);
    when_str_too_big(shared_object_name, AMXM_SHARED_OBJECT_LENGTH, exit);

    so = amxm_get_so(shared_object_name);
    when_null(so, exit);

    retval = amxm_so_close(&so);

exit:
    return retval;
}

int amxm_close_all(void) {
    int retval = 0;

    amxc_llist_clean(&amxm_so_llist, amxm_close_it);

    return retval;
}

const amxc_llist_t* amxm_get_so_list(void) {
    return &amxm_so_llist;
}

amxm_shared_object_t* amxm_get_so(const char* const shared_object_name) {
    amxm_shared_object_t* ret = NULL;
    const char* so_name = shared_object_name;

    if((so_name == NULL) || (*so_name == 0)) {
        so_name = "self";
    }

    amxc_llist_for_each(it, (&amxm_so_llist)) {
        ret = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(strncmp(ret->name, so_name, AMXM_MODULE_NAME_LENGTH) == 0) {
            break;
        }
        ret = NULL;
    }

    return ret;
}

amxm_module_t* amxm_get_module(const char* const shared_object_name,
                               const char* const module_name) {

    amxm_module_t* ret = NULL;
    // No verification of arguments are done here,
    // the called functions will do the verification anyway
    // see amxm_get_so and amxm_so_get_module
    amxm_shared_object_t* so = amxm_get_so(shared_object_name);
    when_null(so, exit);

    ret = amxm_so_get_module(so, module_name);

exit:
    return ret;
}

int amxm_execute_function(const char* const shared_object_name,
                          const char* const module_name,
                          const char* const func_name,
                          amxc_var_t* args,
                          amxc_var_t* ret) {
    int error = -1;
    // No verification of arguments are done here,
    // the called functions will do the verification anyway
    // see amxm_get_so and amxm_so_execute_function
    amxm_shared_object_t* so = amxm_get_so(shared_object_name);
    when_null(so, exit);

    error = amxm_so_execute_function(so, module_name, func_name, args, ret);

exit:
    return error;
}

bool amxm_has_function(const char* const shared_object_name,
                       const char* const module_name,
                       const char* const func_name) {
    bool retval = false;
    amxm_shared_object_t* so = NULL;
    // No verification of arguments are done here,
    // the called functions will do the verification anyway
    // see amxm_get_so and amxm_so_has_function

    so = amxm_get_so(shared_object_name);
    when_null(so, exit);

    retval = amxm_so_has_function(so, module_name, func_name);

exit:
    return retval;
}

static AMXM_CONSTRUCTOR amxm_register_self(void) {
    amxm_shared_object_t* so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    when_null(so, exit_free);

    when_failed(amxc_llist_init(&so->amxm_module_llist), exit_free);

    strncpy(so->name, "self", AMXM_MODULE_NAME_LENGTH);
    strncpy(so->file, ".", AMXM_MODULE_NAME_LENGTH);

    when_failed(amxc_llist_append(&amxm_so_llist, &so->it), exit_free);

    return 0;

exit_free:
    free(so);
    return -1;
}

static AMXM_DESTRUCTOR amxm_deregister_self(void) {
    amxm_shared_object_t* so = amxm_get_so("self");
    amxm_so_close(&so);
    return 0;
}