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
#include <stdlib.h>
#include <dlfcn.h>

#include <amxc/amxc.h>
#include <amxm/amxm.h>

#include "amxm_priv.h"

static void function_cb_htable_it_free(UNUSED const char* key, amxc_htable_it_t* it) {
    amxm_function_callback_t* cb = NULL;

    cb = amxc_htable_it_get_data(it, amxm_function_callback_t, it);
    free(cb);
}

static amxm_function_callback_t* amxm_function_callback_get(const amxc_htable_t* const func_htable,
                                                            const char* const function_name) {
    const char* key = NULL;
    amxm_function_callback_t* ret = NULL;
    amxc_htable_it_t* it = NULL;

    it = amxc_htable_get(func_htable, function_name);
    when_null(it, exit);

    key = amxc_htable_it_get_key(it);
    when_str_empty(key, exit);

    ret = amxc_htable_it_get_data(it, amxm_function_callback_t, it);

exit:
    return ret;
}

static inline amxc_htable_t* amxm_function_htable_get(amxm_module_t* mod) {
    return &mod->amxm_function_htable;
}


int amxm_module_register(amxm_module_t** mod,
                         amxm_shared_object_t* const shared_object,
                         const char* const module_name) {
    int err = -1;
    amxm_shared_object_t* so = shared_object;

    when_null(mod, exit);
    when_str_empty(module_name, exit);
    when_str_too_big(module_name, AMXM_MODULE_NAME_LENGTH, exit);

    if(so == NULL) {
        so = amxm_get_so("self");
    }
    when_null(so, exit);

    when_not_null(amxm_so_get_module(so, module_name), exit);

    *mod = (amxm_module_t*) calloc(1, sizeof(amxm_module_t));
    when_null(*mod, exit);
    strncpy((*mod)->name, module_name, AMXM_MODULE_NAME_LENGTH);

    err = amxc_llist_append(&so->amxm_module_llist, &(*mod)->it);
    when_failed(err, exit_free);

    err = amxc_htable_init(&(*mod)->amxm_function_htable, 0);
    when_failed(err, exit);
    amxc_htable_set_hash_func(&(*mod)->amxm_function_htable, amxc_DJB_hash);

    return 0;

exit_free:
    free(*mod);
exit:
    if(mod != NULL) {
        *mod = NULL;
    }
    return err;
}

int amxm_module_deregister(amxm_module_t** mod) {
    int retval = -1;
    when_null(mod, exit);
    when_null(*mod, exit);

    amxc_llist_it_take(&(*mod)->it);
    amxc_htable_clean(&(*mod)->amxm_function_htable, function_cb_htable_it_free);
    free(*mod);
    *mod = NULL;

    retval = 0;

exit:
    return retval;
}

int amxm_module_add_function(amxm_module_t* const mod,
                             const char* const func_name,
                             amxm_callback_t cb) {
    int err = -1;
    amxm_function_callback_t* func_cb = NULL;

    when_str_empty(func_name, exit);
    when_str_too_big(func_name, AMXM_FUNCTION_NAME_LENGTH, exit);

    when_null(mod, exit);

    // check if function already exists in htable
    func_cb = amxm_function_callback_get(&mod->amxm_function_htable, func_name);
    if(func_cb) {
        // yes --> overwrite callback pointer
        // overwriting with NULL is possible
        func_cb->function_cb = cb;
    } else {
        // no --> new function cb
        when_null(cb, exit);
        // create structure that goes into htable
        func_cb = (amxm_function_callback_t*) calloc(1, sizeof(amxm_function_callback_t));
        when_null(func_cb, exit);

        func_cb->function_cb = cb;
        strncpy(func_cb->function_name, func_name, AMXM_FUNCTION_NAME_LENGTH);

        when_failed(amxc_htable_insert(&mod->amxm_function_htable,
                                       func_cb->function_name,
                                       &func_cb->it), exit);
    }

    err = 0;

exit:
    if(err != 0) {
        free(func_cb);
    }
    return err;
}

int amxm_module_remove_function(amxm_module_t* const mod,
                                const char* const func_name) {
    int retval = -2;
    amxc_htable_t* ht = NULL;
    amxm_function_callback_t* cb = NULL;

    when_null(mod, exit);
    when_null(func_name, exit);
    when_str_empty(func_name, exit);
    when_str_too_big(func_name, AMXM_FUNCTION_NAME_LENGTH, exit);

    ht = amxm_function_htable_get(mod);
    when_null(mod, exit);

    cb = amxm_function_callback_get(ht, func_name);
    when_null(cb, exit);

    amxc_htable_it_clean(&(cb->it), function_cb_htable_it_free);

    retval = 0;

exit:
    return retval;
}

int amxm_module_execute_function(amxm_module_t* mod,
                                 const char* const func_name,
                                 amxc_var_t* args,
                                 amxc_var_t* ret) {
    int error = -1;
    amxm_callback_t cb;
    amxc_htable_t* func_htable = NULL;
    amxm_function_callback_t* function_cb = NULL;

    when_str_empty(func_name, exit);
    when_str_too_big(func_name, AMXM_FUNCTION_NAME_LENGTH, exit);

    when_null(args, exit);
    when_null(ret, exit);
    when_null(mod, exit);

    func_htable = amxm_function_htable_get(mod);
    when_null(func_htable, exit);

    function_cb = amxm_function_callback_get(func_htable, func_name);
    when_null(function_cb, exit);

    cb = function_cb->function_cb;
    when_null(cb, exit);

    error = cb(func_name, args, ret);

exit:
    return error;
}

bool amxm_module_has_function(amxm_module_t* mod,
                              const char* const func_name) {
    bool retval = false;
    amxc_htable_t* func_htable = NULL;

    when_str_empty(func_name, exit);
    when_str_too_big(func_name, AMXM_FUNCTION_NAME_LENGTH, exit);
    when_null(mod, exit);

    func_htable = amxm_function_htable_get(mod);

    retval = amxc_htable_contains(func_htable, func_name);

exit:
    return retval;
}

amxc_array_t* amxm_module_get_function_names(amxm_module_t* mod) {
    amxc_array_t* names = NULL;
    amxc_htable_t* func_htable = NULL;

    when_null(mod, exit);

    func_htable = amxm_function_htable_get(mod);
    names = amxc_htable_get_sorted_keys(func_htable);

exit:
    return names;
}