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
#include <dlfcn.h>

#include <amxc/amxc.h>
#include <amxm/amxm.h>

#include "amxm_priv.h"

static amxm_shared_object_t* current_shared_object;

void amxm_so_remove_all_mods(amxm_shared_object_t* so) {
    for(amxc_llist_it_t* it = amxc_llist_get_first(&so->amxm_module_llist); it;) {
        amxm_module_t* mod = amxc_llist_it_get_data(it, amxm_module_t, it);
        it = amxc_llist_it_get_next(it);
        amxm_module_deregister(&mod);
    }
}

int amxm_so_close_internal(amxm_shared_object_t** so) {
    int retval = 0;
    char* no_dl_close = getenv("AMXM_NO_DLCLOSE");
    if((*so)->handle != NULL) {
        dlerror();
        current_shared_object = *so;
        if(no_dl_close == NULL) {
            retval = dlclose((*so)->handle);
        }
        current_shared_object = NULL;
        when_failed(retval, exit);
    }

    amxc_llist_it_take(&(*so)->it);
    amxm_so_remove_all_mods(*so);

    free(*so);
    *so = NULL;

exit:
    return retval;
}

amxm_shared_object_t* amxm_so_get_current(void) {
    return current_shared_object;
}

int amxm_so_open(amxm_shared_object_t** so,
                 const char* shared_object_name,
                 const char* const path_to_so) {
    void* handle = NULL;

    // Clean error state from any previous invocation of dlopen
    amxm_so_error();

    when_null(so, exit);
    when_str_empty(shared_object_name, exit);
    when_str_empty(path_to_so, exit);
    when_str_too_big(shared_object_name, AMXM_SHARED_OBJECT_LENGTH, exit);

    when_not_null(amxm_get_so(shared_object_name), exit);

    *so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    when_null(*so, exit);

    current_shared_object = *so;

    when_failed(amxc_llist_init(&(*so)->amxm_module_llist), exit_free);

    strncpy((*so)->name, shared_object_name, AMXM_MODULE_NAME_LENGTH);
    strncpy((*so)->file, path_to_so, AMXM_MODULE_NAME_LENGTH);

    handle = dlopen(path_to_so, RTLD_LAZY);
    current_shared_object = NULL;
    when_null(handle, exit_free);
    (*so)->handle = handle;

    when_failed(amxm_add_so(*so), exit_dl);

    return 0;

exit_dl:
    dlclose((*so)->handle);
exit_free:
    free(*so);
exit:
    *so = NULL;
    return -1;
}

int amxm_so_close(amxm_shared_object_t** so) {
    int retval = -1;

    when_null(so, exit);
    when_null((*so), exit);

    when_true(!amxm_contains_so(*so), exit);

    retval = amxm_so_close_internal(so);

exit:
    return retval;
}

const char* amxm_so_error(void) {
    return dlerror();
}

size_t amxm_so_count_modules(const amxm_shared_object_t* const shared_object) {
    size_t retval = 0;
    when_null(shared_object, exit);

    retval = amxc_llist_size(&(shared_object->amxm_module_llist));

exit:
    return retval;
}

char* amxm_so_probe(const amxm_shared_object_t* const shared_object, size_t index) {
    amxm_module_t* mod = NULL;
    char* ret = NULL;
    size_t count_of_modules = 0;
    amxc_llist_it_t* it = NULL;

    when_null(shared_object, exit);

    count_of_modules = amxm_so_count_modules(shared_object);
    when_true(index >= count_of_modules, exit);

    it = amxc_llist_get_at(&shared_object->amxm_module_llist, index);

    mod = amxc_llist_it_get_data(it, amxm_module_t, it);
    when_null(mod, exit);

    ret = (char*) calloc(1, AMXM_MODULE_NAME_LENGTH + 1);
    when_null(ret, exit);

    memcpy(ret, mod->name, AMXM_MODULE_NAME_LENGTH);

exit:
    return ret;
}

amxm_module_t* amxm_so_get_module(const amxm_shared_object_t* const shared_object,
                                  const char* const module_name) {
    amxm_module_t* ret = NULL;
    const amxm_shared_object_t* so = shared_object;

    when_null(module_name, exit);
    when_str_empty(module_name, exit);
    when_str_too_big(module_name, AMXM_MODULE_NAME_LENGTH, exit);

    if(shared_object == NULL) {
        so = amxm_get_so("self");
    }
    when_null(so, exit);

    amxc_llist_for_each(it, (&so->amxm_module_llist)) {
        ret = amxc_llist_it_get_data(it, amxm_module_t, it);
        if(strncmp(ret->name, module_name, AMXM_MODULE_NAME_LENGTH) == 0) {
            break;
        }
        ret = NULL;
    }

exit:
    return ret;
}

int amxm_so_remove_function(amxm_shared_object_t* const so,
                            const char* const module_name,
                            const char* const func_name) {
    int retval = -3;
    amxm_module_t* mod = NULL;

    when_null(so, exit);
    when_null(module_name, exit);
    when_str_empty(module_name, exit);

    mod = amxm_so_get_module(so, module_name);
    when_null(mod, exit);

    retval = amxm_module_remove_function(mod, func_name);

exit:
    return retval;
}

int amxm_so_execute_function(amxm_shared_object_t* const so,
                             const char* const module_name,
                             const char* const func_name,
                             amxc_var_t* args,
                             amxc_var_t* ret) {
    int retval = -1;
    amxm_module_t* mod = NULL;

    when_null(so, exit);

    mod = amxm_so_get_module(so, module_name);
    when_null(mod, exit);

    retval = amxm_module_execute_function(mod, func_name, args, ret);

exit:
    return retval;
}

bool amxm_so_has_function(const amxm_shared_object_t* const so,
                          const char* const module_name,
                          const char* const func_name) {

    bool retval = false;
    // No verification of namearguments are done here,
    // the called functions will do the verification anyway
    // see amxm_so_get_module and amxm_module_has_function
    amxm_module_t* mod = NULL;
    when_null(so, exit);

    mod = amxm_so_get_module(so, module_name);
    when_null(mod, exit);

    retval = amxm_module_has_function(mod, func_name);

exit:
    return retval;
}