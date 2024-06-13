/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxd/amxd_dm.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb_register.h>
#include <amxb/amxb.h>

#include "utils.h"
#include "check.h"

static void print_version_nr(int32_t nr, const char* delim) {
    if(nr == -1) {
        printf("*%s", delim);
    } else {
        printf("%d%s", nr, delim);
    }
}

void* check_can_load(const char* file) {
    void* handle = NULL;

    print_message(STR_CAN_LOAD);

    handle = dlopen(file, RTLD_LAZY);
    if(handle == NULL) {
        print_error("No\n");
        print_reason(dlerror());
        printf("\n");
    } else {
        print_success("Yes\n");
    }

    return handle;
}

amxb_be_info_fn_t check_is_amxb_backend(void* handle) {
    amxb_be_info_fn_t be_get_info = NULL;

    print_message(STR_IS_BACKEND);

    be_get_info = (amxb_be_info_fn_t) dlsym(handle, "amxb_be_info");
    if(be_get_info == NULL) {
        print_error("No\n");
        print_reason("amxb_be_info function not found");
        printf("\n");
    } else {
        print_success("Yes\n");
    }

    return be_get_info;
}

amxb_be_info_t* check_can_fetch_info(amxb_be_info_fn_t be_get_info) {
    amxb_be_info_t* be_info = NULL;

    print_message(STR_CAN_FETCH_INFO);

    be_info = be_get_info();
    if(be_info == NULL) {
        print_error("No\n");
        print_reason("amxb_be_info returns NULL");
        printf("\n");
    } else {
        print_success("Yes\n");
    }

    return be_info;
}

int check_info_has_name(amxb_be_info_t* info) {
    int retval = -1;

    print_message(STR_INFO_HAS_NAME);

    if(info->name == NULL) {
        print_error("No\n");
        print_reason("[name] field is NULL");
        printf("\n");
    } else if(*(info->name) == 0) {
        print_error("No\n");
        print_reason("[name] field is empty string");
        printf("\n");
    } else {
        print_success("Yes ");
        print_message("[");
        printf("%s", info->name);
        print_message("]\n");
        retval = 0;
    }

    return retval;
}

int check_info_version(const char* msg,
                       const char* field,
                       const amxb_version_t* version) {
    int retval = -1;

    print_message(msg);

    if(version == NULL) {
        print_error("No\n");
        print_reason("Field is NULL");
        print_message("[");
        printf("%s", field);
        print_message("]\n");
    } else {
        print_success("Yes ");
        print_message("[");
        print_version_nr(version->major, ".");
        print_version_nr(version->minor, ".");
        print_version_nr(version->build, "");
        print_message("]\n");
        retval = 0;
    }

    return retval;
}

int check_versions_are_valid(amxb_be_info_t* info) {
    int retval = -1;

    print_message(STR_INFO_MIN_NAX_VALID);

    if(amxb_check_be_versions(info->min_supported, info->max_supported) != 0) {
        print_error("No\n");
        print_reason("major version can not be a wild card or maximum is lower than minimum");
        print_message("\n");
    } else {
        print_success("Yes\n");
        retval = 0;
    }

    return retval;
}

int check_be_is_supported(amxb_be_info_t* info) {
    int retval = -1;
    const amxb_version_t* libv = amxb_get_version();

    print_message(STR_CURRENT_LIBAMXB_VERSION);
    print_version_nr(libv->major, ".");
    print_version_nr(libv->minor, ".");
    print_version_nr(libv->build, "");
    print_message("]\n");

    print_message(STR_BE_IS_SUPPORTED);

    if(amxb_check_version(info->min_supported) < 0) {
        print_error("No\n");
        print_reason("libamxb version is lower than minimum supported");
        print_message("\n");
    } else if(amxb_check_version(info->max_supported) > 0) {
        print_error("No\n");
        print_reason("libamxb version is higher than maximum supported");
        print_message("\n");
    } else {
        print_success("Yes\n");
        retval = 0;
    }

    return retval;
}

int check_amxb_can_load(const char* file) {
    int retval = -1;

    print_message(STR_AMXB_CAN_LOAD);

    retval = amxb_be_load(file);
    if(retval != 0) {
        print_error("No\n");
        print_reason("Function table not compatible - please recompile backend");
        print_message("\n");
    } else {
        print_success("Yes\n");
    }

    return retval;
}

amxb_be_funcs_t* check_be_registers_function_table(const char* name) {
    amxb_be_funcs_t* func_table = NULL;

    print_message(STR_BACKEND_REGISTERS_FUNCT);

    func_table = amxb_be_find(name);
    if(func_table == NULL) {
        print_error("No\n");
        print_reason("Function table name does not match info name");
        print_message("\n");
    } else if(func_table->handle == NULL) {
        print_error("No\n");
        print_reason("No  handle set - unexpected internal error");
        print_message("\n");
    } else {
        print_success("Yes\n");
    }

    return func_table;
}

int check_be_supports_fn(const char* funcname,
                         void* funcptr,
                         bool mandatory) {
    int retval = -1;

    print_message(STR_BACKEND_SUPPORTS_FUNC);

    if(funcptr == NULL) {
        print_error("No  ");
        print_message("[");
        printf("%s", funcname);
        print_message("]\n");
        print_reason("Function pointer is NULL");
        print_message("\n");
        if(mandatory) {
            print_error("Function must be implemented");
        }
        retval = 0;
    } else {
        print_success("Yes ");
        print_message("[");
        printf("%s", funcname);
        print_message("]\n");
        retval = 0;
    }
    return retval;
}