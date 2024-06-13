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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include "common_mock.h"

void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

void amxm_test_so_remove_mod(amxc_llist_it_t* it) {
    amxm_module_t* mod = amxc_llist_it_get_data(it, amxm_module_t, it);
    amxm_module_deregister(&mod);
}

int test_check_completion_list(const long unsigned d, const long unsigned c) {
    amxc_var_t* data = (amxc_var_t*) d;
    amxc_var_t* check_data = (amxc_var_t*) c;

    uint32_t index = 0;
    uint32_t size = 0;
    const char* check_string = NULL;
    const char* string = NULL;
    const amxc_llist_t* check_list = NULL;
    const amxc_llist_t* list = NULL;

    printf("Received completion list =\n");
    fflush(stdout);
    amxc_var_dump(data, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_LIST);

    list = amxc_var_constcast(amxc_llist_t, data);
    check_list = amxc_var_constcast(amxc_llist_t, check_data);
    size = amxc_llist_size(check_list);
    assert_int_equal(amxc_llist_size(list), size);

    for(index = 0; index < size; index++) {
        string = GETI_CHAR(data, index);
        check_string = GETI_CHAR(check_data, index);

        assert_string_equal(string, check_string);
    }

    return 1;
}

void test_complete_cb(const char* const sig_name, const amxc_var_t* const data, void* const priv) {
    assert_string_equal(sig_name, "tty:docomplete");
    assert_null(priv);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_LIST);
    check_expected(data);
}
