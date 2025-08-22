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
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_amxrt_load_backends.h"

int test_load_backends_setup(UNUSED void** state) {
    amxrt_new();
    return 0;
}

int test_load_backends_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_can_load_backends(UNUSED void** state) {
    amxo_parser_t* parser = amxrt_get_parser();
    int index = 0; \
    amxc_var_t* backends = NULL;
    const amxc_llist_t* lbackends = NULL;
    char* argv[] = { "amxrt" };

    assert_int_equal(amxrt_config_init(sizeof(argv) / sizeof(argv[0]), argv, &index, NULL), 0);
    amxrt_config_scan_backend_dirs();

    amxc_var_dump(&parser->config, STDOUT_FILENO);
    backends = GET_ARG(&parser->config, "backends");
    assert_non_null(backends);
    lbackends = amxc_var_constcast(amxc_llist_t, backends);
    assert_non_null(lbackends);
    assert_false(amxc_llist_is_empty(lbackends));
}

void test_can_connect_default_sockets(UNUSED void** state) {
    amxo_parser_t* parser = amxrt_get_parser();
    amxc_var_t* uris = NULL;
    const amxc_llist_t* luris = NULL;

    assert_int_equal(amxrt_connect(), 0);
    assert_non_null(amxb_be_get_info("ubus"));
    amxc_var_dump(&parser->config, STDOUT_FILENO);
    uris = GET_ARG(&parser->config, "backends");
    assert_non_null(uris);
    luris = amxc_var_constcast(amxc_llist_t, uris);
    assert_non_null(luris);
    assert_false(amxc_llist_is_empty(luris));
    assert_false(amxc_llist_is_empty(amxp_connection_get_connections()));
}

