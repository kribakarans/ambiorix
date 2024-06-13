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
#include <getopt.h>
#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>

#include "test_amxo_config.h"
#include "amxo_xml_to.h"

static bool test_verify_data(const amxc_var_t* data, const char* field, const char* value) {
    bool rv = false;
    char* field_value = NULL;
    amxc_var_t* field_data = GETP_ARG(data, field);

    printf("Verify event data: check field [%s] contains [%s]\n", field, value);
    fflush(stdout);
    when_null(field_data, exit);

    field_value = amxc_var_dyncast(cstring_t, field_data);
    when_null(field_value, exit);

    rv = (strcmp(field_value, value) == 0);

exit:
    free(field_value);
    return rv;
}

static void amxo_xml_set_test_config(amxc_var_t* config) {
    amxc_var_add_key(cstring_t, config, "cfg-dir", "./");
    amxc_var_add_key(cstring_t, config, "cfg-file", "default.conf");
    amxc_var_add_key(cstring_t, config, "output-dir", "./");
}

void test_xml_join_config(UNUSED void** state) {
    amxc_var_t config;

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);
    amxo_xml_set_test_config(&config);

    amxo_xml_join_config(&config);

    assert_true(test_verify_data(&config, "cfg-dir", "./"));
    assert_true(test_verify_data(&config, "cfg-file", "default.conf"));
    assert_true(test_verify_data(&config, "output-dir", "./"));
    assert_true(test_verify_data(&config, "sub-title", "Data Model"));
    assert_true(test_verify_data(&config, "title", "SoftAtHome"));
    assert_true(test_verify_data(&config, "version", "1.0.0"));

    amxc_var_clean(&config);
}
